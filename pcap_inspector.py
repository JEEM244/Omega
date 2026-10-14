#!/usr/bin/env python3
"""WireLab: bounded offline PCAP/PCAPNG reader for OMEGA."""
import argparse, ipaddress, json, socket, struct, sys
from collections import Counter
MAX_BLOCK=16*1024*1024

def result(protocol="OTHER",src="",dst="",info="",details="",src_port=None,dst_port=None,app_protocol=""):
    return {"protocol":protocol,"src":src,"dst":dst,"src_port":src_port,"dst_port":dst_port,"app_protocol":app_protocol,"info":info,"details":details}

def decode_dns(data):
    if len(data)<12:return "DNS header truncated",""
    tx,flags,qd,an,ns,ar=struct.unpack("!HHHHHH",data[:12]); kind="response" if flags&0x8000 else "query"
    return f"DNS {kind}",f"id=0x{tx:04x}, questions={qd}, answers={an}"

def decode_transport(frame,off,proto,src,dst,end):
    end=min(end,len(frame))
    if proto==6:
        if end<off+20:return result("TCP",src,dst,"TCP header truncated")
        sp,dp,seq,ack=struct.unpack("!HHII",frame[off:off+12]); size=(frame[off+12]>>4)*4
        if size<20 or off+size>end:return result("TCP",src,dst,"Invalid TCP header")
        flags=frame[off+13]; names=[n for b,n in [(2,"SYN"),(16,"ACK"),(1,"FIN"),(4,"RST"),(8,"PSH")] if flags&b]
        payload=frame[off+size:end]; app=""; info=f"TCP {sp} → {dp} [{','.join(names)}]"
        details=f"seq={seq}, ack={ack}, payload={len(payload)} bytes"
        if sp==53 or dp==53: app="DNS"; dns,dd=decode_dns(payload[2:] if len(payload)>2 else b""); info+=f" | {dns}"; details+="; "+dd
        return result("TCP",src,dst,info,details,sp,dp,app)
    if proto==17:
        if end<off+8:return result("UDP",src,dst,"UDP header truncated")
        sp,dp,length=struct.unpack("!HHH",frame[off:off+6])
        if length < 8:
            return result("UDP",src,dst,"Invalid UDP length",f"length={length}",sp,dp)
        if off+length > end:
            return result("UDP",src,dst,"UDP payload truncated",f"length={length}; available={max(0,end-off)}",sp,dp)
        payload=frame[off+8:off+length]
        app=""; info=f"UDP {sp} → {dp}"; details=f"length={length}"
        if sp==53 or dp==53: app="DNS"; dns,dd=decode_dns(payload); info+=" | "+dns; details+="; "+dd
        return result("UDP",src,dst,info,details,sp,dp,app)
    if proto in (1,58):
        label="ICMP" if proto==1 else "ICMPv6"
        return result(label,src,dst,f"{label} type={frame[off] if off<end else -1} code={frame[off+1] if off+1<end else -1}")
    return result("OTHER",src,dst,f"IP protocol {proto}")

def decode_ip(frame,offset=0):
    if len(frame)<=offset:return result(info="Empty IP packet")
    version=frame[offset]>>4
    if version==4:
        if len(frame)<offset+20:return result("IPv4",info="IPv4 header truncated")
        ihl=(frame[offset]&15)*4; total=struct.unpack("!H",frame[offset+2:offset+4])[0]
        if ihl<20 or offset+ihl>len(frame) or total<ihl:return result("IPv4",info="Invalid IPv4 header")
        src=socket.inet_ntop(socket.AF_INET,frame[offset+12:offset+16]); dst=socket.inet_ntop(socket.AF_INET,frame[offset+16:offset+20])
        frag=struct.unpack("!H",frame[offset+6:offset+8])[0]&0x1fff
        if frag:return result("IPv4",src,dst,"IPv4 non-initial fragment")
        return decode_transport(frame,offset+ihl,frame[offset+9],src,dst,min(len(frame),offset+total))
    if version==6:
        if len(frame)<offset+40:return result("IPv6",info="IPv6 header truncated")
        plen=struct.unpack("!H",frame[offset+4:offset+6])[0]; src=socket.inet_ntop(socket.AF_INET6,frame[offset+8:offset+24]); dst=socket.inet_ntop(socket.AF_INET6,frame[offset+24:offset+40])
        return decode_transport(frame,offset+40,frame[offset+6],src,dst,min(len(frame),offset+40+plen))
    return result(info=f"Unknown network version {version}")

def decode_frame(frame,linktype):
    if linktype in (101,12,228,229):return decode_ip(frame)
    if linktype!=1:return result(info=f"Unsupported link type {linktype}")
    if len(frame)<14:return result(info="Ethernet frame truncated")
    et,off=struct.unpack("!H",frame[12:14])[0],14
    while et in (0x8100,0x88a8,0x9100):
        if len(frame)<off+4:return result(info="VLAN truncated")
        et=struct.unpack("!H",frame[off+2:off+4])[0]; off+=4
    if et==0x0806:return result("ARP",info="ARP / address resolution")
    if et in (0x0800,0x86dd):return decode_ip(frame,off)
    return result(info=f"EtherType 0x{et:04x}")

def read_shb(stream,length):
    bom=stream.read(4); endian={b"\x4d\x3c\x2b\x1a":"<",b"\x1a\x2b\x3c\x4d":">"}.get(bom)
    if not endian:raise ValueError("PCAPNG byte-order magic invalid")
    total=struct.unpack(endian+"I",length)[0]
    if total<28 or total>MAX_BLOCK or total%4:raise ValueError("PCAPNG SHB size invalid")
    rest=stream.read(total-12)
    if len(rest)!=total-12 or struct.unpack(endian+"I",rest[-4:])[0]!=total:raise ValueError("PCAPNG SHB invalid")
    major=struct.unpack(endian+"H",rest[:2])[0]
    if major!=1:raise ValueError("Unsupported PCAPNG version")
    return endian

def iter_capture(path):
    with open(path,"rb") as stream:
        first=stream.read(8)
        if first[:4]==b"\x0a\x0d\x0d\x0a":
            endian=read_shb(stream,first[4:8]); interfaces=[]; yield "header",{"format":"PCAPNG"}
            while True:
                bh=stream.read(8)
                if not bh:return
                if len(bh)!=8:raise ValueError("PCAPNG block header truncated")
                bt,lb=bh[:4],bh[4:]
                if bt==b"\x0a\x0d\x0d\x0a":endian=read_shb(stream,lb);interfaces=[];continue
                typ,total=struct.unpack(endian+"II",bt+lb)
                if total<12 or total>MAX_BLOCK or total%4:raise ValueError("PCAPNG block size invalid")
                tail=stream.read(total-8)
                if len(tail)!=total-8 or struct.unpack(endian+"I",tail[-4:])[0]!=total:raise ValueError("PCAPNG block invalid")
                body=tail[:-4]
                if typ==1:
                    if len(body)<8:raise ValueError("PCAPNG interface block truncated")
                    lt,_,snap=struct.unpack(endian+"HHI",body[:8])
                    resolution=1e6
                    pos=8
                    while pos+4<=len(body):
                        code,optlen=struct.unpack(endian+"HH",body[pos:pos+4]);pos+=4
                        if code==0:
                            if optlen!=0:raise ValueError("PCAPNG end-of-options invalid")
                            break
                        padded=(optlen+3)&~3
                        if pos+padded>len(body):raise ValueError("PCAPNG interface option truncated")
                        value=body[pos:pos+optlen]
                        if code==9:
                            if optlen!=1:raise ValueError("PCAPNG timestamp resolution invalid")
                            exponent=value[0]&0x7f
                            resolution=(2**exponent) if value[0]&0x80 else (10**exponent)
                        pos+=padded
                    interfaces.append({"linktype":lt,"snaplen":snap,"timestamp_resolution":resolution})
                elif typ in (2,3,6) and interfaces:
                    if typ==6:
                        if len(body)<20:raise ValueError("PCAPNG enhanced packet block truncated")
                        iface,hi,lo,cap,orig=struct.unpack(endian+"IIIII",body[:20]);data=body[20:20+cap]
                    elif typ==2:
                        if len(body)<20:raise ValueError("PCAPNG packet block truncated")
                        iface,_,hi,lo,cap,orig=struct.unpack(endian+"HHIIII",body[:20]);data=body[20:20+cap]
                    else:
                        if len(body)<4:raise ValueError("PCAPNG simple packet block truncated")
                        iface=0;orig=struct.unpack(endian+"I",body[:4])[0];data=body[4:]
                        cap=min(orig,interfaces[0]["snaplen"] or orig)
                        hi=lo=0
                    if cap>MAX_BLOCK:raise ValueError("PCAPNG packet too large")
                    if len(data)<cap:raise ValueError("PCAPNG packet data truncated")
                    if iface>=len(interfaces):raise ValueError("PCAPNG packet references unknown interface")
                    if cap>orig:raise ValueError("PCAPNG captured length exceeds original length")
                    snap=interfaces[iface]["snaplen"]
                    if snap and cap>snap:raise ValueError("PCAPNG captured length exceeds snaplen")
                    resolution=interfaces[iface]["timestamp_resolution"]
                    yield "packet",{"timestamp":None if typ==3 else ((hi<<32)|lo)/resolution,"captured_length":cap,"original_length":orig,"linktype":interfaces[iface]["linktype"],"data":data[:cap]}
        else:
            magics={b"\xd4\xc3\xb2\xa1":("<",1e6),b"\xa1\xb2\xc3\xd4":(">",1e6),b"\x4d\x3c\xb2\xa1":("<",1e9),b"\xa1\xb2\x3c\x4d":(">",1e9)}
            if first[:4] not in magics:raise ValueError("Not PCAP/PCAPNG")
            endian,scale=magics[first[:4]];rest=stream.read(16)
            if len(rest)!=16:raise ValueError("PCAP global header truncated")
            major,minor=struct.unpack(endian+"HH",first[4:8]);_,_,snap,link=struct.unpack(endian+"IIII",rest)
            if major!=2:raise ValueError("Unsupported PCAP version")
            if snap==0 or snap>MAX_BLOCK:raise ValueError("PCAP snaplen invalid")
            yield "header",{"format":"PCAP","major":major,"minor":minor,"snaplen":snap,"linktype":link}
            while True:
                h=stream.read(16)
                if not h:return
                if len(h)!=16:raise ValueError("Packet header truncated")
                sec,frac,cap,orig=struct.unpack(endian+"IIII",h)
                max_fraction=int(scale)
                if frac>=max_fraction:raise ValueError("PCAP timestamp fraction out of range")
                if cap>MAX_BLOCK:raise ValueError("Packet too large")
                if cap>orig:raise ValueError("PCAP captured length exceeds original length")
                if cap>snap:raise ValueError("PCAP captured length exceeds snaplen")
                data=stream.read(cap)
                if len(data)!=cap:raise ValueError("Packet data truncated")
                yield "packet",{"timestamp":sec+frac/scale,"captured_length":cap,"original_length":orig,"linktype":link,"data":data}

def packet_matches(row,protocol,ip,port):
    if protocol and protocol.casefold() not in (row["protocol"].casefold(),row.get("app_protocol","").casefold()):return False
    if ip and ip not in (row["src"],row["dst"]):return False
    if port and port not in (row.get("src_port"),row.get("dst_port")):return False
    return True

def summarize(rows):return {"packets":len(rows),"protocols":dict(Counter(r["decoded"]["protocol"] for r in rows))}
def render_text(rows,header,summary_only=False):
    lines=[f"WireLab — {header.get('format','capture')} | paquetes mostrados: {len(rows)}"]
    for p in rows:
        d=p["decoded"];lines.append(f"#{p['number']} {d['protocol']} {d['src']}:{d.get('src_port') or '-'} → {d['dst']}:{d.get('dst_port') or '-'} | {d['info']}")
    if summary_only:lines=["Resumen: "+json.dumps(summarize(rows),ensure_ascii=False)]
    return "\n".join(lines)+"\n"
def main():
    parser=argparse.ArgumentParser(description="WireLab: inspección offline PCAP/PCAPNG.")
    parser.add_argument("file");parser.add_argument("--limit",type=int,default=200);parser.add_argument("--protocol",choices=("tcp","udp","icmp","icmpv6","arp","dns"));parser.add_argument("--ip");parser.add_argument("--port",type=int);parser.add_argument("--summary-only",action="store_true");parser.add_argument("--json",action="store_true");parser.add_argument("--output")
    args=parser.parse_args()
    if not 1<=args.limit<=100000:parser.error("--limit debe ser 1–100000")
    if args.port is not None and not 1<=args.port<=65535:parser.error("--port fuera de rango")
    if args.ip:
        try:ipaddress.ip_address(args.ip)
        except ValueError:parser.error("--ip debe ser IP literal")
    try:
        header={"format":"unknown"};rows=[];examined=0
        for kind,item in iter_capture(args.file):
            if kind=="header":header=item;continue
            examined+=1;decoded=decode_frame(item["data"],item["linktype"])
            if packet_matches(decoded,args.protocol,args.ip,args.port):rows.append({"number":examined,"timestamp":item["timestamp"],"captured_length":item["captured_length"],"original_length":item["original_length"],"decoded":decoded})
            if examined>=args.limit:break
        output=json.dumps({"file":args.file,"header":header,"examined":examined,"summary":summarize(rows),"packets":rows},ensure_ascii=False,indent=2)+"\n" if args.json else render_text(rows,header,args.summary_only)
        if args.output:
            with open(args.output,"x",encoding="utf-8") as stream:stream.write(output)
            print(f"Resultado guardado en {args.output}",file=sys.stderr)
        print(output,end="")
    except (OSError,ValueError,struct.error,OverflowError) as exc:
        print(f"Error: {exc}",file=sys.stderr);raise SystemExit(1)
if __name__=="__main__":main()
