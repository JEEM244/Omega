#!/usr/bin/env python3
"""Receive PCAPdroid UDP exporter records on loopback and write classic PCAP."""
import argparse, datetime, os, shutil, socket, struct, subprocess, sys, time
PCAPDROID_HEADER_PREFIXES=(b"\xd4\xc3\xb2\xa1",b"\xa1\xb2\xc3\xd4",b"\x4d\x3c\xb2\xa1",b"\xa1\xb2\x3c\x4d")
ETHERTYPES={0x0800,0x0806,0x86dd,0x8100,0x88a8,0x9100};MAX_PACKET=65507
PCAPDROID_COMPONENT="com.emanuelef.remote_capture/.activities.CaptureCtrl"
def pcapdroid_command(action,port,app_filter=None):
    cmd=["am","start","-e","action",action]
    if action=="start":
        cmd += ["-e","pcap_dump_mode","udp_exporter","-e","collector_host","127.0.0.1","-e","collector_port",str(port)]
        if app_filter:cmd += ["-e","app_filter",app_filter]
    return cmd+["-n",PCAPDROID_COMPONENT]
def detect_linktype(packet):
    if packet:
        v=packet[0]>>4
        if v==4 and len(packet)>=20:
            ihl=(packet[0]&15)*4; total=struct.unpack("!H",packet[2:4])[0]
            if ihl>=20 and total>=ihl:return 101
        if v==6 and len(packet)>=40:return 101
    if len(packet)>=14 and struct.unpack("!H",packet[12:14])[0] in ETHERTYPES:return 1
    return None
def parse_record_datagram(data):
    if len(data)<16:return None
    size=len(data)-16;candidates=[]
    for endian in ("<",">"):
        sec,frac,cap,orig=struct.unpack(endian+"IIII",data[:16])
        if cap==size and cap<=MAX_PACKET and orig>=cap:candidates.append((endian,sec,frac,cap,orig))
    if not candidates:return None
    chosen=next((c for c in candidates if c[0]=="<"),candidates[0]);endian,sec,frac,cap,orig=chosen
    if frac>=1_000_000:
        alt=next((c for c in candidates if c[0]!=endian and c[2]<1_000_000),None)
        if not alt:return None
        endian,sec,frac,cap,orig=alt
    return {"seconds":sec,"fraction":frac,"captured":cap,"original":orig,"frame":data[16:16+cap]}
def pcap_global_header(linktype):return b"\xd4\xc3\xb2\xa1"+struct.pack("<HHIIII",2,4,0,0,65535,linktype)
def safe_output_path(path):
    parent=os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):raise OSError(f"Output directory does not exist: {parent}")
    if os.path.lexists(path):raise OSError(f"Refusing to overwrite existing file: {path}")
    return path
def main():
    parser=argparse.ArgumentParser(description="Recibe exportación UDP de PCAPdroid y crea un PCAP.")
    parser.add_argument("--port",type=int,default=5123);parser.add_argument("--output");parser.add_argument("--seconds",type=int,default=0);parser.add_argument("--max-packets",type=int,default=0);parser.add_argument("--launch-pcapdroid",action="store_true");parser.add_argument("--app-filter")
    args=parser.parse_args()
    if not 1<=args.port<=65535:parser.error("--port debe ser 1–65535")
    if not 1<=args.seconds<=60:parser.error("--seconds debe ser 1–60 para limitar la captura")
    if not 1<=args.max_packets<=500:parser.error("--max-packets debe ser 1–500 para limitar la captura")
    path=safe_output_path(os.path.expanduser(args.output) if args.output else os.path.expanduser("~/wirelab-capture-%s.pcap"%datetime.datetime.now().strftime("%Y%m%d-%H%M%S")))
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,0)
    try:sock.bind(("127.0.0.1",args.port))
    except OSError as exc:sock.close();print(exc,file=sys.stderr);return 2
    if args.launch_pcapdroid:
        am=shutil.which("am") or ("/system/bin/am" if os.path.exists("/system/bin/am") else None)
        if not am:sock.close();print("No se encontró Android am; abre PCAPdroid manualmente.",file=sys.stderr);return 2
        cmd=pcapdroid_command("start",args.port,args.app_filter);cmd[0]=am
        try:launch=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        except (OSError,subprocess.TimeoutExpired) as exc:sock.close();print(exc,file=sys.stderr);return 2
        if launch.returncode!=0:sock.close();print("PCAPdroid no aceptó la solicitud.",file=sys.stderr);return 2
    started=time.monotonic();count=invalid=0;linktype=None;out=None
    try:
        sock.settimeout(.5)
        while True:
            if args.seconds and time.monotonic()-started>=args.seconds:break
            if args.max_packets and count>=args.max_packets:break
            try:data,_=sock.recvfrom(MAX_PACKET)
            except socket.timeout:continue
            if len(data)==24 and data[:4] in PCAPDROID_HEADER_PREFIXES:continue
            rec=parse_record_datagram(data)
            if rec is None:invalid+=1;continue
            if linktype is None:
                linktype=detect_linktype(rec["frame"])
                if linktype is None:invalid+=1;continue
                out=open(path,"xb");out.write(pcap_global_header(linktype))
            candidate=detect_linktype(rec["frame"])
            if candidate is not None and candidate!=linktype:invalid+=1;continue
            out.write(struct.pack("<IIII",rec["seconds"],rec["fraction"],rec["captured"],rec["original"]));out.write(rec["frame"]);count+=1
    except KeyboardInterrupt:pass
    finally:
        try:
            sock.close()
        finally:
            try:
                if out is not None:
                    try:
                        out.flush()
                    finally:
                        out.close()
            finally:
                # Always attempt to stop PCAPdroid, even if receiving or writing
                # the capture fails unexpectedly.
                if args.launch_pcapdroid:
                    try:
                        am=shutil.which("am") or "/system/bin/am";cmd=pcapdroid_command("stop",args.port);cmd[0]=am
                        subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=False)
                    except (OSError,subprocess.TimeoutExpired):pass
    print(f"Captura terminada: {count} paquetes guardados, {invalid} inválidos; salida {path}")
    return 0
if __name__=="__main__":raise SystemExit(main())
