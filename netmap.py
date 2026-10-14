#!/usr/bin/env python3
"""NetMap: lightweight TCP connect scanner for Termux, no root required."""
import argparse, csv, errno, ipaddress, json, socket, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
DEFAULT_PORTS=[22,53,80,443,445,8080,8443,8022]
MAX_PORTS=1000

def parse_ports(value):
    ports=set()
    try:
        for item in value.split(","):
            item=item.strip()
            if not item: continue
            if "-" in item:
                a,b=map(int,item.split("-",1))
                if a<1 or b>65535 or a>b or b-a>=MAX_PORTS: raise ValueError
                ports.update(range(a,b+1))
            else:
                p=int(item)
                if not 1<=p<=65535: raise ValueError
                ports.add(p)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Puertos inválidos o rango demasiado grande.") from exc
    if not ports or len(ports)>MAX_PORTS: raise argparse.ArgumentTypeError(f"Indica 1–{MAX_PORTS} puertos.")
    return sorted(ports)

def check_target(value):
    try: addr=ipaddress.ip_address(value)
    except ValueError as exc: raise argparse.ArgumentTypeError("Usa una IP literal, no un dominio.") from exc
    if not isinstance(addr,ipaddress.IPv4Address): raise argparse.ArgumentTypeError("Solo IPv4.")
    if not (addr.is_private or addr.is_loopback or addr.is_link_local):
        raise argparse.ArgumentTypeError("Solo IPv4 privada, loopback o link-local.")
    return str(addr)

def classify_error(code):
    if code==0: return "open"
    if code==errno.ECONNREFUSED: return "closed"
    if code==errno.ETIMEDOUT: return "filtered_or_timeout"
    if code in (errno.EHOSTUNREACH,errno.ENETUNREACH): return "unreachable"
    return "no_response"

def probe(host,port,timeout):
    start=time.perf_counter(); sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM); sock.settimeout(timeout)
    try:
        code=sock.connect_ex((host,port)); state=classify_error(code); service=""
        if state=="open":
            try: service=socket.getservbyport(port,"tcp")
            except OSError: service="unknown"
        return {"port":port,"protocol":"tcp","state":state,"service_name_by_port":service,
                "connect_ms":round((time.perf_counter()-start)*1000,2),"error_code":code}
    except OSError as exc:
        return {"port":port,"protocol":"tcp","state":"error","error":str(exc),
                "connect_ms":round((time.perf_counter()-start)*1000,2),"error_code":exc.errno}
    finally: sock.close()

def main():
    parser=argparse.ArgumentParser(description="NetMap: TCP connect scanner without root.")
    parser.add_argument("target",type=check_target)
    parser.add_argument("--ports",type=parse_ports,default=DEFAULT_PORTS)
    parser.add_argument("--timeout",type=float,default=.5)
    parser.add_argument("--workers",type=int,default=8)
    parser.add_argument("--all",action="store_true")
    parser.add_argument("--format",choices=("text","json","csv"),default="text")
    parser.add_argument("--output")
    parser.add_argument("--authorized",action="store_true")
    args=parser.parse_args()
    if not args.authorized: parser.error("Confirma autorización con --authorized.")
    if not .1<=args.timeout<=5: parser.error("--timeout debe estar entre 0.1 y 5.")
    if not 1<=args.workers<=48: parser.error("--workers debe estar entre 1 y 48.")
    started=time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows=sorted((f.result() for f in as_completed([pool.submit(probe,args.target,p,args.timeout) for p in args.ports])),key=lambda x:x["port"])
    if args.format=="json": output=json.dumps(rows,ensure_ascii=False,indent=2)+"\n"
    elif args.format=="csv":
        from io import StringIO
        stream=StringIO(); writer=csv.DictWriter(stream,fieldnames=["port","protocol","state","service_name_by_port","connect_ms","error_code"],extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows); output=stream.getvalue()
    else:
        shown=[r for r in rows if args.all or r["state"]=="open"]
        output="NetMap TCP | objetivo: %s | revisados: %d\n"%(args.target,len(rows))
        output+="\n".join("%5d/tcp %-20s %s"%(r["port"],r["state"],r.get("service_name_by_port","")) for r in shown)+"\n"
        output+="Tiempo: %.2fs; abiertos: %d\n"%(time.perf_counter()-started,sum(r["state"]=="open" for r in rows))
    print(output,end="")
    if args.output:
        with open(args.output,"x",encoding="utf-8") as stream: stream.write(output)
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except KeyboardInterrupt: raise SystemExit(130)
