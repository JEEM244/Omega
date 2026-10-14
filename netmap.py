#!/usr/bin/env python3
"""NetMap: lightweight TCP connect scanner for Termux, no root required."""
import argparse, csv, errno, ipaddress, json, socket, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
DEFAULT_PORTS=[22,53,80,443,445,8080,8443,8022]
MAX_PORTS=1000

def parse_ports(value):
    ports=set()
    try:
        for part in value.split(","):
            part=part.strip()
            if not part: continue
            if "-" in part:
                a,b=map(int,part.split("-",1))
                if a<1 or b>65535 or a>b or b-a>=MAX_PORTS: raise ValueError
                ports.update(range(a,b+1))
            else:
                p=int(part)
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

def render_text(target,rows,elapsed,show_all=False):
    lines=[f"NetMap TCP | objetivo: {target} | puertos revisados: {len(rows)}",
           "Método: TCP connect (conexiones normales; sin raw sockets ni root).",
           f"{'PUERTO':>7}  {'ESTADO':<19} {'NOMBRE ESTÁNDAR DEL PUERTO':<30} {'TIEMPO':>10}",
           "-"*74]
    for row in rows:
        if not show_all and row["state"]!="open": continue
        service=row.get("service_name_by_port","") or "-"
        lines.append(f"{row['port']:>7}/tcp  {row['state']:<19} {service:<30} {row.get('connect_ms',0):>8.2f} ms")
    lines.extend([f"\nTiempo total: {elapsed:.2f} s | abiertos: {sum(r['state']=='open' for r in rows)} | cerrados: {sum(r['state']=='closed' for r in rows)}",
                  "Los nombres de puerto son asignaciones estándar, no identificación confirmada del servicio."])
    return "\n".join(lines)+"\n"

def serialize(rows,fmt):
    if fmt=="json": return json.dumps(rows,ensure_ascii=False,indent=2)+"\n"
    from io import StringIO
    stream=StringIO(); writer=csv.DictWriter(stream,fieldnames=["port","protocol","state","service_name_by_port","connect_ms","error_code","error"],extrasaction="ignore")
    writer.writeheader(); writer.writerows(rows); return stream.getvalue()

def main():
    parser=argparse.ArgumentParser(description="NetMap: TCP connect scanner without root.")
    parser.add_argument("target",type=check_target); parser.add_argument("--ports",type=parse_ports,default=DEFAULT_PORTS)
    parser.add_argument("--timeout",type=float,default=.6); parser.add_argument("--workers",type=int,default=24)
    parser.add_argument("--all",action="store_true"); parser.add_argument("--format",choices=("text","json","csv"),default="text")
    parser.add_argument("--output"); parser.add_argument("--authorized",action="store_true"); args=parser.parse_args()
    if not args.authorized: parser.error("Confirma autorización con --authorized.")
    if not .1<=args.timeout<=5: parser.error("--timeout debe estar entre 0.1 y 5.")
    if not 1<=args.workers<=48: parser.error("--workers debe estar entre 1 y 48.")
    started=time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows=sorted((f.result() for f in as_completed([pool.submit(probe,args.target,p,args.timeout) for p in args.ports])),key=lambda x:x["port"])
    elapsed=time.perf_counter()-started
    output=render_text(args.target,rows,elapsed,args.all) if args.format=="text" else serialize(rows,args.format)
    print(output,end="")
    if args.output:
        try:
            with open(args.output,"x",encoding="utf-8",newline="") as stream: stream.write(output)
        except OSError as exc: print(f"No se pudo guardar: {exc}",file=sys.stderr); return 2
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except KeyboardInterrupt: print("\nCancelado.",file=sys.stderr); raise SystemExit(130)
