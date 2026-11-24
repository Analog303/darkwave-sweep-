from __future__ import annotations
import concurrent.futures as cf
import ipaddress
import socket

from .models import Target
from .audit import Audit

SCHEME = {80: "http", 443: "https", 8080: "http", 8443: "https",
          8000: "http", 8888: "http"}


def expand(cidrs: list) -> list:
    out = []
    for c in cidrs:
        out += [str(h) for h in ipaddress.ip_network(c, strict=False).hosts()]
    return out


def _probe(args):
    host, port, timeout = args
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def sweep(hosts: list, ports: list, workers: int, timeout: float,
          audit: Audit) -> list:
    jobs = [(h, p, timeout) for h in hosts for p in ports]
    found = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for (h, p, _), ok in zip(jobs, ex.map(_probe, jobs)):
            if ok:
                t = Target(host=h, port=p, scheme=SCHEME.get(p, "http"))
                found.append(t)
                audit.write("discovery", "port_open", t.url, port=p)
    return found
