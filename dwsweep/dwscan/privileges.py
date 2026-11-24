from __future__ import annotations
import shlex

CHECKS = {
    "ident": "id; echo ---; whoami",
    "host": "uname -a; echo ---; hostname",
    "os": "cat /etc/os-release 2>/dev/null | head -5",
    "sudo": "sudo -n -l 2>&1 | head -20",
    "writable": ("D=$(pwd 2>/dev/null); for d in / /var/www /var/www/html /var/www/htdocs "
                 "/usr/share/nginx/html /srv/www /srv/http /opt/lampp/htdocs /var/www/site "
                 "/public_html /home/*/public_html /tmp /dev/shm \"$D\"; do "
                 "[ -n \"$d\" ] && [ -d \"$d\" ] && [ -w \"$d\" ] && echo \"RW $d\"; done"),
    "limits": ("php -r 'echo ini_get(\"memory_limit\"),\"|\","
               "ini_get(\"disable_functions\"),\"|\",ini_get(\"open_basedir\");' 2>/dev/null"),
    "tools": "for t in curl wget python3 perl nc gcc; do command -v $t; done",
}


def assess(runner, target: str) -> dict:
    out = {}
    for name, cmd in CHECKS.items():
        r = runner.run(target, cmd, timeout=90)
        out[name] = r.stdout.strip()[:1500] if r.ok else ""
    uid = out.get("ident", "")
    out["is_root"] = "uid=0(" in uid
    out["user"] = uid.split("\n")[-1].strip() if uid else "?"
    out["can_sudo"] = "NOPASSWD" in out.get("sudo", "")
    out["writable_dirs"] = [l[3:] for l in out.get("writable", "").splitlines()
                            if l.startswith("RW ")]
    out["web_writable"] = [d for d in out["writable_dirs"]
                           if any(k in d for k in ("/var/www", "htdocs", "nginx/html",
                                                   "/srv/www", "/srv/http", "public_html"))]
    return out


def provisionable(p: dict) -> bool:
    return bool(p.get("is_root") or p.get("can_sudo"))


def summarize(p: dict) -> str:
    bits = [f"user={p.get('user')}"]
    if p.get("is_root"):
        bits.append("ROOT")
    if p.get("can_sudo"):
        bits.append("NOPASSWD-sudo")
    if p.get("writable_dirs"):
        bits.append("rw=" + ",".join(p["writable_dirs"][:4]))
    return " ".join(bits)


def guard_cmd(cmd: str) -> str:
    return shlex.quote(cmd)
