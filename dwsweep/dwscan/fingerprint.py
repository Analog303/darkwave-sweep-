from __future__ import annotations
import re

import requests

from .models import Target
from .audit import Audit

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

EGGS = ["?=PHPE9568F36-D428-11d2-A769-00AA001ACF42",
        "?=PHPE9568F35-D428-11d2-A769-00AA001ACF42",
        "?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"]

OS_MAP = [(r"ubuntu", "Ubuntu"), (r"debian", "Debian"), (r"centos", "CentOS"),
          (r"alpine", "Alpine"), (r"win32|windows", "Windows"), (r"freebsd", "FreeBSD")]


def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    s.verify = False
    return s


def fingerprint(t: Target, timeout: int, audit: Audit) -> Target:
    try:
        r = session().get(t.url + "/", timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        t.reachable = False
        t.extra["fingerprint_error"] = type(e).__name__
        audit.write("fingerprint", "unreachable", t.url, error=type(e).__name__)
        return t

    h = {k.lower(): v for k, v in r.headers.items()}
    t.server = h.get("server", "")
    t.powered_by = h.get("x-powered-by", "")
    blob = " ".join([t.server, t.powered_by, r.text[:20000]]).lower()

    for pat, osname in OS_MAP:
        if re.search(pat, blob):
            t.os_hint = osname
            break

    m = re.search(r"php/(\d+\.\d+\.\d+)", t.powered_by.lower())
    if m:
        t.php_version = m.group(1)
    if not t.php_version and "phpsessid" in r.headers.get("set-cookie", "").lower():
        t.extra["php_cookie"] = True

    if not t.php_version:
        for egg in EGGS:
            try:
                e = session().get(t.url + "/" + egg, timeout=timeout)
            except requests.RequestException:
                continue
            if e.status_code == 200 and ("php" in e.text.lower()
                                         or "image/gif" in e.headers.get("content-type", "")):
                t.extra["php_egg"] = True
                vm = re.search(r"PHP Version\s*([\d.]+)", e.text)
                if vm:
                    t.php_version = vm.group(1)
                break

    t.extra["status"] = r.status_code
    t.extra["headers"] = {k: v[:200] for k, v in h.items()}
    t.extra["body"] = r.text[:4000]
    mt = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
    t.extra["title"] = (mt.group(1).strip()[:120] if mt else "")
    t.extra["is_php"] = bool(t.php_version or t.extra.get("php_cookie")
                             or t.extra.get("php_egg"))
    audit.write("fingerprint", "done", t.url, server=t.server, title=t.extra.get("title",""),
                php=t.php_version, php_detected=t.extra["is_php"])
    return t
