from __future__ import annotations
import re

from .models import Sev, Target

DB = {
    "CVE-2026-109618": {
        "title": "PHP2Shell: OOM-Korruption in _zend_hash_str_add_or_update_i()",
        "cvss": 9.8, "sev": Sev.CRITICAL,
        "ranges": {"8.2": ("8.2.0", "8.2.35"), "8.3": ("8.3.0", "8.3.36"),
                   "8.4": ("8.4.0", "8.4.27"), "8.5": ("8.5.0", "8.5.12")},
        "sink": "Multipart-Parsing, php_request_startup()",
        "remediation": ("Auf 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 anheben. "
                        "Kurzfristig memory_limit >= 128M setzen."),
    },
    "CVE-2026-109619": {
        "title": "PHP2Shell: UAF ueber veralteten PS-Session-Globalzustand",
        "cvss": 9.1, "sev": Sev.CRITICAL,
        "ranges": {"8.2": ("8.2.0", "8.2.35"), "8.3": ("8.3.0", "8.3.36"),
                   "8.4": ("8.4.0", "8.4.27"), "8.5": ("8.5.0", "8.5.12")},
        "sink": "session.upload_progress nach Request-Abbruch",
        "remediation": ("Wie 109618. Zusaetzlich session.upload_progress.* "
                        "deaktivieren, falls ungenutzt."),
    },
}

EOL_BELOW = (8, 1, 99)


def _t(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def affected(cve: str, version: str | None):
    if not version:
        return None
    rec = DB.get(cve)
    if not rec:
        return None
    try:
        v = _t(version)
    except ValueError:
        return None
    if len(v) < 3:
        return None
    branch = f"{v[0]}.{v[1]}"
    if branch not in rec["ranges"]:
        return v < EOL_BELOW or v[0] < 8
    lo, hi = rec["ranges"][branch]
    return _t(lo) <= v < _t(hi)


def match(t: Target) -> list:
    out = []
    for cve in DB:
        if affected(cve, t.php_version):
            rec = DB[cve]
            out.append({"cve": cve, "sev": rec["sev"], "cvss": rec["cvss"],
                        "title": rec["title"], "remediation": rec["remediation"],
                        "sink": rec["sink"]})
    if t.php_version and _t(t.php_version) < EOL_BELOW:
        t.eol = True
    return out


def for_export(t: Target) -> dict:
    return {"php_version": t.php_version, "eol": t.eol, "cves": match(t)}
