from __future__ import annotations
from .models import Result, Sev

REMEDIATION_GENERIC = {
    Sev.CRITICAL: "Sofort patchen. Bis dahin WAF-Regel oder memory_limit hochsetzen.",
    Sev.HIGH: "Innerhalb von 7 Tagen patchen.",
}


def to_dict(r: Result) -> dict:
    return {
        "target": r.target.url,
        "host": r.target.host,
        "port": r.target.port,
        "verdict": r.best.value,
        "php_version": r.target.php_version,
        "eol": r.target.eol,
        "server": r.target.server,
        "os_hint": r.target.os_hint,
        "privileges": {k: v for k, v in r.privileges.items()
                       if k in ("user", "is_root", "can_sudo", "writable_dirs")},
        "accesses": [a.__dict__ for a in r.accesses],
        "findings": [
            {"cve": f.cve, "severity": f.severity.value, "verdict": f.verdict.value,
             "confidence": round(f.confidence, 2), "remediation": f.remediation,
             "evidence": [e.as_dict() for e in f.evidence]}
            for f in r.findings
        ],
        "errors": r.errors,
        "timing": {"started": r.started, "finished": r.finished},
    }


def summary(results: list) -> str:
    counts = {}
    for r in results:
        counts[r.best.value] = counts.get(r.best.value, 0) + 1
    owned = [r for r in results if any(a.verified for a in r.accesses)]
    lines = ["DARKWAVE: Zusammenfassung", "=" * 40]
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        lines.append(f"{k:14s} {v}")
    lines.append("")
    lines.append(f"Zugaenge gesichert: {len(owned)}")
    for r in owned:
        for a in r.accesses:
            if a.verified:
                lines.append(f"  {r.target.url}  {a.kind}  {a.locator}  {a.secret}")
    return "\n".join(lines)
