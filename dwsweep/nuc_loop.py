import os, subprocess, time
T = "/var/lib/dw/targets.txt"; IDX = "/var/lib/dw/nuc.idx"; LOG = "/var/lib/dw/nuclei.log"
os.makedirs("/var/lib/dw", exist_ok=True)


def note(msg):
    with open(LOG, "a") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ") + msg + "\n")


while True:
    try:
        n = int(open(IDX).read().strip()) if os.path.exists(IDX) else 0
    except Exception:
        n = 0
    try:
        lines = open(T).read().splitlines()
    except FileNotFoundError:
        lines = []
    chunk = lines[n:n + 400]
    if not chunk:
        time.sleep(15); continue
    open("/tmp/nuc.batch", "w").write("\n".join(chunk))
    note(f"BATCH {n+1}-{n+len(chunk)} gestartet ({len(chunk)} ziele)")
    r = subprocess.run(["nuclei", "-l", "/tmp/nuc.batch", "-severity", "critical,high",
                        "-rl", "80", "-c", "40", "-silent", "-jsonl",
                        "-o", "/var/lib/dw/nuclei.jsonl", "-timeout", "8"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(IDX, "w").write(str(n + len(chunk)))
    note(f"BATCH {n+1}-{n+len(chunk)} fertig rc={r.returncode}")
