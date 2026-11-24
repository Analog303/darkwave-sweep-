import os, re, subprocess, time
T = "/var/lib/dw/targets.txt"; IDX = "/var/lib/dw/sql.idx"; OUT = "/var/lib/dw/sql.jsonl"
os.makedirs("/var/lib/dw", exist_ok=True)


def note(m):
    open(OUT, "a").write(time.strftime("%Y-%m-%dT%H:%M:%SZ ") + m + "\n")


while True:
    try:
        n = int(open(IDX).read()) if os.path.exists(IDX) else 0
    except Exception:
        n = 0
    try:
        lines = [x for x in open(T).read().splitlines() if "?" in x and "=" in x]
    except FileNotFoundError:
        lines = []
    if n >= len(lines):
        time.sleep(20); continue
    url = lines[n]
    open(IDX, "w").write(str(n + 1))
    r = subprocess.run(["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
                        "--smart", "--timeout", "8", "--retries", "0", "--threads", "2",
                        "--output-dir", "/var/lib/dw/sqlmap"], capture_output=True, text=True)
    if "is vulnerable" in r.stdout or "Parameter:" in r.stdout:
        msg = "\n".join([l for l in r.stdout.splitlines() if "Parameter" in l or "Type:" in l or "vulnerable" in l])[:400]
        note(f"{url} :: {msg}")
        open("/var/lib/dw/sql.url", "a").write(url + "\n")
