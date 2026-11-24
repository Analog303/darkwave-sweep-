from __future__ import annotations


def collect(runner, t, sudo: str = "") -> dict:
    cmd = (
        "printf 'OS='; grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"'; "
        "printf '\\nCPU='; grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //'; "
        "printf '\\nCORES='; nproc 2>/dev/null; "
        "printf '\\nRAMMB='; free -m 2>/dev/null | awk '/Mem:/{print $2}'; "
        "printf '\\nDISK='; df -h / 2>/dev/null | awk 'NR==2{print $2\" total/\"$4\" frei\"}'; "
        "printf '\\nVIRT='; systemd-detect-virt 2>/dev/null | head -1; "
        "printf '\\nGPU='; nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null | tr '\\n' ';'; "
        "lspci 2>/dev/null | grep -Ei 'vga|3d' | head -2 | tr '\\n' ';'; echo"
    ).replace("'", "'\\''")
    r = runner.run(t.url, f"{sudo} sh -c '{cmd}'", timeout=120)
    out = {}
    for line in r.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip().lower()] = v.strip()[:180]
    return out
