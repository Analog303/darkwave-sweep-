from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timezone

_lock = threading.Lock()


class Audit:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def write(self, actor: str, action: str, target: str = "", **kw):
        rec = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
               "actor": actor, "action": action, "target": target, **kw}
        with _lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")


class JsonWriter:
    def __init__(self, path: str):
        self.path = path
        self.tmp = path + ".part"

    def write(self, payload: dict):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
        os.replace(self.tmp, self.path)
