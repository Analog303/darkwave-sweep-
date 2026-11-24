"""Prueft gefundene API-Keys gegen die jeweilige API."""
from __future__ import annotations

import requests

CHECKS = {
    "huggingface": ("GET", "https://huggingface.co/api/whoami-v2", "Authorization"),
    "openai": ("GET", "https://api.openai.com/v1/models", "Authorization"),
    "anthropic": ("GET", "https://api.anthropic.com/v1/models", "x-api-key"),
    "github": ("GET", "https://api.github.com/user", "Authorization"),
}


def check(kind: str, key: str) -> bool | None:
    c = CHECKS.get(kind)
    if not c:
        return None
    method, url, hdr = c
    h = {hdr: ("Bearer " + key if hdr == "Authorization" else key)}
    if kind == "anthropic":
        h["anthropic-version"] = "2023-06-01"
    try:
        r = requests.request(method, url, headers=h, timeout=10)
        return r.status_code in (200, 201)
    except Exception:
        return None
