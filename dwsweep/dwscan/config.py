from __future__ import annotations
import ipaddress
import json
import os
from dataclasses import dataclass, field, asdict

from .errors import NotAuthorized

PROFILE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "profiles")


@dataclass
class Profile:
    name: str
    discover_ports: list = field(default_factory=lambda: [80, 443])
    fingerprint: bool = True
    verify: bool = False
    verify_reps: int = 3
    exploit: bool = False
    exploit_on: str = "confirmed"
    deploy: bool = False
    provision: bool = False
    workers: int = 16
    timeout: int = 30
    mib: int = 8
    levels: int = 62
    max_retries: int = 2
    shell_path: str = "/"
    cleanup: bool = False
    patch: bool = False
    wipe_logs: bool = False
    harvest: bool = True

    @classmethod
    def load(cls, name: str) -> "Profile":
        path = os.path.join(PROFILE_DIR, f"{name}.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Profil unbekannt: {name}")
        with open(path) as fh:
            return cls(name=name, **json.load(fh))

    def dump(self) -> dict:
        return asdict(self)


def _hostmatch(host: str, pattern: str) -> bool:
    if host == pattern:
        return True
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


@dataclass
class Scope:
    """Offen per Default. Exclude gewinnt immer. strict=True schliesst."""

    cidrs: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    exclude: list = field(default_factory=list)
    authorized_by: str = ""
    ticket: str = ""
    strict: bool = False

    def allows(self, host: str) -> bool:
        if any(_hostmatch(host, ex) for ex in self.exclude):
            return False
        if any(_hostmatch(host, h) for h in self.hosts):
            return True
        if any(_hostmatch(host, c) for c in self.cidrs):
            return True
        return not self.strict

    def guard(self, host: str):
        if not self.allows(host):
            raise NotAuthorized(f"{host} ausserhalb des Scopes")

    def reason(self, host: str) -> str:
        if any(_hostmatch(host, ex) for ex in self.exclude):
            return "excluded"
        return "allowed" if self.allows(host) else "not_in_scope"
