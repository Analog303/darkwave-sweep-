from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Verdict(str, Enum):
    UNREACHABLE = "unreachable"
    NO_PHP = "no_php"
    PATCHED = "patched"
    LIKELY = "likely"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    OWNED = "owned"


class Sev(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Target:
    host: str
    port: int
    scheme: str
    label: str = ""
    reachable: bool = True
    server: str = ""
    powered_by: str = ""
    os_hint: str = ""
    php_version: str | None = None
    eol: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def url(self) -> str:
        default = (self.scheme == "https" and self.port == 443) or \
                  (self.scheme == "http" and self.port == 80)
        return f"{self.scheme}://{self.host}" + ("" if default else f":{self.port}")

    def key(self) -> str:
        return f"{self.host}:{self.port}/{self.scheme}"


@dataclass
class Evidence:
    phase: str
    kind: str
    detail: str
    status: int | None = None
    bytes: int | None = None
    marker: str | None = None
    ts: str = field(default_factory=utc)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class Finding:
    cve: str
    severity: Sev
    verdict: Verdict
    confidence: float = 0.0
    evidence: list = field(default_factory=list)
    remediation: str = ""


@dataclass
class Access:
    kind: str
    locator: str
    secret: str = ""
    privileged: bool = False
    verified: bool = False
    removed: bool = False


@dataclass
class Result:
    target: Target
    findings: list = field(default_factory=list)
    privileges: dict = field(default_factory=dict)
    accesses: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    started: str = field(default_factory=utc)
    finished: str | None = None

    @property
    def best(self) -> Verdict:
        order = [Verdict.OWNED, Verdict.EXPLOITED, Verdict.CONFIRMED,
                 Verdict.LIKELY, Verdict.PATCHED, Verdict.NO_PHP, Verdict.UNREACHABLE]
        for v in order:
            if any(f.verdict == v for f in self.findings):
                return v
        return Verdict.UNREACHABLE
