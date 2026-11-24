from __future__ import annotations
import argparse
import os
import sys

from .config import Profile, Scope
from .audit import Audit, JsonWriter
from .discovery import expand, sweep
from .engine import run
from .exploit import NativeRunner, ExternalRunner
from .report import to_dict, summary


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.partition(":")[0].split("/")[0]


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser("dwscan")
    ap.add_argument("profile", choices=["recon", "verify", "full", "sweep"])
    ap.add_argument("-t", "--target", action="append", default=[])
    ap.add_argument("-f", "--file")
    ap.add_argument("-c", "--cidr", action="append", default=[])
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--strict", action="store_true",
                    help="geschlossener Scope: nur benannte Ziele")
    ap.add_argument("--authorized-by", default="")
    ap.add_argument("--ticket", default="")
    ap.add_argument("--skip-auth", action="store_true")
    ap.add_argument("--runner", help="optional: externes Exploit-Template")
    ap.add_argument("--offsets", help="JSON mit Offset-Overrides")
    ap.add_argument("--exploit-debug", action="store_true")
    ap.add_argument("--out", default="out")
    ap.add_argument("-w", "--workers", type=int)
    ap.add_argument("--mib", type=int)
    ap.add_argument("--reps", type=int)
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)

    if a.profile != "recon" and not a.authorized_by and not a.skip_auth:
        ap.error("--authorized-by fehlt (Profil verify/full/sweep), abschaltbar mit --skip-auth")

    p = Profile.load(a.profile)
    for k in ("workers", "mib"):
        v = getattr(a, k)
        if v:
            setattr(p, k, v)
    if a.reps:
        p.verify_reps = a.reps
    p.cleanup = a.cleanup

    targets = a.target[:]
    if a.file:
        with open(a.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]

    scope = Scope(cidrs=a.cidr, hosts=[_host_of(t) for t in targets],
                  exclude=a.exclude, authorized_by=a.authorized_by,
                  ticket=a.ticket, strict=a.strict)

    if a.dry_run:
        print(p.dump())
        print(f"{len(targets)} Ziele, {len(a.cidr)} cidrs, strict={scope.strict}, "
              f"{len(scope.exclude)} excluded")
        return 0

    audit = Audit(os.path.join(a.out, "audit.jsonl"))
    audit.write("cli", "start", "", profile=p.name, scope=scope.__dict__)

    if a.cidr:
        targets += [t.url for t in sweep(expand(a.cidr), p.discover_ports, 128, 2.5, audit)]
    if not targets:
        ap.error("kein Ziel")
    targets = list(dict.fromkeys(targets))

    runner = (ExternalRunner(a.runner) if a.runner else
              NativeRunner(mib=p.mib, levels=p.levels, timeout=p.timeout,
                           offsets=a.offsets, debug=a.exploit_debug))

    writer = JsonWriter(os.path.join(a.out, "report.json"))
    results = []

    def sink(r):
        results.append(r)
        payload = {"meta": {"profile": p.name, "authorized_by": scope.authorized_by,
                            "ticket": scope.ticket, "scope": scope.__dict__},
                   "results": [to_dict(x) for x in results]}
        if getattr(runner, "log", None):
            payload["exploit_debug"] = runner.log[-50:]
        writer.write(payload)

    run(targets, p, scope, audit, runner, on_result=sink)
    writer.write({"meta": {"profile": p.name, "authorized_by": scope.authorized_by},
                  "results": [to_dict(x) for x in results]})
    print(summary(results))
    audit.write("cli", "end", "", total=len(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
