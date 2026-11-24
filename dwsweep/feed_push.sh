#!/bin/sh
# Dunkle Ziele aus dem Audit an Artex auf demselben Host übergeben.
AUD=/opt/dwsweep/loot/audit.jsonl
OUT=/opt/artex/feed.txt
[ -f "$AUD" ] || exit 0
mkdir -p /opt/artex
grep -E "\"action\": \"(opened|cred|stalker)\"" "$AUD" | python3 -c "import sys,json;s=set();[s.add(json.loads(l).get(\"target\",\"\")) for l in sys.stdin];print(\"\n\".join(x for x in s if x))" > "$OUT.tmp" 2>/dev/null && mv "$OUT.tmp" "$OUT"
