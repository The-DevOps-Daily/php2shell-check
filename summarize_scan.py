#!/usr/bin/env python3
"""Summarise every results/scan-*.json: counts per run, each image across runs,
and how long after the 14:00 UTC release each patched image was built.

The status is recomputed from the recorded PHP version with the same rule as
the scan, so runs made with older code are judged the same way.
"""

import argparse
import datetime
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from php2shell_check import classify_upstream  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
# The release was scheduled for 14:00 UTC (php.net, 20 October 2026).
RELEASE = datetime.datetime(2026, 10, 21, 14, 0, 0)
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def ts(s):
    """RFC 3339 timestamp -> naive UTC datetime, or None."""
    m = TS_RE.match((s or "").strip())
    if not m:
        return None
    t = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    if m.group(2):
        t += datetime.timedelta(microseconds=int((m.group(2) + "000000")[:6]))
    tz = m.group(3)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        t -= sign * datetime.timedelta(hours=hh, minutes=mm)
    return t


def status(rec):
    if rec.get("error"):
        return "error"
    return classify_upstream(rec.get("php_version"))[0]


def load(results):
    runs = []
    for path in sorted(glob.glob(os.path.join(results, "scan-*.json"))):
        with open(path) as f:
            run = json.load(f)
        if "started_utc" not in run or "code_sha256" not in run:
            sys.exit("refusing %s: not a stamped scan file" % path)
        run["_file"] = os.path.basename(path)
        runs.append(run)
    return runs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--results", default=os.path.join(HERE, "results"))
    ap.add_argument("--chart", action="store_true", help="also print chart JSON for the post")
    args = ap.parse_args(argv)
    runs = load(args.results)
    if not runs:
        sys.exit("no scan files in %s" % args.results)

    print("Runs")
    for run in runs:
        counts = {}
        for r in run["records"]:
            counts[status(r)] = counts.get(status(r), 0) + 1
        start = ts(run["started_utc"])
        if start is None:
            sys.exit("refusing %s: bad started_utc" % run["_file"])
        hours = (start - RELEASE).total_seconds() / 3600
        print("  %s  started %s (scheduled release +%.1f h)  %d images: %s" % (
            run["_file"], run["started_utc"], hours, len(run["records"]),
            ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
        print("      code %s / %s, images list %s" % (
            run["code_sha256"]["registry_scan.py"][:12], run["code_sha256"]["php2shell_check.py"][:12],
            run["images_sha256"][:12]))

    print("\nImages (status, metadata PHP version and image build time per run)")
    keys = []
    for run in runs:
        for r in run["records"]:
            key = (r["ref"], r.get("platform"))
            if key not in keys:
                keys.append(key)
    for ref, platform in keys:
        cells = []
        for run in runs:
            rec = next((r for r in run["records"] if (r["ref"], r.get("platform")) == (ref, platform)), None)
            if rec is None:
                cells.append("-")
                continue
            b = ts(rec.get("config_created"))
            built = b.strftime("%m-%d %H:%M") if b else "?"
            if b and b >= RELEASE:
                built += " (+%.1f h)" % ((b - RELEASE).total_seconds() / 3600)
            cells.append("%s %s, built %s" % (status(rec), rec.get("php_version") or "?", built))
        print("  %-34s %s" % ("%s [%s]" % (ref, platform), " | ".join("%-44s" % c for c in cells)))

    last = runs[-1]
    patched_after = []
    for r in last["records"]:
        b = ts(r.get("config_created"))
        if status(r) == "patched" and b and b >= RELEASE:
            patched_after.append((b - RELEASE).total_seconds() / 3600)
    if patched_after:
        patched_after.sort()
        mid = patched_after[len(patched_after) // 2] if len(patched_after) % 2 else \
            (patched_after[len(patched_after) // 2 - 1] + patched_after[len(patched_after) // 2]) / 2
        print("\nPatched images built after the scheduled release, last run: %d, built %.1f to %.1f h after it (median %.1f h)"
              % (len(patched_after), patched_after[0], patched_after[-1], mid))

    if args.chart:
        series = ["patched", "vulnerable", "unknown"]
        rows = []
        for run in runs:
            label = "%s UTC" % run["started_utc"][5:16].replace("T", " ")
            counts = {s: 0 for s in series}
            for r in run["records"]:
                s = status(r)
                counts[s if s in counts else "unknown"] += 1
            for s in series:
                rows.append({"label": "%s %s" % (label, s), "value": counts[s], "series": s})
        print(json.dumps({"type": "bar", "rows": rows}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
