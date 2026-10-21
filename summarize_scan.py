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
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from php2shell_check import classify_upstream  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE = datetime.datetime(2026, 10, 21, 14, 0, 0)


def ts(s):
    if not s:
        return None
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = head + "." + frac[:6]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


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
        hours = (start - RELEASE).total_seconds() / 3600
        print("  %s  started %s (release +%.1f h)  %d images: %s" % (
            run["_file"], run["started_utc"], hours, len(run["records"]),
            ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
        print("      code %s / %s, images list %s" % (
            run["code_sha256"]["registry_scan.py"][:12], run["code_sha256"]["php2shell_check.py"][:12],
            run["images_sha256"][:12]))

    print("\nImages (status and PHP version per run; built = image config 'created')")
    refs = []
    for run in runs:
        for r in run["records"]:
            if r["ref"] not in refs:
                refs.append(r["ref"])
    for ref in refs:
        cells = []
        built = None
        for run in runs:
            rec = next((r for r in run["records"] if r["ref"] == ref), None)
            if rec is None:
                cells.append("-")
                continue
            cells.append("%s %s" % (status(rec), rec.get("php_version") or "?"))
            built = rec.get("config_created") or built
        b = ts(built)
        delta = ""
        if b and b >= RELEASE:
            delta = " (release +%.1f h)" % ((b - RELEASE).total_seconds() / 3600)
        print("  %-36s %s  built %s%s" % (ref, " | ".join("%-18s" % c for c in cells), (built or "?")[:16], delta))

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
        print("\nPatched images built after the release in the last run: %d, built %.1f to %.1f h after it (median %.1f h)"
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
