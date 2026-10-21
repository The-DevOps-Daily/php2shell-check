#!/usr/bin/env python3
# Test stand-in for dpkg-query, rpm, apk, docker and the fake PHP binaries.
# It looks up "<name> <args>" in the JSON table at $SHIM_TABLE (a list of
# [glob pattern, exit code, stdout]) and prints the first match.
import fnmatch
import json
import os
import sys

name = os.environ.get("SHIM_NAME") or os.path.basename(sys.argv[0])
call = " ".join([name] + sys.argv[1:])
with open(os.environ["SHIM_TABLE"]) as f:
    table = json.load(f)
with open(os.environ["SHIM_TABLE"] + ".calls", "a") as log:
    log.write(call + "\n")
for pattern, code, out in table:
    if fnmatch.fnmatchcase(call, pattern):
        sys.stdout.write(out)
        sys.exit(code)
sys.exit(1)
