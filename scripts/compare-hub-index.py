#!/usr/bin/env python3
"""Cross-check the scan's method: compare the linux/amd64 digest the Docker Hub
tags API reports with the one in the registry's own manifest index, and print
the PHP version in each. Costs two counted manifest GETs per image.

Usage: scripts/compare-hub-index.py joomla:latest nextcloud:latest ...
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import registry_scan as rs  # noqa: E402


def php_version(registry, repo, digest):
    st, _, body = rs.registry_get(registry, repo, "manifests/" + digest, rs.ACCEPT_INDEX)
    if st != 200:
        return "manifest HTTP %d" % st
    cfg_digest = json.loads(body)["config"]["digest"]
    st, _, body = rs.registry_get(registry, repo, "blobs/" + cfg_digest)
    cfg = json.loads(body)
    return "%s built %s" % (rs.version_from_config(cfg)[0], cfg.get("created", "?")[:19])


for ref in sys.argv[1:]:
    registry, repo, tag = rs.parse_ref(ref)
    hub = rs.hub_tag(repo, tag)
    hub_digest = rs.pick_platform(hub.get("images") or [], "linux/amd64")["digest"]
    st, _, body = rs.registry_get(registry, repo, "manifests/" + tag, rs.ACCEPT_INDEX)
    index = json.loads(body)
    reg_digest = rs.pick_platform(index.get("manifests", []), "linux/amd64")["digest"]
    print(ref)
    print("  hub tags API amd64: %s  %s" % (hub_digest[:19], php_version(registry, repo, hub_digest)))
    if reg_digest == hub_digest:
        print("  registry index amd64: same digest")
    else:
        print("  registry index amd64: %s  %s" % (reg_digest[:19], php_version(registry, repo, reg_digest)))
