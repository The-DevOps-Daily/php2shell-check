#!/usr/bin/env python3
"""Read the PHP version of container images from registry metadata only.

For each image it fetches the manifest and the image config blob (a few KB of
JSON) and reads ENV PHP_VERSION or a version label. It never downloads a
layer. Results go to results/scan-<UTC time>.json.

Docker Hub counts every manifest GET against the anonymous pull limit
(100 per hour per IP when this was written). For Docker Hub images the scan
takes the platform digest from the Hub tags API, so each image costs one
counted manifest GET.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from php2shell_check import classify_upstream  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ACCEPT_INDEX = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
USER_AGENT = "php2shell-check registry_scan (+https://github.com/The-DevOps-Daily/php2shell-check)"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def http_get(url, headers=None, timeout=30):
    """GET with manual redirects, so the registry token is not sent to the blob CDN."""
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    for _ in range(5):
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with OPENER.open(req, timeout=timeout) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                url = urllib.parse.urljoin(url, e.headers["Location"])
                hdrs = {"User-Agent": USER_AGENT}
                continue
            return e.code, dict(e.headers), e.read()
    raise RuntimeError("too many redirects")


def parse_ref(ref):
    """'php:8.4-fpm' -> ('registry-1.docker.io', 'library/php', '8.4-fpm')."""
    name, _, tag = ref.rpartition(":")
    if not name or "/" in tag:
        name, tag = ref, "latest"
    parts = name.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", name
    if registry in ("docker.io", "index.docker.io", "registry-1.docker.io"):
        registry = "registry-1.docker.io"
        if "/" not in repo:
            repo = "library/" + repo
    return registry, repo, tag


TOKENS = {}


def registry_get(registry, repo, path, accept=None):
    url = "https://%s/v2/%s/%s" % (registry, repo, path)
    headers = {}
    if accept:
        headers["Accept"] = accept
    key = (registry, repo)
    if key in TOKENS:
        headers["Authorization"] = "Bearer " + TOKENS[key]
    status, hdrs, body = http_get(url, headers)
    if status == 401 and key not in TOKENS:
        challenge = next((v for k, v in hdrs.items() if k.lower() == "www-authenticate"), "")
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        if "realm" not in params:
            return status, hdrs, body
        q = {"scope": params.get("scope", "repository:%s:pull" % repo)}
        if params.get("service"):
            q["service"] = params["service"]
        st, _, tok = http_get(params["realm"] + "?" + urllib.parse.urlencode(q))
        if st != 200:
            return status, hdrs, body
        data = json.loads(tok)
        TOKENS[key] = data.get("token") or data.get("access_token")
        headers["Authorization"] = "Bearer " + TOKENS[key]
        status, hdrs, body = http_get(url, headers)
    return status, hdrs, body


def pick_platform(entries, platform):
    os_name, _, arch = platform.partition("/")
    for e in entries:
        p = e.get("platform", e)
        if p.get("os") == os_name and p.get("architecture") == arch and not p.get("variant"):
            return e
    return None


def hub_tag(repo, tag):
    url = "https://hub.docker.com/v2/repositories/%s/tags/%s" % (repo, urllib.parse.quote(tag))
    status, _, body = http_get(url)
    if status != 200:
        return None
    return json.loads(body)


def version_from_config(cfg):
    """PHP version from image metadata. Returns (version, source)."""
    c = cfg.get("config") or {}
    env = dict(e.split("=", 1) for e in (c.get("Env") or []) if "=" in e)
    labels = c.get("Labels") or {}
    if env.get("PHP_VERSION"):
        return env["PHP_VERSION"], "ENV PHP_VERSION"
    if env.get("BITNAMI_APP_NAME", "").startswith("php") and env.get("APP_VERSION"):
        return env["APP_VERSION"], "ENV APP_VERSION (Bitnami)"
    for key in ("org.opencontainers.image.version",):
        v = labels.get(key, "")
        if re.match(r"^8\.[0-9]+\.[0-9]+", v) and "php" in (labels.get("org.opencontainers.image.title", "") +
                                                          labels.get("org.opencontainers.image.ref.name", "")).lower():
            return v, "LABEL %s" % key
    return None, "no PHP version in ENV or labels"


def scan_one(ref, platform):
    rec = {"ref": ref, "platform": platform}
    registry, repo, tag = parse_ref(ref)
    rec.update({"registry": registry, "repo": repo, "tag": tag})
    digest = None
    if registry == "registry-1.docker.io":
        info = hub_tag(repo, tag)
        if info is None:
            rec["error"] = "tag not found on Docker Hub"
            return rec
        rec["hub_tag_last_pushed"] = info.get("tag_last_pushed") or info.get("last_updated")
        img = pick_platform(info.get("images") or [], platform)
        if img is None:
            rec["error"] = "no %s image for this tag" % platform
            return rec
        digest = img.get("digest")
        rec["hub_image_last_pushed"] = img.get("last_pushed")
    if digest is None:
        status, _, body = registry_get(registry, repo, "manifests/" + tag, ACCEPT_INDEX)
        if status != 200:
            rec["error"] = "manifest HTTP %d" % status
            return rec
        top = json.loads(body)
        if "manifests" in top:
            m = pick_platform(top["manifests"], platform)
            if m is None:
                rec["error"] = "no %s manifest" % platform
                return rec
            digest = m["digest"]
        else:
            rec["manifest_digest"] = None
            manifest = top
    rec["manifest_digest"] = digest
    if digest:
        status, _, body = registry_get(registry, repo, "manifests/" + digest, ACCEPT_INDEX)
        if status != 200:
            rec["error"] = "platform manifest HTTP %d" % status
            return rec
        manifest = json.loads(body)
    cfg_digest = (manifest.get("config") or {}).get("digest")
    if not cfg_digest:
        rec["error"] = "manifest has no config"
        return rec
    status, _, body = registry_get(registry, repo, "blobs/" + cfg_digest)
    if status != 200:
        rec["error"] = "config blob HTTP %d" % status
        return rec
    if hashlib.sha256(body).hexdigest() != cfg_digest.split(":", 1)[-1]:
        rec["error"] = "config blob digest mismatch"
        return rec
    cfg = json.loads(body)
    rec["config_digest"] = cfg_digest
    rec["config_created"] = cfg.get("created")
    version, source = version_from_config(cfg)
    rec["php_version"] = version
    rec["version_source"] = source
    rec["status"], rec["reason"] = classify_upstream(version)
    if version and rec["reason"] == "no PHP version found":
        rec["reason"] = "%s=%s is a branch, not a full version" % (source, version)
    return rec


def load_images(path):
    images = []
    group = ""
    with open(path) as f:
        for line in f:
            s = line.strip()
            if s.startswith("## "):
                group = s[3:]
                continue
            if not s or s.startswith("#"):
                continue
            ref, _, why = s.partition("#")
            images.append({"ref": ref.strip(), "group": group, "why": why.strip()})
    return images


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("refs", nargs="*", help="image references; default: the list in images.txt")
    ap.add_argument("--images", default=os.path.join(HERE, "images.txt"))
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    ap.add_argument("--platform", default="linux/amd64")
    ap.add_argument("--label", default="", help="free text saved with the run")
    args = ap.parse_args(argv)

    if args.refs:
        images = [{"ref": r, "group": "command line", "why": ""} for r in args.refs]
        images_sha = hashlib.sha256("\n".join(args.refs).encode()).hexdigest()
    else:
        images = load_images(args.images)
        images_sha = sha256_file(args.images)

    started = datetime.datetime.utcnow().replace(microsecond=0)
    os.makedirs(args.out, exist_ok=True)
    out_path = os.path.join(args.out, "scan-%s.json" % started.strftime("%Y%m%dT%H%M%SZ"))
    # One writer per file: refuse to reuse a path.
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)

    records = []
    for img in images:
        try:
            rec = scan_one(img["ref"], args.platform)
        except Exception as e:  # keep going; the error is part of the result
            rec = {"ref": img["ref"], "error": "%s: %s" % (type(e).__name__, e)}
        rec["group"], rec["why"] = img["group"], img["why"]
        rec["checked_utc"] = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        records.append(rec)
        print("%-44s %-11s %-10s %s" % (img["ref"], rec.get("status", "error"), rec.get("php_version") or "-",
                                         rec.get("error") or rec.get("reason", "")), flush=True)

    run = {
        "tool": "registry_scan.py",
        "started_utc": started.isoformat() + "Z",
        "finished_utc": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "platform": args.platform,
        "label": args.label,
        "code_sha256": {"registry_scan.py": sha256_file(os.path.abspath(__file__)),
                        "php2shell_check.py": sha256_file(os.path.join(HERE, "php2shell_check.py"))},
        "images_sha256": images_sha,
        "records": records,
    }
    with os.fdopen(fd, "w") as f:
        json.dump(run, f, indent=2)
        f.write("\n")
    counts = {}
    for r in records:
        k = r.get("status", "error")
        counts[k] = counts.get(k, 0) + 1
    print("\n%s  %s" % (out_path, ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
