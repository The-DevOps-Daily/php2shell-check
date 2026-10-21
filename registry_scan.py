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


class RateLimited(Exception):
    pass


def http_get(url, headers=None, timeout=30):
    """GET with manual redirects. Authorization is dropped when a redirect
    leaves the original host (registry blobs redirect to a CDN)."""
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    origin = urllib.parse.urlsplit(url)
    for _ in range(5):
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with OPENER.open(req, timeout=timeout) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                new = urllib.parse.urljoin(url, e.headers["Location"])
                target = urllib.parse.urlsplit(new)
                if target.scheme != "https":
                    raise RuntimeError("refusing redirect to %s" % target.scheme)
                if target.netloc != origin.netloc:
                    hdrs = {k: v for k, v in hdrs.items() if k.lower() != "authorization"}
                url = new
                continue
            if e.code == 429:
                raise RateLimited("HTTP 429, Retry-After %s" % e.headers.get("Retry-After", "?"))
            return e.code, dict(e.headers), e.read()
    raise RuntimeError("too many redirects")


def parse_ref(ref):
    """'php:8.4-fpm' -> ('registry-1.docker.io', 'library/php', '8.4-fpm').
    A digest reference ('php@sha256:...') returns the digest as the tag."""
    ref = ref.strip()
    if ref.startswith("docker-pullable://"):
        ref = ref[len("docker-pullable://"):]
    if "@" in ref:
        name, _, tag = ref.partition("@")
        name = name.rsplit(":", 1)[0] if ":" in name.split("/")[-1] else name
    else:
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


def fetch_token(challenge, repo):
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    if "realm" not in params:
        return None
    q = {"scope": params.get("scope", "repository:%s:pull" % repo)}
    if params.get("service"):
        q["service"] = params["service"]
    realm = params["realm"]
    sep = "&" if urllib.parse.urlsplit(realm).query else "?"
    st, _, body = http_get(realm + sep + urllib.parse.urlencode(q))
    if st != 200:
        return None
    data = json.loads(body)
    token = data.get("token") or data.get("access_token")
    return token if isinstance(token, str) and token else None


def registry_get(registry, repo, path, accept=None):
    url = "https://%s/v2/%s/%s" % (registry, repo, path)
    key = (registry, repo)
    for attempt in range(2):
        headers = {"Accept": accept} if accept else {}
        if key in TOKENS:
            headers["Authorization"] = "Bearer " + TOKENS[key]
        status, hdrs, body = http_get(url, headers)
        if status != 401 or attempt == 1:
            return status, hdrs, body
        # No token yet, or it expired: answer the challenge once.
        TOKENS.pop(key, None)
        challenge = next((v for k, v in hdrs.items() if k.lower() == "www-authenticate"), "")
        token = fetch_token(challenge, repo)
        if not token:
            return status, hdrs, body
        TOKENS[key] = token
    return status, hdrs, body


def split_platform(platform):
    parts = platform.split("/")
    return parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else None


def pick_platform(entries, platform):
    """Exact os/arch/variant match; with no variant requested, prefer an entry
    without one (linux/amd64), else accept the only variant offered (arm64/v8)."""
    os_name, arch, variant = split_platform(platform)
    candidates = []
    for e in entries:
        p = e.get("platform", e)
        if p.get("os") == os_name and p.get("architecture") == arch:
            candidates.append((p.get("variant"), e))
    if variant is not None:
        return next((e for v, e in candidates if v == variant), None)
    plain = [e for v, e in candidates if not v]
    if plain:
        return plain[0]
    return candidates[0][1] if len(candidates) == 1 else None


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
    if env.get("PHP_VERSION"):
        return env["PHP_VERSION"], "ENV PHP_VERSION"
    if env.get("BITNAMI_APP_NAME", "").startswith("php") and env.get("APP_VERSION"):
        return env["APP_VERSION"], "ENV APP_VERSION (Bitnami)"
    return None, "no PHP version in ENV"


def check_digest(body, digest):
    algo, _, want = digest.partition(":")
    if algo != "sha256":
        return "unsupported digest algorithm %s" % algo
    if hashlib.sha256(body).hexdigest() != want:
        return "digest mismatch"
    return None


def scan_one(ref, platform):
    rec = {"ref": ref, "platform": platform}
    registry, repo, tag = parse_ref(ref)
    rec.update({"registry": registry, "repo": repo, "tag": tag})
    digest = None
    if registry == "registry-1.docker.io" and not tag.startswith("sha256:"):
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
    manifest = None
    if digest is None:
        status, _, body = registry_get(registry, repo, "manifests/" + tag, ACCEPT_INDEX)
        if status != 200:
            rec["error"] = "manifest HTTP %d" % status
            return rec
        if tag.startswith("sha256:"):
            problem = check_digest(body, tag)
            if problem:
                rec["error"] = "manifest %s" % problem
                return rec
        top = json.loads(body)
        if "manifests" in top:
            m = pick_platform(top["manifests"], platform)
            if m is None:
                rec["error"] = "no %s manifest" % platform
                return rec
            digest = m["digest"]
        else:
            manifest = top
            digest = tag if tag.startswith("sha256:") else "sha256:" + hashlib.sha256(body).hexdigest()
    rec["manifest_digest"] = digest
    if manifest is None:
        status, _, body = registry_get(registry, repo, "manifests/" + digest, ACCEPT_INDEX)
        if status != 200:
            rec["error"] = "platform manifest HTTP %d" % status
            return rec
        problem = check_digest(body, digest)
        if problem:
            rec["error"] = "platform manifest %s" % problem
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
    problem = check_digest(body, cfg_digest)
    if problem:
        rec["error"] = "config blob %s" % problem
        return rec
    cfg = json.loads(body)
    os_name, arch, variant = split_platform(platform)
    if cfg.get("os") and (cfg.get("os"), cfg.get("architecture")) != (os_name, arch):
        rec["error"] = "image is %s/%s, not %s" % (cfg.get("os"), cfg.get("architecture"), platform)
        return rec
    rec["config_digest"] = cfg_digest
    rec["config_created"] = cfg.get("created")
    version, source = version_from_config(cfg)
    rec["php_version"] = version
    rec["version_source"] = source
    # This is the version the image metadata reports. An image can replace
    # PHP after setting the variable; only a look inside proves the binary.
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
    stopped = None
    for img in images:
        if stopped:
            rec = {"ref": img["ref"], "error": "not scanned: %s" % stopped}
        else:
            try:
                rec = scan_one(img["ref"], args.platform)
            except RateLimited as e:
                stopped = "rate limited (%s)" % e
                rec = {"ref": img["ref"], "error": stopped}
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
    return 1 if counts.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
