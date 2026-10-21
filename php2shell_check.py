#!/usr/bin/env python3
"""Find every PHP on a host and its containers, and say whether each one has
the fixes for CVE-2026-109618 and CVE-2026-109619 (PHP2Shell).

Read-only: it reads files, runs `php -v` / `php -i` style commands, lists
processes and, for containers, runs the same commands with `docker exec`.
It sends no requests to any PHP application.

Exit codes: 0 = every PHP found is patched, 1 = something is vulnerable or a
process still runs a replaced binary, 2 = something could not be checked.
"""

import argparse
import glob
import gzip
import json
import os
import re
import shutil
import subprocess
import sys

# Fixed releases per branch, from the PHP advisories GHSA-w8hw-w9fx-j79w and
# GHSA-6wmf-4rv5-p3rp. Branches older than 8.2 get no upstream fix.
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
VULNS = {
    "CVE-2026-109618": ("CVE-2026-109618", "GHSA-w8hw-w9fx-j79w"),
    "CVE-2026-109619": ("CVE-2026-109619", "GHSA-6wmf-4rv5-p3rp"),
}

PATCHED, VULNERABLE, STALE, UNKNOWN = "patched", "vulnerable", "restart-needed", "unknown"

# How each SAPI is exposed, per the php.net advisory of 21 October 2026.
EXPOSURE = {
    "apache2handler": "web SAPI (mod_php): highest risk per php.net",
    "fpm": "web SAPI (PHP-FPM)",
    "cgi": "web SAPI (php-cgi)",
    "litespeed": "web SAPI (LiteSpeed LSAPI)",
    "frankenphp": "web SAPI (FrankenPHP)",
    "embed": "embed library: exposed if a server loads it",
    "cli": "CLI: not a web SAPI unless it runs `php -S`; same package line often ships FPM/mod_php",
}

# Settings named in the php.net interim guidance. Reported only; they never
# turn a vulnerable result into a pass.
WATCHED_INI = ("session.upload_progress.enabled", "fatal_error_backtraces", "memory_limit", "post_max_size")

BIN_GLOBS = [
    "/usr/bin/*", "/usr/sbin/*", "/usr/local/bin/*", "/usr/local/sbin/*", "/bin/*", "/sbin/*",
    "/usr/lib/cgi-bin/*",
    "/opt/remi/php*/root/usr/bin/*", "/opt/remi/php*/root/usr/sbin/*",
    "/opt/cpanel/ea-php*/root/usr/bin/*", "/opt/cpanel/ea-php*/root/usr/sbin/*",
    "/opt/plesk/php/*/bin/*", "/opt/plesk/php/*/sbin/*",
    "/opt/alt/php*/usr/bin/*", "/opt/alt/php*/usr/sbin/*",
    "/usr/local/lsws/lsphp*/bin/*", "/www/server/php/*/bin/*", "/www/server/php/*/sbin/*",
    "/opt/php*/bin/*", "/opt/php*/sbin/*", "/usr/local/php*/bin/*", "/usr/local/php*/sbin/*",
]
LIB_GLOBS = [
    "/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
    "/usr/lib/httpd/modules/libphp*.so", "/usr/local/apache2/modules/libphp*.so",
    "/usr/lib/libphp*.so", "/usr/lib64/libphp*.so", "/usr/local/lib/libphp*.so",
    "/usr/lib/*-linux-gnu/libphp*.so",
]
NAME_RE = re.compile(r"^(php(-fpm|-cgi)?[0-9.]*|lsphp[0-9.]*|frankenphp)$")
PROC_RE = re.compile(r"(^|/)(php(-fpm|-cgi)?[0-9.]*|lsphp[0-9.]*|frankenphp|apache2|httpd)(\s|:|$)")
VERSION_STRING_RE = re.compile(rb"X-Powered-By: PHP/([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.~+-]*)")
DASH_V_RE = re.compile(r"(?m)^(?:PHP|FrankenPHP \S+ PHP) ([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.~+-]*)")
PRERELEASE_RE = re.compile(r"(?i)^-?(dev|alpha|beta|rc)")
CONTAINER_ID_RE = re.compile(r"([0-9a-f]{64})")


# ---------------------------------------------------------------- versions

def parse_version(text):
    """'8.4.23' -> ((8, 4, 23), ''); '7.2.24-0ubuntu0.18.04.17' keeps the suffix."""
    m = re.match(r"^\s*([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$", text or "")
    if not m:
        return None, ""
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), m.group(4).strip()


def classify_upstream(version_text):
    """Verdict from the upstream version alone: patched, vulnerable or unknown."""
    version, suffix = parse_version(version_text)
    if version is None:
        return UNKNOWN, "no PHP version found"
    if PRERELEASE_RE.match(suffix):
        return UNKNOWN, "pre-release build %s: check the commit it was built from" % version_text
    branch = version[:2]
    if branch in FIXED:
        fixed = FIXED[branch]
        fixed_text = "%d.%d.%d" % fixed
        if version >= fixed:
            return PATCHED, "upstream %d.%d.%d >= %s" % (version + (fixed_text,))
        return VULNERABLE, "upstream %d.%d.%d < %s" % (version + (fixed_text,))
    if branch < (8, 2):
        return VULNERABLE, "PHP %d.%d is end of life: no upstream fix" % branch
    return UNKNOWN, "PHP %d.%d is not covered by the advisories" % branch


def decide(version_text, evidence):
    """Combine the upstream version with distro package evidence.

    A version below the fixed release only counts as patched when the
    changelog of the package that owns this exact file names both
    vulnerabilities, and that changelog belongs to the installed version.
    """
    verdict, reason = classify_upstream(version_text)
    if verdict == PATCHED:
        return verdict, reason
    if evidence and evidence.get("trusted"):
        hits = evidence.get("hits", [])
        if len(hits) == len(VULNS):
            return PATCHED, "backport: %s %s changelog lists %s" % (
                evidence["package"], evidence["version"], ", ".join(hits))
        if hits:
            return UNKNOWN, "%s; %s changelog lists only %s" % (reason, evidence["package"], ", ".join(hits))
    if evidence and evidence.get("note"):
        reason = "%s; %s" % (reason, evidence["note"])
    return verdict, reason


# ---------------------------------------------------------------- runners

class HostRunner(object):
    """Runs commands and reads files on this host (optionally under --root)."""

    def __init__(self, root="/", exec_scripts=False):
        self.root = root
        self.exec_scripts = exec_scripts
        self.label = "host"

    def path(self, p):
        if self.root == "/":
            return p
        return os.path.join(self.root, p.lstrip("/"))

    def run(self, cmd, timeout=30):
        if cmd and cmd[0].startswith("/"):
            cmd = [self.path(cmd[0])] + list(cmd[1:])
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except (OSError, subprocess.SubprocessError) as e:
            return 127, b"", str(e).encode()

    def read(self, p, limit=None):
        try:
            with open(self.path(p), "rb") as f:
                return f.read(limit) if limit else f.read()
        except OSError:
            return None

    def can_exec(self, p):
        head = self.read(p, 4)
        if head is None:
            return False
        return head == b"\x7fELF" or (self.exec_scripts and head[:2] == b"#!")


class ContainerRunner(object):
    """Runs the same probes inside a running container with `<runtime> exec`."""

    def __init__(self, runtime, cid, host):
        self.prefix = [runtime, "exec", cid]
        self.host = host
        self.label = "container"

    def run(self, cmd, timeout=30):
        return self.host.run(self.prefix + cmd, timeout)

    def read(self, p, limit=None):
        rc, out, _ = self.host.run(self.prefix + ["cat", p], timeout=60)
        if rc != 0:
            return None
        return out[:limit] if limit else out

    def can_exec(self, p):
        return True


# ---------------------------------------------------------------- probes

def scan_version_bytes(data):
    m = VERSION_STRING_RE.search(data or b"")
    return m.group(1).decode() if m else None


def static_version(path):
    """Read the PHP version compiled into a binary or libphp without running it."""
    try:
        with open(path, "rb") as f:
            tail = b""
            while True:
                chunk = f.read(4 << 20)
                if not chunk:
                    return None
                found = scan_version_bytes(tail + chunk)
                if found:
                    return found
                tail = chunk[-64:]
    except OSError:
        return None


def dash_v(runner, path, sapi):
    cmd = [path, "version"] if sapi == "frankenphp" else [path, "-v"]
    rc, out, err = runner.run(cmd)
    m = DASH_V_RE.search((out + err).decode("utf-8", "replace"))
    return m.group(1) if m else None


def parse_phpinfo(text):
    """Return {key: local value} from `php -i` text or HTML output."""
    values = {}
    for m in re.finditer(r"(?m)^([A-Za-z0-9_.]+) => (.*?) => (.*)$", text):
        values[m.group(1)] = m.group(2).strip()
    for m in re.finditer(r'<td class="e">\s*([A-Za-z0-9_.]+)\s*</td><td class="v">(.*?)</td>', text):
        values.setdefault(m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip())
    m = re.search(r"Loaded Configuration File\s*(?: => |</td><td class=\"v\">)\s*([^<\n]+)", text)
    if m:
        values["_loaded_ini"] = m.group(1).strip()
    m = re.search(r"Scan this dir for additional \.ini files\s*(?: => |</td><td class=\"v\">)\s*([^<\n]+)", text)
    if m:
        values["_scan_dir"] = m.group(1).strip()
    return values


def norm_bool(value):
    v = (value or "").strip().strip('"').lower()
    if v in ("1", "on", "true", "yes"):
        return "On"
    if v in ("0", "off", "false", "no", "", "none"):
        return "Off"
    return value


def ini_from_phpinfo(runner, path, sapi):
    cmd = [path, "php-cli", "-i"] if sapi == "frankenphp" else [path, "-i"]
    rc, out, _ = runner.run(cmd)
    if rc != 0 or not out:
        return None
    info = parse_phpinfo(out.decode("utf-8", "replace"))
    result = {"source": "%s -i" % os.path.basename(path), "loaded_ini": info.get("_loaded_ini")}
    if "session.save_handler" not in info and "session.upload_progress.enabled" not in info:
        result["session.upload_progress.enabled"] = "n/a (session extension not loaded)"
    for key in WATCHED_INI:
        if key in info:
            result[key] = norm_bool(info[key]) if key in ("session.upload_progress.enabled", "fatal_error_backtraces") else info[key]
    return result


def parse_ini_files(runner, paths):
    values = {}
    for p in paths:
        data = runner.read(p)
        if data is None:
            continue
        for line in data.decode("utf-8", "replace").splitlines():
            line = line.split(";", 1)[0].strip()
            m = re.match(r"^([A-Za-z0-9_.]+)\s*=\s*(.*)$", line)
            if m and m.group(1) in WATCHED_INI:
                values[m.group(1)] = m.group(2).strip().strip('"')
    return values


def parse_fpm_pools(runner, pattern):
    """php_value / php_admin_value / php_flag / php_admin_flag per pool."""
    pools = {}
    for p in sorted(runner_glob(runner, pattern)):
        data = runner.read(p)
        if data is None:
            continue
        pool = None
        for line in data.decode("utf-8", "replace").splitlines():
            line = line.split(";", 1)[0].strip()
            m = re.match(r"^\[([^\]]+)\]$", line)
            if m:
                pool = m.group(1)
                pools.setdefault(pool, {"file": p})
                continue
            m = re.match(r"^php_(admin_)?(value|flag)\[([A-Za-z0-9_.]+)\]\s*=\s*(.*)$", line)
            if m and pool and m.group(3) in WATCHED_INI:
                pools[pool][m.group(3)] = m.group(4).strip()
    return pools


def runner_glob(runner, pattern):
    if isinstance(runner, HostRunner):
        return [p[len(runner.root.rstrip("/")):] if runner.root != "/" else p
                for p in glob.glob(runner.path(pattern))]
    rc, out, _ = runner.run(["sh", "-c", "for f in %s; do [ -e \"$f\" ] && echo \"$f\"; done" % pattern])
    return out.decode("utf-8", "replace").split() if rc == 0 else []


def fpm_pool_globs(loaded_ini):
    if not loaded_ini or loaded_ini == "(none)":
        return []
    d = os.path.dirname(loaded_ini)
    parent = os.path.dirname(d)
    return [d + "/pool.d/*.conf", d + "/php-fpm.d/*.conf", parent + "/php-fpm.d/*.conf",
            parent + "/etc/php-fpm.d/*.conf"]


def server_overrides(runner):
    """Apache php_value/php_flag for the watched keys and FastCGI PHP_VALUE params."""
    found = []
    dirs = ["/etc/apache2", "/etc/httpd", "/usr/local/apache2/conf", "/etc/nginx", "/usr/local/etc/nginx"]
    pat = re.compile(r"(php_(admin_)?(value|flag)\s+(%s)|PHP_(ADMIN_)?VALUE)" % "|".join(re.escape(k) for k in WATCHED_INI))
    if not isinstance(runner, HostRunner):
        return found
    for d in dirs:
        base = runner.path(d)
        for dirpath, _, files in os.walk(base):
            for name in files:
                full = os.path.join(dirpath, name)
                try:
                    with open(full, "rb") as f:
                        text = f.read(1 << 20).decode("utf-8", "replace")
                except OSError:
                    continue
                for n, line in enumerate(text.splitlines(), 1):
                    s = line.strip()
                    if s.startswith("#"):
                        continue
                    if pat.search(s):
                        shown = full[len(runner.root.rstrip("/")):] if runner.root != "/" else full
                        found.append("%s:%d: %s" % (shown, n, s[:160]))
    return found


def package_evidence(runner, path):
    """Which distro package owns `path`, its version, and whether its changelog
    names the CVE or GHSA IDs."""
    rc, out, _ = runner.run(["dpkg-query", "-S", path])
    if rc == 0:
        pkg = None
        for line in out.decode("utf-8", "replace").splitlines():
            if line.startswith("diversion"):
                continue
            name, _, owned = line.partition(": ")
            if owned.strip() == path:
                pkg = name.split(",")[0].strip()
                break
        if pkg:
            rc, ver, _ = runner.run(["dpkg-query", "-W", "-f=${Version}", pkg])
            version = ver.decode().strip() if rc == 0 else None
            ev = {"manager": "dpkg", "package": pkg, "version": version, "hits": [], "trusted": False}
            doc = "/usr/share/doc/%s/changelog.Debian.gz" % pkg.split(":")[0]
            data = runner.read(doc)
            if data is None:
                ev["note"] = "no %s (docs stripped?)" % doc
                return ev
            try:
                text = gzip.decompress(data).decode("utf-8", "replace")
            except (OSError, EOFError):
                ev["note"] = "unreadable %s" % doc
                return ev
            m = re.match(r"^\S+ \(([^)]+)\)", text)
            top = m.group(1) if m else None
            # /usr/share/doc/<pkg> is often a symlink to another package's
            # docs; after a partial upgrade that changelog can be newer than
            # the binary. Only trust it when its top entry is this version.
            if top != version:
                ev["note"] = "changelog top entry %s does not match installed %s" % (top, version)
                return ev
            ev["trusted"] = True
            ev["hits"] = [cve for cve, ids in VULNS.items() if any(i in text for i in ids)]
            return ev
    rc, out, _ = runner.run(["rpm", "-qf", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n", path])
    if rc == 0 and out.strip():
        lines = out.decode("utf-8", "replace").strip().splitlines()
        name, _, version = lines[0].partition("\t")
        ev = {"manager": "rpm", "package": name, "version": version, "hits": [], "trusted": False}
        if len(lines) > 1:
            ev["note"] = "file owned by %d packages" % len(lines)
            return ev
        rc, log, _ = runner.run(["rpm", "-q", "--changelog", "%s-%s" % (name, version.split(":", 1)[-1])])
        if rc != 0:
            ev["note"] = "rpm changelog not readable"
            return ev
        text = log.decode("utf-8", "replace")
        ev["trusted"] = True
        ev["hits"] = [cve for cve, ids in VULNS.items() if any(i in text for i in ids)]
        return ev
    rc, out, _ = runner.run(["apk", "info", "--who-owns", path])
    if rc == 0 and b"is owned by" in out:
        owner = out.decode().strip().rsplit(" ", 1)[-1]
        return {"manager": "apk", "package": owner, "version": owner, "hits": [], "trusted": False,
                "note": "apk keeps no changelog; upstream version decides"}
    return None


def check_binary(runner, path, sapi, static=True):
    item = {"where": runner.label, "path": path, "sapi": sapi, "exposure": EXPOSURE.get(sapi, "")}
    version = None
    if static and isinstance(runner, HostRunner):
        version = static_version(runner.path(path))
        item["version_source"] = "embedded string"
    elif not static:
        version = scan_version_bytes(runner.read(path))
        item["version_source"] = "embedded string"
    if version is None and sapi not in ("apache2handler", "embed") and runner.can_exec(path):
        version = dash_v(runner, path, sapi)
        item["version_source"] = "-v"
    item["version"] = version
    ev = package_evidence(runner, path)
    if ev:
        item["package"] = ev
    item["status"], item["reason"] = decide(version, ev)
    if sapi in ("cli", "fpm", "cgi", "litespeed", "frankenphp") and runner.can_exec(path):
        ini = ini_from_phpinfo(runner, path, sapi)
        if ini:
            item["ini"] = ini
            if sapi == "fpm":
                pools = {}
                for pattern in fpm_pool_globs(ini.get("loaded_ini")):
                    pools.update(parse_fpm_pools(runner, pattern))
                if pools:
                    item["fpm_pools"] = pools
    elif sapi in ("apache2handler", "embed"):
        item["ini"] = modphp_ini(runner, path)
    return item


def modphp_ini(runner, libpath):
    m = re.search(r"libphp([0-9.]*)\.so$", libpath)
    branch = m.group(1) if m else ""
    candidates = []
    if branch:
        candidates.append(("/etc/php/%s/apache2/php.ini" % branch, "/etc/php/%s/apache2/conf.d/*.ini" % branch))
    candidates += [("/etc/php.ini", "/etc/php.d/*.ini"),
                   ("/usr/local/etc/php/php.ini", "/usr/local/etc/php/conf.d/*.ini")]
    for ini, scan in candidates:
        files = runner_glob(runner, ini) + sorted(runner_glob(runner, scan))
        if files:
            values = parse_ini_files(runner, files)
            out = {"source": "parsed %s" % ini, "loaded_ini": ini}
            out["session.upload_progress.enabled"] = norm_bool(values["session.upload_progress.enabled"]) \
                if "session.upload_progress.enabled" in values else "On (default)"
            for k in WATCHED_INI[1:]:
                if k in values:
                    out[k] = values[k]
            return out
    return {"source": "no php.ini found for this module", "session.upload_progress.enabled": "unknown"}


def sapi_for(path):
    name = os.path.basename(path)
    if name.startswith("libphp"):
        return "apache2handler" if ("apache" in path or "httpd" in path) else "embed"
    if name.startswith("php-fpm"):
        return "fpm"
    if name.startswith("php-cgi"):
        return "cgi"
    if name.startswith("lsphp"):
        return "litespeed"
    if name == "frankenphp":
        return "frankenphp"
    return "cli"


def discover_host(runner):
    found = {}
    patterns = list(BIN_GLOBS)
    if runner.root == "/":
        patterns += [d.rstrip("/") + "/*" for d in os.environ.get("PATH", "").split(":") if d]
    for pattern in patterns:
        for p in glob.glob(runner.path(pattern)):
            if not NAME_RE.match(os.path.basename(p)):
                continue
            real = os.path.realpath(p)
            if os.path.isfile(real) and os.access(real, os.X_OK):
                rel = real[len(runner.root.rstrip("/")):] if runner.root != "/" else real
                found.setdefault(rel, set()).add(p[len(runner.root.rstrip("/")):] if runner.root != "/" else p)
    for pattern in LIB_GLOBS:
        for p in glob.glob(runner.path(pattern)):
            real = os.path.realpath(p)
            if os.path.isfile(real):
                rel = real[len(runner.root.rstrip("/")):] if runner.root != "/" else real
                found.setdefault(rel, set()).add(p[len(runner.root.rstrip("/")):] if runner.root != "/" else p)
    return found


def modphp_enabled(runner, libpath):
    for pattern in ("/etc/apache2/mods-enabled/php*.load", "/etc/httpd/conf.modules.d/*php*.conf",
                    "/usr/local/apache2/conf/httpd.conf", "/etc/apache2/apache2.conf"):
        for f in runner_glob(runner, pattern):
            data = runner.read(f) or b""
            if os.path.basename(libpath).encode() in data and re.search(rb"(?m)^\s*LoadModule\s+php", data):
                return "yes (%s)" % f
    return "no LoadModule line found"


# ---------------------------------------------------------------- processes

def scan_processes(proc="/proc"):
    """Running PHP processes, including those inside containers. A process whose
    binary or libphp shows '(deleted)' still runs the code from before the
    last upgrade."""
    groups = {}
    denied = 0
    for pid in sorted(os.listdir(proc), key=lambda s: int(s) if s.isdigit() else 0):
        if not pid.isdigit():
            continue
        base = os.path.join(proc, pid)
        try:
            with open(os.path.join(base, "comm")) as f:
                comm = f.read().strip()
        except OSError:
            continue
        try:
            exe = os.readlink(os.path.join(base, "exe"))
        except OSError:
            exe = None
        name = os.path.basename((exe or "").replace(" (deleted)", "")) or comm
        candidate = PROC_RE.search(name) or PROC_RE.search(comm)
        if not candidate:
            continue
        if exe is None:
            denied += 1
            continue
        lib, lib_deleted = None, False
        try:
            with open(os.path.join(base, "maps")) as f:
                for line in f:
                    if "libphp" in line:
                        lib = line.split(None, 5)[-1].strip()
                        lib_deleted = lib.endswith("(deleted)")
                        break
        except OSError:
            pass
        is_web_server = re.search(r"^(apache2|httpd)", name)
        if is_web_server and lib is None:
            continue
        container = None
        try:
            with open(os.path.join(base, "cgroup")) as f:
                m = CONTAINER_ID_RE.search(f.read())
                container = m.group(1)[:12] if m else None
        except OSError:
            pass
        key = (container, exe, lib)
        g = groups.setdefault(key, {"container": container, "exe": exe, "libphp": lib, "pids": [],
                                    "deleted": exe.endswith(" (deleted)") or lib_deleted})
        g["pids"].append(int(pid))
        if "version" not in g:
            target = os.path.join(base, "exe")
            if lib and not lib_deleted and container is None:
                target = lib
            g["version"] = static_version(target)
    return list(groups.values()), denied


# ---------------------------------------------------------------- containers

def container_runtime(requested):
    if requested:
        return requested if shutil.which(requested) else None
    for name in ("docker", "podman"):
        if shutil.which(name):
            return name
    return None


CONTAINER_FIND = (
    "for f in php php-fpm php-cgi frankenphp lsphp; do command -v $f; done 2>/dev/null; "
    "ls /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /usr/bin/php[0-9]* /usr/sbin/php-fpm[0-9]* "
    "/usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so "
    "/usr/local/apache2/modules/libphp*.so 2>/dev/null; true"
)


def check_containers(host, runtime):
    results, notes = [], []
    rc, out, err = host.run([runtime, "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"])
    if rc != 0:
        return [{"where": "containers", "status": UNKNOWN,
                 "reason": "%s ps failed: %s" % (runtime, err.decode("utf-8", "replace").strip()[:200])}], notes
    rows = [l.split("\t") for l in out.decode("utf-8", "replace").splitlines() if l.strip()]
    for row in rows:
        cid, image, name = (row + ["", "", ""])[:3]
        rc, top, _ = host.run([runtime, "top", cid])
        cmds = []
        for line in top.decode("utf-8", "replace").splitlines()[1:]:
            parts = line.split(None, 7)
            cmds.append(parts[7] if len(parts) == 8 else line)
        php_cmds = [c for c in cmds if PROC_RE.search(c.split()[0] if c.split() else "")]
        if rc != 0:
            results.append({"where": "container", "container": name, "image": image, "status": UNKNOWN,
                            "reason": "%s top failed" % runtime})
            continue
        if not php_cmds:
            continue
        cr = ContainerRunner(runtime, cid, host)
        rc, found, _ = cr.run(["sh", "-c", CONTAINER_FIND])
        paths = []
        if rc == 0:
            for p in found.decode("utf-8", "replace").split():
                rc2, real, _ = cr.run(["readlink", "-f", p])
                real = real.decode().strip() if rc2 == 0 and real.strip() else p
                if real not in paths:
                    paths.append(real)
        env_rc, env, _ = host.run([runtime, "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", cid])
        image_php = None
        for line in env.decode("utf-8", "replace").splitlines():
            if line.startswith("PHP_VERSION="):
                image_php = line.split("=", 1)[1]
        if not paths:
            results.append({"where": "container", "container": name, "image": image, "status": UNKNOWN,
                            "reason": "PHP processes running (%s) but no PHP binary found via exec"
                                      % ", ".join(sorted(set(c.split()[0] for c in php_cmds)))[:200],
                            "image_env_PHP_VERSION": image_php})
            continue
        for p in paths:
            sapi = sapi_for(p)
            item = check_binary(cr, p, sapi, static=sapi in ("apache2handler", "embed"))
            item.update({"container": name, "container_id": cid, "image": image,
                         "image_env_PHP_VERSION": image_php,
                         "processes": sorted(set(c.split()[0] for c in php_cmds))})
            results.append(item)
    return results, notes


# ---------------------------------------------------------------- report

def overall(items):
    statuses = [i.get("status") for i in items]
    if VULNERABLE in statuses or STALE in statuses:
        return 1
    if UNKNOWN in statuses:
        return 2
    return 0


def run(args):
    host = HostRunner(args.root, exec_scripts=args.exec_scripts)
    report = {"tool": "php2shell-check", "fixed": {"%d.%d" % k: "%d.%d.%d" % v for k, v in FIXED.items()},
              "items": [], "processes": [], "notes": []}
    for path, aliases in sorted(discover_host(host).items()):
        sapi = sapi_for(path)
        item = check_binary(host, path, sapi)
        item["aliases"] = sorted(a for a in aliases if a != path)
        if sapi == "apache2handler":
            item["enabled"] = modphp_enabled(host, path)
        report["items"].append(item)
    report["server_overrides"] = server_overrides(host)

    if not args.no_processes:
        groups, denied = scan_processes(args.proc)
        disk = {i["path"]: i for i in report["items"]}
        prefix = args.root.rstrip("/")
        for g in groups:
            exe = (g["exe"] or "").replace(" (deleted)", "")
            lib = g["libphp"]
            if prefix and exe.startswith(prefix + "/"):
                exe = exe[len(prefix):]
            if prefix and lib and lib.startswith(prefix + "/"):
                lib = lib[len(prefix):]
            entry = dict(g)
            entry["where"] = "process"
            if g["deleted"]:
                entry["status"] = STALE
                entry["reason"] = "running binary was replaced on disk: restart these processes"
            elif g["container"]:
                entry["status"] = "see container"
                entry["reason"] = "checked in the container section"
            elif (lib or exe) in disk:
                entry["status"] = disk[lib or exe]["status"]
                entry["reason"] = "same file as %s" % (lib or exe)
            else:
                entry["status"], entry["reason"] = classify_upstream(g.get("version"))
            report["processes"].append(entry)
        if denied:
            report["notes"].append("%d PHP-like processes could not be inspected (run as root to include them)" % denied)
            report["processes"].append({"where": "process", "status": UNKNOWN,
                                        "reason": "%d processes not readable without root" % denied})

    if not args.no_containers:
        rt = container_runtime(args.runtime)
        if rt:
            items, notes = check_containers(host, rt)
            report["containers"] = items
            report["notes"] += notes
        else:
            report["containers"] = []
            report["notes"].append("no docker or podman CLI found; container processes are still listed under processes")

    all_items = report["items"] + report["processes"] + report.get("containers", [])
    report["exit_code"] = overall(all_items)
    if not report["items"] and not report["processes"] and not report.get("containers"):
        report["notes"].append("no PHP found in the searched locations")
    return report


def print_report(r):
    out = []
    w = out.append
    w("php2shell-check: fixed releases %s" % ", ".join(sorted(r["fixed"].values())))
    w("")
    w("PHP on disk")
    if not r["items"]:
        w("  none found")
    for i in r["items"]:
        w("  %-14s %-34s %s" % ("[" + i["status"] + "]", i["path"], i["sapi"]))
        w("      version: %s (%s)" % (i.get("version") or "?", i.get("version_source", "?")))
        if i.get("exposure"):
            w("      exposure: %s" % i["exposure"])
        if i.get("aliases"):
            w("      also as: %s" % ", ".join(i["aliases"]))
        pkg = i.get("package")
        if pkg:
            hits = ", ".join(pkg.get("hits") or []) or "none"
            w("      package: %s %s (%s); CVE IDs in changelog: %s" % (pkg["package"], pkg.get("version"), pkg["manager"], hits))
        else:
            w("      package: not owned by dpkg/rpm/apk (built from source?)")
        w("      why: %s" % i["reason"])
        ini = i.get("ini")
        if ini:
            w("      session.upload_progress.enabled: %s  [%s]" % (ini.get("session.upload_progress.enabled", "?"), ini.get("source")))
            extra = ["%s=%s" % (k, ini[k]) for k in WATCHED_INI[1:] if k in ini]
            if extra:
                w("      %s" % "  ".join(extra))
        for pool, vals in sorted((i.get("fpm_pools") or {}).items()):
            ov = ["%s=%s" % (k, v) for k, v in vals.items() if k != "file"]
            w("      pool [%s] %s: %s" % (pool, vals["file"], ", ".join(ov) or "no overrides (inherits php.ini)"))
        if i.get("enabled"):
            w("      mod_php loaded: %s" % i["enabled"])
    if r.get("server_overrides"):
        w("")
        w("Web server lines that set watched PHP settings or pass PHP_VALUE")
        for line in r["server_overrides"]:
            w("  %s" % line)
    w("")
    w("Running PHP processes")
    if not r["processes"]:
        w("  none")
    for p in r["processes"]:
        if "pids" not in p:
            w("  [%s] %s" % (p["status"], p["reason"]))
            continue
        where = "container %s" % p["container"] if p["container"] else "host"
        w("  [%s] %s %s pids=%s version=%s" % (p["status"], where, p.get("libphp") or p["exe"],
                                               ",".join(map(str, p["pids"][:6])), p.get("version") or "?"))
        w("      why: %s" % p["reason"])
    w("")
    w("Containers")
    cs = r.get("containers", [])
    if not cs:
        w("  none checked")
    for c in cs:
        w("  [%s] %s (%s) %s %s" % (c["status"], c.get("container", "?"), c.get("image", "?"),
                                   c.get("path", ""), c.get("version") or ""))
        if c.get("image_env_PHP_VERSION"):
            w("      image ENV PHP_VERSION=%s" % c["image_env_PHP_VERSION"])
        if c.get("package"):
            pkg = c["package"]
            w("      package: %s %s; CVE IDs in changelog: %s" % (pkg["package"], pkg.get("version"), ", ".join(pkg.get("hits") or []) or "none"))
        w("      why: %s" % c["reason"])
        if c.get("ini"):
            w("      session.upload_progress.enabled: %s" % c["ini"].get("session.upload_progress.enabled", "?"))
    for n in r["notes"]:
        w("note: %s" % n)
    w("")
    w("result: %s (exit %d)" % ({0: "all patched", 1: "VULNERABLE or restart needed", 2: "could not check everything"}[r["exit_code"]], r["exit_code"]))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--no-containers", action="store_true")
    ap.add_argument("--no-processes", action="store_true")
    ap.add_argument("--runtime", help="container CLI to use (docker or podman); default: first found")
    ap.add_argument("--root", default="/", help=argparse.SUPPRESS)
    ap.add_argument("--proc", default="/proc", help=argparse.SUPPRESS)
    ap.add_argument("--exec-scripts", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    report = run(args)
    if args.json:
        print(json.dumps(report, indent=2, default=list))
    else:
        print(print_report(report))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
