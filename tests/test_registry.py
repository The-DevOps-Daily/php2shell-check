import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import registry_scan as rs  # noqa: E402


class ParseRef(unittest.TestCase):
    def test_refs(self):
        self.assertEqual(rs.parse_ref("php:8.4-fpm"), ("registry-1.docker.io", "library/php", "8.4-fpm"))
        self.assertEqual(rs.parse_ref("serversideup/php:8.4-fpm-nginx"),
                         ("registry-1.docker.io", "serversideup/php", "8.4-fpm-nginx"))
        self.assertEqual(rs.parse_ref("wordpress"), ("registry-1.docker.io", "library/wordpress", "latest"))
        self.assertEqual(rs.parse_ref("ghcr.io/org/app:1.2"), ("ghcr.io", "org/app", "1.2"))
        self.assertEqual(rs.parse_ref("localhost:5000/app"), ("localhost:5000", "app", "latest"))

    def test_digest_refs_from_kubectl(self):
        d = "sha256:" + "a" * 64
        self.assertEqual(rs.parse_ref("docker.io/library/php@" + d), ("registry-1.docker.io", "library/php", d))
        self.assertEqual(rs.parse_ref("php:8.4-fpm@" + d), ("registry-1.docker.io", "library/php", d))
        self.assertEqual(rs.parse_ref("docker-pullable://ghcr.io/org/app@" + d), ("ghcr.io", "org/app", d))


class VersionFromConfig(unittest.TestCase):
    def cfg(self, env=(), labels=None):
        return {"config": {"Env": list(env), "Labels": labels or {}}}

    def test_official_env(self):
        self.assertEqual(rs.version_from_config(self.cfg(["PHP_VERSION=8.4.27"])), ("8.4.27", "ENV PHP_VERSION"))

    def test_bitnami(self):
        v = rs.version_from_config(self.cfg(["BITNAMI_APP_NAME=php-fpm", "APP_VERSION=8.5.12"]))
        self.assertEqual(v[0], "8.5.12")

    def test_unrelated_app_version_is_ignored(self):
        v = rs.version_from_config(self.cfg(["BITNAMI_APP_NAME=nginx", "APP_VERSION=1.27.0"]))
        self.assertIsNone(v[0])

    def test_nothing(self):
        self.assertIsNone(rs.version_from_config(self.cfg(["PATH=/usr/bin"]))[0])


class ScanOne(unittest.TestCase):
    """scan_one with the network replaced by canned responses."""

    def setUp(self):
        self.orig = rs.http_get
        rs.TOKENS.clear()

    def tearDown(self):
        rs.http_get = self.orig

    def fake(self, config_bytes, claimed_digest=None, manifest_tamper=False):
        digest = claimed_digest or "sha256:" + hashlib.sha256(config_bytes).hexdigest()
        manifest = json.dumps({"config": {"digest": digest}}).encode()
        self.amd = "sha256:" + hashlib.sha256(manifest).hexdigest()
        hub = {"tag_last_pushed": "2026-10-21T17:30:05Z",
               "images": [{"os": "linux", "architecture": "arm64", "variant": "v8", "digest": "sha256:" + "1" * 64},
                          {"os": "linux", "architecture": "amd64", "digest": self.amd, "last_pushed": "x"}]}
        served = manifest + (b" " if manifest_tamper else b"")

        def http_get(url, headers=None, timeout=30):
            if url.startswith("https://hub.docker.com/"):
                return 200, {}, json.dumps(hub).encode()
            if url.endswith("manifests/" + self.amd):
                return 200, {}, served
            if "/blobs/" in url:
                return 200, {}, config_bytes
            return 404, {}, b""
        rs.http_get = http_get

    def test_reads_amd64_config(self):
        cfg = json.dumps({"created": "2026-10-21T15:54:31Z", "config": {"Env": ["PHP_VERSION=8.4.27"]}}).encode()
        self.fake(cfg)
        rec = rs.scan_one("php:8.4-fpm", "linux/amd64")
        self.assertEqual((rec["php_version"], rec["status"], rec["manifest_digest"]), ("8.4.27", "patched", self.amd))

    def test_refuses_manifest_with_wrong_digest(self):
        cfg = json.dumps({"config": {"Env": ["PHP_VERSION=8.4.27"]}}).encode()
        self.fake(cfg, manifest_tamper=True)
        rec = rs.scan_one("php:8.4-fpm", "linux/amd64")
        self.assertIn("digest mismatch", rec["error"])

    def test_refuses_config_for_another_platform(self):
        cfg = json.dumps({"os": "linux", "architecture": "arm64", "config": {"Env": ["PHP_VERSION=8.4.27"]}}).encode()
        self.fake(cfg)
        rec = rs.scan_one("php:8.4-fpm", "linux/amd64")
        self.assertIn("not linux/amd64", rec["error"])

    def test_platform_variants(self):
        entries = [{"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}, "digest": "a"},
                   {"platform": {"os": "linux", "architecture": "amd64"}, "digest": "b"},
                   {"platform": {"os": "linux", "architecture": "arm", "variant": "v6"}, "digest": "c"},
                   {"platform": {"os": "linux", "architecture": "arm", "variant": "v7"}, "digest": "d"}]
        self.assertEqual(rs.pick_platform(entries, "linux/arm64")["digest"], "a")
        self.assertEqual(rs.pick_platform(entries, "linux/arm64/v8")["digest"], "a")
        self.assertEqual(rs.pick_platform(entries, "linux/amd64")["digest"], "b")
        self.assertEqual(rs.pick_platform(entries, "linux/arm/v7")["digest"], "d")
        self.assertIsNone(rs.pick_platform(entries, "linux/arm"))  # ambiguous

    def test_refuses_config_with_wrong_digest(self):
        cfg = json.dumps({"config": {"Env": ["PHP_VERSION=8.4.27"]}}).encode()
        self.fake(cfg, claimed_digest="sha256:" + "0" * 64)
        rec = rs.scan_one("php:8.4-fpm", "linux/amd64")
        self.assertIn("digest mismatch", rec["error"])
        self.assertNotIn("status", rec)

    def test_branch_only_version_is_unknown(self):
        cfg = json.dumps({"config": {"Env": ["PHP_VERSION=8.4"]}}).encode()
        self.fake(cfg)
        rec = rs.scan_one("thecodingmachine/php:8.4-v5-fpm", "linux/amd64")
        self.assertEqual(rec["status"], "unknown")
        self.assertIn("branch", rec["reason"])


if __name__ == "__main__":
    unittest.main()
