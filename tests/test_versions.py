import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import php2shell_check as c  # noqa: E402


class ClassifyUpstream(unittest.TestCase):
    def check(self, version, expected):
        self.assertEqual(c.classify_upstream(version)[0], expected, version)

    def test_fixed_releases_and_later_are_patched(self):
        for v in ("8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.4.30", "8.5.13"):
            self.check(v, c.PATCHED)

    def test_one_below_fixed_is_vulnerable(self):
        for v in ("8.2.34", "8.3.35", "8.4.26", "8.5.11", "8.4.0", "8.4.23"):
            self.check(v, c.VULNERABLE)

    def test_end_of_life_branches_are_vulnerable(self):
        for v in ("8.1.34", "8.0.30", "7.4.33", "5.4.45"):
            self.check(v, c.VULNERABLE)
        self.assertIn("end of life", c.classify_upstream("7.4.33")[1])

    def test_distro_suffix_is_not_a_prerelease(self):
        # Ubuntu 18.04 builds report PHP_VERSION with the package suffix.
        self.check("7.2.24-0ubuntu0.18.04.17", c.VULNERABLE)
        self.check("8.4.27-1+ubuntu24.04.1+deb.sury.org+1", c.PATCHED)

    def test_prereleases_and_partial_versions_are_unknown(self):
        for v in ("8.6.0RC3", "8.4.27-dev", "8.5.12alpha1", "8.4", "", None):
            self.check(v, c.UNKNOWN)

    def test_newer_branch_is_unknown(self):
        self.check("8.6.0", c.UNKNOWN)
        self.check("9.0.0", c.UNKNOWN)


class Decide(unittest.TestCase):
    def ev(self, hits, trusted=True, version="8.3.6-0ubuntu0.24.04.13"):
        return {"manager": "dpkg", "package": "php8.3-cli", "version": version, "hits": hits, "trusted": trusted}

    def test_backport_with_both_ids_is_patched(self):
        status, reason = c.decide("8.3.6", self.ev(["CVE-2026-109618", "CVE-2026-109619"]))
        self.assertEqual(status, c.PATCHED)
        self.assertIn("backport", reason)

    def test_one_id_only_is_unknown(self):
        self.assertEqual(c.decide("8.3.6", self.ev(["CVE-2026-109618"]))[0], c.UNKNOWN)

    def test_untrusted_changelog_never_patches(self):
        ev = self.ev(["CVE-2026-109618", "CVE-2026-109619"], trusted=False)
        ev["note"] = "changelog top entry x does not match installed y"
        self.assertEqual(c.decide("8.3.6", ev)[0], c.VULNERABLE)

    def test_no_package_falls_back_to_upstream(self):
        self.assertEqual(c.decide("8.4.26", None)[0], c.VULNERABLE)
        self.assertEqual(c.decide("8.4.27", None)[0], c.PATCHED)

    def test_patched_upstream_needs_no_changelog(self):
        self.assertEqual(c.decide("8.4.27", self.ev([]))[0], c.PATCHED)


class PhpInfo(unittest.TestCase):
    def test_text(self):
        text = ("Loaded Configuration File => /etc/php/8.4/fpm/php.ini\n"
                "Scan this dir for additional .ini files => /etc/php/8.4/fpm/conf.d\n"
                "session.upload_progress.enabled => Off => On\n"
                "memory_limit => 128M => 128M\n")
        info = c.parse_phpinfo(text)
        self.assertEqual(info["_loaded_ini"], "/etc/php/8.4/fpm/php.ini")
        self.assertEqual(info["session.upload_progress.enabled"], "Off")
        self.assertEqual(info["memory_limit"], "128M")

    def test_html(self):
        html = ('<tr><td class="e">Loaded Configuration File </td><td class="v">/etc/php.ini </td></tr>\n'
                '<tr><td class="e">session.upload_progress.enabled</td><td class="v">On</td><td class="v">On</td></tr>')
        info = c.parse_phpinfo(html)
        self.assertEqual(info["session.upload_progress.enabled"], "On")
        self.assertEqual(info["_loaded_ini"], "/etc/php.ini")

    def test_embedded_version_string(self):
        blob = b"\x00\x01junk X-Powered-By: PHP/8.3.6\x00more"
        self.assertEqual(c.scan_version_bytes(blob), "8.3.6")
        self.assertIsNone(c.scan_version_bytes(b"PHP 8.3.6"))


if __name__ == "__main__":
    unittest.main()
