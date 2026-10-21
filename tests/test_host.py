"""End-to-end tests of php2shell_check.py against fake hosts.

Each scenario builds a small filesystem under a temp root, fake PHP binaries
that carry the same embedded version string as real ones, and stand-ins for
dpkg-query, rpm, apk and docker that answer from a table.
"""

import argparse
import gzip
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import php2shell_check as c  # noqa: E402

SHIM = os.path.join(HERE, "fixtures", "shim.py")
WRAPPER = """#!/usr/bin/env python3
# {marker}
import os, runpy, sys
os.environ["SHIM_NAME"] = os.path.basename(sys.argv[0])
runpy.run_path({shim!r}, run_name="__main__")
"""
BOTH_CVES = "  * SECURITY UPDATE: PHP2Shell\n    - CVE-2026-109618\n    - CVE-2026-109619\n"


def changelog(source, version, body=""):
    return ("%s (%s) noble-security; urgency=medium\n\n%s\n -- Maintainer <m@example.org>  Wed, 21 Oct 2026 12:00:00 +0000\n\n"
            "%s (8.3.6-0ubuntu0.24.04.1) noble; urgency=medium\n\n  * older entry\n" % (source, version, body, source))


def phpinfo(ini, upload="On", memory="128M"):
    return ("Loaded Configuration File => %s\n"
            "session.save_handler => files => files\n"
            "session.upload_progress.enabled => %s => %s\n"
            "memory_limit => %s => %s\npost_max_size => 8M => 8M\n" % (ini, upload, upload, memory, memory))


class Scenario(object):
    def __init__(self, tmp):
        self.base = tmp
        self.root = os.path.join(tmp, "root")
        self.bin = os.path.join(tmp, "bin")
        self.proc = os.path.join(tmp, "proc")
        for d in (self.root, self.bin, self.proc):
            os.makedirs(d)
        self.table = []
        for tool in ("dpkg-query", "dpkg", "rpm", "apk", "docker", "podman"):
            self._wrapper(os.path.join(self.bin, tool), "shim")

    def _wrapper(self, path, marker):
        with open(path, "w") as f:
            f.write(WRAPPER.format(marker=marker, shim=SHIM))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def answer(self, pattern, out="", code=0):
        # Later answers take precedence, so a test can override a default.
        self.table.insert(0, [pattern, code, out])

    def file(self, path, data):
        full = os.path.join(self.root, path.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(full, mode) as f:
            f.write(data)
        return full

    def link(self, path, target):
        full = os.path.join(self.root, path.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        os.symlink(target, full)

    def php(self, path, version):
        full = os.path.join(self.root, path.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        self._wrapper(full, "X-Powered-By: PHP/%s" % version)
        return full

    def dpkg(self, path, package, version, doc_text=None, doc_pkg=None):
        self.answer("dpkg-query -S %s" % path, "%s: %s\n" % (package, path))
        self.answer("dpkg-query -W -f=${Version} %s" % package, version)
        self.answer("dpkg --verify %s" % package, "")
        if doc_text is not None:
            self.file("/usr/share/doc/%s/changelog.Debian.gz" % (doc_pkg or package), gzip.compress(doc_text.encode()))
            if doc_pkg:
                self.link("/usr/share/doc/%s" % package, doc_pkg)

    def process(self, pid, comm, exe, cgroup="0::/system.slice/php.service\n", maps=""):
        d = os.path.join(self.proc, str(pid))
        os.makedirs(d)
        for name, text in (("comm", comm + "\n"), ("cgroup", cgroup), ("maps", maps)):
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        os.symlink(exe, os.path.join(d, "exe"))

    def run(self, containers=False, processes=False):
        table_path = os.path.join(self.base, "table.json")
        with open(table_path, "w") as f:
            json.dump(self.table, f)
        old = dict(os.environ)
        os.environ["SHIM_TABLE"] = table_path
        os.environ["PATH"] = self.bin + os.pathsep + old.get("PATH", "")
        try:
            args = argparse.Namespace(root=self.root, proc=self.proc, exec_scripts=True, runtime=None,
                                      no_containers=not containers, no_processes=not processes, json=False)
            report = c.run(args)
            c.print_report(report)  # must not raise
            return report
        finally:
            os.environ.clear()
            os.environ.update(old)


class HostTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="php2shell-test-")
        self.s = Scenario(self._tmp)

    def tearDown(self):
        shutil.rmtree(self._tmp)

    def item(self, report, path):
        return next(i for i in report["items"] if i["path"] == path)

    # -- distro backports ---------------------------------------------------

    def noble(self, pkg_version, body):
        self.s.php("/usr/bin/php8.3", "8.3.6")
        self.s.dpkg("/usr/bin/php8.3", "php8.3-cli", pkg_version, changelog("php8.3", pkg_version, body))
        self.s.answer("php8.3 -i", phpinfo("/etc/php/8.3/cli/php.ini"))

    def test_ubuntu_backport_is_patched_although_version_is_old(self):
        self.noble("8.3.6-0ubuntu0.24.04.13", BOTH_CVES)
        r = self.s.run()
        i = self.item(r, "/usr/bin/php8.3")
        self.assertEqual(i["version"], "8.3.6")
        self.assertEqual(i["status"], c.PATCHED)
        self.assertEqual(r["exit_code"], 0)

    def test_ubuntu_without_update_is_vulnerable_with_the_same_version(self):
        self.noble("8.3.6-0ubuntu0.24.04.12", "  * no security changes\n")
        r = self.s.run()
        i = self.item(r, "/usr/bin/php8.3")
        self.assertEqual(i["version"], "8.3.6")  # identical to the patched host
        self.assertEqual(i["status"], c.VULNERABLE)
        self.assertEqual(r["exit_code"], 1)

    def test_partial_upgrade_does_not_borrow_another_packages_changelog(self):
        # php8.3-cli was held back; its doc dir is a symlink to php8.3-common,
        # which was upgraded and lists the CVEs. That must not count.
        self.s.php("/usr/bin/php8.3", "8.3.6")
        self.s.dpkg("/usr/bin/php8.3", "php8.3-cli", "8.3.6-0ubuntu0.24.04.12",
                    changelog("php8.3", "8.3.6-0ubuntu0.24.04.13", BOTH_CVES), doc_pkg="php8.3-common")
        r = self.s.run()
        i = self.item(r, "/usr/bin/php8.3")
        self.assertEqual(i["status"], c.VULNERABLE)
        self.assertIn("does not match", i["reason"])

    def test_changelog_with_one_cve_is_unknown(self):
        self.noble("8.3.6-0ubuntu0.24.04.13", "  * CVE-2026-109618\n")
        r = self.s.run()
        self.assertEqual(self.item(r, "/usr/bin/php8.3")["status"], c.UNKNOWN)
        self.assertEqual(r["exit_code"], 2)

    def test_ghsa_ids_count_as_evidence(self):
        self.noble("8.3.6-0ubuntu0.24.04.13", "  * GHSA-w8hw-w9fx-j79w\n  * GHSA-6wmf-4rv5-p3rp\n")
        self.assertEqual(self.item(self.s.run(), "/usr/bin/php8.3")["status"], c.PATCHED)

    def test_binary_that_differs_from_its_package_is_not_trusted(self):
        # An older binary copied over the path of a patched package.
        self.noble("8.3.6-0ubuntu0.24.04.13", BOTH_CVES)
        self.s.answer("dpkg --verify php8.3-cli", "??5??????   /usr/bin/php8.3\n", code=1)
        i = self.item(self.s.run(), "/usr/bin/php8.3")
        self.assertEqual(i["status"], c.VULNERABLE)
        self.assertIn("differs", i["reason"])

    def test_binary_that_cannot_be_verified_is_not_trusted(self):
        self.noble("8.3.6-0ubuntu0.24.04.13", BOTH_CVES)
        self.s.answer("dpkg --verify php8.3-cli", "", code=2)  # dpkg --verify failed to run
        i = self.item(self.s.run(), "/usr/bin/php8.3")
        self.assertEqual(i["status"], c.VULNERABLE)
        self.assertIn("could not verify", i["reason"])

    def test_binary_whose_digest_was_not_checked_is_not_trusted(self):
        self.noble("8.3.6-0ubuntu0.24.04.13", BOTH_CVES)
        self.s.answer("dpkg --verify php8.3-cli", "??????????   /usr/bin/php8.3\n", code=1)
        self.assertEqual(self.item(self.s.run(), "/usr/bin/php8.3")["status"], c.VULNERABLE)

    def test_unknown_installed_version_is_not_trusted(self):
        self.s.php("/usr/bin/php8.3", "8.3.6")
        self.s.answer("dpkg-query -S /usr/bin/php8.3", "php8.3-cli: /usr/bin/php8.3\n")
        self.s.file("/usr/share/doc/php8.3-cli/changelog.Debian.gz", gzip.compress(BOTH_CVES.encode()))
        i = self.item(self.s.run(), "/usr/bin/php8.3")
        self.assertEqual(i["status"], c.VULNERABLE)

    def test_stripped_docs_leave_a_vulnerable_version_vulnerable(self):
        self.s.php("/usr/bin/php8.3", "8.3.6")
        self.s.dpkg("/usr/bin/php8.3", "php8.3-cli", "8.3.6-0ubuntu0.24.04.13")  # no changelog file
        i = self.item(self.s.run(), "/usr/bin/php8.3")
        self.assertEqual(i["status"], c.VULNERABLE)
        self.assertIn("docs stripped", i["reason"])

    def test_rhel_rpm_backport(self):
        self.s.php("/usr/bin/php", "7.4.33")
        nvr = "0:7.4.33-8.module+el8.10.0+25117+30337cca.x86_64"
        self.s.answer("rpm -qf --qf * /usr/bin/php", "php-cli\t%s\n" % nvr)
        self.s.answer("rpm -qf --changelog /usr/bin/php",
                      "* Wed Oct 21 2026 Packager - 7.4.33-8\n- fix CVE-2026-109618\n- fix CVE-2026-109619\n")
        self.s.answer("rpm -Vf /usr/bin/php", "")
        i = self.item(self.s.run(), "/usr/bin/php")
        self.assertEqual(i["status"], c.PATCHED)
        self.assertEqual(i["package"]["manager"], "rpm")

    def test_eol_without_backport_is_vulnerable(self):
        self.s.php("/usr/bin/php8.1", "8.1.2")
        self.s.dpkg("/usr/bin/php8.1", "php8.1-cli", "8.1.2-1ubuntu2.27", changelog("php8.1", "8.1.2-1ubuntu2.27", ""))
        i = self.item(self.s.run(), "/usr/bin/php8.1")
        self.assertEqual(i["status"], c.VULNERABLE)

    # -- source builds, SAPIs, config ----------------------------------------

    def test_source_build_uses_upstream_version_per_binary(self):
        self.s.php("/usr/local/bin/php", "8.4.27")
        self.s.php("/usr/local/sbin/php-fpm", "8.4.26")  # FPM left on the old build
        r = self.s.run()
        self.assertEqual(self.item(r, "/usr/local/bin/php")["status"], c.PATCHED)
        fpm = self.item(r, "/usr/local/sbin/php-fpm")
        self.assertEqual((fpm["sapi"], fpm["status"]), ("fpm", c.VULNERABLE))
        self.assertEqual(r["exit_code"], 1)

    def test_fpm_pool_override_is_reported_but_does_not_patch(self):
        self.s.php("/usr/sbin/php-fpm8.4", "8.4.26")
        self.s.answer("php-fpm8.4 -i", phpinfo("/etc/php/8.4/fpm/php.ini"))
        self.s.file("/etc/php/8.4/fpm/pool.d/www.conf",
                    "[www]\nuser = www-data\nphp_admin_flag[session.upload_progress.enabled] = off\n"
                    "php_admin_value[memory_limit] = -1\n")
        i = self.item(self.s.run(), "/usr/sbin/php-fpm8.4")
        self.assertEqual(i["status"], c.VULNERABLE)
        self.assertEqual(i["fpm_pools"]["www"]["session.upload_progress.enabled"], "off")
        self.assertEqual(i["ini"]["session.upload_progress.enabled"], "On")

    def test_mod_php_version_from_the_module_and_ini_from_files(self):
        self.s.file("/usr/lib/apache2/modules/libphp8.3.so", b"\x7fELF....X-Powered-By: PHP/8.3.6\x00")
        self.s.dpkg("/usr/lib/apache2/modules/libphp8.3.so", "libapache2-mod-php8.3", "8.3.6-0ubuntu0.24.04.13",
                    changelog("php8.3", "8.3.6-0ubuntu0.24.04.13", BOTH_CVES))
        self.s.file("/etc/php/8.3/apache2/php.ini", "[Session]\nsession.upload_progress.enabled = Off\n")
        self.s.file("/etc/apache2/mods-enabled/php8.3.load",
                    "LoadModule php_module /usr/lib/apache2/modules/libphp8.3.so\n")
        i = self.item(self.s.run(), "/usr/lib/apache2/modules/libphp8.3.so")
        self.assertEqual(i["sapi"], "apache2handler")
        self.assertEqual(i["status"], c.PATCHED)
        self.assertEqual(i["ini"]["session.upload_progress.enabled"], "Off")
        self.assertTrue(i["enabled"].startswith("yes"))

    def test_prerelease_is_unknown(self):
        self.s.php("/usr/local/bin/php", "8.6.0RC3")
        r = self.s.run()
        self.assertEqual(self.item(r, "/usr/local/bin/php")["status"], c.UNKNOWN)
        self.assertEqual(r["exit_code"], 2)

    def test_nginx_php_value_is_listed(self):
        self.s.file("/etc/nginx/sites-enabled/app", "location ~ \\.php$ {\n  fastcgi_param PHP_VALUE \"memory_limit=256M\";\n}\n")
        r = self.s.run()
        self.assertTrue(any("PHP_VALUE" in line for line in r["server_overrides"]))

    def test_nothing_found(self):
        r = self.s.run()
        self.assertEqual(r["exit_code"], 0)
        self.assertFalse(r["found_php"])
        self.assertIn("no PHP found in the searched locations", c.print_report(r))

    def test_alternative_binary_names_are_found(self):
        self.s.php("/usr/sbin/php84-fpm", "8.4.26")
        self.s.php("/usr/bin/php83", "8.3.36")
        r = self.s.run()
        self.assertEqual(self.item(r, "/usr/sbin/php84-fpm")["sapi"], "fpm")
        self.assertEqual(self.item(r, "/usr/bin/php83")["status"], c.PATCHED)

    # -- running processes -----------------------------------------------------

    def test_process_on_a_replaced_binary_needs_a_restart(self):
        self.noble("8.3.6-0ubuntu0.24.04.13", BOTH_CVES)
        self.s.process(812, "php-fpm8.3", "/usr/sbin/php-fpm8.3 (deleted)")
        r = self.s.run(processes=True)
        self.assertEqual(self.item(r, "/usr/bin/php8.3")["status"], c.PATCHED)
        stale = [p for p in r["processes"] if p.get("pids") == [812]]
        self.assertEqual(stale[0]["status"], c.STALE)
        self.assertEqual(r["exit_code"], 1)

    def test_mod_php_process_with_deleted_libphp(self):
        self.s.process(900, "apache2", "/usr/sbin/apache2",
                       maps="7f00-7f10 r-xp 00000000 08:01 1234 /usr/lib/apache2/modules/libphp8.3.so (deleted)\n")
        r = self.s.run(processes=True)
        self.assertEqual(r["processes"][0]["status"], c.STALE)

    def test_apache_without_php_is_ignored(self):
        self.s.process(901, "apache2", "/usr/sbin/apache2", maps="7f00-7f10 r-xp 0 08:01 1 /usr/lib/libc.so.6\n")
        self.assertEqual(self.s.run(processes=True)["processes"], [])

    def test_container_process_without_a_container_check_is_not_a_pass(self):
        cid = "a" * 64
        self.s.process(1000, "php-fpm", "/usr/local/sbin/php-fpm", cgroup="0::/system.slice/docker-%s.scope\n" % cid)
        r = self.s.run(processes=True)
        self.assertEqual(r["processes"][0]["container"], "a" * 12)
        self.assertEqual(r["processes"][0]["status"], c.UNKNOWN)
        self.assertEqual(r["exit_code"], 2)

    def test_container_process_judged_by_version_in_proc(self):
        # e.g. a Kubernetes node with containerd and no docker CLI
        binary = self.s.php("/srv/k8s/php-fpm-copy", "8.4.26")
        self.s.process(1001, "php-fpm", binary, cgroup="0::/kubepods/pod1/cri-containerd-%s.scope\n" % ("b" * 64))
        r = self.s.run(processes=True)
        self.assertEqual(r["processes"][0]["status"], c.VULNERABLE)
        self.assertEqual(r["exit_code"], 1)

    def test_host_process_on_a_different_file_is_judged_by_its_own_version(self):
        self.s.php("/usr/sbin/php-fpm8.4", "8.4.27")
        other = os.path.join(self._tmp, "elsewhere", "php-fpm8.4")
        os.makedirs(os.path.dirname(other))
        with open(other, "w") as f:
            f.write("# X-Powered-By: PHP/8.4.26\n")
        self.s.process(1002, "php-fpm8.4", other)
        r = self.s.run(processes=True)
        self.assertEqual(self.item(r, "/usr/sbin/php-fpm8.4")["status"], c.PATCHED)
        self.assertEqual(r["processes"][0]["status"], c.VULNERABLE)
        self.assertEqual(r["exit_code"], 1)

    def test_host_process_on_the_checked_file_inherits_its_verdict(self):
        binary = self.s.php("/usr/sbin/php-fpm8.4", "8.4.27")
        self.s.process(1003, "php-fpm8.4", binary)
        r = self.s.run(processes=True)
        self.assertEqual(r["processes"][0]["status"], c.PATCHED)
        self.assertIn("same file", r["processes"][0]["reason"])
        self.assertEqual(r["exit_code"], 0)

    def test_apache_with_unreadable_maps_is_unknown(self):
        self.s.process(1004, "apache2", "/usr/sbin/apache2")
        os.chmod(os.path.join(self.s.proc, "1004", "maps"), 0)
        if os.access(os.path.join(self.s.proc, "1004", "maps"), os.R_OK):
            self.skipTest("running as root: permissions are not enforced")
        r = self.s.run(processes=True)
        self.assertEqual(r["exit_code"], 2)

    # -- containers ------------------------------------------------------------

    def docker_container(self, cid, image, version, procs):
        s = self.s
        s.answer("docker top %s" % cid, "UID PID PPID C STIME TTY TIME CMD\n" +
                 "".join("root %d 1 0 10:00 ? 00:00:00 %s\n" % (100 + n, p) for n, p in enumerate(procs)))
        s.answer("docker exec %s sh -c *" % cid, "/usr/local/bin/php\n/usr/local/sbin/php-fpm\n")
        s.answer("docker exec %s readlink -f /usr/local/bin/php" % cid, "/usr/local/bin/php\n")
        s.answer("docker exec %s readlink -f /usr/local/sbin/php-fpm" % cid, "/usr/local/sbin/php-fpm\n")
        s.answer("docker exec %s /usr/local/bin/php -v" % cid, "PHP %s (cli) (built: Oct 21 2026)\n" % version)
        s.answer("docker exec %s /usr/local/sbin/php-fpm -v" % cid, "PHP %s (fpm-fcgi) (built: Oct 21 2026)\n" % version)
        s.answer("docker exec %s /usr/local/bin/php -i" % cid, phpinfo("/usr/local/etc/php/php.ini"))
        s.answer("docker exec %s /usr/local/sbin/php-fpm -i" % cid, phpinfo("/usr/local/etc/php/php.ini"))
        s.answer("docker inspect -f * %s" % cid, "PATH=/usr/local/bin\nPHP_VERSION=%s\n" % version)

    def test_containers(self):
        self.s.answer("docker ps --format *", "c1\tphp:8.4-fpm\told-app\nc2\tphp:8.4-fpm\tnew-app\nc3\tnginx:1.27\tproxy\n")
        self.docker_container("c1", "php:8.4-fpm", "8.4.26", ["php-fpm: master process (/usr/local/etc/php-fpm.conf)", "php-fpm: pool www"])
        self.docker_container("c2", "php:8.4-fpm", "8.4.27", ["php-fpm: master process (/usr/local/etc/php-fpm.conf)"])
        self.s.answer("docker top c3", "UID PID PPID C STIME TTY TIME CMD\nroot 5 1 0 10:00 ? 00:00:00 nginx: master process\n")
        r = self.s.run(containers=True)
        by = {}
        for item in r["containers"]:
            by.setdefault(item["container"], set()).add(item["status"])
        self.assertEqual(by["old-app"], {c.VULNERABLE})
        self.assertEqual(by["new-app"], {c.PATCHED})
        self.assertNotIn("proxy", by)
        self.assertEqual(r["exit_code"], 1)

    def test_container_process_on_an_unchecked_file_takes_the_worse_verdict(self):
        cid = "c" * 12
        self.s.answer("docker ps --format *", "%s\tphp:8.4-fpm\tapp\n" % cid)
        self.docker_container(cid, "php:8.4-fpm", "8.4.27", ["php-fpm: master process (/usr/local/etc/php-fpm.conf)"])
        old = os.path.join(self._tmp, "outside", "php-fpm")
        os.makedirs(os.path.dirname(old))
        with open(old, "w") as f:
            f.write("# X-Powered-By: PHP/8.4.26\n")
        self.s.process(2001, "php-fpm", old, cgroup="0::/system.slice/docker-%s.scope\n" % ("c" * 64))
        r = self.s.run(containers=True, processes=True)
        self.assertEqual(set(i["status"] for i in r["containers"]), {c.PATCHED})
        self.assertEqual(r["processes"][0]["status"], c.VULNERABLE)
        self.assertEqual(r["exit_code"], 1)

    def test_container_process_on_the_checked_path_inherits_it(self):
        cid = "d" * 12
        self.s.answer("docker ps --format *", "%s\tphp:8.4-fpm\tapp\n" % cid)
        self.docker_container(cid, "php:8.4-fpm", "8.4.27", ["php-fpm: master process (/usr/local/etc/php-fpm.conf)"])
        self.s.process(2002, "php-fpm", "/usr/local/sbin/php-fpm", cgroup="0::/system.slice/docker-%s.scope\n" % ("d" * 64))
        r = self.s.run(containers=True, processes=True)
        self.assertEqual(r["processes"][0]["status"], c.PATCHED)
        self.assertEqual(r["exit_code"], 0)

    def test_container_process_without_a_matching_binary_is_unknown(self):
        s = self.s
        s.answer("docker ps --format *", "c4\tcustom:1\tapp\n")
        s.answer("docker top c4", "UID PID PPID C STIME TTY TIME CMD\nroot 1 0 0 10:00 ? 00:00:00 php-fpm: master process (/etc/fpm.conf)\n")
        s.answer("docker exec c4 sh -c *", "/usr/bin/php8.4\n/usr/bin/ls\n")
        s.answer("docker exec c4 readlink -f /usr/bin/php8.4", "/usr/bin/php8.4\n")
        s.answer("docker exec c4 /usr/bin/php8.4 -v", "PHP 8.4.27 (cli)\n")
        r = s.run(containers=True)
        statuses = sorted(i["status"] for i in r["containers"])
        self.assertEqual(statuses, [c.PATCHED, c.UNKNOWN])
        self.assertEqual(r["exit_code"], 2)

    def test_container_listing_failure_is_unknown(self):
        self.s.answer("docker ps --format *", "", code=1)
        r = self.s.run(containers=True)
        self.assertEqual(r["containers"][0]["status"], c.UNKNOWN)
        self.assertEqual(r["exit_code"], 2)


if __name__ == "__main__":
    unittest.main()
