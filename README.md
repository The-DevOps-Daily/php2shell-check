# php2shell-check

```bash
sudo python3 php2shell_check.py          # every PHP on this host and in its running containers
python3 registry_scan.py                 # PHP version of 39 popular images, from registry metadata only
python3 summarize_scan.py                # compare the saved scan runs
```

Find every PHP you run and show whether it has the fixes for **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell), fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 on 21 October 2026.

`php -v` is not enough. Ubuntu, RHEL and other distributions backport the fix and keep the old version number: Ubuntu 24.04's fixed php8.3 still says 8.3.6, the same as the vulnerable one (`examples/ubuntu-noble-backport.txt`). A running PHP-FPM or Apache keeps the old code in memory after the package upgrade. A container keeps the PHP it was built with until you rebuild and redeploy it.

The checks are read-only. They read files and package databases, run `php -v` / `php -i` style commands and, for containers, run the same commands with `docker exec`. Nothing is sent to any PHP application, and nothing here exercises the vulnerabilities.

## php2shell_check.py

Python 3.6+ standard library, one file, so you can copy it to a server.

For each PHP it finds, it reports:

- **Where and which SAPI**: CLI, PHP-FPM, php-cgi, Apache mod_php (`libphp*.so`), LiteSpeed, FrankenPHP and embed builds, in the distro paths plus Remi, cPanel EA-PHP, Plesk, CloudLinux alt-php, LiteSpeed and aaPanel locations and `$PATH`.
- **Upstream version**: read from the `X-Powered-By: PHP/x.y.z` string compiled into the binary or module, so mod_php is checked without Apache and nothing has to run.
- **Package and backport evidence**: the dpkg, rpm or apk package that owns the file, its version, and whether that package's changelog names both CVE IDs (or the GHSA IDs). A Debian changelog only counts if its top entry is the installed version, because `/usr/share/doc/php8.x-cli` is often a symlink to another package's docs and a partial upgrade would otherwise borrow the wrong changelog.
- **Interim settings**: `session.upload_progress.enabled`, `fatal_error_backtraces`, `memory_limit` and `post_max_size` from `php -i` (or the php.ini files for mod_php), FPM pool overrides, and web server lines that set these or pass `PHP_VALUE`. These are reported only. They never turn a vulnerable result into a pass, because PHP says they are partial.
- **Running processes**: every PHP-FPM, php-cgi, LiteSpeed, FrankenPHP or Apache-with-libphp process. If its binary or `libphp` shows `(deleted)` in `/proc`, the process still runs the code from before the upgrade: `restart-needed`. Run as root to see processes of other users.
- **Containers**: for each running container (docker or podman) with a PHP process, the PHP binaries inside, `-v`, `-i`, the package evidence inside the container and the image's `ENV PHP_VERSION`.

Verdict per item: `patched` (upstream version at or above the fixed release, or the owning package's changelog names both CVEs), `vulnerable`, `restart-needed` or `unknown` (pre-release builds, PHP 8.6 and later, one CVE listed but not the other, anything it could not read).

Exit code: `0` all patched, `1` something vulnerable or needs a restart, `2` something could not be checked. `--json` prints the full report.

What it does not see: PHP in directories it does not search, `.htaccess` overrides, statically linked PHP that strips the version string, stopped containers, images that are not running, and Kubernetes nodes without a docker or podman CLI (their PHP processes still appear under "Running PHP processes" with the version read from `/proc`, but without package evidence).

## registry_scan.py

Reads each image's manifest and config blob (a few KB of JSON) from the registry and takes the PHP version from `ENV PHP_VERSION` (set by the official `php` images and inherited by everything built `FROM` them) or a Bitnami version variable. It never downloads a layer. On Docker Hub it gets the platform digest from the Hub tags API, so each image costs one manifest GET against the anonymous pull limit. Images that install PHP from distro packages carry no version in their metadata and come out `unknown`.

`images.txt` is the list and says why each image is on it. Pass image references as arguments to scan your own, for example the output of `kubectl get pods -A -o jsonpath='{..image}'`.

Each run is saved to `results/scan-<UTC start time>.json` with the hash of the code and of the image list. `summarize_scan.py` recomputes every status from the recorded PHP version, so runs made with older code are judged the same way.

## Results

### Registry scan, 21 October 2026

| Run (UTC) | Hours after the 14:00 UTC release | Patched | Vulnerable | Unknown |
|---|---|---|---|---|
| 18:21 | 4.4 | 29 | 8 | 2 |

Still vulnerable at 18:21 UTC: `php:8.1-fpm` and `php:8.1-apache` (8.1.34, end of life, last built December 2025), `joomla:latest` (8.4.26), `nextcloud:latest` and `nextcloud:fpm` (8.5.11), `phpmyadmin:latest` (8.3.35), `yourls:latest` (8.5.11) and `laravelsail/php84-composer:latest` (8.4.1, built November 2024). The official `php` images for 8.2 to 8.5 were rebuilt 1.8 to 2.1 hours after the release.

`joomla:latest` shows why a push time is not enough: Docker Hub lists the tag as pushed at 15:46 UTC, after the release, but its amd64 image config was built at 01:52 UTC with PHP 8.4.26.

### This host

`examples/pi-host-check.txt`: a Raspberry Pi with the PHP 8.4.23 CLI from packages.sury.org and no web server. Exit 1. At the time of the run, packages.sury.org had not yet published 8.4.27.

### Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests build fake hosts (a file tree, fake PHP binaries with the real embedded version string, and stand-ins for dpkg-query, rpm, apk and docker) and cover the cases a version check gets wrong: an Ubuntu backport, the same version without the update, a partial upgrade whose symlinked changelog belongs to another package, a changelog with only one of the two CVEs, a source build where FPM was left on the old version, a process running a deleted binary, and containers on old and new images.

## Write-up

https://devops-daily.com/posts/php2shell-check-every-php-is-patched

Sources for every fact are in `SOURCES.md`.

## License

MIT
