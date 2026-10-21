# php2shell-check

```bash
sudo python3 php2shell_check.py          # PHP on this host, its running processes and its running containers
python3 registry_scan.py                 # PHP version of 39 popular images, from registry metadata only
python3 summarize_scan.py                # compare the saved scan runs
```

Find the PHP you run and show whether it has the fixes for **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell), fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 on 21 October 2026.

`php -v` is not enough. Ubuntu, RHEL and other distributions backport the fix and keep the old version number: Ubuntu 24.04's fixed php8.3 still says 8.3.6, the same as the vulnerable one (`examples/ubuntu-noble-backport.txt`). A running PHP-FPM or Apache keeps the old code in memory after the package upgrade. A container keeps the PHP it was built with until you rebuild and redeploy it.

The checks only read. They read files and package databases, run `php -i` (and `php -v` when a binary has no readable version string), run `dpkg --verify` or `rpm -V`, and for containers run the same commands with `docker exec`. Nothing is sent to any PHP application, and nothing here exercises the vulnerabilities. Running an installed PHP binary with `-i` loads its extensions, as any `php -i` does.

## php2shell_check.py

Python 3.6+ standard library, one file, so you can copy it to a server.

For each PHP it finds, it reports:

- **Where and which SAPI**: CLI, PHP-FPM, php-cgi, Apache mod_php (`libphp*.so`), LiteSpeed, FrankenPHP and embed builds, in the distribution paths plus Remi, cPanel EA-PHP, Plesk, CloudLinux alt-php, LiteSpeed and aaPanel locations and `$PATH`. Names such as `php8.4`, `php84`, `php-fpm8.4` and `php84-fpm` are recognised.
- **Upstream version**: read from the `X-Powered-By: PHP/x.y.z` string compiled into the binary or module, so mod_php is checked without running Apache.
- **Package and backport evidence**: the dpkg or rpm package that owns the file, its version, and whether that package's changelog names both CVE IDs (or the GHSA IDs). The changelog only counts when it belongs to the installed package (on Debian and Ubuntu, `/usr/share/doc/php8.x-cli` is often a symlink to another package's docs, and a partial upgrade would otherwise borrow the wrong changelog) and when `dpkg --verify` or `rpm -V` does not report the binary as changed. For apk it reports the owning package only: Alpine keeps no changelog, so the upstream version decides.
- **Interim settings**: `session.upload_progress.enabled`, `fatal_error_backtraces`, `memory_limit` and `post_max_size` as a fresh `php -i` sees them (or the php.ini files for mod_php), FPM pool overrides, and web server lines that set these or pass `PHP_VALUE`. These are observations, not the live settings of a running service started with other options, and they never turn a vulnerable result into a pass, because PHP says they are partial.
- **Running processes**: every PHP-FPM, php-cgi, LiteSpeed, FrankenPHP or Apache-with-libphp process. If its binary or `libphp` shows `(deleted)` in `/proc`, the process still runs the code from before the upgrade: `restart-needed`. A process takes the verdict of a checked file only when it runs that exact file (same device and inode); otherwise it is judged by the version read from `/proc`. Processes it cannot read (run as a normal user, or an unreadable `maps` or `cgroup`) count as `unknown`.
- **Containers**: for each running container (docker or podman) with a PHP process, the PHP binaries inside, their version, settings and package evidence, and the image's `ENV PHP_VERSION`. Every PHP process that `docker top` shows must be matched by a checked binary of the same kind, or the container is `unknown`. Container processes on hosts without a docker or podman CLI (for example Kubernetes nodes with containerd) are judged by the version read from `/proc`, without package evidence.

Verdict per item: `patched` (upstream version at or above the fixed release, or the owning package's changelog names both CVEs under the conditions above), `vulnerable`, `restart-needed` or `unknown` (pre-release builds, unrecognised version suffixes, PHP 8.6 and later, one CVE listed but not the other, anything it could not read).

Exit code: `0` when every PHP it found and inspected is patched (it prints "no PHP found in the searched locations" when it found none), `1` when something is vulnerable or needs a restart, `2` when something could not be checked. `--json` prints the full report.

What it does not see: PHP in directories it does not search or under names it does not know, Apache with PHP linked in statically, `.htaccess` overrides, stopped containers, and images that are not running. A changelog that names both CVEs in an entry that was later reverted would still count.

## registry_scan.py

Reads each image's manifest and config blob (a few KB of JSON) from the registry, checks both against their digests, and takes the PHP version from `ENV PHP_VERSION` (set by the official `php` images and inherited by everything built `FROM` them) or Bitnami's `APP_VERSION`. It never downloads a layer. This is the version the metadata reports: an image could replace PHP after the variable was set, and only a look inside a container proves the binary. Images that install PHP from distribution packages carry no version in their metadata and come out `unknown`.

On Docker Hub it gets the platform digest from the Hub tags API, so each image costs one manifest GET against the anonymous pull limit (100 per hour per IP when this was run). A 429 stops the run and marks the remaining images as not scanned. `--platform` defaults to `linux/amd64`.

`images.txt` is the list and says why each image is on it. Pass image references as arguments to scan your own, including digest references from Kubernetes:

```bash
python3 registry_scan.py $(kubectl get pods -A -o jsonpath='{..imageID}' | tr ' ' '\n' | sort -u)
```

Each run is saved to `results/scan-<UTC start time>.json` with the hash of the code and of the image list. `summarize_scan.py` recomputes every status from the recorded PHP version, so runs made with older code are judged the same way.

`scripts/compare-hub-index.py` is the method check: it compares the platform digest from the Docker Hub API with the one in the registry's own index (`results/method-check-*.txt`).

## Results

### Registry scan, 21 October 2026, linux/amd64, PHP version as reported by image metadata

| Run (UTC) | Hours after the scheduled 14:00 UTC release | Patched | Vulnerable | Unknown |
|---|---|---|---|---|
| 18:21 | 4.4 | 29 | 8 | 2 |

Still vulnerable at 18:21 UTC: `php:8.1-fpm` and `php:8.1-apache` (8.1.34, end of life, last built December 2025), `joomla:latest` (8.4.26), `nextcloud:latest` and `nextcloud:fpm` (8.5.11), `phpmyadmin:latest` (8.3.35), `yourls:latest` (8.5.11) and `laravelsail/php84-composer:latest` (8.4.1, built November 2024). The official `php` images for 8.2 to 8.5 were built 1.8 to 2.1 hours after the scheduled release.

`joomla:latest` shows why a push time is not enough: Docker Hub lists the tag as pushed at 15:46 UTC, after the release, but its amd64 image config was built at 01:52 UTC with PHP 8.4.26. `nextcloud:latest` and `nextcloud:fpm` looked the same at 18:21 and had moved to 8.5.12 by 18:30 (`results/method-check-20261021T183037Z.txt`).

### This host

`examples/pi-host-check.txt`: a Raspberry Pi with the PHP 8.4.23 CLI from packages.sury.org and no web server. Exit 1. At about 18:10 UTC, packages.sury.org had not yet published 8.4.27 for Debian 12.

### Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests build fake hosts (a file tree, fake PHP binaries with the real embedded version string, and stand-ins for dpkg-query, dpkg, rpm, apk and docker) and cover the cases a version check gets wrong: an Ubuntu backport, the same version without the update, a partial upgrade whose symlinked changelog belongs to another package, a binary that differs from its package, a changelog with only one of the two CVEs, a source build where FPM was left on the old version, a process running a deleted binary or a different file from the one on disk, container processes without a container check, and containers on old and new images.

## Scripts

| script | what it does |
|---|---|
| `php2shell_check.py` | The host, process and container check. |
| `registry_scan.py` | Reads the PHP version of images from registry metadata, writes `results/scan-*.json`. |
| `summarize_scan.py` | Counts per run, each image across runs, build times after the release. |
| `scripts/ubuntu-backport-demo.sh` | Downloads Ubuntu 24.04 php8.3 packages from before and after the fix and shows both report 8.3.6. |
| `scripts/compare-hub-index.py` | Compares Docker Hub API digests with the registry index (method check). |
| `scripts/record-example.sh`, `scripts/record-method-check.sh` | Save timestamped output to `examples/` and `results/`. |

## Write-up

https://devops-daily.com/posts/php2shell-check-every-php-is-patched

Sources for every fact are in `SOURCES.md`.

## License

MIT
