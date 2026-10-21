#!/bin/sh
# Show why `php -v` cannot tell a patched Ubuntu 24.04 PHP from an unpatched
# one. Downloads php8.3-fpm and php8.3-common before (.12) and after (.13) the
# PHP2Shell fix from the Ubuntu archive, extracts them (nothing is installed or
# run), and prints the PHP version compiled into php-fpm8.3 plus whether the
# package changelog names the CVEs.
# Needs: curl, dpkg-deb, python3. About 5 MB of downloads.
set -eu
cd "$(dirname "$0")/.."
work=${WORK:-work/ubuntu-backport}
archive=http://archive.ubuntu.com/ubuntu/pool
mkdir -p "$work"
echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) Ubuntu 24.04 php8.3 packages from $archive"
for rev in 12 13; do
  v=8.3.6-0ubuntu0.24.04.$rev
  for pkg in php8.3-fpm php8.3-common; do
    deb=${pkg}_${v}_amd64.deb
    component=main
    [ "$pkg" = php8.3-fpm ] && component=universe
    [ -f "$work/$deb" ] || curl -sSf -o "$work/$deb" "$archive/$component/p/php8.3/$deb"
    echo "sha256 $(sha256sum "$work/$deb" | cut -d' ' -f1)  $deb"
    rm -rf "$work/x-$pkg-$rev"
    mkdir "$work/x-$pkg-$rev"
    dpkg-deb -x "$work/$deb" "$work/x-$pkg-$rev"
  done
done
echo
for rev in 12 13; do
  v=8.3.6-0ubuntu0.24.04.$rev
  embedded=$(python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import php2shell_check as c; print(c.static_version(sys.argv[2]))' \
    "$PWD" "$work/x-php8.3-fpm-$rev/usr/sbin/php-fpm8.3")
  log=$work/x-php8.3-common-$rev/usr/share/doc/php8.3-common/changelog.Debian.gz
  top=$(zcat "$log" | head -1)
  ids=$(zcat "$log" | grep -o -E 'CVE-2026-10961[89]|GHSA-w8hw-w9fx-j79w|GHSA-6wmf-4rv5-p3rp' | sort -u | tr '\n' ' ')
  echo "package $v"
  echo "  php-fpm8.3 embeds: PHP/$embedded"
  echo "  changelog top:     $top"
  echo "  PHP2Shell IDs:     ${ids:-none}"
done
