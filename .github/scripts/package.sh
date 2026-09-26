#!/bin/sh
# package.sh VERSION OS ARCH BINDIR
#
# Pack the three binaries from BINDIR into dist/nqvpn-VERSION-OS-ARCH.tar.gz
# plus a `.sha256` ("<hex>  <file>"). These names are what --self-update
# looks for, so every platform goes through here. POSIX sh: runs on the
# Linux and macOS runners and inside the FreeBSD VM.
set -eu
v=$1 os=$2 arch=$3 dir=$4
bins="nqvpn-coord nqvpn-relay nqvpn-client"
name="nqvpn-$v-$os-$arch.tar.gz"
mkdir -p dist
for b in $bins; do
  test -x "$dir/$b" || { echo "missing $dir/$b" >&2; exit 1; }
done
tar -czf "dist/$name" -C "$dir" $bins
if command -v sha256sum >/dev/null; then sum=$(sha256sum "dist/$name" | cut -d' ' -f1)
elif command -v shasum >/dev/null; then sum=$(shasum -a 256 "dist/$name" | cut -d' ' -f1)
else sum=$(sha256 -q "dist/$name"); fi
printf '%s  %s\n' "$sum" "$name" > "dist/$name.sha256"
echo "dist/$name  $sum"
