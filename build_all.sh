#!/usr/bin/env bash
#
# build_all.sh — fully static Linux binaries for amd64 and arm64.
#
# One artifact per architecture that runs on any Linux (no libc
# dependency): x86_64-unknown-linux-musl and aarch64-unknown-linux-musl.
#
# Three ways to cross-compile, tried in this order:
#   1. cargo-zigbuild (zig as the C cross compiler) — works from macOS or
#      Linux, any host arch. A fresh run installs it into a local Python
#      venv (.build-tools/, git-ignored) automatically; nothing else on
#      the machine is touched. `--setup` forces (re)install.
#   2. cross (Docker-based) if it is on PATH.
#   3. Native musl toolchains on a Linux host: musl-gcc for the host's
#      own arch, plus a musl.cc cross toolchain for the other one,
#      downloaded into .build-tools/ on first use.
#
#   ./build_all.sh                 # both targets -> dist/linux-{amd64,arm64}/ + tarballs
#   ./build_all.sh --setup         # (re)install cargo-zigbuild + zig locally, then build
#   ./build_all.sh amd64           # one target
#   ./build_all.sh arm64
#
# Written for bash 3.2 (the version macOS ships) — no associative arrays.
# Re-exec under bash if started with `sh build_all.sh` (POSIX sh lacks
# the arrays and shebang handling this needs).
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

BINS="nqvpn-coord nqvpn-relay nqvpn-client"
TOOLS="$ROOT/.build-tools"
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

# Portable lookups instead of bash-4 associative arrays.
target_for() {
  case "$1" in
    amd64) echo x86_64-unknown-linux-musl ;;
    arm64) echo aarch64-unknown-linux-musl ;;
    *) die "unknown arch: $1" ;;
  esac
}
muslcc_for() {
  case "$1" in
    amd64) echo x86_64-linux-musl ;;
    arm64) echo aarch64-linux-musl ;;
    *) die "unknown arch: $1" ;;
  esac
}

WANT=""
SETUP=0
for a in "$@"; do
  case "$a" in
    --setup) SETUP=1 ;;
    amd64|arm64) WANT="$WANT $a" ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) die "unknown argument: $a (use amd64, arm64, --setup)" ;;
  esac
done
[ -n "$WANT" ] || WANT="amd64 arm64"

command -v cargo >/dev/null || die "cargo not found; install Rust first (https://rustup.rs)"

# A distro/Homebrew rust on PATH can shadow the rustup toolchain that
# actually has the musl targets; when rustup is here, use its toolchain.
if command -v rustup >/dev/null && rustup which cargo >/dev/null 2>&1; then
  PATH="$(dirname "$(rustup which cargo)"):$PATH"
fi

# A local venv keeps zig + cargo-zigbuild out of the system Python.
if [ -x "$TOOLS/venv/bin/cargo-zigbuild" ]; then
  PATH="$TOOLS/venv/bin:$PATH"
fi

setup_zigbuild() {
  say "Installing cargo-zigbuild + zig into $TOOLS/venv"
  command -v python3 >/dev/null || die "python3 is needed to install zig (or install zig + cargo-zigbuild yourself)"
  python3 -m venv "$TOOLS/venv"
  "$TOOLS/venv/bin/pip" install --quiet --upgrade pip
  "$TOOLS/venv/bin/pip" install --quiet ziglang cargo-zigbuild
  PATH="$TOOLS/venv/bin:$PATH"
  command -v cargo-zigbuild >/dev/null || die "cargo-zigbuild did not install"
}

have_zig() {
  command -v cargo-zigbuild >/dev/null || return 1
  command -v zig >/dev/null && return 0
  python3 -c 'import ziglang' >/dev/null 2>&1
}

[ "$SETUP" = 1 ] && setup_zigbuild

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo other ;;
  esac
}

# Prints the C compiler for a target, fetching a musl.cc cross toolchain
# when the target is not the host's own architecture.
native_cc() {
  arch="$1"
  [ "$(uname -s)" = "Linux" ] || return 1
  if [ "$arch" = "$(host_arch)" ] && command -v musl-gcc >/dev/null; then
    echo musl-gcc
    return 0
  fi
  triple=$(muslcc_for "$arch")
  cc="$TOOLS/$triple-cross/bin/$triple-gcc"
  if [ ! -x "$cc" ]; then
    say "Fetching musl.cc cross toolchain for $arch"
    mkdir -p "$TOOLS"
    curl -fsSL "https://musl.cc/$triple-cross.tgz" | tar -xz -C "$TOOLS" || return 1
  fi
  [ -x "$cc" ] && echo "$cc"
}

# ---- pick a strategy --------------------------------------------------------

STRATEGY=""
if have_zig; then
  STRATEGY=zigbuild
elif command -v cross >/dev/null; then
  STRATEGY=cross
elif [ "$(uname -s)" = "Linux" ]; then
  STRATEGY=native
elif command -v python3 >/dev/null; then
  # A fresh macOS clone: bootstrap zig automatically rather than failing.
  setup_zigbuild
  STRATEGY=zigbuild
else
  die "no cross toolchain and no python3 to install one. Install zig + cargo-zigbuild, or Docker + cross."
fi
say "Strategy: $STRATEGY  (version $VERSION, targets:$WANT)"

if command -v rustup >/dev/null; then
  for arch in $WANT; do rustup target add "$(target_for "$arch")" >/dev/null; done
fi

build_one() {
  arch="$1"
  target=$(target_for "$arch")
  say "Building $arch ($target)"
  case "$STRATEGY" in
    zigbuild) cargo zigbuild --release --target "$target" ;;
    cross) cross build --release --target "$target" ;;
    native)
      cc=$(native_cc "$arch") || die "no musl C compiler for $arch (install musl-tools, or use --setup for zig)"
      up=$(echo "$target" | tr 'a-z-' 'A-Z_')
      env "CC_$(echo "$target" | tr - _)=$cc" "CARGO_TARGET_${up}_LINKER=$cc" \
        cargo build --release --target "$target" ;;
  esac
}

collect() {
  arch="$1"
  target=$(target_for "$arch")
  out="dist/linux-$arch"
  mkdir -p "$out"
  for b in $BINS; do
    src="target/$target/release/$b"
    [ -f "$src" ] || die "expected binary missing: $src"
    cp -f "$src" "$out/$b"
  done
  for b in $BINS; do
    f="$out/$b"
    desc=$(file -b "$f" 2>/dev/null || true)
    case "$desc" in
      *statically\ linked*|*static-pie*)
        printf '  %-14s %6s  static \xe2\x9c\x93\n' "$b" "$(du -h "$f" | cut -f1)" ;;
      *)
        printf '  %-14s %6s  %s\n' "$b" "$(du -h "$f" | cut -f1)" "$desc"
        die "$b does not look statically linked" ;;
    esac
  done
  tar="dist/nqvpn-$VERSION-linux-$arch.tar.gz"
  # --no-xattrs keeps macOS's bsdtar from embedding extended attributes
  # (e.g. com.apple.provenance) as LIBARCHIVE.xattr.* PAX headers, which
  # make GNU tar on Linux warn "Ignoring unknown extended header keyword"
  # on extraction. The flag is understood by both bsdtar and GNU tar.
  tar --no-xattrs -czf "$tar" -C "$out" $BINS
  ( cd dist && shasum -a 256 "$(basename "$tar")" > "$(basename "$tar").sha256" )
  echo "  -> $tar"
}

for arch in $WANT; do
  build_one "$arch"
  collect "$arch"
done

say "Done — artifacts in dist/"
ls -1 dist/*.tar.gz
