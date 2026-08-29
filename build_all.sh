#!/usr/bin/env bash
#
# build_all.sh — fully static Linux binaries for amd64 and arm64.
#
# One artifact per architecture that runs on any Linux (no libc
# dependency): x86_64-unknown-linux-musl and aarch64-unknown-linux-musl.
#
# Three ways to cross-compile, tried in this order:
#   1. cargo-zigbuild (zig as the C cross compiler) — works from macOS or
#      Linux, any host arch. `./build_all.sh --setup` installs it into a
#      local Python venv (.build-tools/, git-ignored); nothing else on
#      the machine is touched.
#   2. cross (Docker-based) if it is on PATH.
#   3. Native musl toolchains on a Linux host: musl-gcc for the host's
#      own arch, plus a musl.cc cross toolchain for the other one,
#      downloaded into .build-tools/ on first use.
#
#   ./build_all.sh                 # both targets -> dist/linux-{amd64,arm64}/ + tarballs
#   ./build_all.sh --setup         # install cargo-zigbuild + zig locally, then build
#   ./build_all.sh amd64           # one target
#   ./build_all.sh arm64
#
# ring (via rustls/quinn) compiles assembly and rusqlite bundles SQLite's
# C source, so every route needs a C compiler that targets musl; that is
# what the three strategies provide.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

BINS=(nqvpn-coord nqvpn-relay nqvpn-client)
TOOLS="$ROOT/.build-tools"
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

declare -A TARGET=([amd64]=x86_64-unknown-linux-musl [arm64]=aarch64-unknown-linux-musl)
declare -A MUSLCC=([amd64]=x86_64-linux-musl [arm64]=aarch64-linux-musl)

WANT=()
SETUP=0
for a in "$@"; do
  case "$a" in
    --setup) SETUP=1 ;;
    amd64|arm64) WANT+=("$a") ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) die "unknown argument: $a (use amd64, arm64, --setup)" ;;
  esac
done
[ "${#WANT[@]}" -gt 0 ] || WANT=(amd64 arm64)

command -v cargo >/dev/null || die "cargo not found; install Rust first (https://rustup.rs)"

# A distro/Homebrew rust on PATH can shadow the rustup toolchain that
# actually has the musl targets; when rustup is here, use its toolchain.
if command -v rustup >/dev/null && rustup which cargo >/dev/null 2>&1; then
  export PATH="$(dirname "$(rustup which cargo)"):$PATH"
fi

# ---- strategy 1: cargo-zigbuild --------------------------------------------

# A local venv keeps zig + cargo-zigbuild out of the system Python.
if [ -x "$TOOLS/venv/bin/cargo-zigbuild" ]; then
  export PATH="$TOOLS/venv/bin:$PATH"
fi

setup_zigbuild() {
  say "Installing cargo-zigbuild + zig into $TOOLS/venv"
  command -v python3 >/dev/null || die "python3 is needed for --setup (or install zig and cargo-zigbuild yourself)"
  python3 -m venv "$TOOLS/venv"
  "$TOOLS/venv/bin/pip" install --quiet --upgrade pip
  "$TOOLS/venv/bin/pip" install --quiet ziglang cargo-zigbuild
  export PATH="$TOOLS/venv/bin:$PATH"
  command -v cargo-zigbuild >/dev/null || die "cargo-zigbuild did not install"
}

[ "$SETUP" = 1 ] && setup_zigbuild

have_zig() { command -v cargo-zigbuild >/dev/null && (command -v zig >/dev/null || python3 -c 'import ziglang' 2>/dev/null); }

# ---- strategy 3 helpers: native musl toolchains on Linux ---------------------

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo other ;;
  esac
}

# Prints the C compiler to use for a target, fetching a musl.cc cross
# toolchain when the target is not the host's own architecture.
native_cc() {
  local arch=$1
  if [ "$(uname -s)" != "Linux" ]; then
    return 1
  fi
  if [ "$arch" = "$(host_arch)" ] && command -v musl-gcc >/dev/null; then
    echo musl-gcc; return 0
  fi
  local triple=${MUSLCC[$arch]}
  local cc="$TOOLS/$triple-cross/bin/$triple-gcc"
  if [ ! -x "$cc" ]; then
    say "Fetching musl.cc cross toolchain for $arch"
    mkdir -p "$TOOLS"
    curl -fsSL "https://musl.cc/$triple-cross.tgz" | tar -xz -C "$TOOLS" \
      || { echo "download failed"; return 1; }
  fi
  [ -x "$cc" ] && echo "$cc"
}

# ---- pick a strategy ------------------------------------------------------------

STRATEGY=""
if have_zig; then
  STRATEGY=zigbuild
elif command -v cross >/dev/null; then
  STRATEGY=cross
elif [ "$(uname -s)" = "Linux" ]; then
  STRATEGY=native
else
  die "no cross toolchain found. Run:  ./build_all.sh --setup   (installs zig + cargo-zigbuild locally)"
fi
say "Strategy: $STRATEGY  (version $VERSION, targets: ${WANT[*]})"

if command -v rustup >/dev/null; then
  for arch in "${WANT[@]}"; do rustup target add "${TARGET[$arch]}" >/dev/null; done
fi

build_one() {
  local arch=$1 target=${TARGET[$1]}
  say "Building $arch ($target)"
  case "$STRATEGY" in
    zigbuild)
      cargo zigbuild --release --target "$target" ;;
    cross)
      cross build --release --target "$target" ;;
    native)
      local cc
      cc=$(native_cc "$arch") || die "no musl C compiler for $arch (install musl-tools, or use --setup)"
      local up
      up=$(echo "$target" | tr '[:lower:]-' '[:upper:]_')
      env "CC_${target//-/_}=$cc" "CARGO_TARGET_${up}_LINKER=$cc" \
        cargo build --release --target "$target" ;;
  esac
}

collect() {
  local arch=$1 target=${TARGET[$1]} out="dist/linux-$1"
  mkdir -p "$out"
  for b in "${BINS[@]}"; do
    local src="target/$target/release/$b"
    [ -f "$src" ] || die "expected binary missing: $src"
    cp -f "$src" "$out/$b"
  done
  # Static check: `file` on any host; ldd only means something on Linux.
  for b in "${BINS[@]}"; do
    local f="$out/$b" desc
    desc=$(file -b "$f" 2>/dev/null || true)
    if echo "$desc" | grep -qiE "statically linked|static-pie"; then
      printf '  %-14s %6s  static ✓\n' "$b" "$(du -h "$f" | cut -f1)"
    else
      printf '  %-14s %6s  %s\n' "$b" "$(du -h "$f" | cut -f1)" "$desc"
      die "$b does not look statically linked"
    fi
  done
  local tar="dist/nqvpn-$VERSION-linux-$arch.tar.gz"
  tar -czf "$tar" -C "$out" "${BINS[@]}"
  ( cd dist && shasum -a 256 "$(basename "$tar")" > "$(basename "$tar").sha256" )
  echo "  -> $tar"
}

for arch in "${WANT[@]}"; do
  build_one "$arch"
  collect "$arch"
done

say "Done — artifacts in dist/"
ls -1 dist/*.tar.gz
