#!/usr/bin/env bash
#
# musl-x64.sh — build fully static x86_64 Linux binaries.
#
# Why: nqvpn hosts run different distros, and a binary linked against a
# newer glibc will not start on an older one (cp.wushilin.net has glibc
# 2.32; a Rocky 9 build needs 2.33+). A musl static build has no libc
# dependency at all, so one artifact runs on every x86_64 Linux host.
#
# Run this ON a Linux x86_64 machine that has cargo. It installs the
# musl target and, if needed and sudo is available, a musl C toolchain
# (ring's assembly needs one).
#
#   ./musl-x64.sh                        # build into dist/x86_64-musl/
#   ./musl-x64.sh user@host1 user@host2  # build, then copy to those hosts
#
# Binaries land in dist/x86_64-musl/ and are copied to /tmp on each host.

set -euo pipefail

TARGET=x86_64-unknown-linux-musl
BINS=(nqvpn-coord nqvpn-relay nqvpn-client)
OUT=dist/x86_64-musl
REMOTE_DIR=${NQVPN_REMOTE_DIR:-/tmp}

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "run this on Linux (musl targets need a Linux host toolchain)"
[ "$(uname -m)" = "x86_64" ] || die "this script builds x86_64; host is $(uname -m)"
command -v cargo >/dev/null || die "cargo not found; install Rust first (https://rustup.rs)"

say "Ensuring the $TARGET std library is installed"
if command -v rustup >/dev/null; then
  rustup target add "$TARGET"
else
  # A distro-packaged cargo may already ship the target; the build will
  # tell us plainly if it does not.
  echo "rustup not found — assuming $TARGET std is already available"
fi

# ring (via rustls/quinn) compiles assembly, so it needs a C compiler
# that targets musl. Without it the link step fails with a confusing
# error, so check up front and install when we can.
if ! command -v musl-gcc >/dev/null; then
  say "musl C toolchain missing — attempting to install"
  SUDO=""
  if [ "$(id -u)" != "0" ]; then
    sudo -n true 2>/dev/null && SUDO="sudo -n" || die \
      "musl-gcc is missing and passwordless sudo is unavailable.
   Install it yourself, then re-run:
     Debian/Ubuntu : sudo apt-get install -y musl-tools
     Fedora/RHEL   : sudo dnf install -y musl-gcc
     Alpine        : apk add musl-dev"
  fi
  if command -v apt-get >/dev/null; then
    $SUDO apt-get update -qq && $SUDO apt-get install -y -qq musl-tools
  elif command -v dnf >/dev/null; then
    $SUDO dnf install -y -q musl-gcc || $SUDO dnf install -y -q musl-devel
  elif command -v apk >/dev/null; then
    $SUDO apk add --no-cache musl-dev
  else
    die "no supported package manager found; install musl-gcc manually"
  fi
  command -v musl-gcc >/dev/null || die "musl-gcc still not on PATH after install"
fi
echo "musl-gcc: $(command -v musl-gcc)"

say "Building (release, static, $TARGET)"
# Point both the linker and ring's build script at musl-gcc.
export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
cargo build --release --target "$TARGET"

say "Collecting artifacts"
mkdir -p "$OUT"
for b in "${BINS[@]}"; do
  src="target/$TARGET/release/$b"
  [ -f "$src" ] || die "expected binary missing: $src"
  cp -f "$src" "$OUT/$b"
  strip "$OUT/$b" 2>/dev/null || true
done

for b in "${BINS[@]}"; do
  f="$OUT/$b"
  size=$(du -h "$f" | cut -f1)
  # A truly static binary reports "not a dynamic executable"; anything
  # else means we would still depend on the host's libc.
  if ldd "$f" 2>&1 | grep -qiE "not a dynamic executable|statically linked"; then
    printf '  %-14s %6s  static ✓\n' "$b" "$size"
  else
    printf '  %-14s %6s  DYNAMIC ✗\n' "$b" "$size"
    ldd "$f" | sed 's/^/      /'
    die "$b is not static; it will not run on older-glibc hosts"
  fi
done

if [ "$#" -gt 0 ]; then
  say "Copying to $# host(s)"
  # Copying needs SSH access *from this build host* to each target,
  # which is not always how key trust is arranged. One unreachable host
  # must not discard a successful build, so failures are reported and
  # the rest continue.
  failed=0
  for host in "$@"; do
    echo "  -> $host:$REMOTE_DIR"
    if ! scp -q -o BatchMode=yes "${BINS[@]/#/$OUT/}" "$host:$REMOTE_DIR/" 2>/dev/null; then
      echo "     copy failed (no SSH access from this host?) — artifacts are still in $OUT/"
      failed=$((failed + 1))
      continue
    fi
    # Confirm it actually starts there; a silent copy proves nothing.
    ssh -o BatchMode=yes "$host" \
      "chmod +x $REMOTE_DIR/nqvpn-* 2>/dev/null;
       $REMOTE_DIR/nqvpn-relay --help >/dev/null 2>&1 && echo '     runs ✓' || echo '     FAILED TO RUN ✗'" \
      2>/dev/null || echo "     could not verify (ssh failed)"
  done
  [ "$failed" -eq 0 ] || echo "
$failed host(s) could not be reached from here; copy $OUT/* from a machine that can."
fi

say "Done — artifacts in $OUT/"
