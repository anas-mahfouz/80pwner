#!/usr/bin/env bash
# 80PWNER sample builder — by Anas Mahfouz (The 80)
# Compiles tests/samples/vulnerable.c into variants with different protections.
# Usage: ./build_samples.sh [outdir]   (default: this directory)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$DIR}"
SRC="$DIR/vulnerable.c"
CC="${CC:-gcc}"
command -v "$CC" > /dev/null 2>&1 || CC=cc

echo "[80PWNER] building sample variants with $CC -> $OUT"

# 1. No protections at all (the easy CTF target).
"$CC" -O0 -g -Wall \
    -fno-stack-protector -no-pie -z norelro -z execstack \
    -U_FORTIFY_SOURCE -o "$OUT/vuln_none.elf" "$SRC" 2> >(grep -v "warning" || true)

# 2. Distro defaults: typically PIE + canary + partial RELRO, no fortify.
"$CC" -O0 -g \
    -fstack-protector -o "$OUT/vuln_defaults.elf" "$SRC" 2> >(grep -v "warning" || true)

# 3. Everything on: PIE, full RELRO, canary, fortify source.
"$CC" -O1 -g \
    -fstack-protector-strong -pie -z relro -z now \
    -D_FORTIFY_SOURCE=2 \
    -o "$OUT/vuln_full.elf" "$SRC" 2> >(grep -v "warning" || true)

ls -la "$OUT"/vuln_*.elf
echo "[80PWNER] done — load any variant in the Binary Overview module."
