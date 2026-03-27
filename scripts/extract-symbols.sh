#!/usr/bin/env bash
set -euo pipefail

TALOS_VERSION="${1:-v1.12.5}"
ARCH="${2:-amd64}"
WORKDIR="/tmp/talos-kernel"

mkdir -p "$WORKDIR"

[ -f "$WORKDIR/vmlinuz" ] || curl -fSL --retry 3 -o "$WORKDIR/vmlinuz" \
  "https://github.com/siderolabs/talos/releases/download/${TALOS_VERSION}/vmlinuz-${ARCH}"

# Decompress vmlinuz -> raw vmlinux ELF (Talos uses zstd)
python3 -c "
import zstandard
d = open('$WORKDIR/vmlinuz','rb').read()
off = d.find(b'\x28\xb5\x2f\xfd')
out = zstandard.ZstdDecompressor().decompress(d[off:], max_output_size=200*1024*1024)
open('$WORKDIR/vmlinux','wb').write(out)
print(f'Decompressed {len(out)} bytes from offset {off}')
"

# Extract kallsyms (stripped kernel, nm won't work)
# Requires: uv tool install vmlinux-to-elf
kallsyms-finder "$WORKDIR/vmlinux" > "$WORKDIR/symbols.txt"
echo "$WORKDIR/symbols.txt ($(wc -l < "$WORKDIR/symbols.txt") symbols)"
