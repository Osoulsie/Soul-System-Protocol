#!/bin/sh
# Builds dist/anchor.wasm (freestanding, no imports) and the native sanitizer test binary.
# Needs clang with the wasm32 target and wasm-ld (tested with clang 18.1.3), and gcc or clang for native.
set -eu
cd "$(dirname "$0")"
mkdir -p dist build

WARN="-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Werror"

EXPORTS="an_global an_scratch an_scratch_size
an_init an_label an_define an_seal
an_incept an_rotate an_recover an_revoke
an_episode an_say an_tell an_user_line an_confirm an_redefine an_forget
an_issue_confirm an_issue_redefine an_issue_recover
an_expressed an_core an_give an_view_get an_writer_get an_fingerprint an_definition an_head an_info
an_distance an_verbatim an_line_id an_lean
an_save_size an_save an_load an_sha256"

FLAGS=""
for name in $EXPORTS; do FLAGS="$FLAGS -Wl,--export=$name"; done

clang --target=wasm32 -std=c17 -O2 -ffreestanding -fno-builtin -nostdlib -mbulk-memory $WARN \
  -Wl,--no-entry -Wl,--initial-memory=1048576 -Wl,--max-memory=1048576 -Wl,-z,stack-size=65536 \
  $FLAGS -o dist/anchor.wasm src/anchor.c src/sha256.c src/wasm.c

# Native: the same sources under AddressSanitizer and UndefinedBehaviorSanitizer.
# gcc by default: its sanitizer runtime ships with it; clang needs the compiler-rt package.
CC=${CC:-gcc}
$CC -std=c17 -O1 -g $WARN -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  -o build/native-test tests/native.c src/anchor.c src/sha256.c

echo "built dist/anchor.wasm ($(wc -c < dist/anchor.wasm) bytes) and build/native-test"
