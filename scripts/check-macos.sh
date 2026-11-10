#!/bin/sh
# Type-checks the whole workspace for macOS from Linux (or WSL), without a
# Mac or its SDK: `cargo clippy` never links, so the C code that build
# scripts compile (ring, libusb) only has to produce *an* object file. A
# stand-in compiler provides one. This proves the Rust code compiles for
# macOS; running it still needs a Mac (or the macOS CI job).
#
# Usage: sh scripts/check-macos.sh    (needs gcc, ar and rustup)
set -eu

stub=$(mktemp -d)
trap 'rm -rf "$stub"' EXIT
cat > "$stub/cc" <<'EOF'
#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  case "$a" in -o?*) out="${a#-o}" ;; -Fo?*) out="${a#-Fo}" ;; esac
  prev="$a"
done
case " $* " in
  # cc-rs tells compiler families apart by their preprocessor output.
  *" -E "*) echo "clang"; exit 0 ;;
  *" --version "*) echo "stand-in 1.0"; exit 0 ;;
esac
if [ -n "$out" ]; then gcc -c -x c /dev/null -o "$out"; fi
EOF
chmod +x "$stub/cc"
mkdir "$stub/sdk"

export SDKROOT="$stub/sdk"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  rustup target add "$target" >/dev/null
  var=$(echo "$target" | tr '-' '_')
  export "CC_$var=$stub/cc" "CXX_$var=$stub/cc" "AR_$var=ar"
  echo "== $target"
  cargo clippy --workspace --all-targets --target "$target" -- -D warnings
done
