fmt:
	cargo fmt --all

sort:
	cargo sort --workspace --grouped

lint: fmt sort

check:
	cargo check --workspace --all-targets

clippy:
	cargo clippy --workspace --all-targets

doc:
	RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc  --no-deps

test:
	cargo test

# Run the library tests against a BoringSSL built with ASan and UBSan (macOS, Apple clang).
test-sanitized:
	#!/usr/bin/env bash
	set -euo pipefail
	[[ "$(uname)" == Darwin ]] || { echo "test-sanitized supports macOS only" >&2; exit 1; }
	asan="$(clang -print-file-name=libclang_rt.asan_osx_dynamic.dylib)"
	ubsan="$(clang -print-file-name=libclang_rt.ubsan_osx_dynamic.dylib)"
	host="$(rustc -vV | sed -n 's/^host: //p')"
	flags="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
	export CFLAGS="$flags" CXXFLAGS="$flags"
	export RUSTFLAGS="-C link-arg=$asan -C link-arg=$ubsan -C link-arg=-Wl,-rpath,$(dirname "$asan")"
	export ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
	cargo test --target "$host" --target-dir target/sanitized -p rama-boring --lib

qa: lint check clippy doc test

publish:
	bash scripts/publish.sh
