"""Maintainer-only prefix audit of both native archives."""
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[2]
outputs = {
    pathlib.Path(event["out_dir"])
    for event in map(json.loads, sys.stdin)
    if event.get("reason") == "build-script-executed"
    and "rama-boring-sys@" in event["package_id"]
}
checked = 0
for output in outputs:
    cache = output / "build/CMakeCache.txt"
    prefix = next(line.split("=", 1)[1] for line in cache.read_text().splitlines()
                  if line.startswith("BORINGSSL_PREFIX:"))
    assert prefix.startswith("rama_boring_"), prefix
    subprocess.run([
        "go", "run", str(output / "boringssl/util/audit_symbols.go"),
        "-ignore-symbols-with", prefix,
        str(output / "build/libcrypto.a"), str(output / "build/libssl.a"),
    ], cwd=root / "boring-sys/deps/boringssl", check=True)
    checked += 1
assert checked, "no built native libraries found"
