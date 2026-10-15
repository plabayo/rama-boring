# Windows BoringSSL diagnostics

The AES capability probe, 16 KiB crypto benchmark and local HTTPS MITM relay
link the same workspace BoringSSL build. Run commands from the repository root
with MSVC, CMake, NASM, Go and libclang available.

```powershell
$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin'
cargo build --manifest-path tools/windows-bench/Cargo.toml --release --target-dir target/wb
target/wb/release/windows-boring-bench.exe probe 1
.github/scripts/check-windows-build.ps1 -TargetDirectory target/wb
target/wb/release/windows-boring-bench.exe crypto 3
```

`probe 1` requires AES hardware acceleration; use `probe 0` for an unaccelerated
control. Crypto results use decimal MB/s. The release profile retains symbols.

```powershell
tools/windows-bench/run.ps1 `
  -EndpointExe target/wb/release/windows-boring-bench.exe `
  -RelayExe target/wb/release/windows-boring-bench.exe `
  -OutputDirectory tools/windows-bench/results/run -PayloadMiB 256 -Repeats 3
```

The relay uses HTTP/1.1 and TLS 1.2 `ECDHE-RSA-AES128-GCM-SHA256` on both legs,
checks every payload byte and disables per-record logging. Results include
throughput in Mbps, CPU relative to one core, ciphers and executable architecture.
The loopback fixture skips certificate verification without installing a CA.

Compare separate clean builds with identical dependencies, profile and CRT.
Keep the accelerated endpoint fixed and change only `RelayExe`. Include an
optimized software control to separate compiler optimization from assembly.
Use larger payloads for sustained transfers, and measure native ARM64 and
emulated x64 separately. This harness does not include production inspection
logic or Rama's async runtime. Generated `results/` are ignored by Git.

For CPU sampling, run the relay command as administrator with `-Profile`.
Keep its executable and PDBs, then use Windows Performance Toolkit:

```powershell
$xperf = 'C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe'
tools/windows-bench/analyze.ps1 `
  -OutputDirectory tools/windows-bench/results/run -Xperf $xperf `
  -SymbolPath "$PWD\target\wb\release;srv*$PWD\target\symbols*https://msdl.microsoft.com/download/symbols"
```

Inspect the relay leaf/inclusive CSVs, stack HTML and trace statistics. Inclusive
percentages overlap; check unresolved symbols and lost events. Keep profiled
timings separate. `-WprProfile CPU` adds scheduler tracing with higher overhead.
