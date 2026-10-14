# LocalAuth Home

See ../SETUP.md and ../SECURITY.md before pairing or internet exposure.

Build: cargo build --release --locked
Test: cargo test --locked
Lint: cargo clippy --locked --all-targets -- -D warnings
Run: target/release/localauth-home (Windows: target\release\localauth-home.exe)

The admin access link is printed at startup. The dashboard is loopback-only. Default backup listener: private-address clients on IPv4 port 7443, with TLS. Use --remote explicitly to permit public source addresses. Build separately on Windows, Linux, macOS or the target machine; only the included Windows x64 release executable was tested here.

Optional live HTTPS integration test (Python 3 with cryptography installed): python tests/https_integration.py. It starts a temporary loopback server, uses a synthetic software test key, verifies the actual HTTP/TLS routes, then stops the server and removes temporary test data. This fixture does not test Android hardware keys.
