## LinkHelm-exp beta0.4.0 — first public release

Experimental branch of LinkHelm: transparent proxying for Windows **without a virtual adapter** — no Wintun, no lwIP adapter, no default-route replacement. All public TCP/UDP is captured at the WinDivert NETWORK layer and relayed over the phone's existing SOCKS5 Host endpoint (RFC 1929) across the Wi-Fi Direct link. The phone-side app is 100% the mainline LinkHelm host — zero phone-side changes.

### What beta0.4.0 fixes

**"Good connections occasionally killed" — control-plane timeout mismatch.**
The PC control plane previously applied a 6 s receive timeout on the SOCKS5 control socket, while the phone's upstream dial budget is 15 s (`connectTimeoutMs`). A cellular dial completing between 6 s and 15 s was reset by the PC at exactly 6 s (`CONNECT_REPLY_MISSING [WSA 10060]`) — the PC killed connections the phone would have opened. The control-plane receive timeout is now 15 s, matching the phone's dial window; the redundant 2x retry loop was removed (the application's own SYN retransmission is the natural retry).

**Shared signing identity.**
The Android APK is signed by CI with the same keystore as every main LinkHelm build (`ci/debug.keystore`, alias `androiddebugkey`). The APK certificate is identical to the mainline LinkHelm release, so no "developer identity unverified" warning applies. versionCode 68, versionName beta0.4.0.

**Log volume.**
Per-flow lifecycle logging is off by default (`FlowLog=0`); anomalous lines are globally throttled to one per 30 s; the aggregate stats row defaults to 30 s cadence (`StatsIntervalSec`). Slow-but-valid dials no longer count as failures, further reducing per-flow noise.

### Package contents

- `LinkHelm-exp-beta0.4.0-win64.zip` — Windows desktop build (statically linked C++, WinDivert.dll + WinDivert64.sys, ICS sharing module, test tools, full sources, `BUILD_HASHES.txt` with per-file SHA-256).
- `LinkHelm-exp-Android-beta0.4.0.apk` — signed APK (same certificate as main LinkHelm).
- `SHA256SUMS.txt` — SHA-256 of both artifacts.

### Verification (honest scope)

- Windows: `cmake` build clean on MinGW-w64; self-test 17/17 (cross-real-socket end-to-end assertions: SOCKS5 handshake/auth, HTTP relay, DNS relay, AAAA suppression, UDP robustness, byte-exact 1 MB loopback, capture-filter correctness). The self-test output ships in the zip as `SELFTEST_RESULT.txt`.
- Android: `assembleRelease` + `apksigner verify` in CI.
- **The WinDivert driver layer is not exercised by CI** (requires admin on a real PC with the phone link). Before first use, run `tests\driver_probe.exe` **as Administrator** — it judges capture (A), inbound reinject loop (B), and DNS-filter reachability (C) in one shot; exit code 0 = working. `tests\socks5_probe.exe` (no admin) verifies the phone SOCKS5/UDP relay independently.
