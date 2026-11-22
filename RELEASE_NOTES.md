# LinkHelm-exp v0.5.0

Consolidated release covering everything that changed on the PC (Windows) and
Android sides since the **beta0.4.0** baseline tag. The WinDivert + SOCKS5 data
plane, the capture filter and the no-virtual-adapter / no-system-DNS /
no-route-table guarantees are unchanged throughout.

## Highlights

- **Application-level DNS stack (PC).** UDP:53 is intercepted by WinDivert and
  relayed over SOCKS5 TCP DNS — the system/adapter DNS configuration is never
  modified and needs no restore (`SystemDnsProxy=1` restores the legacy
  loopback+netsh behaviour). On top of that: an in-app DNS response cache
  (TTL-clamped 30–300 s, patched transaction ID, negative replies never cached,
  cleared on reconnect) and a connection pool of up to 8 healthy SOCKS5 links
  reused across queries with idle redial. Together these remove the per-query
  connection flood that saturated the phone and caused DNS/CONNECT timeouts and
  intermittent fast/slow behaviour.
- **Anti-cheat-friendly transparent transport (PC).** Every process —
  including anti-cheat / protected ones — is relayed identically: kernel-level
  capture and local reflection only. No DLL injection, no system proxy, no
  virtual adapter, no per-process local loopback listener, and no flow-specific
  traffic markers: the on-the-wire profile is indistinguishable from ordinary
  relayed traffic, and the public egress is the same for all applications.
  Optional per-process routing is available via `RelayMode` (`0` = all-relay,
  default; `1`/`2` = split modes) and the process list can be extended through
  `linkhelm_direct_exes.txt`.
- **Phone-liveness watchdog (PC, new).** A dedicated monitor probes the phone
  every 10 s with a real SOCKS5 CONNECT to a public resolver — covering "phone
  app closed", "out of range / no signal" and "cellular uplink down", even when
  there are no active flows (`tcp=0`). Three consecutive failed probes trigger
  an automatic disconnect; the UI resets to "not connected" and does not
  auto-reconnect (a manual reconnect resumes). `PhoneLiveness=0` disables the
  watchdog; `ProbeIntervalSec` / `ProbeStrikes` tune the sensitivity.
- **Steam++ / Watt Toolkit coexistence (PC).** Loopback traffic is never
  captured, so Steam++'s `127.0.0.1` leg always stays local; its upstream rides
  the same transparent relay as everything else. The accelerator works
  alongside LinkHelm in both system-proxy and hosts modes.
- **Optional short handshake (PC).** `FastHandshake=1` pipelines the SOCKS5
  greeting + RFC 1929 auth + CONNECT into a single send — protocol-safe against
  the phone's fixed-byte parser (verified against a live phone). Default off;
  the serial handshake remains the default path.
- **Quieter logs (PC).** Periodic stats cadence 30 s → 60 s; per-flow failure
  noise further reduced.
- **Bugfix (PC).** Escaped registry path in the optional logon startup entry.

## Android

- versionName **v0.5.0**, versionCode 78. The phone-side SOCKS5 Host data plane
  is unchanged from the shared LinkHelm host app. CI builds the release APK and
  signs it with the same keystore as the mainline, so the developer identity
  carries over.

## Verification (honest scope)

- PC: clean build (4 targets); self-test **17/17**; routing / liveness policy
  tests **16/16**.
- Real-phone probes: SOCKS5 TCP CONNECT + UDP ASSOCIATE + data round-trip
  verified against a live phone; the liveness probe returns ONLINE for a
  reachable phone and OFFLINE for an unroutable address.
- The WinDivert driver layer itself is judged only by `tests/driver_probe.exe`
  run as Administrator on the target PC — never claimed here.
