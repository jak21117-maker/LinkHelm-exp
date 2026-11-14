# LinkHelm-exp

**beta0.4.0 — experimental branch: transparent proxying without a virtual adapter (WinDivert + SOCKS5), rebuilt from the LinkHelm 1.1.3 baseline**

This repository is an independent experimental branch of LinkHelm. The beta0.2.0 source baseline is **v1.1.3** (`backup_v1.1.3/`: UI polish, reconnect governance, ICS, and file transfer are kept as-is); Wintun+lwIP and the store booster are removed, and the data plane is replaced with WinDivert+SOCKS5 (relay layer aligned with the ProxyBridge architecture).

This is an independent experimental branch of the LinkHelm v1.1.x C++ desktop client (separate from the mainline stable repo). Goal: **no TUN/virtual adapter, no modification of the system default route** — let Windows native apps transparently reach the internet through the phone (SOCKS5 Host on the Wi-Fi Direct link), and keep the **real Wi-Fi adapter showing "Internet connected"** (NCSI probing travels the same capture path; no registry hijacking).

## Differences from the mainline (LinkHelm 1.1.3)

| Item | Mainline LinkHelm 1.1.3 | LinkHelm-exp beta0.4.0 |
|---|---|---|
| Data plane | Wintun (TUN) → hev-socks5-tunnel (lwIP) → SOCKS5 | WinDivert intercept → local TCP reflection bridge / SOCKS5 UDP ASSOCIATE → SOCKS5 |
| Virtual adapter | LinkHelm-IwIP (lwIP adapter) | **None** |
| Default route | 0.0.0.0/1 + 128.0.0.0/1 bound to TUN | Not replaced; only adds a half-route via the phone when no usable egress route exists, removes it on disconnect |
| Store booster | Present (mihomo) | **Removed** |
| Connection page / sharing-transfer page | Kept | **Kept as-is** (ICS sharing, file-transfer helper, UDP detection) |
| Phone side | SOCKS5 Host (RFC 1929 auth) | 100% reused, zero changes |
| Admin rights | Not required for normal use | **Required** (loads the WinDivert64.sys driver) |
| Runtime logs | Bilingual UI labels | Runtime logs are English-only; UI labels keep bilingual `TR()` |

## Data path

```
TCP:  App → Windows native stack → WinDivert captures SYN/flow
      → address reflected to a local listener (middle kernel connection:
        orig_ip:app_port ↔ app_ip:local_port)
      → listener accept → RFC 1929 auth → SOCKS5 CONNECT(original target)
      → phone → internet
UDP:  App datagram → WinDivert capture → session by source endpoint
      → RFC 1929 + UDP ASSOCIATE
      → relay encapsulation (RSV/FRAG=0, ATYP=IPv4) → phone relay
      → return packet endpoint-validated → rebuild IP/UDP header
      → WinDivert inbound reinject
```

The TCP reflection scheme is inspired by okatodev/wfp-divert (MIT, source snapshot in `wfp-divert-ref/`), with the P0 issues from the architecture study fixed:

1. The SOCKS5 client implements **method 0x02 username/password auth** (wfp-divert only had 0x00);
2. The UDP ASSOCIATE handshake **does not hold a global lock** (a slow handshake does not block other UDP flows);
3. Every UDP return packet **validates the relay endpoint**; FRAG≠0 is dropped outright (no silent corruption);
4. Proxy failure is **fail-closed dropped** with counter/log — never passed through as-is (the beta0.1.2 fail-open was the source of the egress-IP hop).

## Routing strategy (does not modify the route table)

**Since beta0.1.3 the engine never touches the system route table.** beta0.1.2 tried `0.0.0.0/1 + 128.0.0.0/1` half-routes; field logs showed "half default route add failed err 0" yet WinDivert still captured 30+ TCP — meaning a usable route already existed, so the half-route was both unnecessary and left a real routing black hole after a hard kill.

On Start the engine only does **read-only diagnostics**: `GetBestRoute` compares the phone link's egress interface with 1.1.1.1, prints `ENGINE_ROUTE_SNAPSHOT` (including whether a legacy `LinkHelm-IwIP` / Wintun virtual adapter is detected, with `ENGINE_BASELINE_WARN`). EXP **does not** disable, rename, or re-route any adapter. All public TCP/UDP is taken over by the WinDivert NETWORK layer; NCSI probing shares the same capture path.

## Build

```
cmake -S . -B build -G "MinGW Makefiles" ^
      -DCMAKE_CXX_COMPILER=../toolchain/mingw64/bin/g++.exe
cmake --build build --parallel
```

Output `build/LinkHelmExp.exe` (statically linked libgcc/libstdc++/winpthread, no runtime DLL dependency). WinDivert is loaded via `LoadLibrary`, no import library needed.

## Deployment (dist/)

```
LinkHelmExp.exe            main program
WinDivert.dll              LGPL-2.1/GPL-2.0 dual license (reqrypt.org)
WinDivert64.sys            WinDivert kernel driver (must sit beside the DLL)
engine/linkhelm_ics.exe    ICS sharing module (same build as the mainline)
```

Running requires **Administrator rights** (to load WinDivert64.sys). Windows 10/11 x64 only. On first run the WinDivert service is installed; uninstall happens automatically when the program exits.

## Experimental boundaries (honest disclosure)

- **The driver layer is not tested on this machine**: `WinDivertOpen` returns `err=5` (no admin) on the dev box. Since beta0.1.7 the package ships `tests/driver_probe.exe`: **run it as Administrator to decide in one shot** whether "real outbound packets can be captured" and "injected inbound UDP packets can be received by a normal socket" (the latter is the UDP return-loop). Without elevation it prints `SKIP / NOT PROVEN` explicitly — not a pass.
- `tests/exp_selftest.cpp` keeps only 10 cross-real-socket end-to-end assertions; pure-function/self-proving assertions were removed per request. **Assertion count is not proof of internet access** — only `driver_probe.exe` judges the driver layer.
- IPv6 global unicast egress is **explicitly blocked and counted** (the phone SOCKS5 has no IPv6 capability); local link-local / multicast are passed. The DNS proxy returns NOERROR empty answer for AAAA.
- UDP:443 / IPv6 / AAAA policies are controlled by the optional `exp_policy.ini`; **defaults are identical to beta0.1.6**; template in `exp_policy.ini.example`. Change one item at a time, keep logs.
- NAT key collision (different local address/dest port reusing the same `{dst_ip, src_port}`) is **rejected for reuse and counted**; FIN/RST retires the mapping immediately (aligned with ProxyBridge conntrack), with a 15 s silent fallback reclamation.
- IP fragmented packets (non-first fragment) cannot match the NAT table and are dropped per policy (rare under LAN MTU 1500).
- Each TCP connection uses 2 pump threads; concurrency defaults to **adaptive AIMD** (init 8, halve on phone saturation, +1 after 16 consecutive successes, range 2–12); `ConnectConcurrency` can pin it for A/B experiments.
- Multi-device gateway (FORWARD+NAT) is a separate topic per the design doc and is not promised in this repo.

## Directory

```
backup_v1.1.3_src/   full unmodified backup of the mainline v1.1.3 C++ sources
src/                 exp working sources (trimmed app_main + new exp_engine/exp_socks5)
wfp-divert-ref/      wfp-divert source snapshot (MIT, study reference)
windivert/           WinDivert headers and runtime files
docs/                architecture docs (this README is the docs/ARCHITECTURE summary)
```

## Field diagnosis: run `socks5_probe.exe` first (no admin needed)

With the phone's LinkHelm Host unchanged and the PC on the Wi-Fi Direct network, run the bundled **read-only probe**:

```
tests\socks5_probe.exe 192.168.49.1 8080 <account> <password>
```

It changes no route / adapter / DNS / registry, loads no WinDivert driver, and only prints: whether auth and TCP CONNECT succeed, the `BND.ADDR/BND.PORT` returned by `UDP ASSOCIATE`, the actual UDP return source port and ATYP/FRAG, and the return code of the production `ExpSocks5UdpRecv`. Credentials are passed only on the command line — never printed, never logged.

This output distinguishes three problems at once: the phone not opening UDP relay at all (ASSOCIATE fails or no reply in 4 s), the phone's return port differing from `BND.PORT` (beta0.1.5 would permanently kill the receive thread; beta0.1.6 is compatible), or a non-standard return ATYP/FRAG. This is exactly the unknown the architecture review kept flagging — "prove it with real measurements, do not assume the phone SOCKS5 is fully standard".

## Field acceptance step 1: `driver_probe.exe` (needs admin)

```
run as Administrator  tests\driver_probe.exe 192.168.49.1
```

Using RFC 5737 documentation address `203.0.113.7` and a very narrow filter, it does three things:
**A** verifies real outbound UDP packets are captured by WinDivert; **B** injects an inbound UDP packet and verifies a normal UDP socket receives it (B is the "return loop" the engine's `UdpRecvThread` depends on); **C** evaluates the **product's actual installed filter string** to confirm "the phone's UDP/53 is captured" (the DNS fallback path is reachable — directly tied to whether the Wi-Fi Internet icon is stable).

It changes no route / DNS / firewall / registry; exit code `0=WORKING`, `1=BROKEN`, `2=no elevation (unverified)`. **B2 failure pinpoints**: when `WinDivertSend` succeeds but the socket never receives, the problem is `IfIdx` / firewall / network profile — continuing to edit SOCKS5 code is futile. **C2 failure** means the local filter is inconsistent with the DNS fallback and the Wi-Fi Internet icon will flicker intermittently.

Also bundled: `tests/egress_compare.ps1` (read-only, 5-round comparison of explicit-SOCKS5 egress vs transparent egress) to separate "Windows traffic bypass" from "phone cellular CGNAT rotation".

## Changelog

### beta0.4.0 — fix "good connections wrongly killed" (control-plane timeout 15 s) + remove redundant retry + trim logs + shared signing identity

**Root cause of the "good links occasionally killed" bug (field logs).**
The PC control plane set `SO_RCVTIMEO = 6000 ms` on the SOCKS5 control socket, while the phone's upstream dial budget is `connectTimeoutMs = 15000 ms` (`ProxyServer.kt`). A slow cellular upstream dial that completes between 6 s and 15 s was reset by the PC at exactly 6 s with `CONNECT_REPLY_MISSING [WSA 10060]` — i.e. the PC killed a connection the phone would have opened successfully. This was the dominant source of the high `TCP fail` count in the field logs.

**PC — control-plane timing**
- Raised the control-plane receive timeout `6000 ms → 15000 ms` in `exp_socks5.cpp` (`DialWithTimeout`), matching the phone's 15 s upstream dial budget. The application's own SYN retransmission is the natural retry, so a single blocking dial now covers the phone's full dial window.
- Removed the redundant 2× retry loop in `exp_engine.cpp` `TcpWorker`. A single blocking dial is sufficient; the previous retry only doubled the slot-hold time for exactly the slow links we were trying to stop killing.

**PC — logging**
- `StatsIntervalSec` default stays 30 s (the 30 s `WarnLog` throttle from beta0.3.1 remains). With the 15 s control budget, slow-but-valid dials are no longer counted as failures, so per-flow failure noise drops further.

**Android — signing**
- Built UNSIGNED locally and signed by CI with the **same keystore as the main LinkHelm app** (`linkhelm_repo/ci/debug.keystore`, alias `androiddebugkey`, SHA-256 `9E:48:BA:9F:…:C4:B1`). Shares LinkHelm's developer identity; the "developer identity unverified" warning does not apply. versionCode 68, versionName beta0.4.0.

**Verification (local, honest scope)**
- PC: `cmake --build` clean; self-test 17/17 (beta0.4.0); exe carries 4× `beta0.4.0`.
- Android: `assembleRelease` BUILD SUCCESSFUL; `apksigner` confirms Signer#1 SHA-256 equals the 1.1.3 APK exactly.
- End-to-end not reproduced here (phone offline, WinDivert needs admin).

Earlier internal iterations (beta0.1.0 – beta0.3.1) were never published and are intentionally not documented here — see git history for details.

---

## Support my research

LinkHelm-exp is an experimental branch of LinkHelm. Development and maintenance are done in the author's own time. If it saved you a headache, a completely voluntary tip is welcome — there are **no premium features** and nothing is gated behind a donation.

**Support my research, donations are voluntary. No premium features.**

<!-- Donation QR code: sponsor_qr.png ships next to this README -->
<img src="sponsor_qr.png" alt="Donate to support my research" width="240"/>

---

## Acknowledgements and credits

LinkHelm-exp is an experimental branch of [LinkHelm](https://github.com/jak21117-maker/LinkHelm). The data plane is rebuilt on top of these open-source projects — studied, adapted, and shipped:

- **WinDivert** by basil00 (LGPL-2.1/GPL-2.0 dual license) — the kernel-level capture/reinject foundation this branch runs on: <https://reqrypt.org/windivert.html> · <https://github.com/basil00/WinDivert>
- **okatodev/wfp-divert** (MIT) — the TCP reflection scheme; the source snapshot is shipped in `wfp-divert-ref/`: <https://github.com/okatodev/wfp-divert>
- **InterceptSuite/ProxyBridge** (MIT) — relay architecture reference: TCP NAT/conntrack lifecycle, per-endpoint underlay exclusion, adaptive concurrency: <https://github.com/InterceptSuite/ProxyBridge>

The phone-side SOCKS5 Host is 100% the mainline LinkHelm host app — unchanged.

Third-party components keep their own licenses — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Provided "as is", without warranty.
