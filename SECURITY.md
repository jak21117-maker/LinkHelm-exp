# Security Policy

## What this program does on your machine (disclosure first)

- LinkHelm-exp is a **transparent proxy**. It captures the machine's outbound
  TCP/UDP packets at the WinDivert NETWORK layer and relays them through the
  phone's SOCKS5 Host endpoint. That is its entire purpose — anything else is
  a bug, not a feature.
- **Administrator privileges are required** to load the WinDivert64.sys kernel
  driver. The driver is installed on demand when the engine starts and is
  uninstalled when the program exits cleanly. The bundled `WinDivert.dll` /
  `WinDivert64.sys` are the unmodified official binaries (reqrypt.org,
  LGPL-2.1/GPL-2.0 dual license).
- The engine **never modifies the system route table** (read-only diagnostics
  only), never touches the NCSI probe registry values, never disables or
  renames network adapters, and never writes outside its own working
  directory (log + optional `exp_policy.ini`).
- The ICS sharing module (`engine/linkhelm_ics.exe`) is invoked only when the
  user clicks "Share to game console"; it is the same module the mainline
  LinkHelm client uses.
- The Android host is the **unmodified mainline LinkHelm app** (`com.linkhelm.exp`
  aside). See the main LinkHelm repository's Security Policy for the phone-side
  service scope: SOCKS5 bound to the Wi-Fi Direct subnet with mandatory
  RFC 1929 authentication.

## What is NOT collected

- No telemetry, no update checks, no analytics. The only network traffic this
  program generates is the traffic you (or your apps) generate, relayed to the
  phone and onward to the internet.

## Reporting a Vulnerability

- Please report security issues through the project's Issue tracker
  (<https://github.com/jak21117-maker/LinkHelm-exp/issues>), including minimal
  reproduction steps and the scope of impact. For anything you believe is
  actively exploitable, prefer a private security advisory over a public issue.

## Antivirus / SmartScreen false positives

- The Windows build is a statically linked, unsigned native binary that loads
  a kernel driver and intercepts all network traffic — genuine behaviors that
  may trigger "unknown publisher" warnings. Verify the SHA-256 manifest
  (`SHA256SUMS.txt` / `BUILD_HASHES.txt`) of the release before running; do
  not disable Defender because of this project.
- If you confirm a false positive, appeal through Microsoft's official sample
  submission channel with the file hash and build records.
