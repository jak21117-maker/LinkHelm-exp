# Third-party notices (LinkHelm-exp)

## WinDivert
- Files: `windivert/WinDivert.dll`, `windivert/WinDivert64.sys`, `windivert/windivert.h`
- Copyright (c) Harvey-Georg/reqrypt.org
- License: LGPL-2.1-or-later OR GPL-2.0-only (dual license, per upstream).
- Source: https://reqrypt.org/windivert.html
- NOTE: the DLL/SYS are shipped as third-party components and are NOT part
  of LinkHelm's own MIT-licensed code. Do not relabel them.

## wfp-divert (reference only)
- Directory: `wfp-divert-ref/` — snapshot of https://github.com/okatodev/wfp-divert (main)
- License: MIT (see wfp-divert-ref/LICENSE)
- Used as a design reference for the TCP address-reflection scheme. The
  LinkHelm-exp implementation (src/exp_engine.cpp, src/exp_socks5.cpp) is a
  separate implementation with RFC 1929 auth, lock-free UDP association,
  relay endpoint validation and fail-open policy changes.

## LinkHelm mainline sources
- `src/app_main.cpp` (trimmed), `src/net_control.cpp`, `src/tray.cpp`,
  `src/file_transfer.cpp`, `src/ft_receiver.cpp` derive from the LinkHelm
  v1.1.0 desktop build. Pristine copies: `backup_v1.1.0_src/`.
