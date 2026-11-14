# LinkHelm-exp

**beta0.2.0 — 实验版：基于 LinkHelm 1.1.3 基线重建，无虚拟网卡透明上网（WinDivert + SOCKS5）**

本仓库是 LinkHelm 的独立实验分支。beta0.2.0 起源码基线为 **v1.1.3**（`backup_v1.1.3/`：
UI 美化 / 重连治理 / ICS / 文件传输原样保留），删除 Wintun+lwIP 与商店加速，
数据面改用 WinDivert+SOCKS5（relay 层对齐 ProxyBridge 架构）。

本仓库是 LinkHelm v1.1.0 C++ 桌面端的独立实验分支（独立于主线稳定仓库）。
目标：**不创建 TUN/虚拟网卡、不改系统默认路由**，让 Windows 本机应用透明地
经手机（Wi-Fi Direct 链路上的 Android SOCKS5 Host）上网，并让**真实 Wi-Fi
适配器显示"已连接 Internet"**（NCSI 探测走同一捕获路径，不劫持注册表）。

## 与主线 v1.1.0 的差异

| 项 | 主线 v1.1.0 | LinkHelm-exp beta0.1.0 |
|---|---|---|
| 数据面 | Wintun (TUN) → hev-socks5-tunnel (lwIP) → SOCKS5 | WinDivert 拦截 → 本地 TCP 反射桥 / SOCKS5 UDP ASSOCIATE → SOCKS5 |
| 虚拟网卡 | LinkHelm-IwIP（lwIP 网卡） | 无 |
| 默认路由 | 0.0.0.0/1 + 128.0.0.0/1 绑 TUN | 不替换；仅在系统无可用外网路由时经手机加半路由，断开时移除 |
| 商店加速 | 有（mihomo） | **删除** |
| 连接页 / 共享传输页 | 保留 | **原样保留**（含 ICS 共享、文件传输助手、UDP 检测） |
| 手机端 | SOCKS5 Host (RFC 1929 认证) | 100% 复用，零改动 |

## 数据路径

```
TCP:  App → Windows 原生协议栈 → WinDivert 捕获 SYN/流
      → 地址反射到本地 listener（中间内核连接: orig_ip:app_port ↔ app_ip:local_port）
      → listener accept → RFC 1929 认证 → SOCKS5 CONNECT(原始目标)
      → 手机 → 互联网
UDP:  App 数据报 → WinDivert 捕获 → 按源端点会话 → RFC 1929 + UDP ASSOCIATE
      → 中继封装 (RSV/FRAG=0, ATYP=IPv4) → 手机 relay
      → 回包校验源端点 → 重建 IP/UDP 头 → WinDivert 入站注入
```

TCP 反射方案参考 okatodev/wfp-divert（MIT，源码快照在 `wfp-divert-ref/`），
并按《LinkHelm-exp 架构研究与实施方案》修复其 P0 问题：

1. SOCKS5 客户端实现 **method=0x02 用户名/密码认证**（wfp-divert 只有 0x00）；
2. UDP ASSOCIATE 握手**不持全局锁**（慢握手不阻塞其它 UDP 流）；
3. 每个 UDP 回包**校验中继端点**，FRAG≠0 直接丢弃（不静默损坏）；
4. 代理失败 **fail-closed 丢弃**并计数/记日志，绝不原样放行（0.1.2 的
   fail-open 正是出口 IP 跳动的来源）。

## 路由策略（不修改路由表）

**beta0.1.3 起引擎完全不碰系统路由表。** 0.1.2 曾尝试添加
`0.0.0.0/1 + 128.0.0.0/1` 半路由，实测日志为「半默认路由添加失败 err 0」，
但 WinDivert 仍捕获到 30+ 条 TCP —— 说明本机已有可用路由，半路由既无必要，
又会在强杀后残留、制造真正的路由黑洞。

Start 时只做**只读诊断**：`GetBestRoute` 比较手机链路与 1.1.1.1 的出口接口，
输出 `ENGINE_ROUTE_SNAPSHOT`（含是否检测到 `LinkHelm-IwIP` / Wintun 等旧虚拟
适配器，附 `ENGINE_BASELINE_WARN`）。EXP **不会**禁用、改名或重路由任何网卡。
公网 TCP/UDP 全部由 WinDivert NETWORK 层接管，NCSI 探测同走捕获路径。

## 构建

```
cmake -S . -B build -G "MinGW Makefiles" ^
      -DCMAKE_CXX_COMPILER=../toolchain/mingw64/bin/g++.exe
cmake --build build --parallel
```

产物 `build/LinkHelmExp.exe`（静态链接 libgcc/libstdc++/winpthread，无运行时
DLL 依赖）。WinDivert 经 LoadLibrary 动态加载，无需导入库。

## 部署（dist/）

```
LinkHelmExp.exe        主程序
WinDivert.dll          LGPL-2.1/GPL-2.0 双许可（reqrypt.org）
WinDivert64.sys        WinDivert 内核驱动（需与 DLL 同目录）
engine/linkhelm_ics.exe  ICS 共享模块（与主线同一构建）
```

运行需**管理员权限**（加载 WinDivert64.sys 驱动），仅 Windows 10/11 x64。
首次运行会安装 WinDivert 服务；卸载随程序退出自动完成。

## 实验边界（如实声明）

- **驱动层未在本机实测**：`WinDivertOpen` 在开发机返回 `err=5`（无管理员权限）。
  beta0.1.7 起随包提供 `tests/driver_probe.exe`：**以管理员运行即可一次性判定**
  「真实出站包能否被捕获」与「注入的入站 UDP 包能否被普通 socket 收到」（后者
  即 UDP 回包闭环）。无提权时它明确输出 `SKIP / NOT PROVEN`，不算通过。
- `tests/exp_selftest.cpp` 只保留 10 条跨真实 socket 的端到端断言；纯函数/自证类
  断言已按要求删除。**断言数量不代表可上网**，判定驱动层只认 `driver_probe.exe`。
- IPv6 全局单播出站 **显式阻断并计数**（手机 SOCKS5 无 IPv6 能力）；本地
  link-local / multicast 放行。DNS 代理对 AAAA 返回 NOERROR 空答案。
- UDP:443 / IPv6 / AAAA 三项策略由可选的 `exp_policy.ini` 控制，**默认值与
  beta0.1.6 完全一致**；模板见 `exp_policy.ini.example`。每次只改一项、保留日志。
- NAT 键碰撞（不同本机地址/目的端口复用同一 `{dst_ip, src_port}`）**拒绝复用
  并计数**；FIN/RST 到达时立即退休映射（对齐 ProxyBridge conntrack），
  15s 静默兜底回收。
- IP 分片报文（非首片）无法匹配 NAT 表，按策略丢弃（LAN MTU 1500 下罕见）。
- 每条 TCP 连接 2 个泵线程；并发默认**自适应 AIMD**（初始 8，手机饱和时减半，
  连续 16 次成功后 +1，范围 2–12），可用 `ConnectConcurrency` 固定做对照实验。
- 多设备网关（FORWARD+NAT）按方案文档为独立专题，不在本仓库承诺。

## 目录

```
backup_v1.1.0_src/   主线 v1.1.0 C++ 源码完整备份（未改动）
src/                 exp 工作源码（app_main 删减 + exp_engine/exp_socks5 新增）
wfp-divert-ref/      wfp-divert 源码快照（MIT，学习参考）
windivert/           WinDivert 头文件与运行件
docs/                架构文档（本 README 即 docs/ARCHITECTURE 摘要）
```

## 真机诊断：先跑 `socks5_probe.exe`（无需管理员）

手机端保持 LinkHelm Host 原样、PC 连上 Wi-Fi Direct 后，先运行随包附带的**只读探针**：

```
tests\socks5_probe.exe 192.168.49.1 8080 <账号> <密码>
```

它不修改路由 / 适配器 / DNS / 注册表，不加载 WinDivert 驱动，只打印：认证与 TCP CONNECT 是否成功、`UDP ASSOCIATE` 返回的 `BND.ADDR/BND.PORT`、**实际 UDP 回包的源端口与 ATYP/FRAG**、以及生产路径 `ExpSocks5UdpRecv` 的返回码。凭据仅由命令行传入，不打印、不写入日志。

这段输出能一次性区分三类问题：手机根本没开 UDP relay（ASSOCIATE 失败或 4s 无回包）、手机回包端口与 `BND.PORT` 不一致（beta0.1.5 会因此永久杀死接收线程，beta0.1.6 已兼容）、或回包 ATYP/FRAG 非标准。这正是架构评审反复强调「必须用实测说话、不能假设手机 SOCKS5 完全标准」的未知项。

## 真机验收第一步：`driver_probe.exe`（需管理员）

```
以管理员身份运行  tests\driver_probe.exe 192.168.49.1
```

它用 RFC 5737 文档地址 `203.0.113.7` 和一个极窄过滤器，做三件事：
**A** 验证真实出站 UDP 包能被 WinDivert 捕获；**B** 注入一个入站 UDP 包，
验证普通 UDP socket 能收到（B 就是引擎 `UdpRecvThread` 赖以工作的
「回包闭环」）；**C** 用**产品实际安装的过滤器字符串**求值，确认「手机的
UDP/53 会被捕获」（DNS 兜底路径可达 —— 直接对应 Wi-Fi 的 Internet 图标
是否稳定）。

不改路由 / DNS / 防火墙 / 注册表，退出码 `0=WORKING`、
`1=BROKEN`、`2=无提权（未验证）`。**B2 失败即可定点**：`WinDivertSend`
成功但 socket 收不到时，问题在 `IfIdx` / 防火墙 / 网络配置文件，
继续改 SOCKS5 代码是无效的。**C2 失败**则说明本机过滤器与 DNS 兜底
不一致，Wi-Fi 的 Internet 图标会间歇性闪烁。

另附 `tests/egress_compare.ps1`（只读，5 次对照显式 SOCKS5 出口与透明出口）
用于区分「Windows 流量绕过」和「手机蜂窝 CGNAT 轮换」。

## Changelog

### beta0.3.1 — revert broken black-hole suppression; sign exp with the LinkHelm keystore

**Root cause of the beta0.3.0 regression (worse connectivity than beta0.2.3).**
The Android black-hole suppressor never fired: on each sub-3 failure it stored
`untilMs=0`, so the next failure saw `now >= 0` true and reset the counter to 1 —
the 3-consecutive-failure threshold was unreachable. The phone therefore kept
doing full 15 s dials on every black-holed target (Google IPv4, 8.8.8.8:53),
exhausting its TCP thread pool. Symptom in the field: 50 `SELECT_TIMEOUT` to
`192.168.49.1:8080` (PC could not even reach the phone SOCKS5), DNS fail rate
jumped from 1/362 (beta0.2.3) to 114/289 (beta0.3.0), TCP fail 295/506.

**Android**
- Removed the entire black-hole suppressor (fields, entry check, success-clear,
  failure counter). The phone now behaves exactly as beta0.2.3: 15 s
  `connectTimeoutMs`, `singleHandshake`/`deepProbe`, 8080/8082 lanes unchanged.
- Signed with the **same keystore as the main LinkHelm app**
  (`linkhelm_repo/ci/debug.keystore`, alias `androiddebugkey`, SHA-256
  `9E:48:BA:9F:…:C4:B1`). The shipped `LinkHelm-Android-1.1.2-debug.apk` carries
  this exact cert, so exp now shares LinkHelm's developer identity — the
  "developer identity unverified" warning that appeared under the previous
  dedicated `linkhelm-exp-release.keystore` no longer applies (same cert as the
  app that already installs cleanly). versionCode 67, versionName beta0.3.1.

**PC — logging**
- `WarnLog` global throttle tightened from 5 s to 30 s (one anomalous line per
  30 s at most). The periodic stats row still carries every counter, so the
  coarser throttle only trims repeated per-flow noise. With the phone no longer
  thread-starved, SOCKS5 CONNECT / DNS upstream error lines drop to near-zero.
- Version strings bumped beta0.3.0 -> beta0.3.1.

**Verification:** PC `cmake` build clean, self-test 17/17; Android
`assembleRelease` BUILD SUCCESSFUL; `apksigner` confirms Signer#1 SHA-256 of the
exp APK equals the 1.1.2 APK exactly. End-to-end not reproduced here (phone
offline, WinDivert needs admin).

### beta0.3.0 — English-only low-volume logs + independent `linkhelm-exp` host

Field log of beta0.2.3: 6148 lines, ~5000 of them per-flow lifecycle rows for
healthy flows. Flow census: 1275 successful TCP flows, 942 `app closed first`,
204 `phone closed first`, 21 CONNECT failures (all Google IPv4 black holes);
DNS 361 ok / 1 fail with `loopback reset 24` and `recv-fatal 0` — the DNS
receive loop fix holds. 199 flows sent >=300 B and received <100 B (162 on
:8081 with a 26 B + FIN answer, 45 on :443 with 99 B then RST), i.e. target /
phone-uplink silence faithfully relayed by the PC — no packet loss in the
WinDivert reflection path.

**PC — logging**
- All runtime log literals in `exp_engine.cpp` and every `Log()` call in
  `app_main.cpp` are now English regardless of UI language. UI labels keep
  their existing bilingual `TR()` behaviour.
- `FlowLog=0` (default) disables per-flow capture / connect / close / close-
  reason rows. `FlowLog=1` restores them and the full 60+ field stats row.
- Anomalous per-flow rows (CONNECT failure, UDP ASSOCIATE failure, inject
  failure, orphan drop, NAT collision, DNS upstream redirect, session cap,
  no-NAT refusal) go through `WarnLog()` — at most one line per 5 s across all
  detached workers. Counters are never throttled, so trends stay visible.
- Default aggregate row is now one compact line (TCP ok/fail, DNS ok/fail,
  app/phone/zero-byte closes, CONNECT p50/p95, UDP, leak, orphan-drop).
  Cadence is configurable via `StatsIntervalSec` (5..300 s, default 10).
- Fixed a switch that was parsed but never published: `g_flow_log` is now
  copied out of `Impl` in `Start()` exactly once, as detached workers must
  never touch `Impl` after `Stop()`.
- `silent-target` counter separates a normal HTTP short-lived close from a
  request that went unanswered (`up >= 300 B && down < 100 B`), so the 942
  `app-closed` rows no longer look like one uniform failure.

**Phone — independent exp host (new `android/` tree, mainline untouched)**
- `applicationId` / namespace `com.linkhelm.exp`, `versionCode 66`,
  `versionName beta0.3.0`, app label / notification / VPN session renamed to
  `linkhelm-exp`. Installable side by side with the mainline `com.linkhelm.app`.
- Target-level black-hole suppression: after **3 consecutive dial failures**
  to one destination, new CONNECT requests to it are answered immediately with
  `REPLY_CONNECTION_REFUSED` for 60 s, so the PC sends RST at once instead of
  waiting through the 6 s control timeout twice. One later success clears the
  chain. Established sessions are never touched.
- **Deliberately unchanged** (stability contract): `connectTimeoutMs = 15 s`,
  `UpstreamNetworkManager.singleHandshake` / `deepProbe`, the 8080/8082 lane
  logic, and every port-switch / tunnel-rebuild decision. No fast-failover on
  a single failure was introduced.

**Verification (local, honest scope)**
- PC: `cmake --build` clean; self-test 17/17 (beta0.3.0); exe smoke test alive
  after 5 s; binary contains 4x `beta0.3.0` and 0x `beta0.2.3`.
- Phone: `assembleDebug` BUILD SUCCESSFUL; `aapt dump badging` confirms
  `com.linkhelm.exp` / 66 / `beta0.3.0` / label `linkhelm-exp`.
- **Not verified end to end**: the phone (192.168.49.1:8080) was not reachable
  from this machine, and WinDivert NETWORK-layer capture still requires an
  elevated `tests/driver_probe.exe` run. Real-device judgement: default log
  volume should be tens of lines instead of thousands; `app-closed` should
  shrink relative to `silent-target`; Google-IP CONNECT failures should stop
  consuming 12 s each.

### beta0.2.3 — 本地 DNS 接收线程存活加固 + 上游失败可观测（按诊断建议的最小修改范围）

数据源 = beta0.2.2 真机对照测试：透明 HTTPS curl(28) 5004ms、显式 SOCKS5
curl(28) 5007ms、`Resolve-DnsName` 报 10054。结论：手机 SOCKS5 底层可达性与
本地 DNS 接收线程是两处独立故障；本轮**只改 DNS，TCP NAT / WinDivert 反射 /
UDP ASSOCIATE / APK 一律不动**。

**根因预防 — SIO_UDP_CONNRESET 关闭**：Windows UDP socket 会把更早一次
sendto 收到的 ICMP 端口不可达（回包送达时客户端临时端口已关闭）转成
`WSAECONNRESET (10054)` 在**下一次 recvfrom** 上报出。socket 创建后立即用
`WSAIoctl(SIO_UDP_CONNRESET, FALSE)` 关闭该行为（MinGW sysroot 缺该宏时本地
定义，同 SIO_KEEPALIVE_VALS 处理）。

**容错分支（第二道防线）**：`DnsProxyLoop` 原 `n <= 0 → break` 会让 10054
直接杀死接收线程——端口 53 仍绑定但无人应答，全机解析超时（"53 端口有人监听
但解析超时"的源码级解释）。现 10054/10060 计数 `环回重置` + 限频日志（3s）
后继续；其余致命错误计数 `接收致命错` 并带错误码退出（不再静默）。零长度
数据报忽略。

**上游失败分类（`DnsQueryWorker`）**：原来失败只进笼统的 `DNS 失败`。现分
三类计数并入统计行：`DNS 上游连不上`（CONNECT 失败，日志带 ExpSocks5 错误
串，区分手机不可达 vs 解析器超时）、`发送失败`、`接收失败`（均带 WSA 错误码
与池化/新拨链路标注）。日志限频 3s，防止手机断开时 detached worker 刷屏。

统计行新增：`环回重置 / 接收致命错 / DNS 上游连不上 / 发送失败 / 接收失败`；
ENGINE_STOP 最终统计同步加入 DNS 六项。

自测 17/17 PASS（beta0.2.3）。真机判据不变：管理员 driver_probe；DNS 接收
线程存活可通过统计行 `环回重置>0 且 DNS 成功持续增长` 验证。

### beta0.2.2 — NAT 映射生命周期绑定活连接（真机 beta0.2.1 日志实锤的两处引擎缺陷）

数据源 = beta0.2.1 真机 `linkhelm.log` 309 行。数据面已被证明端到端可用：
91 秒长连接、单条 42.8KB 下载、CONNECT p50 98ms、回注 1721/0、DNS 18/0。
用户症状：约 99% 连接「接通后秒关」、Internet 一会儿有一会儿没有。

**缺陷 1（主因）— 30 秒空闲过期删除活连接的 NAT 映射**：
ExpireLoop 把 `last` 超过 30s 的映射无条件删除，但浏览器的 keep-alive 长连接
完全可以 30 秒不发包。日志实锤：审计报「未代理 5-7 条」的目标
（112.46.240.46 / 20.184.175.18 / 150.171.27.11）**恰好就是那几条 91 秒
长连接**——连接还 ESTABLISHED，映射已被拆。后续包走 `!have && !syn`
fail-closed 丢弃（阻断 87），浏览器请求石沉大海 → 杀连接（「应用侧先关闭」）
→ 重开新连接（又被捕获）→ 循环，即「一会儿有一会儿没有」。
修复：映射生命周期跟随其活 TcpSession（对齐 ProxyBridge pb_conntrack 的
连接级生命周期）；会话结束后仍按 retired/age>30s 回收。

**缺陷 2 — listener 回包无映射时原样注入到真实服务器**：
`回环无表项` 分支把 listener 发往 {真实IP,真实端口} 的包**未改写**地注入
出站 = 直连泄漏 + 引发服务器 RST 打回中继 socket（日志 err=10053 写失败）。
修复：改为丢弃 + `孤儿丢弃` 计数（fail-closed，TCP 重传自行恢复）。

另：重试策略保持不变（真机日志证实 5 次重试救回 4 条 CONNECT）。统计行新增
`孤儿丢弃`。

自测 17/17 PASS。边界不变：驱动层需管理员 driver_probe 实测。

### beta0.2.1 — 存活率与缓存强化（真机 beta0.2.0 日志驱动，架构不动）

数据源 = beta0.2.0 真机 `linkhelm.log` 625 行。架构本身已验证：CONNECT p50 70ms、
回注 4157/0、DNS 94/0、UDP 回包 127 丢弃 0、代理端点放行 0。用户反馈：失败率偏高
（成功 104 / 失败 22）、"Internet 一会儿有一会儿没有"、小黑盒不可用。三个补丁：

| # | 补丁 | 依据 |
|---|---|---|
| 1 | **CONNECT 控制超时 4000→6000ms** | 成功 CONNECT p95=3123ms——4s 正好割掉了手机仍在努力完成的流；21 条失败全部死在 4000-4008ms |
| 2 | **瞬态失败单次重试**（仅 `CONNECT_REPLY_MISSING`/`SELECT_TIMEOUT`；`CONNECT_REJECTED`/拒绝是手机终裁不重试） | 同上；小黑盒把一次死连接当会话失败。无闸门，重试只花自己的线程 |
| 3 | **DNS 正缓存（TTL 钳位 30–300s）+ 上游失败时过期回退（TTL+5min）** | 每次解析都要完整 SOCKS5 拨号+交换；手机侧一卡，全机解析同时死 → "Internet 一会儿有一会儿没有" |

统计行新增：`重试/重试成功`、`缓存命中/过期回源`。日志新增 `CONNECT 重试成功`。

自测 **17/17 PASS**（新增 2 条：缓存命中带新事务 ID / 负回复不入缓存）。

### beta0.2.0 — 基于 LinkHelm 1.1.3 基线重建 + ProxyBridge relay 架构（无闸门）

**为什么重建**：0.1.x 分支在真机上始终无法稳定上网，且 patch 叠 patch 已难维护。
beta0.2.0 回到用户验证过的 **1.1.3 源码**（`backup_v1.1.3/`）：

* **保留 1.1.3 全部 UI 成果**：UI 美化、重连治理（10 次封顶、随时可断开）、探测间隔校准、入站表单栅格；连接页 + 共享传输页两页 UI 原样。
* **删除（防冗余）**：`accel_controller`（商店加速整页）、`subscription`、`tun_manager`（Wintun+lwIP 整条数据面）、`relay`、mihomo/hev-socks5-tunnel 依赖。
* **新增**：`exp_engine` + `exp_socks5`（WinDivert 捕获 + SOCKS5，来自 0.1.x 但 relay 层按 ProxyBridge 重写）。
* **单实例互斥量/窗口类改用 exp 专属名**（`LinkHelmExpSingleton`/`LinkHelmExpWindow`）：主线 1.1.3 与 exp 可并存运行，互不阻塞。

**relay 层重写（对照 `refs/proxybridge` pb_relay.c / `exp_ref/wfp-divert-main` divert.cpp 逐行核对）**

| 机制 | 0.1.x（已证坏） | beta0.2.0（ProxyBridge 架构） |
| --- | --- | --- |
| 并发控制 | ConnectGate 排队闸门 + AIMD（0.1.6/0.1.7/0.1.8/0.1.9 四轮真机故障均源于或困于此） | **整体删除**——ProxyBridge/wfp-divert 都无闸门无排队，每 accept 一线程直接阻塞 CONNECT |
| 上游握手 | 重试 2 次 + 三态分类 | **单次阻塞 CONNECT**（4s 控制面超时）；应用自己的 SYN 重传就是天然重试（同 ISN 保映射、异 ISN 新代际） |
| 失败路径 | RST | **立即 RST**（reset_close），应用马上报错并按自己的节奏重试，不再在本地队列里干等 |
| socket 配置 | 1MB 缓冲 | 不变（TCP_NODELAY + 握手期超时→传输期清零 + keepalive 5min/1s），Pump 128KB |
| 保留的正确部分 | ISN 区分重传、underlay 端点匹配（IP+端口）、手机 UDP/53 捕获、DNS 本地代理、retry_at 原子 | 全部保留 |

**验收（本机，一次编译一次运行）**：自测 **15/15 PASS**（闸门策略断言随闸门删除；新增验证「CONNECT 失败 → 15ms 内对应用侧 RST err=10054」与 1KB/1MB 四节点字节精确闭环）。冒烟：标题 `LinkHelm-exp beta0.2.0 (WinDivert, no virtual adapter)`，可与主线 1.1.3 同时运行。

**边界不变**：开发机无管理员权限，WinDivert NETWORK 层真实捕获/回注仍未实测；真机先跑 `tests\driver_probe.exe <手机IP>`（A/B/C 三步）再看数据面。

### beta0.1.9 — TCP 数据面对齐 ProxyBridge（针对 beta0.1.8 真机「TCP 几乎全挂」截图）

beta0.1.8 真机截图的关键事实：CONNECT 全部成功（成功 18 / 失败 1）、**闸门取消 0、排队 0ms**（0.1.7 的死亡螺旋已消失），但 18 条连接合计只有 ↑6.8KB ↓5.3KB，且 CONNECT 时快时慢（53ms / 90ms / 110ms，也有 **3064ms / 3070ms**）。PC 端不排队了，**排队发生在手机端**。

**代码审查结论（对照 `refs/proxybridge` 逐行核对）**

* 引擎反射/NAT/accept/Pump 链路逻辑与 0.1.6 一致，无确定性 bug；**本机四节点闭环测试（app→pump→手机→pump→app）1MB 字节精确、哈希一致**，PC 数据面成立。
* 因此「下行断/应用侧先关闭」的主嫌疑是**手机端承载能力**：并发 CONNECT 与数据转发共用手机一个 Kotlin ProxyServer，8 路并发把它压过载（beta0.1.6 已实证同一手机在低并发下 40–90ms 应答）。

**改动**

| 项 | 0.1.8 | 0.1.9 | 依据 |
| --- | --- | --- | --- |
| 并发上限初始/下限/上限 | 8 / 4 / 12 | **4 / 3 / 8** | 真机 3064ms CONNECT + beta0.1.6 实证；`exp_policy.ini` 显式覆盖不再被 clamp 到上限 |
| Pump 复制缓冲 | 16 KB | **128 KB** | ProxyBridge `one_way_relay`（pb_relay.c:760）用 128KB；16KB 窗口在 Wi-Fi Direct 带宽延迟积下限速 |
| 数据通路验收 | 只测小 HTTP | 新增 **1KB/1MB 双向字节精确闭环**断言（FNV-1a 哈希对比 + 半关闭传播） | 评审要求的 A/B/C/D 四节点证据；CONNECT 成功不等于数据成功 |

**未打包**：本轮只改代码 + 本机实测（19/19 PASS），等真机验证后再发版。请提供 beta0.1.8 运行后的完整 `linkhelm.log`（含统计行 `DNS状态 / SYN重传 / 闸门取消` 新字段）以确认手机端并发假设。

### beta0.1.8 — 按《beta0.1.7 断连、并发拥堵与 Wi-Fi Internet 状态专项诊断》修复 P1

本轮所有结论都来自 beta0.1.7 的**真机 1013 行运行日志**，不是推理。

**日志给出的因果链（决定性证据）**

| 观测 | 含义 |
| --- | --- |
| 前半段 `成功 51 失败 0 闸门取消 0 \| 并发上限 5 \| 排队 p95 0ms` | 数据面本身健康：TCP 捕获、反射、SOCKS5 CONNECT 都正常 |
| 后半段 `并发上限 2 \| 排队 p95 7285ms \| 闸门取消 95 \| 阻断 734` | AIMD 降档到下限 2 → 队列变成 8 秒墙 → 应用 5 秒主动关闭 → 取消累积 → 统计行冻结 |
| `CONNECT reply missing, 18552ms` | 3 次重试 × 6s 控制超时 = **单条流占闸门槽位 18.5 秒**；cap=2 时两条就能饿死全部连接 |
| `代理端点放行 9` | 公网 `:8080` 被按端口误判为 underlay 直连放行 → **未代理出口 = 出口 IP 跳动** |
| `DNS 成功 104 失败 9` | 本地 DNS 代理工作正常，但过滤器的兜底路径实际不可达 |

**按报告 §03–§08 的修复**

| 报告条目 | 修复 |
| --- | --- |
| §03 ConnectGate 负反馈 | 降档改为**需要窗口内重复证据**（10s 内 ≥3 次明确拒绝或 ≥5 次超时）；**重试成功的流永不降档**；下限 2→**4**；取消原因拆为 `GATE_TIMEOUT` 与 `ENGINE_STOP` 两个计数；新增队列长度与当前上限日志 |
| §04 拨号错误误分类 | `select()` 的异常集与真超时分开：新增 `SELECT_TIMEOUT` / `SELECT_ERROR` / `TCP_CONNECT_FAILED` / `CONNECT_REPLY_MISSING` / `CONNECT_REJECTED` / `CONNECT_SEND_FAILED` 六种机器可读前缀；三段计时（TCP / 认证 / CONNECT）+ 本地源 IP 一并记入失败日志 |
| §04 占槽时间 | 控制面超时 6s→**4s**（实测健康值 45–112ms 的 35 倍），重试 3 次→**2 次**；单条流占槽上限 18.5s→**8s** |
| §05 按端口放行 | underlay 排除改为**端点匹配**：TCP 必须「手机 IP + 手机端口」同时命中，UDP 用实际 ASSOCIATE 的 BND 端点识别；**公网 `:8080` 现在正常进入透明转发** |
| §06 DNS/NCSI | 过滤器新增「手机的 UDP/53 必被捕获」子句，兜底路径不再不可达；DNS 分支**前移**到 underlay 排除之前；本地 DNS 未就绪时明确报 `DNS_DEGRADED` 并在统计行显示 `DNS状态 降级`，不再静默当成功。**不改 NCSI 注册表** |
| §07 SYN 重传 | 用 TCP 初始序号(ISN)区分「同一连接重传」与「新连接复用端口」：同 ISN **保留映射**（新计数 `SYN重传`），异 ISN 才换新代际；FIN/RST 退休时置 `retired` 标志 |
| §08 UDP 线程安全 | `UdpSession::retry_at` 由裸 `time_point`（worker 写 / MainLoop 读的真实数据竞争）改为**原子毫秒时间戳** |

**测试**：在 10 条端到端断言基础上补 5 条针对本轮根因的断言（手机 UDP/53 被捕获、
公网 :8080 被捕获、恢复的流不降档、单次饱和不降档、拒绝连接不被误报为 timeout），
**编译一次、只跑一遍**。

### beta0.1.7 — 对照 ProxyBridge / TqkLibrary.WinDivert 的结构性修正 + 测试精简

本轮不再靠推理打补丁，逐条对照两个成熟项目的真实源码。

| 参考出处 | 差异 / 修复 |
| --- | --- |
| `ProxyBridge pb_relay.c:88-92, 640-649, 704-718`；`Tqk TcpRelayServer.cs:105` | 两侧 relay socket 全部 `TCP_NODELAY=1` + 1MB 收发缓冲；数据阶段**清除** `SO_RCVTIMEO/SO_SNDTIMEO`（6s 控制面超时会误杀慢速数据流，对应日志 `↑300B ↓26B 5s`）；`SO_KEEPALIVE` + `SIO_KEEPALIVE_VALS`。`Pump()` 不再重设 1s 超时覆盖上述设置 |
| `ProxyBridge pb_relay.c:575-583, :686` | 代理握手失败时用 `SO_LINGER{1,0}` 发 **RST** 让应用立刻重连，不再等自己的 5s 超时；正常结束仍走 FIN |
| `ProxyBridge relay_pool_start` / `Tqk AcceptLoop Task.Run` | 两者**都没有串行排队闸门**。移除把排队时间计入 CONNECT 耗时的 `t0` 位置错误（日志 `12716ms` 里绝大部分是排队，真实拨号仅 45–99ms）；并发改为自适应 AIMD（初始 8，饱和减半，16 连胜 +1，范围 2–12），等待上限 8s；`排队` 与 `CONNECT` 分别记录 |
| `ProxyBridge ProxyBridge.c:856-871`；`Tqk HoldSynForReconcile` | 新 SYN 清理同端口旧状态；FIN/RST 立即退休 NAT 项；完整五元组碰撞日志；15s 兜底 |
| `ProxyBridge ProxyBridge.c:89-125` | 双向排除手机 SOCKS5 端点（IP 与端口），防止 relay 自代理；filter 第三条改为**全方向**捕获 listener 回包 |
| `ProxyBridge ProxyBridge.c:1153-1215` | 可选「全配置文件入站放行」规则（Public 配置文件会静默丢弃反射 SYN），需提权且默认关闭 |
| 架构评审 §2/§3 | 每条会话输出双向 `EOF/RST/超时/send 失败 + WSA 错误码 + 毫秒时间戳`；UDP 回注成功/失败单独计数；UDP443 / IPv6 / AAAA 三项加可回退开关 |

**测试按要求精简**：删除全部纯函数 / mock / 自证类断言（`exp_selftest.cpp`
1309 行 → 约 420 行，97 项 → **10 项**），只保留跨真实 socket 的端到端断言；
filter 断言改为直接调用产品 `BuildCaptureFilter()`，不再手抄字符串。
全部改完后**编译一次、只跑一遍**：10/10 通过、EXIT=0。关键是新增
`tests/driver_probe.exe`，把「驱动层是否真的工作」交给真机一次性判定，
不再用 mock 通过数冒充可上网。

### beta0.1.6 — 修掉「UDP 回包冻结」与「手机 SOCKS5 并发饱和导致的秒断/卡顿」

**96 项模拟手机自测全部通过（EXIT=0）**，其中 19 项是本轮针对现场日志新增的回归断言。

现场 `linkhelm.log`（beta0.1.5 真机运行）给出的硬证据：

- 网页**已经完整渲染**（CSS/图片齐全），`接管审计 经引擎 13/13 未代理 0`、`回注 成功 846 失败 0` → 反射转发与全量捕获确实工作，问题不再是「完全不通」。
- `UDP 就绪 4 发送 9 回包 8` 之后**回包计数永久冻结，发送继续增长** → UDP 接收线程已死，会话变成只发不收。
- `#28 手机已接通 (10250ms)`、`#29 (3094ms)`、3 条 `CONNECT reply missing` → 8 并发把手机 Kotlin ProxyServer 打爆；而反射握手已先告诉应用「已连接」，应用等不到 TLS 数据就 RST，即「通了又关 / 很卡」。
- 大量 `↑257B ↓183B 0s`、`↑0B ↓0B 0s` 的会话，此前没有任何字段说明是谁先关闭。

| 根因 | 修复 | 验证 |
| --- | --- | --- |
| `ExpSocks5UdpRecv` 对「源端口 ≠ BND.PORT」「ATYP ≠ IPv4」「FRAG ≠ 0」「短包」全部返回 `-1`；`UdpRecvThread` 把 `n<=0` 当作控制连接已断并 **永久退出循环**。手机返回 `BND.ADDR=0.0.0.0` 时实际回包端口常与 BND.PORT 不同，第一个这样的包就杀死了整个会话 | 三态返回码（`>0` 转发 / `0` 超时 / `-1` 真 socket 错误 / `-2..-5` 跳过）；只校验**源 IP**，端口改为 advisory；新增 `ClassifyUdpRecv()` 谓词，只有 `-1` 允许结束线程 | 用与 BND.PORT **不同**的 rogue 端口连发域名 ATYP、FRAG≠0、短包三个异常包，全部为 SKIP；随后一个合法回包仍被正确接收并保留原始远端 IP:端口 |
| RFC 1928 规定 TCP 控制连接关闭即终止 UDP association，但引擎从未检测，会话静默退化为只发不收 | 非阻塞 `ExpSocks5UdpCtrlAlive()`（select + MSG_PEEK 判 FIN）；检测到死亡后标记 `kUdpFailed` 并在 200ms 后由下一个数据包自动重新 ASSOCIATE | socket pair 上真实关闭对端后断言 `CtrlAlive=false`；统计新增 `会话重建` 计数 |
| 手机 SOCKS5 在 8 并发下饱和：单次 CONNECT 3–10s 或干脆不回复，反射握手却已让应用进入 ESTABLISHED | 闸门并发 **8 → 3**（日志显示低并发时同一手机 40–90ms 应答，串行反而更快）、排队 20s→30s；控制面超时 10s→6s、拨号 5s→3s；瞬态失败重试 **2 → 3** 次；NAT 陈旧阈值 60s→15s（避免源端口复用被误判碰撞） | 断言 `cap==3`、第 4 个排队不取消；连续 2 次掉线后第 3 次拨号成功；900ms 慢手机仍成功且延迟被记录 |
| 「接通立马断开」的原因不可观测 | 会话结束日志追加 `[零字节·应用或手机立即关闭 / 手机侧先关闭 / 应用侧先关闭]`；10s 统计新增 `CONNECT p50/p95/最大`、`零字节关闭`、`手机先关`、`应用先关`、`异常跳过`、`会话重建` | 可直接区分是手机侧超时还是应用侧主动放弃 |

**真机验收**：以管理员运行后看 10s 统计行——`UDP 回包` 应随 `UDP 发送` 持续增长（不再冻结）、`异常跳过` 允许非 0 但 `会话重建` 应很快稳定；`CONNECT p95` 应回到百毫秒级；若 `零字节关闭` 仍高，看紧随其后的 `[手机侧先关闭]` 还是 `[应用侧先关闭]` 即可定点。

**边界（如实声明）**：开发机 `WinDivertOpen` 仍返回 `err=5`（无管理员权限），NETWORK 层真实捕获/回注**未在本机实测**；96 项覆盖的是驱动上下游全部产品源码（含用无驱动 helper 验证 filter 语义），不等于「真机已能稳定上网」。

### beta0.1.5 — 针对现场日志的「IP 跳动 / 接通即断 / 未接管 TCP+UDP」实证修复

**77 项模拟手机自测全部通过（EXIT=0）**，且自测直接抓到并修掉了一次由本轮改动引入的回归。

现场 `linkhelm.log` 的硬证据（不是推测）：

- `捕获 698 → 870 → 960` 在 20s 内持续增长，但 `TCP 活动 0`、`↑61.4KB ↓87.8KB`、`DNS 14`、`UDP 全 0` 全部冻结 → 有包在空转，业务计数为零。
- `成功 28 / 失败 4`，4 条 `CONNECT reply missing`；大量会话 `↑257B ↓183B 0s`、`↑1.4KB ↓6.2KB 1s` 即结束（TLS 握手未完成），网页 HTML 加载后 JS/CSS/图片全失败。
- `UDP 就绪 0 握手失败 0 发送 0 回包 0 丢弃 0` → UDP 数据面完全没有证据。
- `未代理泄漏 0` 是**自证循环**：它只统计 WinDivert 交给引擎的包，无法证明没被捕获的包不存在。

| 根因 | 修复 | 验证 |
| --- | --- | --- |
| filter 无 `!impostor`：LAN/IPv6 原样回注的包仍是 outbound，会被同一 handle 再次捕获并再次回注 → 空转占用捕获队列 | 三个 filter 分支全部加 `!impostor`；MainLoop 对 impostor 包只放行一次 | 用 WinDivert 自己的 `EvalFilter` 实测：`0.1.4 filter` 对 impostor 包 = TRUE（循环成立），`0.1.5 filter` = FALSE |
| listener 回包分支被限定 `outbound`，被栈归类为其它方向的回包从未被改写，应用收到错址包后 RST | 第三条 filter 去掉 `outbound`，全方向捕获 `tcp.SrcPort == local_port` | 构造非 outbound + loopback 的回包，`0.1.5` 命中 / `0.1.4` 漏掉 |
| SOCKS5 控制连接只有 connect 超时，`HandshakeAuth` 与 CONNECT 回复 `RecvAll` **无超时**；手机接受 TCP 却不回复时永久占住闸门槽位 | `DialWithTimeout` 补 `SO_RCVTIMEO/SO_SNDTIMEO=10s` | `getsockopt` 断言两者均为 10000ms |
| 24 并发 CONNECT 打爆手机 Kotlin 线程池（`REP=0x05`、`reply missing`），而反射握手已先告诉应用「已连接」 | 闸门并发降到 **8**、等待 8s→20s（排队而非取消）；对 `reply missing/timeout` 类瞬态失败**重试一次**（明确 REP 拒绝不重试） | 闸门 8 槽 + 第 9 个排队 + 释放后放行；手机首次掉线后第二次拨号成功，`connect_retry_ok=1 / socks_ok=1 / live=0` |
| UDP 是否被接管完全没有计数，LAN 放行的包被静默吞掉 | 新增 `udp_capture / udp_lan_pass / udp_proxy` 分类计数并进入 10s 统计 | 统计行可直接看出 UDP 是「局域网放行」还是「交 ASSOCIATE」 |
| 引擎无法自证「是否真的全量接管」 | 新增**独立外部审计**：每 10s 用 `GetExtendedTcpTable` 枚举本机所有 ESTABLISHED 公网 TCP 连接（含 PID），与 NAT 表比对，日志输出「已代理 / 未代理」条数及前 3 条未代理明细 | 只读系统表，不修改任何网络配置 |

**真机验收请直接看这两行**：`接管审计`（未代理必须为 0，否则日志会列出具体 IP:端口/PID，那就是 IP 跳动的物理来源）和 `UDP 捕获/局域网/代理` 三个计数。

**边界如实说明**：开发机 `WinDivertOpen` 仍返回 `err=5`（无管理员权限），NETWORK 层真实捕获与回注注入**未在本机实测**；77 项通过覆盖的是驱动上下游的全部产品源码（含用无驱动 helper 验证 filter 语义），不等于「已经能上网」。

### beta0.1.4 — 按《beta0.1.3 源码诊断与修复方案》一次性修复 F01–F05 及 §4.5/§6/§7

**对照文档逐项落地（60 项模拟手机自测全部通过，EXIT=0）**

| 项 | 修复 | 自测证据 |
| --- | --- | --- |
| F01 | UDP ASSOCIATE 移出抓包线程：会话 `INITIALIZING/READY/FAILED` + 有界首包队列 + 握手中转 worker，失败退避 | 手机握手延迟 1s 时新 TCP CONNECT 仅 16ms 完成；3 个排队首包在 READY 后按序发出 |
| F02 | 统一 `WdInject()` 校验 `BOOL` 与 `sent == len`，记录 `inject_attempt/ok/fail`，低频带 flow_id/err/方向/IfIdx 日志 | 失败与成功注入各一项断言；10s 统计行与 `ENGINE_STOP` 汇总输出计数 |
| F03 | 统一 `SessionFinalize()`（幂等），成功/失败/闸门超时/Stop 都经同一出口，原子句柄所有权 `CloseOnce()` | 强制 100 次 `REP=0x05` 后 `live=0`、`budget=0` |
| F04 | `ConnectGate` 真限流：无名额**不发起 CONNECT**，超时计 `gate_timeout`；`condition_variable` 等待可被 Stop 唤醒 | 饱和闸门拒绝第 3 个（262ms）；Stop 唤醒排队者 154ms |
| F05 | `STARTING/RUNNING/FAULTED/STOPPED` 状态机 + `SetFault()` 回调 UI；`WinDivertRecv` 失败置 FAULTED 并唤醒闸门 | `RUNNING` 与 `FAULTED` 状态名互异断言 |
| §5.1 | WinDivert DNS 兜底把手机网关/私网 DNS 重映射到公网解析器（223.5.5.5），回包仍以原目标为源 | 3 项上游选择断言 |
| §5.3 | 记录原 DNS 模式（DHCP/静态）与服务器顺序；`netsh` 超时强制 `TerminateProcess`，Stop 按原语义恢复 | 引擎恢复逻辑单例化 |
| §6 | DNS 连接池死链首次复用失败 → 关闭、重拨一次、原查询重试；NAT 键碰撞拒绝复用并计数 | 死链场景 `dns_ok=1 / reuse_fail=1 / redial_ok=1`，客户端收到应答 |
| §4.5 | UDP:443 不再静默全局丢弃，改交 UDP ASSOCIATE（失败则 fail-closed 并计数） | 策略谓词断言 |
| §7 | `ENGINE_START/RUNNING/FAULT/STOP`、`ENGINE_ROUTE_SNAPSHOT`（含旧虚拟适配器只读告警）、`ENGINE_BASELINE_WARN`、每 10s 聚合指标、最终统计 | 旧适配器检测确定性断言（本机实测「检测到，未改动」） |

**测试说明**：`tests/exp_selftest.cpp` 直接 `#include` 产品 `exp_engine.cpp`，
测的是发布版同一份源码；内嵌模拟手机（RFC1929 / CONNECT / UDP ASSOCIATE /
DNS-over-TCP）。修正了自测里用真实 `connect(127.0.0.1:1)` 模拟拒绝导致每次约
1s、100 次串行看似「卡死」的问题——改为手机直接回 `REP=0x05`。

**仍未验证**：`WinDivertOpen` 在开发机返回 `err=5`（无管理员权限），NETWORK 层
真实捕获/注入必须在使用者机器上以管理员权限验收；Android Host 的真实 UDP
ASSOCIATE 公网回包能力同样不在本机自测范围内。

### beta0.1.3 — 真正的全量代理（消除出口 IP 跳动）+ 本机模拟手机实测

**根因（本机实测 + WinDivert 求值器实证）**：0.1.2 只代理了一部分流量，
不是"代理没通"。本机有两条默认路由（`WLAN → 192.168.49.1` metric 0、
`LinkHelm-IwIP → 10.0.0.1` metric 1）且 `curl --noproxy` 直连百度返回 200，
所以任何未被捕获的流量都会直连成功 → 出口 IP 在手机与本机网络之间跳。
0.1.2 的 filter 是 `... and (tcp or udp)`（隐含只匹配 IPv4），
**每一个 IPv6 包都绕过引擎直连**；`WinDivertHelperEvalFilter` 实测：
旧 filter 对 IPv6 包 = FALSE，新 filter = TRUE。

- **删除 /1 半路由**：0.1.2 日志实证 `半默认路由添加失败（err 0）`，
  但 WinDivert 仍捕获 30+ TCP → 半路由既不必要又污染路由表。
  beta0.1.3 **完全不修改系统路由表**，只做只读诊断（打印出口/手机链路 ifIndex）。
- **全量接管 / fail-closed**：filter 纳入 `ipv6`；公网 IPv6 出站丢弃 +
  本地 DNS 代理抑制 AAAA（NOERROR + 0 answers）迫使回退 IPv4；
  "未捕获到 SYN 的存量连接"由放行改为丢弃；删除 UDP 所有 fail-open 放行分支。
  每 10s 统计新增 `未代理泄漏（应为 0）`，可自行验证是否真正全量。
- **消除 IP 跳动**：`NatEntry` 记录首包 `app_ip`，反射与回包注入全部固定到该地址，
  不再用 `iph->SrcAddr`（listener 绑 `INADDR_ANY`，双默认路由下会漂到 10.0.0.2）。
- **SOCKS5 并发闸门**（上限 24）：0.1.2 瞬间 30+ CONNECT 打爆手机 ProxyServer
  （日志 `REP=0x5`、3109/5137ms），而反射握手已先告诉应用"已连接" →
  5s 后断开，即"接通立马就结束"。
- **Stop 不再早退**：DNS 改写发生在 `running=true` 之前，启动中途失败时
  0.1.2 会永久留下指向 127.0.0.1:53 的死 DNS。现在任何情况下都执行幂等清理。

**本机模拟手机实测（31/31 通过，`tests/exp_selftest.cpp`）**：
测试程序直接 `#include src/exp_engine.cpp`，测的是发布版同一份源码；
内嵌模拟 LinkHelm Host（RFC1929 认证 / CONNECT / UDP ASSOCIATE / DNS-over-TCP）。
覆盖：SOCKS5 认证与错误密码拒绝、真实 HTTP 往返（HTTP/1.0 200 OK）、
本地 DNS 代理 A 查询中继、AAAA 抑制、UDP ASSOCIATE 双向回包与源端点恢复、
**产品 `TcpWorker` 会话泵真实 HTTP 往返**、全量策略纯逻辑、
WinDivert filter 编译与逐包求值（新 filter 捕获 IPv6 / 旧 filter 漏 IPv6 /
手机端点排除防循环）。

**未覆盖（必须真机验证）**：`WinDivertOpen` 在本机返回 `err=5`
（ERROR_ACCESS_DENIED，无管理员权限），因此 **驱动层的包捕获与回包注入
未在本机实测**。请以管理员身份运行，并按 README 的验收清单核对日志。

### beta0.1.2 — DNS 彻底修复（本地 DNS 代理 + 适配器识别修正）

- **根因定位**：Wi-Fi Direct 由手机 DHCP 下发的 DNS 服务器即手机自身
  （192.168.49.1），但手机是 SOCKS5 代理而非 DNS 解析器。旧版 `BackupAdapterDns`
  按"网卡自身 unicast IP"匹配适配器，永远匹配不到手机网关，导致 DNS 从未被改写、
  查询被 `IsBypassDst`（192.168/16）放行直连手机后被丢弃 →
  `DNS_PROBE_FINISHED_BAD_CONFIG`、NCSI 显示"无法访问 Internet"。
- **本地 DNS 代理（中间层）**：新增进程内 UDP DNS 服务器 `127.0.0.1:53`，把手机
  适配器 DNS 指向回环；每个查询经 SOCKS5（TCP DNS，RFC 7766）中继到公网解析器
  （223.5.5.5，8.8.8.8 兜底），并维护 SOCKS5 连接池摊薄 CONNECT 开销。回环流量
  不被 WinDivert 捕获，彻底消除注入竞态，不依赖手机提供 DNS。
- **适配器识别修正**：`BackupAdapterDns` 改为按"默认网关 == 手机 IP"匹配，确保
  DNS 改写与断开恢复作用在正确的适配器上。
- **保留**：TCP 反射与 UDP ASSOCIATE（实测均可用）；版本串统一升至 beta0.1.2。

### beta0.1.1 — 路由黑洞与 DNS 专项修复（对照《下一阶段优化与透明代理工程路线》G0-G3）

- **G0 出口预检**：启动时先经手机 SOCKS5 做一次真实 CONNECT（223.5.5.5:53），
  手机不能出公网则拒绝启动捕获，杜绝"只抓包不通"的软黑洞。
- **DNS-over-TCP 中继**：UDP 53 查询经 SOCKS5 CONNECT 以 TCP DNS（RFC 7766）
  中继到原 DNS 服务器，**不依赖手机 UDP ASSOCIATE**；适配器无可用公网 DNS 时
  临时设置 223.5.5.5/114.114.114.114（断开自动恢复）。NCSI 探测随之打通，
  实际 Wi-Fi 适配器可显示"Internet 访问"。
- **QUIC/UDP fail-closed**：仅手机上行时，UDP 443（QUIC）直接丢弃（浏览器秒回
  退 TCP），其余 UDP 在 ASSOCIATE 失败时丢弃而非放行进黑洞；存在其它上行时
  保持 fail-open。
- **路由黑洞清扫**：启动时删除强杀残留的 NETMGMT 0/1+128/1 半路由；
  AddHalfRoute 修复缺失 dwForwardIfIndex 的 bug。
- **半关闭修复**：TCP 泵一端 FIN 只 shutdown(SD_SEND) 对端，不再误杀反向数据。
- **结构化会话日志**：#flow_id 捕获→手机接通(ms)→结束(↑/↓字节, 时长)；
  每 10s 聚合统计（TCP 成功/失败、DNS 成功/失败、UDP 丢弃、总字节）。

### beta0.1.0
