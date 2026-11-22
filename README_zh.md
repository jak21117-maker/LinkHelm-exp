# LinkHelm-exp

**v0.5.0 —— beta0.4.0 基线以来的全部演进：应用级 DNS 栈、对反作弊友好的透明传输、手机存活看门狗**

> ### 自 beta0.4.0 以来的更新（汇总）
> - **DNS 栈，完全在应用内部** —— WinDivert 拦截 UDP:53 并经 SOCKS5 TCP DNS 转发；系统/网卡 DNS 设置全程不改、退出无需还原。在此之上叠加了应用内应答缓存（TTL 限幅 30–300 秒，负面应答不缓存）与最多 8 条健康 SOCKS5 长连接的连接池（含空闲重拨）—— 共同解决了连接洪泛打满手机导致的时快时慢与 DNS/CONNECT 大量超时。
> - **对反作弊友好的透明传输** —— 受保护/反作弊进程与其它所有程序走完全相同的 relay：无 DLL 注入、无系统代理、无虚拟网卡、无按进程的本地回环监听，流量特征与普通流量无异（同一出口、同一 SOCKS5 封装、无按流标记）。可选的按进程分流经 `RelayMode` 配置（`0`=全 relay 默认，`1`/`2`=分流模式），进程名单可用 `linkhelm_direct_exes.txt` 扩展。
> - **手机存活看门狗（v0.5.0 新增）** —— PC 端每 10 秒用一次真实 SOCKS5 CONNECT 到公网 DNS 探测手机（`tcp=0` 无活跃流时同样探测）。连续 3 次失败——手机 App 被关闭、走远失去信号或蜂窝断网——即自动断开连接，UI 复位为"未连接"（不自动重连，由你手动恢复）。
> - **Steam++ / Watt Toolkit 共存** —— Steam++ 的 `127.0.0.1` 回环段永不被捕获，其上游与其它流量一样走同一条透明 relay，系统代理模式与 Hosts 模式下都能与 LinkHelm 并存。
> - **可选短握手** —— `FastHandshake=1` 可把 SOCKS5 greeting＋认证＋CONNECT 合并为一次发送（对手机端定长字节解析器协议安全）；默认关闭。
> - **减少日志刷屏** —— 周期统计间隔 30 秒 → 60 秒；逐流失败噪音进一步下降。
> - **Bugfix** —— 修正开机自启动注册表路径的转义错误。
>
> 详见 [RELEASE_NOTES.md](RELEASE_NOTES.md)。

**基线：beta0.4.0 —— 实验分支：无虚拟网卡的透明代理（WinDivert + SOCKS5），基于 LinkHelm 1.1.3 基线重建**

本仓库是 LinkHelm 的独立实验分支。源码基线为 **v1.1.3**（`backup_v1.1.3/`：界面打磨、重连治理、ICS 共享与文件传输原样保留）；移除 Wintun+lwIP 与商店加速，数据面替换为 WinDivert+SOCKS5（relay 层对齐 ProxyBridge 架构）。

目标：**无 TUN/虚拟网卡、不改系统默认路由** —— 让 Windows 原生应用透明地经手机（Wi-Fi Direct 链路上的 SOCKS5 Host）访问互联网，同时**真实 Wi-Fi 网卡保持"已连接 Internet"显示**（NCSI 探测走同一条捕获路径；不劫持注册表）。

> English documentation: see [README.md](README.md). 本文件为中文版。

## 与主线（LinkHelm 1.1.3）的差异

| 项目 | 主线 LinkHelm 1.1.3 | LinkHelm-exp v0.5.0 |
|---|---|---|
| 数据面 | Wintun (TUN) → hev-socks5-tunnel (lwIP) → SOCKS5 | WinDivert 拦截 → 本地 TCP 反射桥 / SOCKS5 UDP ASSOCIATE → SOCKS5 |
| 虚拟网卡 | LinkHelm-IwIP（lwIP 网卡） | **无** |
| 默认路由 | 0.0.0.0/1 + 128.0.0.0/1 绑定 TUN | 不改路由；仅在没有可用出口路由时经手机加半路由，断开即删 |
| 商店加速 | 有（mihomo） | **移除** |
| 连接页 / 共享传输页 | 保留 | **原样保留**（ICS 共享、文件传输助手、UDP 检测） |
| 手机端 | SOCKS5 Host（RFC 1929 认证） | 100% 复用，零改动 |
| 管理员权限 | 正常使用不需要 | **必需**（加载 WinDivert64.sys 驱动） |
| 运行日志 | 双语界面文案 | 运行日志纯英文；界面文案保留双语 `TR()` |

## 数据路径

```
TCP:  应用 → Windows 原生协议栈 → WinDivert 捕获 SYN/流
      → 地址反射到本地监听器（中间内核连接：
        orig_ip:app_port ↔ app_ip:local_port）
      → 监听器 accept → RFC 1929 认证 → SOCKS5 CONNECT(原始目标)
      → 手机 → 互联网
UDP:  应用数据报 → WinDivert 捕获 → 按源端点建立会话
      → RFC 1929 + UDP ASSOCIATE
      → relay 封装（RSV/FRAG=0, ATYP=IPv4）→ 手机 relay
      → 回包端点校验 → 重建 IP/UDP 头
      → WinDivert inbound 回注
```

TCP 反射方案受 okatodev/wfp-divert（MIT，源码快照在 `wfp-divert-ref/`）启发，并修复了架构研究时发现的 P0 问题：

1. SOCKS5 客户端实现 **0x02 用户名/密码认证**（wfp-divert 只有 0x00）；
2. UDP ASSOCIATE 握手**不持全局锁**（慢握手不阻塞其它 UDP 流）；
3. 每个 UDP 回包**校验 relay 端点**；FRAG≠0 直接丢弃（不出静默坏包）；
4. 代理失败一律 **fail-closed 丢弃**并计数/记日志 —— 绝不原样放行（早期 fail-open 行为正是出口 IP 跳动的根源）。

## 路由策略（不改路由表）

**引擎不碰系统路由表。** 早期迭代曾尝试 `0.0.0.0/1 + 128.0.0.0/1` 半路由；真机日志显示"半默认路由添加失败 err 0"而 WinDivert 仍捕获 30+ TCP —— 说明本来就有可用路由，半路由既多余、强杀后还会留下真实路由黑洞。

启动时引擎只做**只读诊断**：`GetBestRoute` 比较手机链路出口接口与 1.1.1.1，打印 `ENGINE_ROUTE_SNAPSHOT`（含是否检测到遗留 `LinkHelm-IwIP` / Wintun 虚拟网卡，附 `ENGINE_BASELINE_WARN`）。EXP **不**禁用、改名、重路由任何网卡。全部公网 TCP/UDP 由 WinDivert NETWORK 层接管；NCSI 探测共享同一捕获路径。

## 构建

```
cmake -S . -B build -G "MinGW Makefiles" ^
      -DCMAKE_CXX_COMPILER=../toolchain/mingw64/bin/g++.exe
cmake --build build --parallel
```

产物 `build/LinkHelmExp.exe`（静态链接 libgcc/libstdc++/winpthread，无运行时 DLL 依赖）。WinDivert 经 `LoadLibrary` 加载，无需导入库。

## 部署（dist/）

```
LinkHelmExp.exe            主程序
WinDivert.dll              LGPL-2.1/GPL-2.0 双许可（reqrypt.org）
WinDivert64.sys            WinDivert 内核驱动（必须与 DLL 同目录）
engine/linkhelm_ics.exe    ICS 共享模块（与主线同源构建）
```

运行需要**管理员权限**（加载 WinDivert64.sys）。仅支持 Windows 10/11 x64。首次运行会安装 WinDivert 服务，程序退出时自动卸载。

## 实验边界（如实声明）

- **驱动层本机未实测**：开发机 `WinDivertOpen` 返回 `err=5`（无管理员）。包内附 `tests/driver_probe.exe`：**以管理员运行一次性判定**"真实出站包能否被捕获"与"注入的入站 UDP 包能否被普通 socket 收到"（后者即 UDP 回环）。未提权时明确打印 `SKIP / NOT PROVEN` —— 不算通过。
- `tests/exp_selftest.cpp` 只保留跨真实 socket 的端到端断言；纯函数/自证类断言按要求移除。**断言数量不代表能上网** —— 驱动层只有 `driver_probe.exe` 有裁判权。
- IPv6 全局单播出口**明确拦截并计数**（手机 SOCKS5 无 IPv6 能力）；本地链路本地/多播放行。DNS 代理对 AAAA 返回 NOERROR 空应答。
- UDP:443 / IPv6 / AAAA 策略由可选的 `exp_policy.ini` 控制；**默认值为真机验证过的稳定值**；模板见 `exp_policy.ini.example`。一次只改一项，保留日志。
- NAT 键冲突（不同本机地址/目标端口复用同一 `{dst_ip, src_port}`）**拒绝复用并计数**；FIN/RST 立即注销映射（对齐 ProxyBridge conntrack），另有 15 秒静默兜底回收。
- IP 分片包（非首片）无法匹配 NAT 表，按策略丢弃（LAN MTU 1500 下罕见）。
- 每条 TCP 连接 2 个泵线程；并发默认**自适应 AIMD**（初始 8，手机饱和减半，连续 16 次成功 +1，范围 2–12）；`ConnectConcurrency` 可钉死做 A/B 实验。
- 多设备网关（FORWARD+NAT）按设计文档属独立课题，本仓库不承诺。

## 目录

```
backup_v1.1.3_src/   主线 v1.1.3 C++ 源码完整未改动备份
src/                 exp 工作源码（裁剪版 app_main + 新增 exp_engine/exp_socks5）
wfp-divert-ref/      wfp-divert 源码快照（MIT，研究参考）
windivert/           WinDivert 头文件与运行时文件
docs/                架构文档（本 README 是 docs/ARCHITECTURE 的摘要）
```

## 真机诊断：先跑 `socks5_probe.exe`（无需管理员）

手机 LinkHelm Host 不变、PC 连上 Wi-Fi Direct 网络后，运行随包的**只读探测**：

```
tests\socks5_probe.exe 192.168.49.1 8080 <账号> <密码>
```

不改路由/网卡/DNS/注册表，不加载 WinDivert 驱动，只打印：认证与 TCP CONNECT 是否成功、`UDP ASSOCIATE` 返回的 `BND.ADDR/BND.PORT`、实际 UDP 回包源端口与 ATYP/FRAG、生产函数 `ExpSocks5UdpRecv` 的返回码。凭据仅经命令行传入 —— 不打印、不落日志。

一次输出即可区分三类问题：手机根本没开 UDP relay（ASSOCIATE 失败或 4 秒无应答）、手机回包端口与 `BND.PORT` 不一致（早期版本会永久杀死接收线程；当前版本已兼容）、回包 ATYP/FRAG 不标准。这正是架构评审反复强调的未知项 —— "用实测证明，不要假设手机 SOCKS5 完全标准"。

## 真机验收第一步：`driver_probe.exe`（需管理员）

```
以管理员运行  tests\driver_probe.exe 192.168.49.1
```

用 RFC 5737 文档地址 `203.0.113.7` 与极窄过滤器做三件事：
**A** 验证真实出站 UDP 包能被 WinDivert 捕获；**B** 注入入站 UDP 包并验证普通 UDP socket 能收到（B 即引擎 `UdpRecvThread` 依赖的"回环"）；**C** 用**产品实际安装的过滤串**评估，确认"手机 UDP/53 被捕获"（DNS 兜底路径可达 —— 直接关系 Wi-Fi Internet 图标是否稳定）。

不改路由/DNS/防火墙/注册表；退出码 `0=WORKING`、`1=BROKEN`、`2=未提权（未验证）`。**B2 失败定位**：`WinDivertSend` 成功但 socket 收不到时，问题在 `IfIdx` / 防火墙 / 网络配置文件 —— 继续改 SOCKS5 代码徒劳。**C2 失败**说明本地过滤串与 DNS 兜底不一致，Wi-Fi Internet 图标会间歇闪烁。

另附 `tests/egress_compare.ps1`（只读，5 轮对比显式 SOCKS5 出口 vs 透明出口），用于区分"Windows 流量绕过"与"手机蜂窝 CGNAT 轮换"。

## Changelog（变更日志）

### v0.5.0 — 自 beta0.4.0 以来的汇总变更

**DNS（PC，完全应用内；系统 DNS 不动）**
- WinDivert 拦截 UDP:53 并经 SOCKS5 TCP DNS 转发；不碰 netsh、不改网卡、无需还原。`SystemDnsProxy=1` 可恢复旧的回环代理+netsh 行为。
- 应用内 DNS 应答缓存（TTL 限幅 30–300 秒、改写事务 ID、负面应答不缓存、重连清空）。
- DNS 连接池：最多 8 条健康 SOCKS5 长连接跨查询复用，含空闲失效重拨 —— 消除每查询一连接的洪泛打满手机导致的 DNS/CONNECT 超时。

**对反作弊友好的传输（PC）**
- 所有进程 —— 包括反作弊/受保护进程 —— 走完全相同的 relay：只有内核级捕获与反射，无 DLL 注入、无系统代理、无虚拟网卡、无按流标记；线上流量特征与普通 relay 流量无异。
- `RelayMode` 策略：`0`（默认）全 relay；`1`/`2` 可选按进程分流；`linkhelm_direct_exes.txt` 扩展进程名单。

**手机存活看门狗（PC，新增）**
- 独立监视线程每 10 秒用一次真实 SOCKS5 CONNECT 到公网 DNS 探测 —— 覆盖"App 被关""走远/无信号""蜂窝断网"三种场景，`tcp=0`（无活跃流）时同样探测。
- 连续 3 次失败即自动断开；UI 复位为"未连接"，不自动重连（手动重连即可恢复）。`PhoneLiveness=0` 可关闭；`ProbeIntervalSec` / `ProbeStrikes` 可调。

**其它（PC）**
- Steam++ / Watt Toolkit 共存：回环流量永不被捕获；加速器上游走同一条透明 relay（系统代理与 Hosts 模式均可用）。
- 可选流水线 SOCKS5 握手（`FastHandshake=1`，默认关闭）—— greeting＋认证＋CONNECT 合并为一次发送；对手机端定长读取协议安全。
- 减少日志：周期统计 30 秒 → 60 秒。
- Bugfix：修正开机自启动注册表路径的转义错误。

**Android**
- versionName v0.5.0，versionCode 78。手机端 SOCKS5 Host 数据面与主线宿主应用一致未改；APK 由 CI 用与主线相同的 keystore 签名。

**验证（如实范围）**
- PC：干净编译；自测 17/17；路由/存活策略专项 16/16；真机 SOCKS5 CONNECT + UDP ASSOCIATE 探测与存活探测均对在线手机实测（在线 → ONLINE，不可路由地址 → OFFLINE）。
- WinDivert 驱动层本身只由目标 PC 上的 `tests/driver_probe.exe`（需管理员）判定。

### beta0.4.0 — 基线 tag：修复"错杀好链接"（控制面超时 15 秒）+ 删除冗余重试 + 日志再减量 + 共享签名身份

**"偶尔错杀好链接"的根因（真机日志实锤）。**
PC 控制面在 SOCKS5 控制 socket 上设 `SO_RCVTIMEO = 6000 ms`，而手机上游拨号预算是 `connectTimeoutMs = 15000 ms`（`ProxyServer.kt`）。一段 6~15 秒才完成的慢拨号，会在第 6 秒被 PC 精确 RST 掉，报 `CONNECT_REPLY_MISSING [WSA 10060]` —— 即 PC 杀死了一条手机本来能拨通的连接。这是真机日志里 `TCP fail` 高企的主要来源。

**PC — 控制面时序**
- `exp_socks5.cpp`（`DialWithTimeout`）控制面接收超时 `6000 ms → 15000 ms`，对齐手机 15 秒上游拨号预算。应用自身的 SYN 重传就是天然重试，单次阻塞拨号即可覆盖手机完整拨号窗口。
- 删除 `exp_engine.cpp` `TcpWorker` 里冗余的 2 次重试循环。单次阻塞拨号已足够；原先的重试只会把我们正要拯救的慢链路占槽时间翻倍。

**PC — 日志**
- `StatsIntervalSec` 默认保持 30 秒（30 秒 `WarnLog` 限频保留）。15 秒控制预算下，慢但有效的拨号不再被计为失败，逐流失败噪音进一步下降。

**Android — 签名**
- 本地构建 UNSIGNED，由 CI 用**与主 LinkHelm 相同的 keystore**（`linkhelm_repo/ci/debug.keystore`，别名 `androiddebugkey`，SHA-256 `9E:48:BA:9F:…:C4:B1`）签名。共享 LinkHelm 开发者身份，"开发者身份未验证"警告不再适用。versionCode 68，versionName beta0.4.0。

**验证（本机，如实范围）**
- PC：`cmake --build` 干净通过；自测 17/17（beta0.4.0）；exe 内含 4 处 `beta0.4.0`。
- Android：`assembleRelease` BUILD SUCCESSFUL；`apksigner` 确认 Signer#1 SHA-256 与 1.1.3 APK 完全一致。
- 端到端本机未复现（手机离线、WinDivert 需管理员）。

> 更早的内部迭代版本从未公开发布，此处有意不展开说明 —— 详见 git 历史。

---

## 支持我的研究

LinkHelm-exp 是 LinkHelm 的实验分支，开发与维护都来自作者的个人时间。如果它帮你省了心，欢迎完全自愿的打赏 —— **没有任何付费功能**，也没有任何内容被捐赠门槛挡住。

**支持我的研究，打赏完全自愿，没有付费功能。**

<!-- 赞赏二维码：sponsor_qr.png 与本 README 同目录分发 -->
<img src="sponsor_qr.png" alt="赞赏支持我的研究" width="240"/>

---

## 致谢

LinkHelm-exp 是 [LinkHelm](https://github.com/jak21117-maker/LinkHelm) 的实验分支。数据面基于以下开源项目研究、改造并落地：

- **WinDivert**（basil00，LGPL-2.1/GPL-2.0 双许可）—— 本分支赖以运行的内核级捕获/回注基础：https://reqrypt.org/windivert.html · https://github.com/basil00/WinDivert
- **okatodev/wfp-divert**（MIT）—— TCP 反射方案来源；源码快照随仓库分发于 `wfp-divert-ref/`：https://github.com/okatodev/wfp-divert
- **InterceptSuite/ProxyBridge**（MIT）—— relay 架构参考：TCP NAT/conntrack 生命周期、按真实端点的 underlay 排除、自适应并发：https://github.com/InterceptSuite/ProxyBridge

手机端 SOCKS5 Host 是主线 LinkHelm 宿主应用 —— 100% 未改动。

第三方组件保留其各自许可证 —— 见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。按"原样"提供，不附带任何担保。
