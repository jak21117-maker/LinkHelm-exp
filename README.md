# LinkHelm-exp

**beta0.1.0 — 实验版：无虚拟网卡透明上网（WinDivert + SOCKS5）**

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
4. 代理失败**fail-open 原样放行**并记录日志，绝不静默吞包。

## ROUTE-00 关卡（路由黑洞处理）

WinDivert 在 NETWORK 层只能截获 Windows **实际发出的**包。若系统没有任何
可达外网的路由，连接在更早阶段就失败，无包可截。引擎 Start 时：

- 用 `GetBestRoute` 检查到手机的路由与到 1.1.1.1 的路由是否同接口；
- 不同（即外网流量不经手机链路）→ 添加 `0.0.0.0/1 + 128.0.0.0/1` 经手机
  IP（仅两条半路由，**不碰真正的默认路由条目**），Stop 时精确删除；
- 相同 → 不做任何路由变更。

由此 NCSI（msftconnecttest）探测同样被截获并经手机出站，真实 Wi-Fi Direct
适配器将显示"Internet 访问"。

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

- IPv6 不在本期范围（过滤器只匹配 IPv4；IPv6 流量原样放行）；
- IP 分片报文（非首片）无法匹配 NAT 表，将原样直发（LAN MTU 1500 下罕见）；
- 每条 TCP 连接 2 个泵线程（wfp-divert 同款），并发上限 400，IOCP 化留待后续；
- 已知理论竞态：app 端口复用导致的 NAT 键碰撞概率极低，接受（同 wfp-divert）；
- 多设备网关（FORWARD+NAT）按方案文档为独立专题（G6），不在本仓库承诺。

## 目录

```
backup_v1.1.0_src/   主线 v1.1.0 C++ 源码完整备份（未改动）
src/                 exp 工作源码（app_main 删减 + exp_engine/exp_socks5 新增）
wfp-divert-ref/      wfp-divert 源码快照（MIT，学习参考）
windivert/           WinDivert 头文件与运行件
docs/                架构文档（本 README 即 docs/ARCHITECTURE 摘要）
```

## Changelog

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
