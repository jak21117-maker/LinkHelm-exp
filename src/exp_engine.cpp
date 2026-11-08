// LinkHelm-exp — WinDivert + SOCKS5 transparent data plane implementation.
// See exp_engine.h for the architecture summary.
//
// Provenance: the TCP "address reflection" scheme follows okatodev/wfp-divert
// (MIT, vendored under wfp-divert-ref/) with the plan document's P0 fixes:
//   - RFC 1929 username/password auth (method 0x02)
//   - no global lock held across the UDP ASSOCIATE handshake
//   - relay endpoint validation on every UDP reply
//   - fail-CLOSED: a packet we cannot proxy is dropped, never reinjected
//     unproxied (beta0.1.3+; fail-open caused the egress-IP flapping).
// WinDivert itself is loaded dynamically (LoadLibrary) — no import lib.
#include "exp_engine.h"

#include "exp_socks5.h"

// NOTE: all libstdc++ headers MUST come before the Windows/SAL headers —
// sal.h `#define __out` (and friends) poisons STL internals otherwise.
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include "windivert.h"

namespace linkhelm {

namespace {

// ---------------------------------------------------------------- WinDivert
// Function pointer table, resolved at Start from WinDivert.dll next to the
// exe. Keeping this dynamic avoids MinGW/MSVC import-lib friction entirely.
typedef HANDLE (*WD_Open)(const char*, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL (*WD_Close)(HANDLE);
typedef BOOL (*WD_Recv)(HANDLE, PVOID, UINT, UINT*, WINDIVERT_ADDRESS*);
typedef BOOL (*WD_Send)(HANDLE, const PVOID, UINT, UINT*,
                        const WINDIVERT_ADDRESS*);
typedef void (*WD_Parse)(const PVOID, UINT, WINDIVERT_IPHDR**,
                         WINDIVERT_IPV6HDR**, UINT8*, WINDIVERT_ICMPHDR**,
                         WINDIVERT_ICMPV6HDR**, WINDIVERT_TCPHDR**,
                         WINDIVERT_UDPHDR**, PVOID*, UINT*, PVOID*, UINT*);
typedef UINT (*WD_Checksums)(PVOID, UINT, WINDIVERT_ADDRESS*, UINT64);

struct WD {
    HMODULE dll = nullptr;
    WD_Open open = nullptr;
    WD_Close close = nullptr;
    WD_Recv recv = nullptr;
    WD_Send send = nullptr;
    WD_Parse parse = nullptr;
    WD_Checksums checksums = nullptr;
    bool ok() const { return dll && open && close && recv && send &&
                             parse && checksums; }
};

bool LoadWinDivert(WD* wd, std::wstring* err) {
    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring dir(self);
    size_t sl = dir.rfind(L'\\');
    if (sl != std::wstring::npos) dir = dir.substr(0, sl);
    std::wstring path = dir + L"\\WinDivert.dll";
    wd->dll = LoadLibraryW(path.c_str());
    if (!wd->dll) {
        if (err)
            *err = L"WinDivert.dll 加载失败（需与 exe 同目录）: " + path;
        return false;
    }
    wd->open = reinterpret_cast<WD_Open>(
        GetProcAddress(wd->dll, "WinDivertOpen"));
    wd->close = reinterpret_cast<WD_Close>(
        GetProcAddress(wd->dll, "WinDivertClose"));
    wd->recv = reinterpret_cast<WD_Recv>(
        GetProcAddress(wd->dll, "WinDivertRecv"));
    wd->send = reinterpret_cast<WD_Send>(
        GetProcAddress(wd->dll, "WinDivertSend"));
    wd->parse = reinterpret_cast<WD_Parse>(
        GetProcAddress(wd->dll, "WinDivertHelperParsePacket"));
    wd->checksums = reinterpret_cast<WD_Checksums>(
        GetProcAddress(wd->dll, "WinDivertHelperCalcChecksums"));
    if (!wd->ok()) {
        if (err) *err = L"WinDivert.dll 缺少必要的导出函数";
        FreeLibrary(wd->dll);
        wd->dll = nullptr;
        return false;
    }
    return true;
}

// ----------------------------------------------------------------- helpers
std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), out.data(), n,
                        nullptr, nullptr);
    return out;
}

std::wstring FromUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

uint32_t IpToNet(const std::string& ip) {  // network order
    uint32_t v = 0;
    inet_pton(AF_INET, ip.c_str(), &v);
    return v;
}

bool IsBypassDst(uint32_t dst_net) {
    uint32_t h = ntohl(dst_net);
    uint8_t o1 = (uint8_t)(h >> 24), o2 = (uint8_t)(h >> 16);
    if (o1 == 0 || o1 == 10 || o1 == 127) return true;             // 0/8, 10/8, 127/8
    if (o1 == 169 && o2 == 254) return true;                       // link-local
    if (o1 == 172 && o2 >= 16 && o2 <= 31) return true;            // 172.16/12
    if (o1 == 192 && o2 == 168) return true;                       // 192.168/16
    if (o1 >= 224) return true;                                    // multicast + reserved
    return false;
}

std::wstring IpW(uint32_t net) {
    in_addr a;
    a.s_addr = net;
    char b[32] = "";
    inet_ntop(AF_INET, &a, b, sizeof(b));
    return FromUtf8(b);
}

// IPv6 addresses that must stay on the LAN and are therefore safe to pass
// through (the phone's SOCKS5 only supports ATYP=IPv4). Everything else is
// dropped so the OS falls back to IPv4 instead of leaking onto the native
// uplink or dying in a black hole.
bool IsIpv6Local(const UINT32 a[4]) {
    uint32_t w0 = ntohl(a[0]);
    uint8_t b0 = (uint8_t)(w0 >> 24);
    uint8_t b1 = (uint8_t)(w0 >> 16);
    if (b0 == 0xff) return true;                          // ff00::/8 multicast
    if (b0 == 0xfe && (b1 & 0xc0) == 0x80) return true;   // fe80::/10 link-local
    if (a[0] == 0 && a[1] == 0 && a[2] == 0 &&
        (a[3] == 0 || a[3] == htonl(1))) return true;      // :: and ::1
    if (a[0] == 0 && a[1] == 0 && a[2] == htonl(0xffff))
        return true;                                       // ::ffff:0:0/96 mapped
    return false;
}

// AAAA (QTYPE=28) suppression. With no IPv6 SOCKS5 support, returning a
// clean NOERROR + zero answers makes the OS stop attempting IPv6 entirely
// (no black-holed Happy-Eyeballs sockets, no egress IP flapping).
bool IsAaaaOnlyQuery(const uint8_t* q, size_t n) {
    if (n < 12) return false;
    uint16_t qdcount = (q[4] << 8) | q[5];
    if (qdcount != 1) return false;
    size_t p = 12;
    while (p < n && q[p] != 0) {
        if (q[p] & 0xc0) return false;          // compressed QNAME in query
        p += 1 + q[p];
    }
    if (p + 4 >= n) return false;
    ++p;                                       // skip the root label
    uint16_t qtype = (q[p] << 8) | q[p + 1];
    return qtype == 28;                         // AAAA
}

// Build a NOERROR / 0-answer response that echoes the query, with the
// question section copied verbatim. used for AAAA suppression.
std::vector<uint8_t> MakeEmptyDnsReply(const uint8_t* q, size_t n) {
    std::vector<uint8_t> r(q, q + n);
    if (r.size() < 12) return {};
    r[2] = (uint8_t)(r[2] | 0x80);            // QR=1 (response), keep RD
    r[3] = 0;                                 // RCODE=0 (NOERROR)
    r[6] = r[7] = r[8] = r[9] = 0;            // AN/NS/AR counts = 0
    return r;
}

// -------------------------------------------------------------------- NAT
// Key semantics (mirrors wfp-divert's proven scheme):
//   outbound app packet  : key = {dst_ip, src_port}   -> entry{orig dst}
//   listener return path : key = {dst_ip, dst_port}   (dst is the app-side
//   peer endpoint after reflection, which equals {orig_dst_ip, app_port})
struct NatKey {
    uint32_t ip;      // host order
    uint16_t port;    // host order
    bool operator<(const NatKey& o) const {
        return ip != o.ip ? ip < o.ip : port < o.port;
    }
};

struct NatEntry {
    uint32_t orig_dst_ip = 0;   // host order
    uint16_t orig_dst_port = 0; // host order
    // The source IP captured on the first SYN. The listener is bound to
    // INADDR_ANY, so with several adapters Windows may pick a DIFFERENT
    // source address for the reply; reusing iph->SrcAddr there made the
    // injected reply's destination drift across adapters and reset the
    // connection ("IP 跳动"). Pin it here and use it on the return path.
    uint32_t app_ip = 0;        // network order
    uint32_t if_idx = 0;
    uint32_t sub_if_idx = 0;
    uint64_t flow_id = 0;       // stable trace id for structured logs
    std::chrono::steady_clock::time_point last;
};

// Plan §6: pure, driver-free predicate. Two different local source addresses
// (or two different destination ports) sharing {dst_ip, src_port} must NEVER
// reuse one NAT entry — that would splice two unrelated TCP flows together.
inline bool NatEntryClashes(const NatEntry& e, uint32_t app_ip_net,
                            uint16_t orig_dst_port_host) {
    return e.app_ip != app_ip_net ||
           e.orig_dst_port != orig_dst_port_host;
}

// Plan §4.5: UDP:443 is not only browser QUIC; some games use it too. It is
// no longer hard-dropped — it goes through UDP ASSOCIATE like every other
// datagram (fail-closed if the phone cannot relay it). Named predicate keeps
// the policy explicit and unit-testable.
inline bool IsQuicPort(uint16_t port_host) { return port_host == 443; }

// -------------------------------------------------------------- TCP session
struct TcpSession {
    // Handles are atomics: Stop() and the owning worker may both decide to
    // close, and exactly one of them must win (see CloseOnce).
    std::atomic<SOCKET> client{INVALID_SOCKET};  // accepted (reflected) socket
    std::atomic<SOCKET> remote{INVALID_SOCKET};  // SOCKS5 socket to the phone
    std::atomic<int>* budget = nullptr;
    std::atomic<bool> finalized{false};
    std::atomic<uint64_t> up{0};     // app -> phone bytes
    std::atomic<uint64_t> down{0};   // phone -> app bytes

    // Single owner of the close. beta0.1.3's CONNECT-failure branch closed
    // the accepted socket and returned WITHOUT deregistering, so the session
    // stayed in tcp_reg.live holding a dead handle; Stop() then closed it a
    // second time — by which point Windows may have recycled the number for
    // an unrelated socket. Whoever flips the atomic to INVALID_SOCKET first
    // performs the shutdown+close; every later caller is a no-op.
    void CloseOnce() {
        SOCKET c = client.exchange(INVALID_SOCKET);
        if (c != INVALID_SOCKET) {
            shutdown(c, SD_BOTH);
            closesocket(c);
        }
        SOCKET r = remote.exchange(INVALID_SOCKET);
        if (r != INVALID_SOCKET) {
            shutdown(r, SD_BOTH);
            closesocket(r);
        }
    }
};

// One direction of a session. A clean EOF (peer FIN) propagates a HALF-close
// (shutdown SD_SEND on the other side) instead of killing both directions —
// a server that closes its upload side while still downloading must keep
// flowing (plan §07: 半关闭不得被误当作立即清理).
void Pump(TcpSession* s, int from) {
    SOCKET a = s->client.load();
    SOCKET b = s->remote.load();
    SOCKET src = from == 0 ? a : b;
    SOCKET dst = from == 0 ? b : a;
    if (src == INVALID_SOCKET || dst == INVALID_SOCKET) return;
    auto* counter = from == 0 ? &s->up : &s->down;
    char buf[16384];
    DWORD tmo = 1000;
    setsockopt(src, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    for (;;) {
        // Termination relies purely on socket closure (Stop closes both
        // ends) — detached pumps never touch Impl members, so they cannot
        // race a later ExpEngine destruction.
        int n = recv(src, buf, sizeof(buf), 0);
        if (n > 0) {
            counter->fetch_add(static_cast<uint64_t>(n));
            int sent = 0;
            bool broken = false;
            while (sent < n) {
                int r = send(dst, buf + sent, n - sent, 0);
                if (r <= 0) { broken = true; break; }
                sent += r;
            }
            if (broken) {
                // hard failure in this direction: tear down BOTH ends so
                // the sibling pump unblocks immediately
                s->CloseOnce();
                break;
            }
        } else {
            int e = WSAGetLastError();
            if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) continue;
            if (n == 0) shutdown(dst, SD_SEND);  // clean EOF: half-close only
            break;
        }
    }
}

struct TcpRegistry {
    std::mutex mtx;
    std::vector<std::shared_ptr<TcpSession>> live;
};

// F04: a REAL concurrency gate. beta0.1.3 spun 300×20ms and then dialled the
// phone ANYWAY without holding a slot, so under load the phone still got 30+
// simultaneous CONNECTs (REP=0x05, 3-5s stalls) while the reflected handshake
// had already told the app "connected" — the app then saw a dead socket after
// ~5s, i.e. "接通立马就结束". Now: no slot, no CONNECT. The wait is
// interruptible so Stop() never hangs behind queued handshakes.
struct ConnectGate {
    std::mutex m;
    std::condition_variable cv;
    int cur = 0;
    int cap = 24;

    bool Acquire(std::atomic<bool>* stop, int timeout_ms) {
        std::unique_lock<std::mutex> lk(m);
        bool signalled = cv.wait_for(
            lk, std::chrono::milliseconds(timeout_ms), [&] {
                return cur < cap || (stop && !stop->load());
            });
        if (!signalled) return false;               // timed out: no slot
        if (stop && !stop->load()) return false;    // engine stopping
        if (cur >= cap) return false;
        ++cur;
        return true;
    }
    void Release() {
        std::lock_guard<std::mutex> lk(m);
        if (cur > 0) --cur;
        cv.notify_one();
    }
    void WakeAll() {
        std::lock_guard<std::mutex> lk(m);
        cv.notify_all();
    }
};

// Aggregate counters (plan §5.3: 会话闭环证据). Shared via shared_ptr so
// detached workers can still account their last bytes safely during Stop.
struct EngineStats {
    std::atomic<uint64_t> bytes_up{0};
    std::atomic<uint64_t> bytes_down{0};
    std::atomic<uint64_t> socks_ok{0};
    std::atomic<uint64_t> socks_fail{0};
    std::atomic<uint64_t> dns_ok{0};
    std::atomic<uint64_t> dns_fail{0};
    std::atomic<uint64_t> udp_drop{0};   // fail-closed drops (QUIC etc.)
    std::atomic<uint64_t> ipv6_drop{0};  // IPv6 egress denied (no IPv6 SOCKS5)
    std::atomic<uint64_t> blocked{0};    // deliberately dropped, never leaked
    // Proof of full capture: ANY packet we neither proxied nor deliberately
    // exempted (LAN) increments this. It must stay 0 — a non-zero value is
    // exactly the "not really a proxy / egress IP flapping" symptom.
    std::atomic<uint64_t> leak{0};

    // ---- F02/F05 observability. "Captured" is NOT "forwarded": every
    // injection is now verified, so these counters distinguish the two.
    std::atomic<uint64_t> recv_ok{0};
    std::atomic<uint64_t> recv_err{0};
    std::atomic<uint64_t> inject_attempt{0};
    std::atomic<uint64_t> inject_ok{0};
    std::atomic<uint64_t> inject_fail{0};
    std::atomic<uint64_t> gate_timeout{0};   // F04: cancelled, no CONNECT
    std::atomic<uint64_t> udp_assoc_ok{0};
    std::atomic<uint64_t> udp_assoc_fail{0};
    std::atomic<uint64_t> udp_sent{0};
    std::atomic<uint64_t> udp_reply{0};
    // Plan §6: the {dst_ip, src_port} NAT key can collide when two local
    // addresses (or two destination ports) reuse the same source port.
    // Count and REFUSE rather than silently splicing two flows together.
    std::atomic<uint64_t> nat_collision{0};
    // Plan §6: a pooled SOCKS5 TCP link may have been closed by the peer.
    // The first reuse then fails; we redial once and retry the query.
    std::atomic<uint64_t> dns_pool_reuse_fail{0};
    std::atomic<uint64_t> dns_pool_redial_ok{0};
    // Plan §4.5: UDP:443 is NOT unconditionally dropped any more; it is
    // offered to UDP ASSOCIATE like any other datagram. Count what happens
    // so a game's QUIC traffic is observable instead of vanishing silently.
    std::atomic<uint64_t> udp443_seen{0};
};

std::wstring HUMAN_BYTES(uint64_t b) {
    wchar_t buf[32];
    if (b >= 1024 * 1024)
        swprintf(buf, 32, L"%.1fMB", (double)b / (1024 * 1024));
    else if (b >= 1024)
        swprintf(buf, 32, L"%.1fKB", (double)b / 1024);
    else
        swprintf(buf, 32, L"%lluB", (unsigned long long)b);
    return buf;
}

// F02: every WinDivertSend is verified. beta0.1.3 discarded the BOOL result
// and the actual sent length at all five call sites, so an inbound injection
// with a wrong IfIdx/SubIfIdx silently vanished while the log happily said
// "captured". A capture is not a forward; this is the evidence line.
bool WdInject(HANDLE divert, const WD& wd, void* pkt, UINT len,
              const WINDIVERT_ADDRESS* addr,
              const wchar_t* what,
              uint64_t flow_id,
              const std::shared_ptr<EngineStats>& stats,
              const std::function<void(const std::wstring&)>& log) {
    UINT sent = 0;
    stats->inject_attempt.fetch_add(1);
    BOOL ok = wd.send(divert, pkt, len, &sent, addr);
    if (ok && sent == len) {
        stats->inject_ok.fetch_add(1);
        return true;
    }
    DWORD err = ok ? ERROR_WRITE_FAULT : GetLastError();
    uint64_t n = stats->inject_fail.fetch_add(1) + 1;
    // Low-frequency by design: first 5 failures are always logged (enough to
    // diagnose), then every 200th so a broken handle cannot flood the UI.
    if (log && (n <= 5 || n % 200 == 0)) {
        log(std::wstring(L"[exp] 回注失败 #") + std::to_wstring(flow_id) + L" " +
            what + L" err=" + std::to_wstring((unsigned long long)err) +
            L" 方向=" + (addr && addr->Outbound ? L"出站" : L"入站") +
            L" IfIdx=" + std::to_wstring(addr ? addr->Network.IfIdx : 0) +
            L"/" + std::to_wstring(addr ? addr->Network.SubIfIdx : 0) +
            L" len=" + std::to_wstring(len) + L" sent=" +
            std::to_wstring(sent) + L"（累计失败 " + std::to_wstring(n) + L"）");
    }
    return false;
}

// ------------------------------------------- Local DNS proxy (loopback)
// The "intermediate layer" for name resolution. The phone's Wi-Fi Direct
// DHCP offers its OWN address as the DNS server, but the phone is a SOCKS5
// proxy, not a resolver — so a resolver pointed at it dies
// (DNS_PROBE_FINISHED_BAD_CONFIG) and NCSI never reports "Internet access".
// Instead we run a tiny in-process UDP DNS server on 127.0.0.1:53 and point
// the phone adapter's DNS at loopback. Every query is relayed over SOCKS5
// (TCP DNS, RFC 7766) to a public resolver. Loopback is excluded from the
// WinDivert capture filter, so there is no packet-injection race and no
// dependence on the phone answering DNS.
bool SendAllRaw(SOCKET s, const uint8_t* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, reinterpret_cast<const char*>(buf + sent), len - sent, 0);
        if (n == SOCKET_ERROR) return false;
        sent += n;
    }
    return true;
}
bool RecvAllRaw(SOCKET s, uint8_t* buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(s, reinterpret_cast<char*>(buf + got), len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

struct DnsProxy {
    SOCKET sock = INVALID_SOCKET;
    std::atomic<bool> running{false};
    std::atomic<int> budget{0};
    std::mutex pool_mtx;
    std::vector<SOCKET> pool;     // idle SOCKS5-TCP links to upstream:53
    size_t pool_cap = 8;
    std::string upstream = "223.5.5.5";
    std::string fallback = "8.8.8.8";
};

void DnsQueryWorker(DnsProxy* p, std::vector<uint8_t> query, sockaddr_in client,
                    const std::string& phone8, uint16_t phone_port,
                    const ExpAuth& auth, std::shared_ptr<EngineStats> stats,
                    const std::function<void(const std::wstring&)>& log) {
    p->budget.fetch_add(1);
    bool ok = false;
    if (query.size() >= 12 && query.size() <= 4096) {
        // TCP DNS (RFC 7766): 2-byte length prefix, then the message
        std::vector<uint8_t> req(2 + query.size());
        req[0] = static_cast<uint8_t>(query.size() >> 8);
        req[1] = static_cast<uint8_t>(query.size());
        std::memcpy(req.data() + 2, query.data(), query.size());

        // Plan §6: a pooled SOCKS5 TCP link can be closed by the peer while
        // idle. Its first reuse then fails with no response. Close it, force a
        // FRESH dial on the second attempt and retry this exact query once.
        // Both outcomes are counted so the behaviour is observable in logs.
        for (int attempt = 0; attempt < 2 && !ok; ++attempt) {
            SOCKET s = INVALID_SOCKET;
            bool from_pool = false;
            std::string err;
            if (attempt == 0) {
                std::lock_guard<std::mutex> lk(p->pool_mtx);
                if (!p->pool.empty()) {
                    s = p->pool.back();
                    p->pool.pop_back();
                    from_pool = true;
                }
            }
            if (s == INVALID_SOCKET) {
                for (const std::string& up : {p->upstream, p->fallback}) {
                    uint32_t up_net = IpToNet(up);
                    s = ExpSocks5TcpConnect(phone8, phone_port, auth, up_net,
                                            htons(53), &err);
                    if (s != INVALID_SOCKET) {
                        if (attempt > 0) stats->dns_pool_redial_ok.fetch_add(1);
                        break;
                    }
                }
            }
            if (s == INVALID_SOCKET) break;  // both upstreams unreachable

            DWORD tmo = 5000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&tmo), sizeof(tmo));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                       reinterpret_cast<const char*>(&tmo), sizeof(tmo));
            bool link_failed = !SendAllRaw(s, req.data(), (int)req.size());
            std::vector<uint8_t> reply;
            if (!link_failed) {
                uint8_t lenb[2];
                if (!RecvAllRaw(s, lenb, 2)) {
                    link_failed = true;
                } else {
                    int rlen = (lenb[0] << 8) | lenb[1];
                    if (rlen <= 0 || rlen > 65535) link_failed = true;
                    else {
                        reply.resize((size_t)rlen);
                        if (!RecvAllRaw(s, reply.data(), rlen))
                            link_failed = true;
                    }
                }
            }
            if (link_failed) {
                if (from_pool) stats->dns_pool_reuse_fail.fetch_add(1);
                closesocket(s);
                continue;  // retry once with a fresh link
            }
            // healthy link: hand it back to the pool for reuse
            {
                std::lock_guard<std::mutex> lk(p->pool_mtx);
                if (p->pool.size() < p->pool_cap) p->pool.push_back(s);
                else closesocket(s);
            }
            int n = sendto(p->sock,
                           reinterpret_cast<const char*>(reply.data()),
                           (int)reply.size(), 0,
                           reinterpret_cast<sockaddr*>(&client),
                           sizeof(client));
            ok = (n == (int)reply.size());
            // a local sendto failure is NOT a link failure: do not redial
        }
    }
    if (ok) stats->dns_ok.fetch_add(1);
    else stats->dns_fail.fetch_add(1);
    p->budget.fetch_sub(1);
}

void DnsProxyLoop(DnsProxy* p, const std::string& phone8, uint16_t phone_port,
                  const ExpAuth& auth, std::shared_ptr<EngineStats> stats,
                  const std::function<void(const std::wstring&)>& log) {
    uint8_t buf[65535];
    while (p->running.load()) {
        sockaddr_in client{};
        int cl = sizeof(client);
        int n = recvfrom(p->sock, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                         reinterpret_cast<sockaddr*>(&client), &cl);
        if (n <= 0) {
            if (p->running.load()) {
                int e = WSAGetLastError();
                if (e == WSAEWOULDBLOCK) continue;
            }
            break;
        }
        // AAAA suppression BEFORE any SOCKS5 work: with no IPv6-capable
        // upstream, a NOERROR/empty answer stops the OS from opening IPv6
        // sockets that would otherwise be dropped or leak out natively.
        if (n >= 12 && IsAaaaOnlyQuery(buf, (size_t)n)) {
            std::vector<uint8_t> r = MakeEmptyDnsReply(buf, (size_t)n);
            sendto(p->sock, reinterpret_cast<const char*>(r.data()),
                   (int)r.size(), 0,
                   reinterpret_cast<sockaddr*>(&client), cl);
            stats->dns_ok.fetch_add(1);
            continue;
        }
        if (p->budget.load() >= 64) continue;  // backpressure: let the app retry
        std::vector<uint8_t> q(buf, buf + n);
        std::thread(DnsQueryWorker, p, std::move(q), client, phone8, phone_port,
                    auth, stats, log).detach();
    }
}

// ------------------------------------------------- DNS over TCP (RFC 7766)
// Fallback path (only used when the loopback proxy above is NOT active, e.g.
// the proxy failed to bind): the app's UDP:53 query is relayed as a TCP DNS
// exchange to the SAME server, through the phone's SOCKS5 CONNECT.
//
// §5.1: "the same server" is wrong when the app's resolver IS the phone (the
// Wi-Fi Direct DHCP hands out 192.168.49.1 as DNS). The phone would then be
// asked to CONNECT to itself on :53 and never answer. Redirect private /
// phone-gateway targets to a public resolver, but keep the ORIGINAL address
// as the reply's source so the app's socket still matches its query.
uint32_t PickDnsUpstream(uint32_t dst_net, uint32_t phone_net) {
    if (dst_net == phone_net || IsBypassDst(dst_net)) return IpToNet("223.5.5.5");
    return dst_net;
}

void DnsWorker(HANDLE divert, WD wd, std::string phone8, uint16_t phone_port,
               ExpAuth auth, std::shared_ptr<EngineStats> stats,
               const std::function<void(const std::wstring&)>& log,
               std::vector<uint8_t> query, uint32_t upstream_ip_net,
               uint32_t reply_src_ip_net, uint16_t dns_port_net,
               uint32_t app_ip_net,
               uint16_t app_port_net, uint32_t if_idx, uint32_t sub_if_idx,
               std::atomic<int>* dns_budget) {
    dns_budget->fetch_add(1);
    int qlen = static_cast<int>(query.size());
    bool ok = false;
    do {
        if (qlen <= 0 || qlen > 4096) break;  // absurd query — drop
        std::string err;
        SOCKET s = ExpSocks5TcpConnect(phone8, phone_port, auth, upstream_ip_net,
                                       dns_port_net, &err);
        if (s == INVALID_SOCKET) break;
        // TCP DNS: 2-byte length prefix, then the message
        std::vector<uint8_t> req(2 + query.size());
        req[0] = static_cast<uint8_t>(qlen >> 8);
        req[1] = static_cast<uint8_t>(qlen);
        std::memcpy(req.data() + 2, query.data(), query.size());
        DWORD tmo = 5000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tmo), sizeof(tmo));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&tmo), sizeof(tmo));
        bool sent = true;
        {
            int off = 0;
            while (off < (int)req.size()) {
                int n = send(s, reinterpret_cast<const char*>(req.data() + off),
                             (int)req.size() - off, 0);
                if (n <= 0) { sent = false; break; }
                off += n;
            }
        }
        if (!sent) { closesocket(s); break; }
        uint8_t lenb[2];
        int got = 0;
        while (got < 2) {
            int n = recv(s, reinterpret_cast<char*>(lenb + got), 2 - got, 0);
            if (n <= 0) break;
            got += n;
        }
        if (got < 2) { closesocket(s); break; }
        int rlen = (lenb[0] << 8) | lenb[1];
        if (rlen <= 0 || rlen > 65535) { closesocket(s); break; }
        std::vector<uint8_t> reply((size_t)rlen);
        got = 0;
        while (got < rlen) {
            int n = recv(s, reinterpret_cast<char*>(reply.data() + got),
                         rlen - got, 0);
            if (n <= 0) break;
            got += n;
        }
        closesocket(s);
        if (got < rlen) break;
        // rebuild the UDP datagram: it looks like it came from the DNS
        // server straight to the app's socket
        size_t psz = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) +
                     reply.size();
        std::vector<uint8_t> pkt(psz, 0);
        auto* iph = reinterpret_cast<WINDIVERT_IPHDR*>(pkt.data());
        auto* udph = reinterpret_cast<WINDIVERT_UDPHDR*>(
            pkt.data() + sizeof(WINDIVERT_IPHDR));
        iph->Version = 4;
        iph->HdrLength = sizeof(WINDIVERT_IPHDR) / 4;
        iph->Length = htons(static_cast<uint16_t>(psz));
        iph->TTL = 64;
        iph->Protocol = IPPROTO_UDP;
        iph->SrcAddr = reply_src_ip_net;   // the address the app queried
        iph->DstAddr = app_ip_net;
        udph->SrcPort = dns_port_net;
        udph->DstPort = app_port_net;
        udph->Length = htons(static_cast<uint16_t>(
            sizeof(WINDIVERT_UDPHDR) + reply.size()));
        std::memcpy(pkt.data() + sizeof(WINDIVERT_IPHDR) +
                        sizeof(WINDIVERT_UDPHDR), reply.data(), reply.size());
        WINDIVERT_ADDRESS addr{};
        addr.Outbound = FALSE;
        addr.Loopback = FALSE;
        addr.Network.IfIdx = if_idx;
        addr.Network.SubIfIdx = sub_if_idx;
        wd.checksums(pkt.data(), (UINT)psz, &addr, 0);
        ok = WdInject(divert, wd, pkt.data(), (UINT)psz, &addr, L"DNS 回包",
                      0, stats, log);
    } while (false);
    if (ok) stats->dns_ok.fetch_add(1);
    else stats->dns_fail.fetch_add(1);
    dns_budget->fetch_sub(1);
}

// F03: ONE exit path for every TCP session — success, SOCKS5 failure, gate
// timeout, engine stop. beta0.1.3 returned early from the CONNECT-failure
// branch after closing the socket, leaving the session in tcp_reg.live with
// a dead handle that Stop() later closed a second time (possibly after the
// OS had recycled the number). Deregistration happens BEFORE the budget
// decrement because Stop waits for budget==0 and only then tears down shared
// state. `finalized` makes the whole sequence idempotent.
void SessionFinalize(const std::shared_ptr<TcpSession>& s, TcpRegistry* reg,
                     const std::shared_ptr<EngineStats>& stats,
                     std::atomic<int>* budget) {
    if (s->finalized.exchange(true)) return;
    // free the slot BEFORE anything else: a queued handshake may be waiting
    {
        std::lock_guard<std::mutex> lk(reg->mtx);
        for (auto it = reg->live.begin(); it != reg->live.end(); ++it) {
            if (it->get() == s.get()) { reg->live.erase(it); break; }
        }
    }
    s->CloseOnce();
    stats->bytes_up.fetch_add(s->up.load());
    stats->bytes_down.fetch_add(s->down.load());
    if (budget) budget->fetch_sub(1);
}

void TcpWorker(std::shared_ptr<TcpSession> s, NatEntry entry,
               std::string phone_ip, uint16_t phone_port, ExpAuth auth,
               uint64_t flow_id,
               std::function<void(const std::wstring&)> log,
               TcpRegistry* reg, std::shared_ptr<EngineStats> stats,
               ConnectGate* gate, std::atomic<bool>* stop,
               std::atomic<int>* budget) {
    auto t0 = std::chrono::steady_clock::now();
    std::wstring dstw = IpW(htonl(entry.orig_dst_ip)) + L":" +
                        std::to_wstring(entry.orig_dst_port);
    // F04: a slot must be HELD before dialling the phone. When the gate is
    // saturated we cancel instead of adding a 25th handshake to a phone that
    // is already answering REP=0x05 / 3-5s. The wait is cancellable, so
    // Stop()/FAULTED never hangs behind a queued handshake.
    if (!gate->Acquire(stop, 8000)) {
        stats->gate_timeout.fetch_add(1);
        log(L"[exp] #" + std::to_wstring(flow_id) +
            L" 并发闸门超时或引擎停止 → 取消（未向手机发起 CONNECT）→ " +
            dstw);
        SessionFinalize(s, reg, stats, budget);
        return;
    }
    std::string err;
    s->remote.store(ExpSocks5TcpConnect(phone_ip, phone_port, auth,
                                        htonl(entry.orig_dst_ip),
                                        htons(entry.orig_dst_port), &err));
    gate->Release();
    if (s->remote.load() == INVALID_SOCKET) {
        // Surface the failure to the app as an immediate disconnect (never
        // fake "connected"): the plan document's observable-failure rule.
        stats->socks_fail.fetch_add(1);
        log(L"[exp] #" + std::to_wstring(flow_id) + L" SOCKS5 CONNECT 失败 (" +
            FromUtf8(err) + L") → " + dstw);
        SessionFinalize(s, reg, stats, budget);
        return;
    }
    stats->socks_ok.fetch_add(1);
    int ms = static_cast<int>(std::chrono::duration_cast<
        std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
        .count());
    log(L"[exp] #" + std::to_wstring(flow_id) + L" 手机已接通 → " + dstw +
        L" (" + std::to_wstring(ms) + L"ms)");
    std::thread t1(Pump, s.get(), 0);
    std::thread t2(Pump, s.get(), 1);
    t1.join();
    t2.join();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - t0).count();
    log(L"[exp] #" + std::to_wstring(flow_id) + L" 结束 " + dstw +
        L" ↑" + HUMAN_BYTES(s->up.load()) + L" ↓" +
        HUMAN_BYTES(s->down.load()) + L" " + std::to_wstring(secs) + L"s");
    SessionFinalize(s, reg, stats, budget);
}

// -------------------------------------------------------------- UDP session
// F01: the ASSOCIATE handshake is ASYNC. beta0.1.3 ran it inline inside the
// WinDivert capture loop: the first datagram from a new source port blocked
// every other packet — TCP SYNs, DNS, other UDP flows — for as long as the
// phone took to answer (3-5s on a loaded ProxyServer), and the whole engine
// looked dead. Now MainLoop only does lookup / enqueue / count; a worker
// performs the handshake and flushes the bounded queue afterwards.
enum UdpState { kUdpInit = 0, kUdpReady = 1, kUdpFailed = 2 };

struct UdpPending {
    uint32_t dst_ip = 0;    // network order
    uint16_t dst_port = 0;  // network order
    std::vector<uint8_t> data;
};

struct UdpSession {
    std::atomic<int> state{kUdpInit};
    std::atomic<int> fails{0};
    std::chrono::steady_clock::time_point retry_at;
    ExpUdpAssoc assoc;
    uint32_t app_ip = 0;     // network order
    uint16_t app_port = 0;   // network order
    uint32_t if_idx = 0;
    uint32_t sub_if_idx = 0;
    std::chrono::steady_clock::time_point last;
    // first datagrams captured while the handshake is in flight (bounded)
    std::mutex q_mtx;
    std::vector<UdpPending> pending;
};

constexpr size_t kUdpPendingMax = 8;

void UdpRecvThread(HANDLE divert, WD wd, std::shared_ptr<UdpSession> sess,
                   std::atomic<int>* udp_budget,
                   std::shared_ptr<EngineStats> stats,
                   std::function<void(const std::wstring&)> log) {
    uint8_t payload[65535];
    for (;;) {
        // Exits when the association sockets are closed (Stop / expiry /
        // control-conn death) — no Impl member is touched after that.
        DWORD tmo = 1500;
        setsockopt(sess->assoc.udp, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tmo), sizeof(tmo));
        uint32_t sip = 0;
        uint16_t sport = 0;
        int n = ExpSocks5UdpRecv(sess->assoc, &sip, &sport, payload,
                                 sizeof(payload));
        if (n <= 0) {
            int e = WSAGetLastError();
            if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) continue;
            break;  // control conn closed -> association dead
        }
        // Rebuild the UDP packet as if it came from the ORIGINAL destination
        // and inject inbound so the app socket accepts it.
        size_t psz = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + n;
        std::vector<uint8_t> pkt(psz, 0);
        auto* iph = reinterpret_cast<WINDIVERT_IPHDR*>(pkt.data());
        auto* udph = reinterpret_cast<WINDIVERT_UDPHDR*>(
            pkt.data() + sizeof(WINDIVERT_IPHDR));
        iph->Version = 4;
        iph->HdrLength = sizeof(WINDIVERT_IPHDR) / 4;
        iph->Length = htons(static_cast<uint16_t>(psz));
        iph->TTL = 64;
        iph->Protocol = IPPROTO_UDP;
        iph->SrcAddr = sip;          // original remote (network order)
        iph->DstAddr = sess->app_ip;
        udph->SrcPort = sport;
        udph->DstPort = sess->app_port;
        udph->Length = htons(static_cast<uint16_t>(
            sizeof(WINDIVERT_UDPHDR) + n));
        std::memcpy(pkt.data() + sizeof(WINDIVERT_IPHDR) +
                        sizeof(WINDIVERT_UDPHDR), payload, (size_t)n);
        WINDIVERT_ADDRESS addr{};
        addr.Outbound = FALSE;
        addr.Loopback = FALSE;
        addr.Network.IfIdx = sess->if_idx;
        addr.Network.SubIfIdx = sess->sub_if_idx;
        wd.checksums(pkt.data(), (UINT)psz, &addr, 0);
        if (WdInject(divert, wd, pkt.data(), (UINT)psz, &addr, L"UDP 回包", 0,
                     stats, log))
            stats->udp_reply.fetch_add(1);
    }
    udp_budget->fetch_sub(1);
}

// Performs the SOCKS5 UDP ASSOCIATE for one session, then flushes whatever
// arrived while the handshake was in flight. Runs on its own thread so the
// capture loop is never blocked by the phone.
void UdpAssociateWorker(std::shared_ptr<UdpSession> sess, std::string phone8,
                        uint16_t phone_port, ExpAuth auth,
                        std::function<void(const std::wstring&)> log,
                        std::shared_ptr<EngineStats> stats,
                        std::atomic<int>* udp_budget, HANDLE divert, WD wd,
                        std::atomic<bool>* stop) {
    auto t0 = std::chrono::steady_clock::now();
    std::string err;
    bool ok = ExpSocks5UdpAssociate(phone8, phone_port, auth, &sess->assoc,
                                   &err);
    int ms = static_cast<int>(std::chrono::duration_cast<
        std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
        .count());
    if (!ok || (stop && !stop->load())) {
        if (ok) ExpSocks5UdpClose(&sess->assoc);
        sess->state.store(kUdpFailed);
        int f = sess->fails.fetch_add(1) + 1;
        int backoff_ms = (f < 4 ? 3000 : 15000);
        sess->retry_at =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(backoff_ms);
        stats->udp_assoc_fail.fetch_add(1);
        // Rate-limit: first 3 failures, then every 20th — otherwise a phone
        // without UDP support would flood the UI once per datagram.
        if (f <= 3 || f % 20 == 0) {
            log(L"[exp] UDP ASSOCIATE 失败 #" + std::to_wstring(f) + L" (" +
                FromUtf8(err) + L", " + std::to_wstring(ms) +
                L"ms) — fail-closed 丢弃，绝不直连放行；" +
                std::to_wstring(backoff_ms) + L"ms 后重试");
        }
        stats->udp_drop.fetch_add(1);
        return;
    }
    stats->udp_assoc_ok.fetch_add(1);
    // Publish READY and take the queued datagrams in ONE critical section:
    // a packet that arrives before this point is queued and flushed in order,
    // one that arrives after sees READY and is sent directly.
    std::vector<UdpPending> q;
    {
        std::lock_guard<std::mutex> plk(sess->q_mtx);
        sess->state.store(kUdpReady);
        q.swap(sess->pending);
    }
    udp_budget->fetch_add(1);
    std::thread(UdpRecvThread, divert, wd, sess, udp_budget, stats, log)
        .detach();
    int flushed = 0;
    for (auto& p : q) {
        if (ExpSocks5UdpSend(sess->assoc, p.dst_ip, p.dst_port, p.data.data(),
                             static_cast<int>(p.data.size()))) {
            stats->udp_sent.fetch_add(1);
            ++flushed;
        } else {
            stats->udp_drop.fetch_add(1);
        }
    }
    log(L"[exp] UDP 会话就绪 (" + std::to_wstring(ms) + L"ms) " +
        IpW(sess->app_ip) + L":" + std::to_wstring(ntohs(sess->app_port)) +
        L" 首包已转发 " + std::to_wstring(flushed) + L"/" +
        std::to_wstring(q.size()) + L"；抓包线程未被阻塞");
}

// ---------------------------------------------------- DNS adapter backup
// With Wi-Fi Direct as the ONLY uplink, the adapter often has no (or a
// phone-gateway) DNS server. Name resolution then dies before any packet
// is emitted — the root cause of the "路由黑洞" browser symptom. We set
// public DNS on the phone-facing adapter for the session and restore the
// original configuration on Stop.
struct DnsBackup {
    std::wstring ifname;                 // adapter friendly name
    std::vector<std::wstring> servers;   // original DNS servers (may be empty)
    // §5.3: whether the adapter got its addressing from DHCP. Restoring a
    // DHCP adapter with "set dns static" silently converted its DNS mode;
    // that is a configuration change the user never asked for.
    bool dhcp = false;
    bool changed = false;
};

// §4.4 / §7 ROUTE_SNAPSHOT: a leftover LinkHelm-IwIP / Wintun adapter can
// still own a default route and pollute EXP's baseline. Report it READ-ONLY —
// EXP must never disable, rename or re-route the user's adapters.
std::wstring FindLegacyTunAdapter() {
    ULONG sz = 32 * 1024;
    std::vector<uint8_t> buf(sz);
    auto* first = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, first, &sz) != NO_ERROR)
        return L"";
    for (auto* ad = first; ad; ad = ad->Next) {
        if (!ad->FriendlyName) continue;
        std::wstring name(ad->FriendlyName), low(name);
        for (auto& ch : low) ch = static_cast<wchar_t>(std::towlower(ch));
        if (low.find(L"iwip") != std::wstring::npos ||
            low.find(L"wintun") != std::wstring::npos ||
            low.find(L"linkhelm") != std::wstring::npos)
            return name;
    }
    return L"";
}

bool RunNetsh(const std::wstring& args) {
    std::wstring cmd = L"netsh.exe " + args;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return false;
    if (WaitForSingleObject(pi.hProcess, 8000) == WAIT_TIMEOUT) {
        // §5.3: a timed-out netsh must not keep running in the background and
        // apply its change AFTER we already reported failure.
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0;
}

// Find the adapter whose DEFAULT GATEWAY is the phone (Wi-Fi Direct GO) and
// back up its DNS list. The PC's own address on that adapter is 192.168.49.x,
// NOT the phone's 192.168.49.1 — matching by unicast IP never fired before,
// which is why DNS was never overridden and name resolution died.
bool BackupAdapterDns(const std::string& phone8, DnsBackup* out) {
    ULONG sz = 16 * 1024;
    std::vector<uint8_t> buf;
    for (int tries = 0; tries < 3; ++tries) {
        buf.resize(sz);
        ULONG r = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS,
                                       nullptr,
                                       reinterpret_cast<IP_ADAPTER_ADDRESSES*>(
                                           buf.data()), &sz);
        if (r == ERROR_SUCCESS) break;
        if (r == ERROR_BUFFER_OVERFLOW) continue;
        return false;
    }
    auto* ad = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    for (; ad; ad = ad->Next) {
        bool gw_match = false;
        for (auto* ga = ad->FirstGatewayAddress; ga; ga = ga->Next) {
            if (!ga->Address.lpSockaddr) continue;
            char ip[64] = "";
            if (getnameinfo(ga->Address.lpSockaddr, ga->Address.iSockaddrLength,
                            ip, sizeof(ip), nullptr, 0, NI_NUMERICHOST) == 0 &&
                phone8 == ip) {
                gw_match = true;
                break;
            }
        }
        if (!gw_match) continue;
        out->ifname = std::wstring(ad->FriendlyName);
        out->dhcp = (ad->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
        for (auto* ds = ad->FirstDnsServerAddress; ds; ds = ds->Next) {
            if (!ds->Address.lpSockaddr) continue;
            wchar_t w[64] = L"";
            sockaddr_in* a =
                reinterpret_cast<sockaddr_in*>(ds->Address.lpSockaddr);
            InetNtopW(AF_INET, &a->sin_addr, w, 64);
            out->servers.push_back(w);
        }
        return true;
    }
    return false;
}

// A private DNS server (typically the phone/ICS gateway itself) cannot
// reliably answer through the SOCKS5 CONNECT path — the phone would connect
// to itself. Only a public resolver is considered usable here.
bool HasPublicDns(const DnsBackup& b) {
    for (const auto& s : b.servers) {
        unsigned o1 = 0;
        swscanf(s.c_str(), L"%u", &o1);
        if (o1 != 10 && o1 != 127 && o1 != 172 && o1 != 192 && o1 != 169)
            return true;
    }
    return false;
}

// beta0.1.3: half-route helpers REMOVED. The architecture review is
// explicit — a WinDivert NETWORK-layer redirector does NOT need
// 0.0.0.0/1 / 128.0.0.0/1. On the test machine they failed to install yet
// WinDivert still captured 30+ flows (two default routes already existed).
// Installing them only risked the very "路由黑洞" the EXP branch set out to
// eliminate. Nothing in this file mutates the system route table now.

// F05: engine life-cycle names for the 10s statistics line.
const wchar_t* StateName(int s) {
    switch (s) {
        case 0: return L"启动中";
        case 1: return L"运行中";
        case 2: return L"故障";
        default: return L"已停止";
    }
}

}  // namespace

// ------------------------------------------------------------------- Impl
struct ExpEngine::Impl {
    ExpConfig cfg;
    std::function<void(const std::wstring&)> log;
    std::function<void(const std::wstring&)> status;

    WD wd;
    std::atomic<bool> running{false};
    HANDLE divert = INVALID_HANDLE_VALUE;
    SOCKET listener = INVALID_SOCKET;
    uint16_t local_port = 0;

    std::mutex nat_mtx;
    std::map<NatKey, NatEntry> nat;

    std::mutex udp_mtx;
    std::map<uint64_t, std::shared_ptr<UdpSession>> udp;  // key: ip<<16|port

    std::atomic<int> tcp_budget{0};
    std::atomic<int> dns_budget{0};
    std::atomic<int> udp_budget{0};
    std::atomic<uint64_t> next_flow{1};
    std::shared_ptr<EngineStats> stats{new EngineStats()};
    TcpRegistry tcp_reg;

    // Diagnostic only. beta0.1.2 used this flag to install 0/1 + 128/1
    // half-routes and to allow UDP fail-open — both were wrong: the routes
    // never installed (log "半默认路由添加失败 err 0") yet WinDivert still
    // captured 30+ flows, and fail-open leaked traffic onto the native
    // uplink (egress IP flapping). beta0.1.3 NEVER touches the route table
    // and NEVER passes a packet through unproxied.
    bool phone_only_uplink = true;
    DWORD uplink_if = 0;

    // Bounds concurrent SOCKS5 CONNECT handshakes (F04: a real gate — no
    // slot means no CONNECT at all, and the wait is cancellable).
    ConnectGate connect_gate;

    // F05: STARTING → RUNNING → FAULTED / STOPPED. "UI says 已连接" must never
    // outlive the capture thread: a dead WinDivertRecv used to break out of
    // MainLoop silently while the UI still showed a healthy tunnel.
    enum EngineState { kStarting = 0, kRunning = 1, kFaulted = 2, kStopped = 3 };
    std::atomic<int> state{kStarting};
    std::atomic<bool> dns_remap_logged{false};
    std::wstring last_fatal;
    std::mutex fatal_mtx;

    void SetFault(const std::wstring& why) {
        {
            std::lock_guard<std::mutex> lk(fatal_mtx);
            last_fatal = why;
        }
        state.store(kFaulted);
        log(L"[exp] ENGINE_FAULT 状态=FAULTED 原因=" + why +
            L"（捕获线程已停止，其它线程将被协调退出）");
        status(L"故障：" + why + L"（请断开后重连）");
    }

    ExpAuth auth;
    std::string phone8;
    uint32_t phone_net = 0;   // network order, for precise loop avoidance

    // DNS adapter override (set on Start, restored on Stop)
    DnsBackup dns_backup;
    // loopback DNS proxy (127.0.0.1:53) — relays queries over SOCKS5
    DnsProxy dnsproxy;
    std::thread dnsproxy_thr;

    std::thread main_thr, accept_thr, expire_thr;

    void MainLoop();
    void AcceptLoop();
    void ExpireLoop();
};

void ExpEngine::Impl::AcceptLoop() {
    while (running.load()) {
        fd_set r;
        FD_ZERO(&r);
        FD_SET(listener, &r);
        timeval tv{0, 300 * 1000};
        int ret = select(0, &r, nullptr, nullptr, &tv);
        if (ret <= 0) continue;
        sockaddr_in ca{};
        int cl = sizeof(ca);
        SOCKET cs = accept(listener, reinterpret_cast<sockaddr*>(&ca), &cl);
        if (cs == INVALID_SOCKET) continue;
        if (tcp_budget.load() >= 400) {
            log(L"[exp] TCP 会话数达上限 400，拒绝新连接（背压）");
            closesocket(cs);
            continue;
        }
        // The reflected connection's remote endpoint == (orig_dst_ip,
        // app_port) — exactly the NAT key we inserted at SYN time.
        NatKey key{ntohl(ca.sin_addr.s_addr), ntohs(ca.sin_port)};
        NatEntry entry;
        {
            std::lock_guard<std::mutex> lk(nat_mtx);
            auto it = nat.find(key);
            if (it == nat.end()) {
                log(L"[exp] 无 NAT 表项，拒绝连接（伪造/过期的反射连接）");
                closesocket(cs);
                continue;
            }
            entry = it->second;
            entry.last = std::chrono::steady_clock::now();
        }
        tcp_budget.fetch_add(1);
        auto s = std::make_shared<TcpSession>();
        s->client.store(cs);
        s->budget = &tcp_budget;
        uint64_t flow_id = entry.flow_id;
        {
            std::lock_guard<std::mutex> lk(tcp_reg.mtx);
            tcp_reg.live.push_back(s);
        }
        std::thread(TcpWorker, s, entry, phone8, cfg.phone_port, auth,
                    flow_id, log, &tcp_reg, stats, &connect_gate, &running,
                    &tcp_budget).detach();
    }
    closesocket(listener);
    listener = INVALID_SOCKET;
}

void ExpEngine::Impl::ExpireLoop() {
    int ticks = 0;
    while (running.load()) {
        for (int i = 0; i < 10 && running.load(); ++i)
            Sleep(100);
        if (!running.load()) break;
        ++ticks;
        auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lk(nat_mtx);
            for (auto it = nat.begin(); it != nat.end();) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.last).count();
                if (age > 300) it = nat.erase(it);
                else ++it;
            }
        }
        std::vector<std::shared_ptr<UdpSession>> dead;
        {
            std::lock_guard<std::mutex> lk(udp_mtx);
            for (auto it = udp.begin(); it != udp.end();) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second->last).count();
                if (age > 120) { dead.push_back(it->second);
                                 it = udp.erase(it); }
                else ++it;
            }
        }
        for (auto& s : dead) {
            // Only a READY association owns live sockets; an INIT one may
            // still be inside ExpSocks5UdpAssociate on its own worker.
            if (s->state.load() == kUdpReady) ExpSocks5UdpClose(&s->assoc);
        }
        // plan §5.3: aggregate session-closure evidence every ~10s
        if (ticks % 10 == 0) {
            const wchar_t* st = StateName(state.load());
            log(L"[exp] 统计[" + std::wstring(st) + L"]: TCP 活动 " +
                std::to_wstring(tcp_budget.load()) +
                L" | 成功 " + std::to_wstring(stats->socks_ok.load()) +
                L" 失败 " + std::to_wstring(stats->socks_fail.load()) +
                L" 闸门取消 " + std::to_wstring(stats->gate_timeout.load()) +
                L" | ↑" + HUMAN_BYTES(stats->bytes_up.load()) +
                L" ↓" + HUMAN_BYTES(stats->bytes_down.load()) +
                L" | 捕获 " + std::to_wstring(stats->recv_ok.load()) +
                L" 收包错误 " + std::to_wstring(stats->recv_err.load()) +
                L" | 回注 成功 " + std::to_wstring(stats->inject_ok.load()) +
                L" 失败 " + std::to_wstring(stats->inject_fail.load()) +
                L" | DNS 成功 " + std::to_wstring(stats->dns_ok.load()) +
                L" 失败 " + std::to_wstring(stats->dns_fail.load()) +
                L" | UDP 就绪 " + std::to_wstring(stats->udp_assoc_ok.load()) +
                L" 握手失败 " + std::to_wstring(stats->udp_assoc_fail.load()) +
                L" 发送 " + std::to_wstring(stats->udp_sent.load()) +
                L" 回包 " + std::to_wstring(stats->udp_reply.load()) +
                L" 丢弃 " + std::to_wstring(stats->udp_drop.load()) +
                L" | UDP443 代理 " + std::to_wstring(stats->udp443_seen.load()) +
                L" | NAT 碰撞 " + std::to_wstring(stats->nat_collision.load()) +
                L" | DNS 池复用失败 " +
                std::to_wstring(stats->dns_pool_reuse_fail.load()) +
                L" 重拨成功 " + std::to_wstring(stats->dns_pool_redial_ok.load()) +
                L" | IPv6 阻断 " + std::to_wstring(stats->ipv6_drop.load()) +
                L" | 阻断 " + std::to_wstring(stats->blocked.load()) +
                L" | 未代理泄漏 " + std::to_wstring(stats->leak.load()) +
                L"（应为 0）");
        }
    }
}

void ExpEngine::Impl::MainLoop() {
    constexpr UINT kBuf = 65535 + 40;
    std::vector<uint8_t> pkt(kBuf);
    WINDIVERT_ADDRESS addr{};
    UINT len = 0;
    while (running.load()) {
        if (!wd.recv(divert, pkt.data(), kBuf, &len, &addr)) {
            DWORD e = GetLastError();
            stats->recv_err.fetch_add(1);
            // F05: a dead capture handle used to break out silently while the
            // UI still said "已连接". Now it is a FAULTED engine state, the
            // UI is told explicitly, and every waiting worker is released.
            if (running.load()) {
                running.store(false);
                connect_gate.WakeAll();
                SetFault(L"WinDivert 捕获已停止 (err=" +
                         std::to_wstring((unsigned long long)e) +
                         L")，数据面不再转发");
            }
            break;
        }
        stats->recv_ok.fetch_add(1);
        WINDIVERT_IPHDR* iph = nullptr;
        WINDIVERT_IPV6HDR* ip6 = nullptr;
        WINDIVERT_TCPHDR* tcph = nullptr;
        WINDIVERT_UDPHDR* udph = nullptr;
        UINT8 proto = 0;
        PVOID data = nullptr;
        UINT dlen = 0;
        PVOID next = nullptr;
        UINT nlen = 0;
        wd.parse(pkt.data(), len, &iph, &ip6, &proto, nullptr, nullptr,
                 &tcph, &udph, &data, &dlen, &next, &nlen);
        if (!iph) {
            // beta0.1.3: IPv6 can NO LONGER be passed through. beta0.1.2's
            // filter was "ip", so EVERY IPv6 packet bypassed the engine and
            // went out natively — that is the egress-IP flap. The phone's
            // SOCKS5 only speaks ATYP=IPv4, so keep LAN-scope IPv6 and drop
            // global IPv6 to force a clean IPv4 fallback (AAAA is also
            // suppressed in the local DNS proxy).
            if (!ip6 || !addr.Outbound || IsIpv6Local(ip6->DstAddr)) {
                WdInject(divert, wd, pkt.data(), len, &addr, L"IPv6 本地放行", 0,
                         stats, log);
                continue;
            }
            stats->ipv6_drop.fetch_add(1);
            continue;  // fail-closed: never leak
        }
        uint32_t dst_ip = iph->DstAddr;          // network order
        uint16_t sport = tcph ? tcph->SrcPort : (udph ? udph->SrcPort : 0);
        uint16_t dport = tcph ? tcph->DstPort : (udph ? udph->DstPort : 0);

        // ---- listener return path (loopback, SrcPort == local_port) ----
        if (tcph && ntohs(sport) == local_port) {
            NatKey key{ntohl(dst_ip), ntohs(dport)};
            NatEntry entry;
            {
                std::lock_guard<std::mutex> lk(nat_mtx);
                auto it = nat.find(key);
                if (it == nat.end()) {
                    stats->blocked.fetch_add(1);  // stray loopback packet
                    WdInject(divert, wd, pkt.data(), len, &addr, L"回环无表项",
                             0, stats, log);
                    continue;
                }
                it->second.last = std::chrono::steady_clock::now();
                entry = it->second;
            }
            // Pin the reply's destination to the app address captured on the
            // first SYN. Previously this used iph->SrcAddr — whatever source
            // INADDR_ANY picked for the listener's reply. With two default
            // routes that address drifts between 192.168.49.74 and 10.0.0.2,
            // so the app got a SYN-ACK addressed to the wrong local IP and
            // immediately reset the connection ("IP 跳动").
            tcph->SrcPort = htons(entry.orig_dst_port);
            iph->DstAddr = entry.app_ip;             // pinned
            iph->SrcAddr = htonl(entry.orig_dst_ip);  // pretend orig server
            addr.Outbound = FALSE;
            addr.Loopback = FALSE;
            addr.Network.IfIdx = entry.if_idx;
            addr.Network.SubIfIdx = entry.sub_if_idx;
            wd.checksums(pkt.data(), len, &addr, 0);
            WdInject(divert, wd, pkt.data(), len, &addr, L"回环反射", 0, stats,
                     log);
            continue;
        }

        // ---- DNS (UDP:53) BEFORE the LAN bypass: with Wi-Fi Direct as the
        // only uplink, the system resolver targets the phone gateway or has
        // no server at all. Relay every query over TCP through the phone's
        // SOCKS5 (DNS-over-TCP, RFC 7766) — no UDP ASSOCIATE needed.
        if (udph && ntohs(dport) == 53 && data && dlen > 0) {
            // vector is copied into the thread — the packet buffer itself
            // must never be referenced after MainLoop moves on
            std::vector<uint8_t> q(static_cast<const uint8_t*>(data),
                                   static_cast<const uint8_t*>(data) + dlen);
            // §5.1: if the app's resolver is the phone itself (Wi-Fi Direct
            // DHCP hands out 192.168.49.1), the phone would have to CONNECT
            // to its own :53 and never answers. Send the query to a public
            // resolver instead, but keep the original address as the reply
            // source so the app's socket still matches.
            uint32_t up = PickDnsUpstream(dst_ip, phone_net);
            if (up != dst_ip && !dns_remap_logged.exchange(true)) {
                log(L"[exp] DNS 上游重定向: " + IpW(dst_ip) +
                    L":53 为手机/私网地址，改用 " + IpW(up) + L":53（回包仍以 " +
                    IpW(dst_ip) + L" 为源）");
            }
            std::atomic<int>* db = &dns_budget;
            auto st = stats;
            auto logfn = log;
            std::string ph = phone8;
            uint16_t pp = cfg.phone_port;
            ExpAuth au = auth;
            std::thread(DnsWorker, divert, wd, ph, pp, au, st, logfn,
                        q, up, dst_ip, dport, iph->SrcAddr,
                        sport, addr.Network.IfIdx, addr.Network.SubIfIdx, db)
                .detach();
            continue;  // captured packet consumed; reply is synthesized
        }

        // ---- policy: never capture LAN/multicast/broadcast ----
        if (IsBypassDst(dst_ip)) {
            WdInject(divert, wd, pkt.data(), len, &addr, L"局域网放行", 0, stats,
                     log);
            continue;
        }

        if (tcph) {
            NatKey key{ntohl(dst_ip), ntohs(sport)};
            bool have = false;
            NatEntry entry;
            auto nat_now = std::chrono::steady_clock::now();
            {
                std::lock_guard<std::mutex> lk(nat_mtx);
                auto it = nat.find(key);
                if (it != nat.end()) {
                    // Plan §6: a stale mapping from a dead flow may be
                    // reclaimed; a LIVE mapping owned by another local
                    // address / destination port must NEVER be reused.
                    bool clash = NatEntryClashes(it->second, iph->SrcAddr,
                                                 ntohs(dport));
                    bool stale = std::chrono::duration_cast<
                        std::chrono::seconds>(nat_now - it->second.last)
                        .count() > 60;
                    if (clash && stale) {
                        nat.erase(it);
                    } else {
                        it->second.last = nat_now;
                        entry = it->second;
                        have = true;
                    }
                }
            }
            if (have && NatEntryClashes(entry, iph->SrcAddr, ntohs(dport))) {
                // Refusing is safe: TCP retransmits the SYN, usually with a
                // different source port, so the next lookup gets a free key.
                uint64_t n = stats->nat_collision.fetch_add(1) + 1;
                if (n <= 3)
                    log(L"[exp] NAT 键碰撞: 拒绝复用 {目标 " + IpW(dst_ip) +
                        L", 源端口 " + std::to_wstring(ntohs(sport)) +
                        L"} 的既有映射（本机地址/目的端口不同），该 SYN 丢弃，" +
                        L"应用将以新源端口重传");
                stats->blocked.fetch_add(1);
                continue;
            }
            if (!have) {
                bool syn = tcph->Syn && !tcph->Ack;
                if (!syn) {
                    // An already-established flow whose SYN we never saw
                    // CANNOT be taken over mid-stream (architecture doc §4).
                    // Passing it through would send it out unproxied — the
                    // egress-IP flap. Drop it; TCP retransmits the SYN and
                    // we then capture that connection cleanly.
                    stats->blocked.fetch_add(1);
                    continue;
                }
                entry.orig_dst_ip = ntohl(dst_ip);
                entry.orig_dst_port = ntohs(dport);
                entry.app_ip = iph->SrcAddr;
                entry.if_idx = addr.Network.IfIdx;
                entry.sub_if_idx = addr.Network.SubIfIdx;
                entry.flow_id = next_flow.fetch_add(1);
                entry.last = std::chrono::steady_clock::now();
                uint64_t flow_id = entry.flow_id;
                {
                    std::lock_guard<std::mutex> lk(nat_mtx);
                    nat[key] = entry;
                }
                log(L"[exp] #" + std::to_wstring(flow_id) + L" 捕获 TCP " +
                    IpW(iph->SrcAddr) + L":" +
                    std::to_wstring(ntohs(sport)) + L" → " +
                    IpW(dst_ip) + L":" + std::to_wstring(ntohs(dport)));
            }
            // Address reflection: the packet becomes INBOUND from the orig
            // server to the app itself, dst port = our local listener.
            // Every packet of the flow is normalised onto the pinned app_ip,
            // so a later OS route change cannot re-address this connection.
            tcph->DstPort = htons(local_port);
            iph->DstAddr = entry.app_ip;             // pinned local address
            iph->SrcAddr = htonl(entry.orig_dst_ip);  // pretend orig server
            addr.Outbound = FALSE;
            addr.Loopback = FALSE;
            addr.Network.IfIdx = entry.if_idx;
            addr.Network.SubIfIdx = entry.sub_if_idx;
            wd.checksums(pkt.data(), len, &addr, 0);
            WdInject(divert, wd, pkt.data(), len, &addr, L"TCP 反射", entry.flow_id,
                     stats, log);
            continue;
        }

        if (udph && data && dlen > 0) {
            // Plan §4.5: UDP:443 is NOT unconditionally dropped any more.
            // Browser QUIC and game traffic both use it; a silent global drop
            // hid game failures behind a "browser just falls back to TCP"
            // assumption. It is now offered to UDP ASSOCIATE like any other
            // datagram. If the phone cannot relay it, the existing
            // fail-closed path drops it — visibly, via udp_assoc_fail /
            // udp_drop, instead of by an invisible special case.
            if (IsQuicPort(ntohs(dport))) {
                uint64_t n = stats->udp443_seen.fetch_add(1) + 1;
                if (n == 1)
                    log(L"[exp] 策略: 检测到 UDP/443（QUIC 或游戏流量）— "
                        L"不再无条件丢弃，交给 SOCKS5 UDP ASSOCIATE 转发；"
                        L"若手机不支持则 fail-closed 丢弃并计入统计");
            }
            uint64_t key = (static_cast<uint64_t>(ntohl(iph->SrcAddr)) << 16) |
                           ntohs(sport);
            std::shared_ptr<UdpSession> sess;
            bool spawn = false;
            bool send_now = false;
            {
                std::lock_guard<std::mutex> lk(udp_mtx);
                auto it = udp.find(key);
                if (it == udp.end()) {
                    // F01: create the session in INITIALIZING and hand the
                    // handshake to a worker. The capture loop NEVER blocks on
                    // the phone here — beta0.1.3 called ExpSocks5UdpAssociate
                    // inline and stalled every TCP SYN / DNS / UDP flow for
                    // as long as the phone took (3–5s under load).
                    auto ns = std::make_shared<UdpSession>();
                    ns->app_ip = iph->SrcAddr;
                    ns->app_port = sport;
                    ns->if_idx = addr.Network.IfIdx;
                    ns->sub_if_idx = addr.Network.SubIfIdx;
                    ns->last = std::chrono::steady_clock::now();
                    ns->state.store(kUdpInit);
                    ns->pending.push_back(UdpPending{
                        dst_ip, dport,
                        std::vector<uint8_t>(
                            static_cast<const uint8_t*>(data),
                            static_cast<const uint8_t*>(data) + dlen)});
                    udp[key] = ns;
                    sess = ns;
                    spawn = true;
                } else {
                    sess = it->second;
                    sess->last = std::chrono::steady_clock::now();
                    int st = sess->state.load();
                    if (st == kUdpReady) {
                        send_now = true;
                    } else if (st == kUdpFailed &&
                               std::chrono::steady_clock::now() >=
                                   sess->retry_at) {
                        // backoff expired: retry the handshake once more
                        sess->state.store(kUdpInit);
                        std::lock_guard<std::mutex> plk(sess->q_mtx);
                        if (sess->pending.size() < kUdpPendingMax)
                            sess->pending.push_back(UdpPending{
                                dst_ip, dport,
                                std::vector<uint8_t>(
                                    static_cast<const uint8_t*>(data),
                                    static_cast<const uint8_t*>(data) + dlen)});
                        else
                            stats->udp_drop.fetch_add(1);
                        spawn = true;
                    } else {
                        // still handshaking (or backing off): bounded queue
                        std::lock_guard<std::mutex> plk(sess->q_mtx);
                        if (sess->pending.size() < kUdpPendingMax)
                            sess->pending.push_back(UdpPending{
                                dst_ip, dport,
                                std::vector<uint8_t>(
                                    static_cast<const uint8_t*>(data),
                                    static_cast<const uint8_t*>(data) + dlen)});
                        else
                            stats->udp_drop.fetch_add(1);
                    }
                }
            }
            if (spawn) {
                std::thread(UdpAssociateWorker, sess, phone8, cfg.phone_port,
                            auth, log, stats, &udp_budget, divert, wd, &running)
                    .detach();
            } else if (send_now) {
                if (ExpSocks5UdpSend(sess->assoc, dst_ip, dport,
                                     static_cast<const uint8_t*>(data),
                                     static_cast<int>(dlen))) {
                    stats->udp_sent.fetch_add(1);
                } else {
                    stats->udp_drop.fetch_add(1);
                    // never reinject: fail-closed, the relay is the only path
                }
            }
            // captured packet is NOT reinjected outbound — it travels via
            // the SOCKS5 relay now
            continue;
        }

        // beta0.1.3: NOTHING that reaches here may leave unproxied. Every
        // public-destination packet must have been consumed by one of the
        // branches above (TCP reflection / DNS relay / UDP relay). Passing
        // it through would be an unproxied egress — the IP flap. Count it as
        // an unhandled packet so the 10s statistics can prove "0 leaks".
        if (!IsBypassDst(dst_ip)) stats->leak.fetch_add(1);
        stats->blocked.fetch_add(1);
        // fail-closed: drop, never reinject
    }
}

// ------------------------------------------------------------ engine API
ExpEngine::ExpEngine(LogFn log, StateFn status)
    : impl_(new Impl()) {
    impl_->log = std::move(log);
    impl_->status = std::move(status);
}

ExpEngine::~ExpEngine() { Stop(); }

bool ExpEngine::Start(const ExpConfig& cfg, std::wstring* error) {
    Impl* I = impl_.get();
    if (I->running.load()) {
        if (error) *error = L"引擎已在运行";
        return false;
    }
    I->cfg = cfg;
    I->state.store(Impl::kStarting);
    I->phone8 = ToUtf8(cfg.phone_ip);
    I->auth.user = ToUtf8(cfg.socks_user);
    I->auth.pass = ToUtf8(cfg.socks_pass);
    if (I->phone8.empty() || cfg.phone_port <= 0) {
        if (error) *error = L"手机 IP/端口无效";
        return false;
    }

    I->status(L"加载 WinDivert…");
    if (!LoadWinDivert(&I->wd, error)) return false;

    // --- SOCKS5 precheck: fail fast with a specific message ---
    I->status(L"检测手机 SOCKS5 认证…");
    std::string perr;
    if (!ExpSocks5Precheck(I->phone8,
                           static_cast<uint16_t>(cfg.phone_port), I->auth,
                           &perr)) {
        if (error) *error = L"手机 SOCKS5 预检失败: " + FromUtf8(perr);
        return false;
    }
    I->log(L"[exp] SOCKS5 认证通过 " + cfg.phone_ip + L":" +
           std::to_wstring(cfg.phone_port));

    // --- G0 gate (plan §11): verify the phone can actually REACH the
    // Internet — a full SOCKS5 CONNECT through the phone to a public DNS
    // endpoint. Auth alone proves nothing about egress. If this fails,
    // WinDivert capture would only create a soft black hole.
    I->status(L"验证手机出口连通（G0）…");
    {
        auto t0 = std::chrono::steady_clock::now();
        std::string gerr;
        uint32_t dns_ip = IpToNet("223.5.5.5");
        SOCKET g = ExpSocks5TcpConnect(
            I->phone8, static_cast<uint16_t>(cfg.phone_port), I->auth,
            dns_ip, htons(53), &gerr);
        if (g == INVALID_SOCKET) {
            if (error)
                *error = L"G0 出口验证失败：手机无法经 SOCKS5 访问公网 (" +
                         FromUtf8(gerr) +
                         L")。请先确认手机数据/上行走廊正常，再启动透明代理。";
            return false;
        }
        closesocket(g);
        int ms = static_cast<int>(std::chrono::duration_cast<
            std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count());
        I->log(L"[exp] G0 出口验证通过（CONNECT 223.5.5.5:53, " +
               std::to_wstring(ms) + L"ms）— 手机可出公网");
    }

    // --- Route DIAGNOSTICS ONLY — the route table is NEVER mutated. ---
    // beta0.1.2 installed 0.0.0.0/1 + 128.0.0.0/1 via the phone. On the
    // test machine those calls failed ("半默认路由添加失败 err 0") while
    // WinDivert still captured 30+ TCP flows: Windows already had two
    // default routes, so the half-routes were unnecessary AND polluted the
    // table. WinDivert NETWORK layer observes every packet Windows routes;
    // we only need to REPORT the uplink, never seize it. This also removes
    // the "路由黑洞" class of failure the architecture doc warns about.
    {
        MIB_IPFORWARDROW phone_row{};
        uint32_t phone_net = IpToNet(I->phone8);
        I->phone_net = phone_net;
        if (GetBestRoute(phone_net, 0, &phone_row) != NO_ERROR) {
            I->log(L"[exp] 找不到到手机的路由 — 请先连接 Wi-Fi Direct");
            if (error) *error = L"本机没有到手机 " + cfg.phone_ip +
                                L" 的路由（Wi-Fi Direct 未连接？）";
            return false;
        }
        MIB_IPFORWARDROW inet_row{};
        uint32_t probe = htonl(0x01010101);  // 1.1.1.1
        DWORD e = GetBestRoute(probe, 0, &inet_row);
        I->phone_only_uplink =
            (e != NO_ERROR) ||
            (inet_row.dwForwardIfIndex == phone_row.dwForwardIfIndex);
        I->uplink_if = (e == NO_ERROR) ? inet_row.dwForwardIfIndex : 0;
        std::wstring legacy = FindLegacyTunAdapter();
        I->log(L"[exp] ENGINE_ROUTE_SNAPSHOT 外网出口 ifIndex=" +
               std::to_wstring(I->uplink_if) +
               L" / 手机链路 ifIndex=" +
               std::to_wstring(phone_row.dwForwardIfIndex) +
               (I->phone_only_uplink
                    ? L" — 同一接口"
                    : L" — 存在其它默认上行") +
               L" / 旧虚拟适配器=" +
               (legacy.empty() ? L"未检测到" : L"「" + legacy + L"」") +
               L"；公网流量全部由 WinDivert 接管，绝不直连放行，不修改路由表");
        if (!legacy.empty())
            I->log(L"[exp] ENGINE_BASELINE_WARN 检测到旧虚拟适配器「" + legacy +
                   L"」仍在系统中，可能污染选路；EXP 只读报告、绝不改动，"
                   L"请在验收前手动确认其默认路由");
    }

    // --- Local DNS proxy + point the phone adapter at 127.0.0.1.
    // The phone's Wi-Fi Direct DHCP offers its own address as the DNS
    // server, but the phone is a SOCKS5 proxy, not a resolver. We run a
    // loopback DNS server and repoint the adapter there; every query is
    // relayed over SOCKS5 (TCP DNS) to a public resolver. (See DnsProxy.)
    if (BackupAdapterDns(I->phone8, &I->dns_backup)) {
        I->dnsproxy.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (I->dnsproxy.sock != INVALID_SOCKET) {
            sockaddr_in la{};
            la.sin_family = AF_INET;
            la.sin_addr.s_addr = inet_addr("127.0.0.1");
            la.sin_port = htons(53);
            if (bind(I->dnsproxy.sock, reinterpret_cast<sockaddr*>(&la),
                     sizeof(la)) == SOCKET_ERROR) {
                closesocket(I->dnsproxy.sock);
                I->dnsproxy.sock = INVALID_SOCKET;
                I->log(L"[exp] 本地 DNS 代理绑定 127.0.0.1:53 失败（端口被占用？）"
                       L" — 保留原 DNS，依赖 WinDivert 拦截转发");
            } else {
                I->dnsproxy.running.store(true);
                I->dnsproxy_thr = std::thread(
                    DnsProxyLoop, &I->dnsproxy, I->phone8,
                    static_cast<uint16_t>(I->cfg.phone_port), I->auth,
                    I->stats, I->log);
                std::wstring name = L"\"" + I->dns_backup.ifname + L"\"";
                bool ok = RunNetsh(L"interface ip set dns name=" + name +
                                   L" static 127.0.0.1 primary");
                I->dns_backup.changed = ok;
                I->log(ok
                    ? L"[exp] 本地 DNS 代理已启动 (127.0.0.1:53)，适配器「" +
                      I->dns_backup.ifname +
                      L"」DNS 已指向 127.0.0.1（断开恢复）"
                    : L"[exp] 127.0.0.1:53 已监听，但适配器 DNS 设置失败 — "
                      L"域名解析可能不可用");
            }
        } else {
            I->log(L"[exp] 创建本地 DNS 代理 socket 失败 — 保留原 DNS");
        }
    } else {
        I->log(L"[exp] 未找到手机适配器（按网关匹配失败）— 保留原 DNS，"
               L"依赖 WinDivert 拦截转发");
    }

    // --- local TCP listener (reflection target) ---
    I->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (I->listener == INVALID_SOCKET) {
        if (error) *error = L"创建本地监听失败";
        return false;
    }
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = INADDR_ANY;
    la.sin_port = 0;
    if (bind(I->listener, reinterpret_cast<sockaddr*>(&la), sizeof(la)) ==
            SOCKET_ERROR ||
        listen(I->listener, SOMAXCONN) == SOCKET_ERROR) {
        if (error) *error = L"本地监听 bind/listen 失败";
        closesocket(I->listener);
        I->listener = INVALID_SOCKET;
        return false;
    }
    int ll = sizeof(la);
    getsockname(I->listener, reinterpret_cast<sockaddr*>(&la), &ll);
    I->local_port = ntohs(la.sin_port);

    // --- capture filter: outbound public traffic + the listener's own
    // packets (loopback return path). The phone IP is excluded at the
    // driver level so the underlay never loops back into the engine.
    // beta0.1.3: capture ALL outbound IPv4 AND IPv6 egress, exempting only
    // loopback and the phone's SOCKS5 endpoint (loop avoidance). beta0.1.2
    // used `ip` only, so every IPv6 packet bypassed the engine and went out
    // natively — with two default routes on this machine that is exactly
    // the unproxied egress that made the public IP flap.
    std::string filter =
        "outbound and !loopback and ip.DstAddr != " + I->phone8 +
        " and (tcp or udp)";
    filter += " or (outbound and !loopback and ipv6)";
    filter += " or (outbound and tcp.SrcPort == " +
              std::to_string(I->local_port) + ")";

    I->status(L"打开 WinDivert 捕获…");
    HANDLE h = I->wd.open(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        std::wstring m;
        if (e == ERROR_ACCESS_DENIED)
            m = L"需要管理员权限（WinDivertOpen ERROR_ACCESS_DENIED）";
        else if (e == ERROR_SERVICE_EXISTS)
            m = L"另一个 WinDivert 实例正在运行（优先级冲突）";
        else if (e == ERROR_INVALID_PARAMETER)
            m = L"过滤表达式无效";
        else
            m = L"WinDivertOpen 失败 err=" + std::to_wstring(e) +
                L"（是否与其他 WFP/VPN 软件冲突？）";
        if (error) *error = m;
        closesocket(I->listener);
        I->listener = INVALID_SOCKET;
        return false;
    }
    I->divert = h;
    I->running.store(true);
    I->state.store(Impl::kRunning);
    I->log(L"[exp] ENGINE_START phone=" + cfg.phone_ip + L":" +
           std::to_wstring(cfg.phone_port) + L" 本地反射端口=" +
           std::to_wstring(I->local_port) + L" 状态=STARTING→RUNNING");

    I->accept_thr = std::thread([I] { I->AcceptLoop(); });
    I->main_thr = std::thread([I] { I->MainLoop(); });
    I->expire_thr = std::thread([I] { I->ExpireLoop(); });

    I->log(L"[exp] ENGINE_RUNNING 数据面已启动: WinDivert 拦截 → 本地反射:" +
           std::to_wstring(I->local_port) + L" → SOCKS5 " + cfg.phone_ip +
           L":" + std::to_wstring(cfg.phone_port) + L"（TCP+UDP）");
    I->status(L"已连接（透明代理运行中 · 无虚拟网卡）");
    return true;
}

void ExpEngine::Stop() {
    Impl* I = impl_.get();
    if (!I) return;
    // beta0.1.3: NO early return. The DNS override and loopback proxy are
    // installed BEFORE running becomes true. If Start failed midway (e.g.
    // WinDivertOpen denied for lack of admin rights), beta0.1.2's early
    // return left the adapter pointing at a now-dead 127.0.0.1:53 — name
    // resolution stayed broken even after "disconnect". Every cleanup step
    // below is idempotent, so always run it.
    I->running.exchange(false);
    I->state.store(Impl::kStopped);
    I->connect_gate.WakeAll();   // F04: release every queued handshake
    I->status(L"断开中…");
    if (I->divert != INVALID_HANDLE_VALUE) {
        I->wd.close(I->divert);
        I->divert = INVALID_HANDLE_VALUE;
    }
    if (I->listener != INVALID_SOCKET) {
        closesocket(I->listener);
        I->listener = INVALID_SOCKET;
    }
    // close all READY UDP associations -> recv threads exit on socket error.
    // An INITIALIZING one is still owned by its handshake worker, which
    // checks the stop flag and closes the association itself.
    {
        std::lock_guard<std::mutex> lk(I->udp_mtx);
        for (auto& kv : I->udp)
            if (kv.second->state.load() == kUdpReady)
                ExpSocks5UdpClose(&kv.second->assoc);
        I->udp.clear();
    }
    // join the three structural threads
    if (I->main_thr.joinable()) I->main_thr.join();
    if (I->accept_thr.joinable()) I->accept_thr.join();
    if (I->expire_thr.joinable()) I->expire_thr.join();
    // detached TCP pumps exit once both of their sockets are closed — close
    // every live session here, then wait for the workers to deregister.
    // CloseOnce is the single owner of the handle: if the worker already
    // closed (or is closing) the same socket, this is a no-op instead of a
    // second closesocket on a possibly recycled number.
    {
        std::lock_guard<std::mutex> lk(I->tcp_reg.mtx);
        for (auto& ts : I->tcp_reg.live) ts->CloseOnce();
    }
    for (int i = 0; i < 50 && I->tcp_budget.load() > 0; ++i) Sleep(100);
    {
        std::lock_guard<std::mutex> lk(I->tcp_reg.mtx);
        I->tcp_reg.live.clear();
    }
    // detached DNS workers and UDP recv threads hold only copied state +
    // shared_ptr stats; wait for them to drain before FreeLibrary
    for (int i = 0; i < 50 && I->dns_budget.load() > 0; ++i) Sleep(100);
    for (int i = 0; i < 50 && I->udp_budget.load() > 0; ++i) Sleep(100);
    // stop the loopback DNS proxy (closing its socket makes the loop exit),
    // then drain the in-flight query workers and close the pooled links.
    if (I->dnsproxy.sock != INVALID_SOCKET) {
        I->dnsproxy.running.store(false);
        closesocket(I->dnsproxy.sock);
        I->dnsproxy.sock = INVALID_SOCKET;
    }
    if (I->dnsproxy_thr.joinable()) I->dnsproxy_thr.join();
    for (int i = 0; i < 50 && I->dnsproxy.budget.load() > 0; ++i) Sleep(100);
    {
        std::lock_guard<std::mutex> lk(I->dnsproxy.pool_mtx);
        for (SOCKET s : I->dnsproxy.pool) closesocket(s);
        I->dnsproxy.pool.clear();
    }
    // restore the adapter DNS configuration we overrode on Start
    if (I->dns_backup.changed) {
        std::wstring name = L"\"" + I->dns_backup.ifname + L"\"";
        if (I->dns_backup.servers.empty() || I->dns_backup.dhcp) {
            // DHCP-advertised DNS returns by itself; forcing "static" here
            // would permanently change a setting the user never touched.
            RunNetsh(L"interface ip set dns name=" + name + L" source=dhcp");
        } else {
            RunNetsh(L"interface ip set dns name=" + name + L" static " +
                     I->dns_backup.servers[0] + L" primary");
            for (size_t k = 1; k < I->dns_backup.servers.size(); ++k)
                RunNetsh(L"interface ip add dns name=" + name + L" " +
                         I->dns_backup.servers[k] + L" index=" +
                         std::to_wstring(k + 1));
        }
        I->dns_backup.changed = false;
        I->log(L"[exp] 适配器 DNS 已恢复原状" +
               std::wstring(I->dns_backup.dhcp ? L"（DHCP 自动获取）"
                                               : L"（原有静态列表）"));
    }
    if (I->wd.dll) { FreeLibrary(I->wd.dll); I->wd = WD{}; }
    I->log(L"[exp] ENGINE_STOP 状态=STOPPED；捕获句柄与 DNS 配置已清理"
           L"（系统路由表未被修改）");
    I->log(L"[exp] 引擎最终统计: 收包 " +
           std::to_wstring(I->stats->recv_ok.load()) + L" / 收包错误 " +
           std::to_wstring(I->stats->recv_err.load()) + L" / 回注成功 " +
           std::to_wstring(I->stats->inject_ok.load()) + L" / 回注失败 " +
           std::to_wstring(I->stats->inject_fail.load()) + L" / NAT 碰撞 " +
           std::to_wstring(I->stats->nat_collision.load()) + L" / 未代理泄漏 " +
           std::to_wstring(I->stats->leak.load()));
    I->status(L"未连接");
}

}  // namespace linkhelm
