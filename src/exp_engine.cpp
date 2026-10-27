// LinkHelm-exp — WinDivert + SOCKS5 transparent data plane implementation.
// See exp_engine.h for the architecture summary.
//
// Provenance: the TCP "address reflection" scheme follows okatodev/wfp-divert
// (MIT, vendored under wfp-divert-ref/) with the plan document's P0 fixes:
//   - RFC 1929 username/password auth (method 0x02)
//   - no global lock held across the UDP ASSOCIATE handshake
//   - relay endpoint validation on every UDP reply
//   - fail-open for traffic we fail to proxy (reinject unchanged)
// WinDivert itself is loaded dynamically (LoadLibrary) — no import lib.
#include "exp_engine.h"

#include "exp_socks5.h"

// NOTE: all libstdc++ headers MUST come before the Windows/SAL headers —
// sal.h `#define __out` (and friends) poisons STL internals otherwise.
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
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
    uint32_t if_idx = 0;
    uint32_t sub_if_idx = 0;
    std::chrono::steady_clock::time_point last;
};

// -------------------------------------------------------------- TCP session
struct TcpSession {
    SOCKET client = INVALID_SOCKET;  // accepted (reflected) socket
    SOCKET remote = INVALID_SOCKET;  // SOCKS5 socket to the phone
    std::atomic<int>* budget = nullptr;
};

void Pump(TcpSession* s, int from, const std::atomic<bool>* running) {
    SOCKET src = from == 0 ? s->client : s->remote;
    SOCKET dst = from == 0 ? s->remote : s->client;
    char buf[16384];
    DWORD tmo = 1000;
    setsockopt(src, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    while (running->load()) {
        int n = recv(src, buf, sizeof(buf), 0);
        if (n > 0) {
            int sent = 0;
            bool broken = false;
            while (sent < n) {
                int r = send(dst, buf + sent, n - sent, 0);
                if (r <= 0) { broken = true; break; }
                sent += r;
            }
            if (broken) break;
        } else {
            int e = WSAGetLastError();
            if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) continue;
            break;
        }
    }
    shutdown(s->client, SD_BOTH);
    shutdown(s->remote, SD_BOTH);
}

void TcpWorker(std::shared_ptr<TcpSession> s, NatEntry entry,
               const std::string& phone_ip, uint16_t phone_port,
               const ExpAuth& auth, std::mutex* log_mtx,
               const std::function<void(const std::wstring&)>& log,
               const std::atomic<bool>* running, std::string* loop_err) {
    std::string err;
    s->remote = ExpSocks5TcpConnect(phone_ip, phone_port, auth,
                                    htonl(entry.orig_dst_ip),
                                    htons(entry.orig_dst_port), &err);
    if (s->remote == INVALID_SOCKET) {
        // Surface the failure to the app as an immediate disconnect (never
        // fake "connected"): the plan document's observable-failure rule.
        {
            std::lock_guard<std::mutex> lk(*log_mtx);
            if (!loop_err->empty()) *loop_err = err;
        }
        log(L"[exp] SOCKS5 CONNECT 失败: " + FromUtf8(err) + L" → " +
            IpW(htonl(entry.orig_dst_ip)) + L":" +
            std::to_wstring(entry.orig_dst_port));
        closesocket(s->client);
        if (s->budget) s->budget->fetch_sub(1);
        return;
    }
    std::thread t1(Pump, s.get(), 0, running);
    std::thread t2(Pump, s.get(), 1, running);
    t1.join();
    t2.join();
    closesocket(s->client);
    closesocket(s->remote);
    if (s->budget) s->budget->fetch_sub(1);
}

// -------------------------------------------------------------- UDP session
struct UdpSession {
    ExpUdpAssoc assoc;
    uint32_t app_ip = 0;     // network order
    uint16_t app_port = 0;   // network order
    uint32_t if_idx = 0;
    uint32_t sub_if_idx = 0;
    std::chrono::steady_clock::time_point last;
};

void UdpRecvThread(HANDLE divert, WD wd, std::shared_ptr<UdpSession> sess,
                   const std::atomic<bool>* running) {
    uint8_t payload[65535];
    while (running->load()) {
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
        UINT sl = 0;
        wd.send(divert, pkt.data(), (UINT)psz, &sl, &addr);
    }
}

// ------------------------------------------------------------- half routes
bool AddHalfRoute(DWORD if_idx, uint32_t phone_net, uint32_t dest_net,
                  uint32_t mask, MIB_IPFORWARDROW* out) {
    MIB_IPFORWARDROW r{};
    r.dwForwardDest = dest_net;
    r.dwForwardMask = mask;
    r.dwForwardPolicy = 0;
    r.dwForwardNextHop = phone_net;
    r.dwForwardType = 4;             // NlRouteTypeGateway-ish (indirect)
    r.dwForwardProto = MIB_IPPROTO_NETMGMT;
    r.dwForwardAge = 0;
    r.dwForwardNextHopAS = 0;
    r.dwForwardMetric1 = 1;
    r.dwForwardMetric2 = (DWORD)-1;
    r.dwForwardMetric3 = (DWORD)-1;
    r.dwForwardMetric4 = (DWORD)-1;
    r.dwForwardMetric5 = (DWORD)-1;
    if (CreateIpForwardEntry(&r) != NO_ERROR) return false;
    *out = r;
    (void)if_idx;
    return true;
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
    bool udp_warned = false;

    std::atomic<int> tcp_budget{0};
    std::mutex log_mtx;
    std::string last_tcp_err;

    ExpAuth auth;
    std::string phone8;

    // routes we added (and must remove on Stop)
    bool route_added = false;
    MIB_IPFORWARDROW route_rows[2]{};

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
        s->client = cs;
        s->budget = &tcp_budget;
        std::thread(TcpWorker, s, entry, phone8, cfg.phone_port, auth,
                    &log_mtx, log, &running, &last_tcp_err).detach();
    }
    closesocket(listener);
    listener = INVALID_SOCKET;
}

void ExpEngine::Impl::ExpireLoop() {
    while (running.load()) {
        for (int i = 0; i < 10 && running.load(); ++i)
            Sleep(100);
        if (!running.load()) break;
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
        for (auto& s : dead) ExpSocks5UdpClose(&s->assoc);  // recv thread exits
    }
}

void ExpEngine::Impl::MainLoop() {
    constexpr UINT kBuf = 65535 + 40;
    std::vector<uint8_t> pkt(kBuf);
    WINDIVERT_ADDRESS addr{};
    UINT len = 0;
    while (running.load()) {
        if (!wd.recv(divert, pkt.data(), kBuf, &len, &addr)) {
            if (running.load())
                log(L"[exp] WinDivertRecv 失败 err=" +
                    std::to_wstring(GetLastError()));
            break;
        }
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
        if (!iph) {  // IPv6 or malformed — never our target, pass through
            wd.send(divert, pkt.data(), len, nullptr, &addr);
            continue;
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
                    wd.send(divert, pkt.data(), len, nullptr, &addr);
                    continue;
                }
                entry = it->second;
                entry.last = std::chrono::steady_clock::now();
            }
            uint32_t tmp = iph->DstAddr;
            tcph->SrcPort = htons(entry.orig_dst_port);
            iph->DstAddr = iph->SrcAddr;   // -> app
            iph->SrcAddr = tmp;            // <- orig server
            addr.Outbound = FALSE;
            addr.Loopback = FALSE;
            addr.Network.IfIdx = entry.if_idx;
            addr.Network.SubIfIdx = entry.sub_if_idx;
            wd.checksums(pkt.data(), len, &addr, 0);
            wd.send(divert, pkt.data(), len, nullptr, &addr);
            continue;
        }

        // ---- policy: never capture LAN/multicast/broadcast ----
        if (IsBypassDst(dst_ip)) {
            wd.send(divert, pkt.data(), len, nullptr, &addr);
            continue;
        }

        if (tcph) {
            NatKey key{ntohl(dst_ip), ntohs(sport)};
            bool have = false;
            NatEntry entry;
            {
                std::lock_guard<std::mutex> lk(nat_mtx);
                auto it = nat.find(key);
                if (it != nat.end()) { entry = it->second; have = true;
                                       entry.last = std::chrono::steady_clock::now(); }
            }
            if (!have) {
                bool syn = tcph->Syn && !tcph->Ack;
                if (!syn) {  // established flow we never saw — pass through
                    wd.send(divert, pkt.data(), len, nullptr, &addr);
                    continue;
                }
                entry.orig_dst_ip = ntohl(dst_ip);
                entry.orig_dst_port = ntohs(dport);
                entry.if_idx = addr.Network.IfIdx;
                entry.sub_if_idx = addr.Network.SubIfIdx;
                entry.last = std::chrono::steady_clock::now();
                std::lock_guard<std::mutex> lk(nat_mtx);
                nat[key] = entry;
                log(L"[exp] TCP " + IpW(iph->SrcAddr) + L":" +
                    std::to_wstring(ntohs(sport)) + L" → " +
                    IpW(dst_ip) + L":" + std::to_wstring(ntohs(dport)));
            }
            // Address reflection: the packet becomes INBOUND from the orig
            // server to the app itself, dst port = our local listener.
            uint32_t tmp = iph->DstAddr;
            tcph->DstPort = htons(local_port);
            iph->DstAddr = iph->SrcAddr;
            iph->SrcAddr = tmp;
            addr.Outbound = FALSE;
            addr.Loopback = FALSE;
            wd.checksums(pkt.data(), len, &addr, 0);
            wd.send(divert, pkt.data(), len, nullptr, &addr);
            continue;
        }

        if (udph && data && dlen > 0) {
            uint64_t key = (static_cast<uint64_t>(ntohl(iph->SrcAddr)) << 16) |
                           ntohs(sport);
            std::shared_ptr<UdpSession> sess;
            bool found = false;
            {
                std::lock_guard<std::mutex> lk(udp_mtx);
                auto it = udp.find(key);
                if (it != udp.end()) { sess = it->second; found = true;
                                       sess->last = std::chrono::steady_clock::now(); }
            }
            if (!found) {
                auto ns = std::make_shared<UdpSession>();
                ns->app_ip = iph->SrcAddr;
                ns->app_port = sport;
                ns->if_idx = addr.Network.IfIdx;
                ns->sub_if_idx = addr.Network.SubIfIdx;
                ns->last = std::chrono::steady_clock::now();
                std::string err;
                // NOTE (plan P0 fix): the ASSOCIATE handshake runs OUTSIDE
                // the global lock — a slow phone handshake cannot stall
                // other UDP flows' creation.
                if (!ExpSocks5UdpAssociate(phone8, cfg.phone_port, auth,
                                           &ns->assoc, &err)) {
                    if (!udp_warned) {
                        udp_warned = true;
                        log(L"[exp] UDP ASSOCIATE 失败: " + FromUtf8(err) +
                            L" — UDP 将保持直连放行（fail-open）");
                    }
                    wd.send(divert, pkt.data(), len, nullptr, &addr);
                    continue;
                }
                std::lock_guard<std::mutex> lk(udp_mtx);
                auto it = udp.find(key);
                if (it != udp.end()) {  // raced: another thread won
                    ExpSocks5UdpClose(&ns->assoc);
                    sess = it->second;
                } else {
                    udp[key] = ns;
                    sess = ns;
                    std::thread(UdpRecvThread, divert, wd, sess,
                                &running).detach();
                }
            }
            if (!ExpSocks5UdpSend(sess->assoc, dst_ip, dport,
                                  static_cast<const uint8_t*>(data),
                                  static_cast<int>(dlen))) {
                // fail-open on transient send failure
                wd.send(divert, pkt.data(), len, nullptr, &addr);
            }
            // captured packet is NOT reinjected outbound — it travels via
            // the SOCKS5 relay now
            continue;
        }

        // anything else (e.g. UDP with no payload) passes through
        wd.send(divert, pkt.data(), len, nullptr, &addr);
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

    // --- ROUTE-00 gate: WinDivert can only capture packets that Windows
    // actually routes. Without any default route, Internet-bound packets
    // are dropped BEFORE the NETWORK layer and nothing can be transparent.
    // Fix: half-routes (0.0.0.0/1 + 128.0.0.0/1) via the phone, on the same
    // interface that reaches the phone. Never touches the real default
    // route entry; removed on Stop. NCSI probes then succeed through the
    // capture path, so the REAL Wi-Fi adapter shows Internet access.
    I->route_added = false;
    {
        PMIB_IPFORWARDROW pr = nullptr;
        MIB_IPFORWARDROW phone_row{};
        uint32_t phone_net = IpToNet(I->phone8);
        if (GetBestRoute(phone_net, 0, &phone_row) == NO_ERROR) {
            MIB_IPFORWARDROW inet_row{};
            uint32_t probe = htonl(0x01010101);  // 1.1.1.1
            if (GetBestRoute(probe, 0, &inet_row) != NO_ERROR ||
                inet_row.dwForwardIfIndex != phone_row.dwForwardIfIndex) {
                // Internet traffic does not ride the phone link — add the
                // two half routes so packets exist (and NCSI passes on the
                // real adapter).
                bool ok1 = AddHalfRoute(phone_row.dwForwardIfIndex,
                                        phone_net, 0, htonl(0x80000000),
                                        &I->route_rows[0]);
                bool ok2 = AddHalfRoute(phone_row.dwForwardIfIndex,
                                        phone_net, htonl(0x80000000),
                                        htonl(0x80000000), &I->route_rows[1]);
                I->route_added = ok1 && ok2;
                I->log(ok1 && ok2
                    ? L"[exp] 无默认路由经手机链路 — 已加 0.0.0.0/1 + 128.0.0.0/1 经 " +
                          cfg.phone_ip + L"（断开时自动移除）"
                    : L"[exp] 半默认路由添加失败（err " +
                          std::to_wstring(GetLastError()) +
                          L"）— 若系统无默认路由，外网流量将无法被截获");
            } else {
                I->log(L"[exp] 默认路由已经由手机链路 — 无需添加路由");
            }
        } else {
            I->log(L"[exp] 找不到到手机的路由 — 请先连接 Wi-Fi Direct");
            if (error) *error = L"本机没有到手机 " + cfg.phone_ip +
                                L" 的路由（Wi-Fi Direct 未连接？）";
            return false;
        }
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
    std::string filter =
        "outbound and !loopback and ip.DstAddr != " + I->phone8 +
        " and (tcp or udp)";
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
        if (I->route_added) {
            DeleteIpForwardEntry(&I->route_rows[0]);
            DeleteIpForwardEntry(&I->route_rows[1]);
            I->route_added = false;
        }
        return false;
    }
    I->divert = h;
    I->running.store(true);

    I->accept_thr = std::thread([I] { I->AcceptLoop(); });
    I->main_thr = std::thread([I] { I->MainLoop(); });
    I->expire_thr = std::thread([I] { I->ExpireLoop(); });

    I->log(L"[exp] 数据面已启动: WinDivert 拦截 → 本地反射:" +
           std::to_wstring(I->local_port) + L" → SOCKS5 " + cfg.phone_ip +
           L":" + std::to_wstring(cfg.phone_port) + L"（TCP+UDP）");
    I->status(L"已连接（透明代理运行中 · 无虚拟网卡）");
    return true;
}

void ExpEngine::Stop() {
    Impl* I = impl_.get();
    if (!I->running.exchange(false)) {
        // still clean any routes a previous hard-killed session left
        return;
    }
    I->status(L"断开中…");
    if (I->divert != INVALID_HANDLE_VALUE) {
        I->wd.close(I->divert);
        I->divert = INVALID_HANDLE_VALUE;
    }
    if (I->listener != INVALID_SOCKET) {
        closesocket(I->listener);
        I->listener = INVALID_SOCKET;
    }
    // close all UDP associations -> recv threads exit
    {
        std::lock_guard<std::mutex> lk(I->udp_mtx);
        for (auto& kv : I->udp) ExpSocks5UdpClose(&kv.second->assoc);
        I->udp.clear();
    }
    // join the three structural threads
    if (I->main_thr.joinable()) I->main_thr.join();
    if (I->accept_thr.joinable()) I->accept_thr.join();
    if (I->expire_thr.joinable()) I->expire_thr.join();
    // detached TCP pumps exit on their next 1s recv tick once both sockets
    // are closed; give them a moment so Impl never outlives a touching
    // thread (sessions own no Impl state after this wait).
    for (int i = 0; i < 30 && I->tcp_budget.load() > 0; ++i) Sleep(100);
    if (I->route_added) {
        DeleteIpForwardEntry(&I->route_rows[0]);
        DeleteIpForwardEntry(&I->route_rows[1]);
        I->route_added = false;
        I->log(L"[exp] 半默认路由已移除，系统路由恢复原状");
    }
    if (I->wd.dll) { FreeLibrary(I->wd.dll); I->wd = WD{}; }
    I->log(L"[exp] 已断开，捕获句柄与路由全部清理");
    I->status(L"未连接");
}

}  // namespace linkhelm
