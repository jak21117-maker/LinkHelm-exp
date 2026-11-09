// LinkHelm-exp beta0.2.2 — MINIMAL end-to-end self-test.
//
// Design rule (per review): no pure-function / mock / self-attesting asserts.
// Every Check() below crosses a REAL socket boundary against an in-process
// mock "phone" (RFC 1928/1929 SOCKS5 + DNS-over-TCP + UDP echo), and exercises
// the PRODUCTION code (#include of exp_engine.cpp, link of exp_socks5.cpp).
// There are deliberately only a handful of them. A large passing number here
// proves nothing about the WinDivert driver layer — use tests/driver_probe.exe
// (elevated) for that.
//
// WinDivert64.sys is NOT loaded here. Filter semantics are still checked with
// WinDivert.dll's no-driver helper API against the SAME string the product
// builds via BuildCaptureFilter().
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../src/exp_engine.cpp"

using namespace linkhelm;

static std::atomic<int> g_pass{0}, g_fail{0};
static void Check(bool ok, const char* name, const std::string& detail = "") {
    std::printf("[%s] %-56s %s\n", ok ? "PASS" : "FAIL", name,
                detail.c_str());
    if (ok) g_pass.fetch_add(1); else g_fail.fetch_add(1);
}
static bool SendAllT(SOCKET s, const void* p, int n) {
    const char* b = (const char*)p; int done = 0;
    while (done < n) {
        int k = send(s, b + done, n - done, 0);
        if (k <= 0) return false;
        done += k;
    }
    return true;
}
static bool RecvAllT(SOCKET s, void* p, int n) {
    char* b = (char*)p; int done = 0;
    while (done < n) {
        int k = recv(s, b + done, n - done, 0);
        if (k <= 0) return false;
        done += k;
    }
    return true;
}

// ------------------------------------------------------------ mock phone
static const uint16_t kPhonePort = 18080;
static const uint16_t kEchoPort = 19099;   // mock-phone byte-exact echo
static std::atomic<bool> g_phone_on{true};

static std::vector<uint8_t> MockDnsAnswer(const uint8_t* q, int n) {
    std::vector<uint8_t> out;
    if (n < 17) return out;
    int p = 12;
    while (p < n && q[p]) p += 1 + q[p];
    if (p + 5 > n) return out;
    ++p;
    uint16_t qtype = (uint16_t)((q[p] << 8) | q[p + 1]);
    int qlen = p + 4;
    out.assign(q, q + qlen);
    out[2] = 0x81; out[3] = 0x80;
    out[4] = 0; out[5] = 1;
    out[6] = out[7] = out[8] = out[9] = 0;
    if (qtype == 1) {
        out[7] = 1;
        const uint8_t rr[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60,
                              0, 4, 93, 184, 216, 34};
        out.insert(out.end(), rr, rr + sizeof(rr));
    }
    return out;
}

static void UdpRelay(SOCKET udp, SOCKET ctrl) {
    uint8_t buf[65535];
    for (;;) {
        sockaddr_in from{}; int fl = sizeof(from);
        int n = recvfrom(udp, (char*)buf, sizeof(buf), 0,
                         (sockaddr*)&from, &fl);
        if (n < 10) break;
        if (buf[3] != 0x01) continue;
        std::vector<uint8_t> rep{0, 0, 0, 0x01};
        rep.insert(rep.end(), buf + 4, buf + 10);   // original dst ip:port
        rep.insert(rep.end(), buf + 10, buf + n);   // payload echo
        sendto(udp, (const char*)rep.data(), (int)rep.size(), 0,
               (sockaddr*)&from, fl);
    }
    (void)ctrl;
}

static void PhoneConn(SOCKET c) {
    DWORD tmo = 4000;
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
    uint8_t g[2];
    if (!RecvAllT(c, g, 2) || g[0] != 5) { closesocket(c); return; }
    std::vector<uint8_t> methods(g[1]);
    if (!methods.empty() && !RecvAllT(c, methods.data(), (int)methods.size())) {
        closesocket(c); return;
    }
    bool want_auth = std::find(methods.begin(), methods.end(), 0x02) != methods.end();
    uint8_t sel[2] = {0x05, (uint8_t)(want_auth ? 0x02 : 0x00)};
    if (!SendAllT(c, sel, 2)) { closesocket(c); return; }
    if (want_auth) {
        uint8_t v[2];
        if (!RecvAllT(c, v, 2) || v[0] != 1) { closesocket(c); return; }
        std::vector<uint8_t> u(v[1]); uint8_t plen = 0;
        if (!u.empty() && !RecvAllT(c, u.data(), (int)u.size())) {
            closesocket(c); return;
        }
        if (!RecvAllT(c, &plen, 1)) { closesocket(c); return; }
        std::vector<uint8_t> pw(plen);
        if (plen && !RecvAllT(c, pw.data(), plen)) { closesocket(c); return; }
        bool good = std::string(u.begin(), u.end()) == "u" &&
                    std::string(pw.begin(), pw.end()) == "p";
        uint8_t ar[2] = {0x01, (uint8_t)(good ? 0 : 1)};
        if (!SendAllT(c, ar, 2) || !good) { closesocket(c); return; }
    }
    uint8_t req[4];
    if (!RecvAllT(c, req, 4)) { closesocket(c); return; }
    uint8_t cmd = req[1];
    uint32_t dst = 0; uint16_t dport = 0;
    if (req[3] == 0x01) {
        if (!RecvAllT(c, &dst, 4) || !RecvAllT(c, &dport, 2)) {
            closesocket(c); return;
        }
    } else if (req[3] == 0x03) {
        uint8_t l = 0; std::vector<uint8_t> host;
        if (!RecvAllT(c, &l, 1)) { closesocket(c); return; }
        host.resize(l + 1);
        if (!RecvAllT(c, host.data(), l)) { closesocket(c); return; }
        if (!RecvAllT(c, &dport, 2)) { closesocket(c); return; }
        host[l] = 0;
        hostent* h = gethostbyname((char*)host.data());
        if (h) memcpy(&dst, h->h_addr, 4);
    } else { closesocket(c); return; }

    if (cmd == 0x03) {                          // UDP ASSOCIATE
        SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in la{}; la.sin_family = AF_INET;
        la.sin_addr.s_addr = inet_addr("127.0.0.1"); la.sin_port = 0;
        bind(u, (sockaddr*)&la, sizeof(la));
        sockaddr_in bound{}; int bl = sizeof(bound);
        getsockname(u, (sockaddr*)&bound, &bl);
        uint8_t rep[10] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 0};
        memcpy(rep + 8, &bound.sin_port, 2);
        if (!SendAllT(c, rep, 10)) { closesocket(u); closesocket(c); return; }
        std::thread(UdpRelay, u, c).detach();
        char keep[16];
        while (g_phone_on.load()) {
            int k = recv(c, keep, sizeof(keep), 0);
            if (k == 0) break;
            if (k < 0) { Sleep(50); continue; }
        }
        closesocket(u); closesocket(c);
        return;
    }
    if (cmd != 0x01) { closesocket(c); return; }

    // Forced REP=0x05 on port 1 = deterministic proxy refusal (RST test).
    if (ntohs(dport) == 1) {
        uint8_t rep[10] = {5, 5, 0, 1, 0, 0, 0, 0, 0, 0};
        SendAllT(c, rep, 10);
        closesocket(c);
        return;
    }
    // Deterministic byte-exact echo on kEchoPort. The bulk-loopback test
    // pushes a large pseudo-random stream through engine Pump() both ways
    // and compares hashes — the A/B/C/D four-node closed-loop the review
    // demanded (app -> relay -> phone -> relay -> app, byte counts AND
    // content, not just a CONNECT verdict).
    if (ntohs(dport) == kEchoPort) {
        uint8_t ok[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        if (!SendAllT(c, ok, 10)) { closesocket(c); return; }
        static char eb[65536];
        for (;;) {
            int n = recv(c, eb, sizeof(eb), 0);
            if (n <= 0) break;
            if (!SendAllT(c, eb, n)) break;
        }
        closesocket(c);
        return;
    }
    if (ntohs(dport) == 53) {                  // DNS over TCP (RFC 7766)
        uint8_t reply0[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        if (!SendAllT(c, reply0, 10)) { closesocket(c); return; }
        for (;;) {
            uint8_t lb[2];
            if (!RecvAllT(c, lb, 2)) break;
            int qlen = (lb[0] << 8) | lb[1];
            if (qlen <= 0 || qlen > 4096) break;
            std::vector<uint8_t> q((size_t)qlen);
            if (!RecvAllT(c, q.data(), qlen)) break;
            std::vector<uint8_t> a = MockDnsAnswer(q.data(), qlen);
            if (a.empty()) break;
            uint8_t hb[2] = {(uint8_t)(a.size() >> 8), (uint8_t)a.size()};
            if (!SendAllT(c, hb, 2) || !SendAllT(c, a.data(), (int)a.size()))
                break;
        }
        closesocket(c);
        return;
    }

    // Plain CONNECT: real TCP to the real target through the host network.
    SOCKET r = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in sa{}; sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = dst; sa.sin_port = dport;
    DWORD ctmo = 5000;
    setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ctmo, sizeof(ctmo));
    if (connect(r, (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        uint8_t rep[10] = {5, 5, 0, 1, 0, 0, 0, 0, 0, 0};
        SendAllT(c, rep, 10);
        closesocket(r); closesocket(c);
        return;
    }
    uint8_t ok[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    if (!SendAllT(c, ok, 10)) { closesocket(r); closesocket(c); return; }
    // Capture by VALUE; detached threads must not outlive PhoneConn's stack.
    auto alive = std::make_shared<std::atomic<bool>>(true);
    std::thread t1([alive, c, r] {
        char b[8192];
        while (alive->load()) {
            int n = recv(c, b, sizeof(b), 0);
            if (n <= 0) { alive->store(false); shutdown(r, SD_BOTH); break; }
            if (send(r, b, n, 0) <= 0) break;
        }
    });
    char b[8192];
    while (alive->load()) {
        int n = recv(r, b, sizeof(b), 0);
        if (n <= 0) { alive->store(false); shutdown(c, SD_BOTH); break; }
        if (send(c, b, n, 0) <= 0) break;
    }
    alive->store(false);
    shutdown(c, SD_BOTH); shutdown(r, SD_BOTH);
    t1.detach();
    closesocket(r); closesocket(c);
}

static void MockPhone() {
    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{}; a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = htons(kPhonePort);
    if (bind(l, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR ||
        listen(l, 64) == SOCKET_ERROR) {
        std::printf("FATAL: cannot bind mock phone on %d\n", kPhonePort);
        return;
    }
    while (g_phone_on.load()) {
        SOCKET c = accept(l, nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;
        std::thread(PhoneConn, c).detach();
    }
    closesocket(l);
}

// ------------------------------------------------------------- helpers
static std::vector<uint8_t> MakeQuery(const char* host, uint16_t qtype) {
    std::vector<uint8_t> q(12, 0);
    q[0] = 0x12; q[1] = 0x34; q[2] = 0x01; q[5] = 0x01;
    const char* p = host;
    while (*p) {
        const char* dot = strchr(p, '.');
        int n = dot ? (int)(dot - p) : (int)strlen(p);
        q.push_back((uint8_t)n);
        q.insert(q.end(), p, p + n);
        p = dot ? dot + 1 : p + n;
    }
    q.push_back(0);
    q.push_back((uint8_t)(qtype >> 8)); q.push_back((uint8_t)qtype);
    q.push_back(0); q.push_back(1);
    return q;
}
static std::vector<uint8_t> UdpAsk(uint16_t port, const std::vector<uint8_t>& q) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    DWORD tmo = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
    sockaddr_in a{}; a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1"); a.sin_port = htons(port);
    std::vector<uint8_t> r;
    if (sendto(s, (const char*)q.data(), (int)q.size(), 0,
               (sockaddr*)&a, sizeof(a)) == q.size()) {
        uint8_t buf[4096];
        int n = recvfrom(s, (char*)buf, sizeof(buf), 0, nullptr, nullptr);
        if (n > 0) r.assign(buf, buf + n);
    }
    closesocket(s);
    return r;
}
static uint32_t ResolveIpv4(const char* host) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "80", &hints, &res) != 0 || !res) return 0;
    uint32_t ip = ((sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    return ip;
}

// One production TCP session over a real socket pair. Returns the HTTP reply
// bytes the app side received. `dst_port` selects phone behaviour.
static std::string RunSession(uint16_t dst_port, uint32_t dst_ip,
                              const ExpAuth& auth, bool* finalized,
                              int* app_err = nullptr) {
    SOCKET ln = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in la{}; la.sin_family = AF_INET;
    la.sin_addr.s_addr = inet_addr("127.0.0.1"); la.sin_port = 0;
    bind(ln, (sockaddr*)&la, sizeof(la));
    listen(ln, 4);
    sockaddr_in got{}; int gl = sizeof(got);
    getsockname(ln, (sockaddr*)&got, &gl);
    SOCKET app = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    connect(app, (sockaddr*)&got, sizeof(got));
    SOCKET accepted = accept(ln, nullptr, nullptr);
    std::string result;
    if (app != INVALID_SOCKET && accepted != INVALID_SOCKET) {
        auto sess = std::make_shared<TcpSession>();
        sess->client.store(accepted);
        static std::atomic<int> budget{0};
        static TcpRegistry reg;
        static std::atomic<bool> stop_flag{true};
        static auto stats = std::make_shared<EngineStats>();
        static auto logfn = [](const std::wstring&) {};
        sess->budget = &budget;
        budget.fetch_add(1);
        {
            std::lock_guard<std::mutex> lk(reg.mtx);
            reg.live.push_back(sess);
        }
        NatEntry ne{};
        ne.orig_dst_ip = ntohl(dst_ip);
        ne.orig_dst_port = dst_port;
        ne.app_ip = inet_addr("127.0.0.1");
        ne.flow_id = 77;
        std::thread(TcpWorker, sess, ne, std::string("127.0.0.1"),
                    kPhonePort, auth, (uint64_t)77, logfn, &reg, stats,
                    &stop_flag, &budget).detach();
        const char* req = "GET / HTTP/1.0\r\nHost: www.baidu.com\r\n"
                          "Connection: close\r\n\r\n";
        SendAllT(app, req, (int)strlen(req));
        char buf[4096];
        int n = recv(app, buf, sizeof(buf) - 1, 0);
        if (n > 0) { buf[n] = 0; result.assign(buf, (size_t)n); }
        if (app_err) *app_err = (n < 0) ? WSAGetLastError() : 0;
        closesocket(app);
        for (int i = 0; i < 60 && budget.load() > 0; ++i) Sleep(50);
        *finalized = (budget.load() == 0 && reg.live.empty());
    }
    closesocket(ln);
    return result;
}

// Four-node closed-loop evidence (review §04): push `total` pseudo-random
// bytes app -> engine Pump -> mock phone -> engine Pump -> app and compare
// length AND FNV-1a content hash. A/B and C/D are the two pump directions;
// the CONNECT verdict alone (B "手机已接通") proves nothing about C/D, which
// is exactly where the 0.1.8 field run collapsed (↓5.3KB across 18 flows).
static bool RunBulkLoopback(size_t total, const ExpAuth& auth,
                            uint64_t* sent_hash_out,
                            uint64_t* recv_hash_out, size_t* recv_len_out,
                            uint64_t* ms_out) {
    SOCKET ln = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in la{}; la.sin_family = AF_INET;
    la.sin_addr.s_addr = inet_addr("127.0.0.1"); la.sin_port = 0;
    bind(ln, (sockaddr*)&la, sizeof(la));
    listen(ln, 4);
    sockaddr_in got{}; int gl = sizeof(got);
    getsockname(ln, (sockaddr*)&got, &gl);
    SOCKET app = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    bool ok = connect(app, (sockaddr*)&got, sizeof(got)) != SOCKET_ERROR;
    SOCKET accepted = INVALID_SOCKET;
    if (ok) {
        accepted = accept(ln, nullptr, nullptr);
        if (accepted == INVALID_SOCKET) ok = false;
    }
    if (ok) {
        auto sess = std::make_shared<TcpSession>();
        sess->client.store(accepted);
        static std::atomic<int> bulk_budget{0};
        static TcpRegistry bulk_reg;
        static std::atomic<bool> bulk_stop{true};
        static auto bulk_stats = std::make_shared<EngineStats>();
        static auto bulk_log = [](const std::wstring&) {};
        sess->budget = &bulk_budget;
        bulk_budget.fetch_add(1);
        {
            std::lock_guard<std::mutex> lk(bulk_reg.mtx);
            bulk_reg.live.push_back(sess);
        }
        NatEntry ne{};
        ne.orig_dst_ip = 0x7F000001;           // 127.0.0.1 host order
        ne.orig_dst_port = kEchoPort;
        ne.app_ip = inet_addr("127.0.0.1");
        ne.flow_id = 78;
        std::thread(TcpWorker, sess, ne, std::string("127.0.0.1"),
                    kPhonePort, auth, (uint64_t)78, bulk_log,
                    &bulk_reg, bulk_stats, &bulk_stop,
                    &bulk_budget).detach();

        auto t0 = std::chrono::steady_clock::now();
        uint32_t rng = 0x12345678u;
        uint64_t hs = 1469598103934665603ull;  // FNV-1a 64 offset basis
        std::vector<char> chunk(65536);
        size_t left = total;
        while (left > 0) {
            size_t n = left < chunk.size() ? left : chunk.size();
            for (size_t i = 0; i < n; ++i) {
                rng = rng * 1664525u + 1013904223u;
                chunk[i] = (char)(rng >> 24);
                hs ^= (uint8_t)chunk[i];
                hs *= 1099511628211ull;
            }
            if (!SendAllT(app, chunk.data(), (int)n)) { ok = false; break; }
            left -= n;
        }
        // Half-close the upload so the echo terminates: this exercises the
        // pump's clean-EOF propagation (shutdown SD_SEND) end to end.
        shutdown(app, SD_SEND);
        uint64_t hr = 1469598103934665603ull;
        size_t got_len = 0;
        if (ok) {
            char rb[65536];
            for (;;) {
                int n = recv(app, rb, sizeof(rb), 0);
                if (n == 0) break;
                if (n < 0) { ok = false; break; }
                for (int i = 0; i < n; ++i) {
                    hr ^= (uint8_t)rb[i];
                    hr *= 1099511628211ull;
                }
                got_len += (size_t)n;
            }
        }
        *ms_out = (uint64_t)std::chrono::duration_cast<
            std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        *sent_hash_out = hs;
        *recv_hash_out = hr;
        *recv_len_out = got_len;
        closesocket(app);
        for (int i = 0; i < 60 && bulk_budget.load() > 0; ++i) Sleep(50);
        if (bulk_budget.load() != 0) ok = false;
    } else {
        closesocket(app);
    }
    closesocket(ln);
    return ok;
}

// ------------------------------------------------------------------ main
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    // --phone-only: standalone mock SOCKS5 server for socks5_probe.exe.
    if (argc > 1 && std::strcmp(argv[1], "--phone-only") == 0) {
        std::thread(MockPhone).detach();
        std::printf("mock phone listening on 127.0.0.1:%u (auth u:p)\n",
                    (unsigned)kPhonePort);
        for (;;) Sleep(1000);
    }

    std::printf("=== LinkHelm-exp beta0.2.2 end-to-end self-test ===\n");
    std::printf("NOTE: driver-layer capture/reinject is NOT covered here. "
                "Use tests/driver_probe.exe as Administrator on the target PC.\n\n");

    std::thread(MockPhone).detach();
    Sleep(300);
    ExpAuth auth; auth.user = "u"; auth.pass = "p";
    auto logfn = [](const std::wstring&) {};
    auto st = std::make_shared<EngineStats>();

    // 1. Real SOCKS5 handshake: auth accepted, wrong password rejected.
    {
        std::string err;
        bool ok = ExpSocks5Precheck("127.0.0.1", kPhonePort, auth, &err);
        ExpAuth bad; bad.user = "u"; bad.pass = "WRONG";
        std::string e2;
        bool rejected = !ExpSocks5Precheck("127.0.0.1", kPhonePort, bad, &e2);
        Check(ok && rejected, "SOCKS5 RFC1929 handshake (accept + reject)",
              err + " / " + e2);
    }

    // 2. Real HTTP request/response through the phone's SOCKS5 CONNECT.
    uint32_t baidu = ResolveIpv4("www.baidu.com");
    if (baidu) {
        std::string err;
        SOCKET s = ExpSocks5TcpConnect("127.0.0.1", kPhonePort, auth,
                                       baidu, htons(80), &err);
        std::string resp;
        if (s != INVALID_SOCKET) {
            const char* req = "GET / HTTP/1.0\r\nHost: www.baidu.com\r\n"
                              "Connection: close\r\n\r\n";
            if (SendAllT(s, req, (int)strlen(req))) {
                char b[4096]; int n = recv(s, b, sizeof(b) - 1, 0);
                if (n > 0) { b[n] = 0; resp.assign(b, (size_t)n); }
            }
            closesocket(s);
        }
        Check(resp.find("HTTP/1.") != std::string::npos,
              "HTTP bytes cross SOCKS5 CONNECT end-to-end",
              resp.substr(0, 15));
    } else {
        Check(false, "HTTP bytes cross SOCKS5 CONNECT end-to-end",
              "host resolution failed (no network)");
    }

    // 3. Local DNS proxy: real UDP query -> SOCKS5 TCP DNS -> real UDP reply.
    {
        static DnsProxy dp;   // static: detached workers stay valid
        dp.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in la{}; la.sin_family = AF_INET;
        la.sin_addr.s_addr = inet_addr("127.0.0.1");
        la.sin_port = htons(15353);
        bool bound = bind(dp.sock, (sockaddr*)&la, sizeof(la)) != SOCKET_ERROR;
        std::vector<uint8_t> ra, raaaa;
        if (bound) {
            dp.running.store(true);
            std::thread(DnsProxyLoop, &dp, std::string("127.0.0.1"),
                        kPhonePort, auth, st, logfn).detach();
            Sleep(100);
            auto qa = MakeQuery("www.example.com", 1);
            ra = UdpAsk(15353, qa);
            auto qaaaa = MakeQuery("www.example.com", 28);
            raaaa = UdpAsk(15353, qaaaa);
            dp.running.store(false);
            closesocket(dp.sock);
            Sleep(100);
        }
        bool a_ok = ra.size() > 12 && ra[0] == 0x12 && ra[1] == 0x34 &&
                    (ra[3] & 0x0f) == 0 && ((ra[6] << 8) | ra[7]) >= 1;
        bool aaaa_ok = raaaa.size() >= 12 && (raaaa[2] & 0x80) != 0 &&
                       (raaaa[3] & 0x0f) == 0 &&
                       raaaa[6] == 0 && raaaa[7] == 0;
        Check(a_ok, "DNS A query relayed over SOCKS5 (real sockets)",
              "answers=" + std::to_string(ra.size() > 12 ? ((ra[6] << 8) | ra[7]) : -1));
        Check(aaaa_ok, "AAAA suppressed (NOERROR + empty answer)",
              "len=" + std::to_string((int)raaaa.size()));
    }

    // 4. UDP ASSOCIATE round trip with original remote endpoint restored,
    //    after three malformed relay datagrams. This is the field failure
    //    "UDP 回包 freezes while 发送 keeps growing".
    {
        std::string err;
        ExpUdpAssoc a{};
        bool ok = ExpSocks5UdpAssociate("127.0.0.1", kPhonePort, auth, &a, &err);
        std::string echo;
        bool endpoint_ok = false;
        if (ok) {
            sockaddr_in mine{}; int ml = sizeof(mine);
            getsockname(a.udp, (sockaddr*)&mine, &ml);
            sockaddr_in to{}; to.sin_family = AF_INET;
            to.sin_addr.s_addr = inet_addr("127.0.0.1");
            to.sin_port = mine.sin_port;   // 0.0.0.0 is not sendable on Windows
            SOCKET rogue = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            // All four are genuinely unusable: ATYP=domain, FRAG!=0, short,
            // ATYP=IPv6. Each must be SKIPPED, never kill the receive loop.
            std::vector<uint8_t> bad1{0, 0, 0, 0x03, 3, 'a', 'b', 'c',
                                      0, 53, 'x'};
            std::vector<uint8_t> bad2{0, 0, 1, 0x01, 8, 8, 8, 8, 0, 53, 'x'};
            std::vector<uint8_t> bad3{0, 0, 0};
            std::vector<uint8_t> bad4{0, 0, 0, 0x04, 8, 8, 8, 8, 0, 53, 'x'};
            for (auto* d : {&bad1, &bad2, &bad3, &bad4})
                sendto(rogue, (const char*)d->data(), (int)d->size(), 0,
                       (sockaddr*)&to, sizeof(to));
            Sleep(50);
            uint32_t dst = inet_addr("8.8.8.8");
            uint16_t dport = htons(9999);
            const char* msg = "PING-EXP";
            ExpSocks5UdpSend(a, dst, dport, (const uint8_t*)msg,
                             (int)strlen(msg));
            uint8_t back[512]; uint32_t sip = 0; uint16_t sport = 0;
            int n = -1;
            for (int i = 0; i < 8; ++i) {
                n = ExpSocks5UdpRecv(a, &sip, &sport, back, sizeof(back));
                if (ClassifyUdpRecv(n) == UdpRecvDecision::kForward) break;
                if (ClassifyUdpRecv(n) == UdpRecvDecision::kExit) break;
            }
            if (n > 0) echo.assign((char*)back, (size_t)n);
            endpoint_ok = (echo == "PING-EXP" && sip == dst && sport == dport);
            closesocket(rogue);
            ExpSocks5UdpClose(&a);
        }
        Check(ok && endpoint_ok,
              "UDP survives malformed relay packets + restores endpoint",
              ok ? ("echo=" + echo) : err);
    }

    // 5. Production TcpWorker over a real socket pair: HTTP through the
    //    phone, session deregistered. Covers gate, socket options, pumps,
    //    close-reason instrumentation and SessionFinalize in ONE path.
    if (baidu) {
        bool finalized = false;
        std::string resp = RunSession(80, baidu, auth, &finalized);
        Check(resp.find("HTTP/1.") != std::string::npos && finalized,
              "TcpWorker: HTTP round trip + clean session teardown",
              resp.substr(0, 15) + " finalized=" +
                  (finalized ? "yes" : "NO"));
        // 6. Proxy refusal must produce an immediate RST (ProxyBridge
        //    reset_close), not a 5 s application timeout.
        auto t0 = std::chrono::steady_clock::now();
        int app_err = 0;
        bool fin2 = false;
        RunSession(1, baidu, auth, &fin2, &app_err);
        int ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        Check(app_err == WSAECONNRESET && ms < 3000,
              "CONNECT failure -> immediate app-side RST",
              "err=" + std::to_string(app_err) + " " +
                  std::to_string(ms) + "ms");
    }

    // 7. Relay socket options (ProxyBridge configure_tcp_socket): Nagle off,
    //    data-phase timeouts cleared, keep-alive on. Real getsockopt.
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ConfigureRelaySocket(s, true);
        int nd = 0, kl = 0, il = sizeof(int);
        DWORD rt = 999; int rl = sizeof(rt);
        getsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nd, &il);
        getsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&kl, &il);
        getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&rt, &rl);
        Check(nd == 1 && kl == 1 && rt == 0,
              "relay socket: Nagle off, timeouts cleared, keepalive on",
              "nodelay=" + std::to_string(nd) + " keepalive=" +
                  std::to_string(kl) + " rcvtimeo=" + std::to_string(rt));
        closesocket(s);
    }

    // 8. The product's OWN filter string (not a hand-copied test constant):
    //    compiles, captures public IPv4/IPv6, excludes reinjected/impostor
    //    packets and the phone endpoint. No driver needed for these helpers.
    {
        HMODULE dll = LoadLibraryA("dist/WinDivert.dll");
        if (!dll) {
            Check(false, "WinDivert.dll helper API available",
                  "LoadLibrary failed (run from the exp project root)");
        } else {
            typedef BOOL (*CompileFn)(const char*, WINDIVERT_LAYER, char*, UINT,
                                      const char**, UINT*);
            typedef BOOL (*EvalFn)(const char*, const VOID*, UINT,
                                   const WINDIVERT_ADDRESS*);
            auto compile = (CompileFn)GetProcAddress(
                dll, "WinDivertHelperCompileFilter");
            auto eval = (EvalFn)GetProcAddress(dll, "WinDivertHelperEvalFilter");
            std::string f = BuildCaptureFilter("192.168.49.1", 7712);
            const char* es = nullptr; UINT pos = 0;
            bool compiled = compile &&
                compile(f.c_str(), WINDIVERT_LAYER_NETWORK, nullptr, 0,
                        &es, &pos) == TRUE;
            Check(compiled, "product BuildCaptureFilter() compiles",
                  compiled ? f : std::string(es ? es : "no helper") + "@" +
                                  std::to_string(pos));
            if (eval && compiled) {
                uint8_t v4[40] = {0};
                v4[0] = 0x45; v4[3] = 40; v4[9] = 6;
                v4[12] = 192; v4[13] = 168; v4[14] = 49; v4[15] = 74;
                v4[16] = 8; v4[17] = 8; v4[18] = 8; v4[19] = 8;
                // [20..21]=SrcPort [22..23]=DstPort
                v4[22] = 0x01; v4[23] = 0xBB;
                v4[32] = 0x50; v4[33] = 0x02;
                WINDIVERT_ADDRESS ad{}; ad.Outbound = 1;
                WINDIVERT_ADDRESS ad_imp = ad; ad_imp.Impostor = 1;
                WINDIVERT_ADDRESS ad6{}; ad6.Outbound = 1; ad6.IPv6 = 1;
                uint8_t v6[60] = {0};
                v6[0] = 0x60; v6[5] = 20; v6[6] = 6; v6[7] = 64;
                v6[8] = 0x20; v6[9] = 0x01; v6[10] = 0x0D; v6[11] = 0xB8;
                v6[24] = 0x20; v6[25] = 0x01; v6[26] = 0x48; v6[27] = 0x60;
                v6[40] = 0x30; v6[41] = 0x39; v6[42] = 0x01; v6[43] = 0xBB;
                v4[16] = 192; v4[17] = 168; v4[18] = 49; v4[19] = 1;  // phone
                bool excl_phone = eval(f.c_str(), v4, sizeof(v4), &ad) != TRUE;
                v4[16] = 8; v4[17] = 8; v4[18] = 8; v4[19] = 8;
                bool cap4 = eval(f.c_str(), v4, sizeof(v4), &ad) == TRUE;
                bool excl_imp = eval(f.c_str(), v4, sizeof(v4), &ad_imp) != TRUE;
                bool cap6 = eval(f.c_str(), v6, sizeof(v6), &ad6) == TRUE;
                Check(cap4 && cap6 && excl_imp && excl_phone,
                      "filter captures IPv4+IPv6, excludes impostor+phone",
                      "v4=" + std::to_string(cap4) + " v6=" +
                          std::to_string(cap6) + " impostor=" +
                          std::to_string(excl_imp) + " phone=" +
                          std::to_string(excl_phone));

                // beta0.2.2 (§06): DNS to the PHONE must be captured so the
                // "WinDivert intercepts DNS" fallback is reachable. The old
                // filter excluded the whole phone IP, which made that
                // fallback unreachable by construction -> NCSI flickered.
                // IPv4 header: [12..15]=SrcAddr [16..19]=DstAddr [20..21]=SrcPort
                // [22..23]=DstPort (same offsets for TCP and UDP).
                v4[16] = 192; v4[17] = 168; v4[18] = 49; v4[19] = 1;  // phone
                v4[9] = 17;                                             // UDP
                v4[22] = 0x00; v4[23] = 0x35;                          // DstPort 53
                bool cap_phone_dns = eval(f.c_str(), v4, sizeof(v4), &ad) == TRUE;
                // ... but TCP to the phone's SOCKS5 port must NOT be captured
                // (it is the underlay; capturing it would proxy the proxy).
                v4[9] = 6;                                             // TCP
                v4[22] = 0x1F; v4[23] = 0x90;                          // DstPort 8080
                bool excl_phone_socks = eval(f.c_str(), v4, sizeof(v4), &ad) != TRUE;
                Check(cap_phone_dns && excl_phone_socks,
                      "filter: phone UDP/53 captured (DNS fallback reachable),"
                      " phone TCP/SOCKS5 excluded (no proxy loop)",
                      "phone_dns=" + std::to_string(cap_phone_dns) +
                          " phone_socks=" + std::to_string(excl_phone_socks));

                // beta0.2.2 (§05): a PUBLIC service on port 8080 must be
                // captured. The old code bypassed ANY port-8080 traffic
                // (including public :8080), which sent it out through the
                // native route — an unproxied egress, i.e. "public IP
                // flapping".
                v4[16] = 203; v4[17] = 0; v4[18] = 113; v4[19] = 10;  // public
                v4[22] = 0x1F; v4[23] = 0x90;                          // DstPort 8080
                bool cap_public_8080 = eval(f.c_str(), v4, sizeof(v4), &ad) == TRUE;
                Check(cap_public_8080,
                      "filter: public :8080 IS captured (not bypassed by port)",
                      std::to_string(cap_public_8080));
            }
            FreeLibrary(dll);
        }
    }

    // 9. beta0.2.2: the ConnectGate is GONE (ProxyBridge architecture — no
    //    local admission queue). Its policy assertions died with it; the
    //    failure path is covered by test 10 (refusal classification) and
    //    the RST-on-failure behaviour of TcpWorker itself.

    // 10. SOCKS5 failure classification (report §04): a REFUSED connection
    //     must NOT be reported as a timeout. The field log claimed
    //     "phone SOCKS5 unreachable (timeout)" at 532ms with a 3000ms
    //     budget, because select()'s exception set was lumped in.
    {
        std::string err;
        // Port 1 on loopback is not listening -> the connection is REFUSED.
        SOCKET s = ExpSocks5TcpConnect("127.0.0.1", 1, ExpAuth{"u", "p"},
                                       inet_addr("1.2.3.4"), htons(80),
                                       &err);
        Check(s == INVALID_SOCKET &&
                  err.find("TCP_CONNECT_FAILED") != std::string::npos,
              "SOCKS5 dial: refused connection is classified, not 'timeout'",
              err);
        if (s != INVALID_SOCKET) closesocket(s);
    }

    // 11. Four-node byte-exact closed loop (review §04). A CONNECT verdict
    //     ("手机已接通") proves nothing about the data path: the 0.1.8 field
    //     run recorded 18 successful CONNECTs but only ↓5.3KB of payload.
    //     1 KB checks correctness; 1 MB checks throughput (128 KB pump
    //     buffer) and clean half-close teardown in BOTH directions.
    {
        for (size_t total : {static_cast<size_t>(1024),
                             static_cast<size_t>(1024 * 1024)}) {
            uint64_t hs = 0, hr = 0, ms = 0;
            size_t got = 0;
            bool done = RunBulkLoopback(total, auth, &hs, &hr, &got, &ms);
            std::string name = "bulk loopback " + std::to_string(total) +
                               "B: app->pump->phone->pump->app byte-exact";
            Check(done && got == total && hs == hr, name.c_str(),
                  "sent=" + std::to_string(total) + " recv=" +
                      std::to_string(got) + " hash_match=" +
                      std::to_string(hs == hr) + " " + std::to_string(ms) +
                      "ms");
        }
    }

    // 12. DNS positive cache (beta0.2.2): a stored reply is served fresh
    //     with the NEW query's transaction ID, negative replies (RCODE!=0)
    //     are never cached, and malformed queries are ignored safely.
    {
        DnsCache c;
        // query: example.com A, ID 0x1111
        std::vector<uint8_t> q = {0x11,0x11, 0x01,0x00, 0,1, 0,0, 0,0, 0,0,
                                  7,'e','x','a','m','p','l','e',
                                  3,'c','o','m', 0, 0,1, 0,1};
        // reply: NOERROR, 1 A answer, TTL 120s, ID 0x2222 (as received)
        std::vector<uint8_t> r = {0x22,0x22, 0x81,0x80, 0,1, 0,1, 0,0, 0,0,
                                  7,'e','x','a','m','p','l','e',
                                  3,'c','o','m', 0, 0,1, 0,1,
                                  0xC0,0x0C, 0,1, 0,1, 0,0,0,120, 0,4,
                                  1,2,3,4};
        DnsCacheStore(&c, q, r);
        // second query: same name/type, different ID
        std::vector<uint8_t> q2 = q;
        q2[0] = 0xAB; q2[1] = 0xCD;
        std::vector<uint8_t> out; bool stale = false;
        bool hit = DnsCacheLookup(&c, q2, &out, &stale);
        Check(hit && !stale && out.size() == r.size() && out[0] == 0xAB &&
                  out[1] == 0xCD && out[41] == 1 && out[42] == 2 &&
                  out[43] == 3 && out[44] == 4,
              "DNS cache: fresh hit serves with the new transaction ID",
              "hit=" + std::to_string(hit) + " stale=" +
                  std::to_string(stale) + " size=" +
                  std::to_string(out.size()));
        // negative reply (NXDOMAIN, an=0) must NOT be cached
        DnsCache c2;
        std::vector<uint8_t> neg = {0x33,0x33, 0x81,0x83, 0,1, 0,0, 0,0, 0,0,
                                    7,'e','x','a','m','p','l','e',
                                    3,'c','o','m', 0, 0,1, 0,1};
        DnsCacheStore(&c2, q, neg);
        std::vector<uint8_t> out2; bool stale2 = false;
        bool hit2 = DnsCacheLookup(&c2, q, &out2, &stale2);
        Check(!hit2, "DNS cache: negative (RCODE!=0) replies are never cached",
              "unexpected_hit=" + std::to_string(hit2));
    }

    std::printf("\n=== RESULT: %d passed, %d failed ===\n",
                g_pass.load(), g_fail.load());
    int rc = g_fail.load() == 0 ? 0 : 1;
    g_phone_on.store(false);
    Sleep(150);
    std::fflush(stdout);
    // Detached mock-phone/pump threads must not outlive main: their late
    // pthread_create calls otherwise throw during CRT teardown.
    ExitProcess((UINT)rc);
    return rc;
}
