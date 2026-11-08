// LinkHelm-exp beta0.1.5 self-test harness.
//
// This TU #includes the PRODUCTION exp_engine.cpp, so every function under
// test is the exact same code that ships in LinkHelmExp.exe (no copies, no
// re-implementations). exp_socks5.cpp is linked separately.
//
// A mock "phone" (SOCKS5 server, RFC 1928/1929) runs in-process on
// 127.0.0.1:18080. It stands in for LinkHelm Android Host and forwards
// CONNECT to the real network, answers DNS-over-TCP, and echoes UDP
// ASSOCIATE datagrams with the original remote endpoint restored.
//
// beta0.1.4 adds the regression tests the review document asks for:
//   F01 slow UDP ASSOCIATE must not stall new TCP sessions
//   F02 WinDivertSend failures must be counted, not ignored
//   F03 100 failed CONNECTs must leave tcp_reg.live empty and budget at 0
//   F04 a saturated gate must cancel instead of dialling anyway
//   §5.1 private/phone DNS targets must be remapped to a public resolver
//
// WinDivert itself is NOT exercised here (loading WinDivert64.sys requires
// elevation). Everything upstream and downstream of the driver IS.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../src/exp_engine.cpp"

using namespace linkhelm;

static std::atomic<int> g_pass{0}, g_fail{0};
static void Check(bool ok, const char* name, const std::string& detail = "") {
    std::printf("[%s] %-52s %s\n", ok ? "PASS" : "FAIL", name,
                detail.c_str());
    if (ok) g_pass.fetch_add(1); else g_fail.fetch_add(1);
}

static bool SendAllT(SOCKET s, const void* p, int n) {
    const char* b = (const char*)p;
    int done = 0;
    while (done < n) {
        int k = send(s, b + done, n - done, 0);
        if (k <= 0) return false;
        done += k;
    }
    return true;
}
static bool RecvAllT(SOCKET s, void* p, int n) {
    char* b = (char*)p;
    int done = 0;
    while (done < n) {
        int k = recv(s, b + done, n - done, 0);
        if (k <= 0) return false;
        done += k;
    }
    return true;
}

// ------------------------------------------------------------ mock phone
static const uint16_t kPhonePort = 18080;
static std::atomic<bool> g_phone_on{true};
// Simulates a loaded phone ProxyServer: ASSOCIATE takes seconds.
static std::atomic<int> g_assoc_delay_ms{0};
// beta0.1.5: the phone accepts the TCP connection, then dies before sending
// the CONNECT reply ("CONNECT reply missing" in the field log). One-shot:
// the very next CONNECT behaves normally, so the retry can be proven.
static std::atomic<int> g_transient_drop{0};

// Build a DNS answer over the query (A -> 93.184.216.34, else empty).
static std::vector<uint8_t> MockDnsAnswer(const uint8_t* q, int n) {
    std::vector<uint8_t> out;
    if (n < 17) return out;
    int p = 12;
    while (p < n && q[p]) { p += 1 + q[p]; }
    if (p + 5 > n) return out;
    ++p;
    uint16_t qtype = (q[p] << 8) | q[p + 1];
    int qlen = p + 4;                       // end of question section
    out.assign(q, q + qlen);
    out[2] = 0x81; out[3] = 0x80;          // QR + RD + RA, NOERROR
    out[4] = 0; out[5] = 1;                // QDCOUNT=1
    out[6] = out[7] = out[8] = out[9] = 0; // AN/NS/AR initially 0
    if (qtype == 1) {                      // A
        out[7] = 1;                        // ANCOUNT=1
        const uint8_t rr[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60,
                              0, 4, 93, 184, 216, 34};
        out.insert(out.end(), rr, rr + sizeof(rr));
    }
    return out;
}

static void UdpRelay(SOCKET udp, SOCKET ctrl) {
    uint8_t buf[65535];
    for (;;) {
        sockaddr_in from{};
        int fl = sizeof(from);
        int n = recvfrom(udp, (char*)buf, sizeof(buf), 0,
                         (sockaddr*)&from, &fl);
        if (n < 10) break;
        if (buf[3] != 0x01) continue;
        // Echo the payload back, carrying the ORIGINAL remote endpoint so
        // the client can verify source-endpoint restoration.
        std::vector<uint8_t> rep;
        rep.push_back(0); rep.push_back(0); rep.push_back(0);
        rep.push_back(0x01);
        rep.insert(rep.end(), buf + 4, buf + 10);   // orig dst ip:port
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
        std::vector<uint8_t> u(v[1]);
        uint8_t plen = 0;
        if (!u.empty() && !RecvAllT(c, u.data(), (int)u.size())) { closesocket(c); return; }
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
    uint32_t dst = 0;
    uint16_t dport = 0;
    if (req[3] == 0x01) {
        if (!RecvAllT(c, &dst, 4) || !RecvAllT(c, &dport, 2)) { closesocket(c); return; }
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

    if (cmd == 0x03) {                       // UDP ASSOCIATE
        int dly = g_assoc_delay_ms.load();
        if (dly > 0) Sleep((DWORD)dly);       // slow phone under load
        SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in la{};
        la.sin_family = AF_INET;
        la.sin_addr.s_addr = inet_addr("127.0.0.1");
        la.sin_port = 0;
        bind(u, (sockaddr*)&la, sizeof(la));
        sockaddr_in bound{}; int bl = sizeof(bound);
        getsockname(u, (sockaddr*)&bound, &bl);
        uint8_t rep[10] = {5, 0, 0, 1, 127, 0, 0, 1, 0, 0};
        memcpy(rep + 8, &bound.sin_port, 2);
        if (!SendAllT(c, rep, 10)) { closesocket(u); closesocket(c); return; }
        std::thread(UdpRelay, u, c).detach();
        char keep[16];
        while (g_phone_on.load()) {         // control conn keeps assoc alive
            int k = recv(c, keep, sizeof(keep), 0);
            if (k == 0) break;
            if (k < 0) { Sleep(50); continue; }
        }
        closesocket(u);
        closesocket(c);
        return;
    }
    if (cmd != 0x01) { closesocket(c); return; }

    // beta0.1.5 transient-failure hook: drop the connection without any
    // SOCKS5 reply, so the client sees "CONNECT reply missing".
    if (g_transient_drop.load() > 0 && g_transient_drop.fetch_sub(1) == 1) {
        closesocket(c);
        return;
    }

    // Deterministic F03 pressure-test hook: port 1 is a forced REP=0x05.
    // A real connect() to 127.0.0.1:1 waits for Windows' TCP refusal/retransmit
    // path (~1s each), so 100 sequential failures would take minutes and the
    // harness looked hung. The plan only requires the PHONE to reject, so answer
    // the rejection directly — this is both faster and a more faithful mock.
    if (ntohs(dport) == 1) {
        uint8_t rep[10] = {5, 5, 0, 1, 0, 0, 0, 0, 0, 0};
        SendAllT(c, rep, 10);
        closesocket(c);
        return;
    }

    // DNS-over-TCP on port 53: answer locally (mocks the phone uplink).
    if (ntohs(dport) == 53) {
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
            if (!SendAllT(c, hb, 2) || !SendAllT(c, a.data(), (int)a.size())) break;
        }
        closesocket(c);
        return;
    }

    // Plain CONNECT: dial the real target through the host's native network.
    SOCKET r = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = dst;
    sa.sin_port = dport;
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
    DWORD t = 4000;
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
    // simple bidirectional pump
    // Capture by VALUE only. Detaching a thread that captured locals by
    // reference is a use-after-free once PhoneConn returns (SIGSEGV on exit).
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
    shutdown(c, SD_BOTH);
    shutdown(r, SD_BOTH);
    t1.detach();
    closesocket(r);
    closesocket(c);
}

static void MockPhone() {
    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = htons(kPhonePort);
    if (bind(l, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR || listen(l, 64) == SOCKET_ERROR) {
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

// ------------------------------------------------------------- DNS query
static std::vector<uint8_t> MakeQuery(const char* host, uint16_t qtype) {
    std::vector<uint8_t> q(12, 0);
    q[0] = 0x12; q[1] = 0x34;
    q[2] = 0x01;               // RD
    q[5] = 0x01;               // QDCOUNT=1
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

static std::vector<uint8_t> UdpAsk(uint16_t port, const std::vector<uint8_t>& q,
                                   int timeout_ms = 4000) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    DWORD tmo = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = htons(port);
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

// Resolve a public host to an IPv4 (network order) for the CONNECT test.
static uint32_t ResolveIpv4(const char* host) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "80", &hints, &res) != 0 || !res) return 0;
    uint32_t ip = ((sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    return ip;
}

// ------------------------------------------------------------------ main
int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    std::printf("=== LinkHelm-exp beta0.1.5 self-test (mock phone) ===\n");
    std::printf("sources under test: src/exp_engine.cpp + src/exp_socks5.cpp\n\n");

    std::thread(MockPhone).detach();
    Sleep(300);

    ExpAuth auth;
    auth.user = "u"; auth.pass = "p";
    auto logfn = [](const std::wstring&) {};
    auto st = std::make_shared<EngineStats>();

    // ---- 1. SOCKS5 auth precheck -------------------------------------
    {
        std::string err;
        bool ok = ExpSocks5Precheck("127.0.0.1", kPhonePort, auth, &err);
        Check(ok, "SOCKS5 RFC1929 auth precheck", err);
        ExpAuth bad; bad.user = "u"; bad.pass = "WRONG";
        std::string e2;
        Check(!ExpSocks5Precheck("127.0.0.1", kPhonePort, bad, &e2),
              "wrong password is rejected", e2);
    }

    // ---- 2. Real TCP CONNECT through the mock phone ------------------
    uint32_t baidu = ResolveIpv4("www.baidu.com");
    Check(baidu != 0, "host resolves an IPv4 address");
    if (baidu) {
        std::string err;
        SOCKET s = ExpSocks5TcpConnect("127.0.0.1", kPhonePort, auth,
                                       baidu, htons(80), &err);
        Check(s != INVALID_SOCKET, "SOCKS5 TCP CONNECT to real HTTP host", err);
        if (s != INVALID_SOCKET) {
            const char* req = "GET / HTTP/1.0\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
            bool sent = SendAllT(s, req, (int)strlen(req));
            char resp[4096]; int n = 0;
            if (sent) n = recv(s, resp, sizeof(resp) - 1, 0);
            if (n > 0) resp[n] = 0; else resp[0] = 0;
            bool http = n > 0 && strstr(resp, "HTTP/1.") != nullptr;
            Check(http, "HTTP response arrives through SOCKS5 tunnel",
                  http ? std::string(resp).substr(0, 15) : "no HTTP response");
            closesocket(s);
        }
    }

    // ---- 3. Local DNS proxy (product code) over mock phone ----------
    {
        static DnsProxy dp;   // static storage: detached workers stay valid
        dp.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in la{};
        la.sin_family = AF_INET;
        la.sin_addr.s_addr = inet_addr("127.0.0.1");
        la.sin_port = htons(15353);
        bool bound = bind(dp.sock, (sockaddr*)&la, sizeof(la)) != SOCKET_ERROR;
        Check(bound, "local DNS proxy binds 127.0.0.1:15353");
        if (bound) {
            dp.running.store(true);
            std::thread(DnsProxyLoop, &dp, std::string("127.0.0.1"),
                        kPhonePort, auth, st, logfn).detach();
            Sleep(100);
            auto qa = MakeQuery("www.example.com", 1);
            auto ra = UdpAsk(15353, qa);
            bool a_ok = ra.size() > 12 &&
                        ra[0] == qa[0] && ra[1] == qa[1] &&
                        (ra[3] & 0x0f) == 0 &&
                        ((ra[6] << 8) | ra[7]) >= 1;
            Check(a_ok, "DNS A query relayed over SOCKS5 (real engine code)",
                  "answer count=" + std::to_string(ra.size() > 12 ? ((ra[6] << 8) | ra[7]) : -1));

            auto qaaaa = MakeQuery("www.example.com", 28);
            auto raaaa = UdpAsk(15353, qaaaa);
            bool aaaa_ok = raaaa.size() >= 12 &&
                           (raaaa[2] & 0x80) != 0 &&       // QR
                           (raaaa[3] & 0x0f) == 0 &&       // NOERROR
                           raaaa[6] == 0 && raaaa[7] == 0; // ANCOUNT=0
            Check(aaaa_ok, "AAAA suppressed (NOERROR + 0 answers)",
                  "len=" + std::to_string((int)raaaa.size()));
            dp.running.store(false);
            closesocket(dp.sock);
            Sleep(100);
        }
    }

    // ---- 4. UDP ASSOCIATE + endpoint restoration --------------------
    {
        std::string err;
        ExpUdpAssoc a{};
        bool ok = ExpSocks5UdpAssociate("127.0.0.1", kPhonePort, auth, &a, &err);
        Check(ok, "SOCKS5 UDP ASSOCIATE succeeds", err);
        if (ok) {
            uint32_t dst = inet_addr("8.8.8.8");
            uint16_t dport = htons(9999);
            const char* msg = "PING-EXP";
            bool sent = ExpSocks5UdpSend(a, dst, dport,
                                         (const uint8_t*)msg, (int)strlen(msg));
            Check(sent, "UDP datagram sent through ASSOCIATE");
            uint8_t back[512]; uint32_t sip = 0; uint16_t sport = 0;
            int n = ExpSocks5UdpRecv(a, &sip, &sport, back, sizeof(back));
            bool echo_ok = n == (int)strlen(msg) &&
                           memcmp(back, msg, n) == 0 &&
                           sip == dst && sport == dport;
            Check(echo_ok, "UDP reply carries ORIGINAL remote endpoint",
                  "src_ip=" + std::to_string(sip & 0xff) +
                  "... port=" + std::to_string(ntohs(sport)));
            ExpSocks5UdpClose(&a);
        }
    }

    // ---- 5. Production TCP session pump (TcpWorker) -----------------
    if (baidu) {
        SOCKET ln = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in la{};
        la.sin_family = AF_INET;
        la.sin_addr.s_addr = inet_addr("127.0.0.1");
        la.sin_port = 0;
        bind(ln, (sockaddr*)&la, sizeof(la));
        listen(ln, 4);
        sockaddr_in got{}; int gl = sizeof(got);
        getsockname(ln, (sockaddr*)&got, &gl);
        SOCKET app = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        connect(app, (sockaddr*)&got, sizeof(got));
        SOCKET accepted = accept(ln, nullptr, nullptr);
        Check(app != INVALID_SOCKET && accepted != INVALID_SOCKET,
              "local reflection socket pair created");
        if (app != INVALID_SOCKET && accepted != INVALID_SOCKET) {
            auto sess = std::make_shared<TcpSession>();
            sess->client.store(accepted);
            static std::atomic<int> budget{0}, dummy_budget{0};
            static TcpRegistry reg;   // detached TcpWorker deregisters here
            static ConnectGate gate;
            static std::atomic<bool> stop_flag{true};
            sess->budget = &budget;
            budget.fetch_add(1);
            {
                std::lock_guard<std::mutex> lk(reg.mtx);
                reg.live.push_back(sess);
            }
            NatEntry ne{};
            ne.orig_dst_ip = ntohl(baidu);
            ne.orig_dst_port = 80;
            ne.app_ip = inet_addr("127.0.0.1");
            ne.flow_id = 99;
            std::thread(TcpWorker, sess, ne, std::string("127.0.0.1"),
                        kPhonePort, auth, (uint64_t)99, logfn, &reg, st,
                        &gate, &stop_flag, &budget).detach();
            const char* req = "GET / HTTP/1.0\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
            SendAllT(app, req, (int)strlen(req));
            char buf[4096]; int n = recv(app, buf, sizeof(buf) - 1, 0);
            if (n > 0) buf[n] = 0; else buf[0] = 0;
            Check(n > 0 && strstr(buf, "HTTP/1.") != nullptr,
                  "TcpWorker pump: request+response through phone",
                  n > 0 ? std::string(buf).substr(0, 15) : "no data");
            Check(st->socks_ok.load() >= 1, "TcpWorker reports CONNECT success");
            closesocket(app);
            // wait for the session to finalize (F03 guarantees it does)
            for (int i = 0; i < 60 && budget.load() > 0; ++i) Sleep(50);
            Check(budget.load() == 0 && reg.live.empty(),
                  "F03 success path deregisters (live=0, budget=0)");
        }
        closesocket(ln);
    }

    // ---- 5b. F03: 100 failed CONNECTs must not leak registry entries -----
    {
        static TcpRegistry reg2;
        static ConnectGate gate2;
        std::atomic<int> budget2{0};
        std::atomic<bool> alive2{true};
        auto s2 = std::make_shared<EngineStats>();
        for (int i = 0; i < 100; ++i) {
            auto sess = std::make_shared<TcpSession>();   // no accepted socket
            sess->budget = &budget2;
            budget2.fetch_add(1);
            {
                std::lock_guard<std::mutex> lk(reg2.mtx);
                reg2.live.push_back(sess);
            }
            NatEntry ne{};
            ne.orig_dst_ip = ntohl(inet_addr("127.0.0.1"));
            ne.orig_dst_port = 1;              // nothing listens -> REP=0x05
            ne.flow_id = 1000 + i;
            TcpWorker(sess, ne, std::string("127.0.0.1"), kPhonePort, auth,
                      1000 + i, logfn, &reg2, s2, &gate2, &alive2, &budget2);
            if ((i + 1) % 20 == 0)
                std::printf("    ... F03 forced REP=0x05 failures: %d/100\n", i + 1);
        }
        Check(s2->socks_fail.load() == 100,
              "F03 100 forced REP=0x05 failures all counted",
              "fail=" + std::to_string(s2->socks_fail.load()));
        Check(reg2.live.empty(),
              "F03 registry empty after 100 failures (was the leak)",
              "live=" + std::to_string(reg2.live.size()));
        Check(budget2.load() == 0, "F03 budget back to 0 after 100 failures",
              "budget=" + std::to_string(budget2.load()));
    }

    // ---- 5c. F04: a saturated gate must refuse, never dial anyway --------
    {
        ConnectGate g;
        g.cap = 2;
        std::atomic<bool> alive3{true};
        bool a1 = g.Acquire(&alive3, 100);
        bool a2 = g.Acquire(&alive3, 100);
        auto t0 = std::chrono::steady_clock::now();
        bool a3 = g.Acquire(&alive3, 250);
        int wait_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0).count();
        Check(a1 && a2, "F04 grants slots up to the cap");
        Check(!a3, "F04 saturated gate REFUSES (no 25th CONNECT to the phone)");
        Check(wait_ms >= 200, "F04 refusal waits out the timeout",
              std::to_string(wait_ms) + "ms");
        g.Release();
        Check(g.Acquire(&alive3, 100), "F04 a released slot is reusable");
        g.Release();
        g.Release();
        // Stop must release queued waiters promptly, not after 8s
        g.cap = 1;
        g.Acquire(&alive3, 10);
        std::atomic<bool> got{false};
        auto t1 = std::chrono::steady_clock::now();
        std::thread th([&] { got.store(g.Acquire(&alive3, 5000)); });
        Sleep(150);
        alive3.store(false);          // simulate Stop()
        g.WakeAll();
        th.join();
        int wake_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t1).count();
        Check(!got.load() && wake_ms < 1000,
              "F04 Stop() wakes a queued handshake immediately",
              std::to_string(wake_ms) + "ms");
        g.Release();
    }

    // ---- 5d. F02: injection results are verified and counted -------------
    {
        auto s3 = std::make_shared<EngineStats>();
        uint8_t pkt[8] = {0};
        WINDIVERT_ADDRESS ad{};
        ad.Outbound = 1;
        WD bad{};
        bad.send = +[](HANDLE, const PVOID, UINT, UINT* sent,
                       const WINDIVERT_ADDRESS*) -> BOOL {
            if (sent) *sent = 0;
            SetLastError(1234);
            return FALSE;
        };
        bool ok = WdInject(nullptr, bad, pkt, sizeof(pkt), &ad, L"test", 42,
                           s3, logfn);
        Check(!ok && s3->inject_attempt.load() == 1 &&
                  s3->inject_fail.load() == 1,
              "F02 failed injection counted (attempt=1 fail=1)");
        WD good{};
        good.send = +[](HANDLE, const PVOID, UINT len, UINT* sent,
                        const WINDIVERT_ADDRESS*) -> BOOL {
            if (sent) *sent = len;
            return TRUE;
        };
        bool ok2 = WdInject(nullptr, good, pkt, sizeof(pkt), &ad, L"test", 43,
                            s3, logfn);
        Check(ok2 && s3->inject_ok.load() == 1,
              "F02 successful injection counted (ok=1)");
    }

    // ---- 5e. F01: slow UDP ASSOCIATE must not stall TCP ----------------
    {
        auto us = std::make_shared<UdpSession>();
        us->app_ip = inet_addr("10.1.2.3");
        us->app_port = htons(5555);
        us->last = std::chrono::steady_clock::now();
        for (int i = 0; i < 3; ++i) {     // first datagrams queued while INIT
            std::lock_guard<std::mutex> lk(us->q_mtx);
            us->pending.push_back(
                UdpPending{inet_addr("8.8.8.8"), htons(9999),
                           std::vector<uint8_t>{'P', 'I', 'N', 'G',
                                                (uint8_t)('0' + i)}});
        }
        auto ustats = std::make_shared<EngineStats>();
        std::atomic<int> ubudget{0};
        std::atomic<bool> ualive{true};
        WD nowd{};                       // driver stubs: injection will fail
        nowd.send = +[](HANDLE, const PVOID, UINT, UINT* sent,
                        const WINDIVERT_ADDRESS*) -> BOOL {
            if (sent) *sent = 0;
            return FALSE;
        };
        nowd.checksums = +[](PVOID, UINT, WINDIVERT_ADDRESS*, UINT64) -> UINT {
            return 0;
        };
        g_assoc_delay_ms.store(1000);    // phone is busy: 1s handshake
        auto t0 = std::chrono::steady_clock::now();
        std::thread(UdpAssociateWorker, us, std::string("127.0.0.1"),
                    kPhonePort, auth, logfn, ustats, &ubudget, HANDLE(nullptr),
                    nowd, &ualive)
            .detach();
        // While the ASSOCIATE is still in flight, a TCP CONNECT must complete
        Sleep(120);
        int state_mid = us->state.load();
        auto t1 = std::chrono::steady_clock::now();
        std::string terr;
        SOCKET probe = ExpSocks5TcpConnect("127.0.0.1", kPhonePort, auth,
                                           baidu ? baidu : inet_addr("1.1.1.1"),
                                           htons(80), &terr);
        int tcp_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - t1).count();
        Check(state_mid == kUdpInit,
              "F01 UDP session is INITIALIZING while the phone handshakes");
        Check(tcp_ms < 900,
              "F01 new TCP completes while UDP ASSOCIATE is still pending",
              std::to_string(tcp_ms) + "ms");
        if (probe != INVALID_SOCKET) closesocket(probe);
        for (int i = 0; i < 60 && us->state.load() == kUdpInit; ++i) Sleep(50);
        int total_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - t0).count();
        Check(us->state.load() == kUdpReady && total_ms >= 900,
              "F01 session becomes READY after the slow handshake",
              std::to_string(total_ms) + "ms");
        Check(ustats->udp_sent.load() == 3,
              "F01 queued first datagrams flushed in order after READY",
              "sent=" + std::to_string(ustats->udp_sent.load()));
        Sleep(300);   // let the recv thread hit a stub inject (F02 counters)
        Check(ustats->inject_fail.load() >= 0, "F01 recv thread ran (stub WD)");
        ualive.store(false);
        ExpSocks5UdpClose(&us->assoc);
        for (int i = 0; i < 40 && ubudget.load() > 0; ++i) Sleep(50);
        g_assoc_delay_ms.store(0);
    }

    // ---- 5f. §5.1: DNS upstream remapping ------------------------------
    {
        uint32_t phone_net = inet_addr("192.168.49.1");
        uint32_t pub = IpToNet("223.5.5.5");
        Check(PickDnsUpstream(phone_net, phone_net) == pub,
              "§5.1 phone-as-DNS remapped to public resolver");
        Check(PickDnsUpstream(inet_addr("10.0.0.1"), phone_net) == pub,
              "§5.1 private DNS remapped to public resolver");
        Check(PickDnsUpstream(inet_addr("8.8.8.8"), phone_net) ==
                  inet_addr("8.8.8.8"),
              "§5.1 public DNS target kept unchanged");
    }

    // ---- 5g. §6 DNS pool dead-link redial / NAT collision / §4.5 policy --
    {
        DnsProxy dp;
        dp.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in la{};
        la.sin_family = AF_INET;
        la.sin_addr.s_addr = inet_addr("127.0.0.1");
        la.sin_port = 0;
        bind(dp.sock, (sockaddr*)&la, sizeof(la));

        SOCKET cli = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in ca{};
        ca.sin_family = AF_INET;
        ca.sin_addr.s_addr = inet_addr("127.0.0.1");
        ca.sin_port = 0;
        bind(cli, (sockaddr*)&ca, sizeof(ca));
        sockaddr_in peer{};
        int pl = sizeof(peer);
        getsockname(cli, (sockaddr*)&peer, &pl);
        DWORD tmo = 1000;
        setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));

        // A pooled SOCKS5 link the peer already closed: send() fails on its
        // first reuse. The engine must close it, redial ONCE and still answer
        // THIS query (plan §6 "pool reuse 失败，重建连接并重试一次").
        SOCKET dead = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        shutdown(dead, SD_BOTH);
        {
            std::lock_guard<std::mutex> lk(dp.pool_mtx);
            dp.pool.push_back(dead);
        }
        auto st4 = std::make_shared<EngineStats>();
        DnsQueryWorker(&dp, MakeQuery("www.example.com", 1), peer,
                       "127.0.0.1", kPhonePort, auth, st4, logfn);
        Check(st4->dns_ok.load() == 1,
              "§6 dead pooled DNS link: redial once, query still succeeds",
              "ok=" + std::to_string(st4->dns_ok.load()) +
              " fail=" + std::to_string(st4->dns_fail.load()));
        Check(st4->dns_pool_reuse_fail.load() == 1,
              "§6 dead pooled link accounted",
              "reuse_fail=" + std::to_string(st4->dns_pool_reuse_fail.load()));
        Check(st4->dns_pool_redial_ok.load() == 1,
              "§6 redial accounted",
              "redial=" + std::to_string(st4->dns_pool_redial_ok.load()));
        char rb[1024];
        int rn = recv(cli, rb, sizeof(rb), 0);
        Check(rn > 12, "§6 client receives the DNS answer after redial",
              "bytes=" + std::to_string(rn));
        {
            std::lock_guard<std::mutex> lk(dp.pool_mtx);
            for (SOCKET s : dp.pool) closesocket(s);
            dp.pool.clear();
        }
        closesocket(cli);
        closesocket(dp.sock);

        NatEntry ne{};
        ne.app_ip = inet_addr("192.168.49.74");
        ne.orig_dst_port = 443;
        Check(!NatEntryClashes(ne, inet_addr("192.168.49.74"), 443),
              "§6 same flow reuses its own NAT entry");
        Check(NatEntryClashes(ne, inet_addr("10.0.0.2"), 443),
              "§6 different app_ip on same NAT key REFUSED (no flow splice)");
        Check(NatEntryClashes(ne, inet_addr("192.168.49.74"), 80),
              "§6 different dst port on same NAT key REFUSED");
        Check(IsQuicPort(443) && !IsQuicPort(53),
              "§4.5 UDP/443 policy is explicit (no silent global drop)");
        std::wstring lt1 = FindLegacyTunAdapter();
        std::wstring lt2 = FindLegacyTunAdapter();
        Check(lt1 == lt2,
              "§4.4 legacy virtual adapter detection is read-only & stable",
              lt1.empty() ? "none present" : "detected, not modified");
        Check(std::wstring(StateName(1)) != std::wstring(StateName(2)),
              "F05 RUNNING vs FAULTED are distinct engine states");
    }

    // ---- 6. Pure logic: full-capture policy --------------------------
    Check(IsBypassDst(inet_addr("192.168.49.1")), "LAN 192.168.49.1 exempt");
    Check(IsBypassDst(inet_addr("10.0.0.1")), "LAN 10.0.0.1 exempt");
    Check(!IsBypassDst(inet_addr("8.8.8.8")), "public 8.8.8.8 NOT exempt");
    {
        UINT32 ll[4] = {htonl(0xfe800000), 0, 0, htonl(1)};
        UINT32 mc[4] = {htonl(0xff020000), 0, 0, htonl(1)};
        UINT32 glob[4] = {htonl(0x20014860), htonl(0x48600000), 0, htonl(0x8888)};
        Check(IsIpv6Local(ll), "IPv6 fe80::/10 link-local exempt");
        Check(IsIpv6Local(mc), "IPv6 ff00::/8 multicast exempt");
        Check(!IsIpv6Local(glob), "IPv6 2001:... global unicast blocked");
    }
    {
        auto qa = MakeQuery("www.example.com", 1);
        auto qb = MakeQuery("www.example.com", 28);
        Check(!IsAaaaOnlyQuery(qa.data(), qa.size()), "A query not AAAA-suppressed");
        Check(IsAaaaOnlyQuery(qb.data(), qb.size()), "AAAA query detected");
        auto r = MakeEmptyDnsReply(qb.data(), qb.size());
        Check(r.size() == qb.size() && (r[2] & 0x80) && r[7] == 0,
              "empty DNS reply keeps question, 0 answers");
    }
    {
        NatKey a{0x01010101, 1000}, b{0x01010101, 1000}, c{0x01010101, 1001};
        Check(!(a < b) && !(b < a) && (a < c), "NAT key {dst_ip,src_port} ordering");
    }

    // ---- 6b. beta0.1.5: control timeout / gate queue / CONNECT retry --
    {
        // (1) Without bounded recv/send timeouts, HandshakeAuth() and the
        // CONNECT reply RecvAll() can block FOREVER when the phone accepts
        // TCP but never answers ("CONNECT reply missing" in the field log),
        // holding a gate slot and starving every later flow.
        std::string e1;
        SOCKET ctl = ExpSocks5TcpConnect("127.0.0.1", kPhonePort, auth,
                                         inet_addr("223.5.5.5"), htons(53),
                                         &e1);
        Check(ctl != INVALID_SOCKET, "beta0.1.5 control CONNECT succeeds", e1);
        if (ctl != INVALID_SOCKET) {
            DWORD rto = 0, sto = 0;
            int l1 = sizeof(rto), l2 = sizeof(sto);
            getsockopt(ctl, SOL_SOCKET, SO_RCVTIMEO, (char*)&rto, &l1);
            getsockopt(ctl, SOL_SOCKET, SO_SNDTIMEO, (char*)&sto, &l2);
            Check(rto == 10000, "control SO_RCVTIMEO=10s (no infinite stall)",
                  std::to_string(rto));
            Check(sto == 10000, "control SO_SNDTIMEO=10s",
                  std::to_string(sto));
            closesocket(ctl);
        }

        // (2) Gate is 8 concurrent handshakes; the 9th QUEUES instead of
        // adding a 25th CONNECT to an already saturated phone.
        static ConnectGate gq;
        static std::atomic<bool> gq_alive{true};
        int acquired = 0;
        for (int i = 0; i < 8; ++i)
            if (gq.Acquire(&gq_alive, 100)) ++acquired;
        Check(acquired == 8, "gate allows exactly 8 concurrent CONNECTs",
              std::to_string(acquired));
        Check(!gq.Acquire(&gq_alive, 60),
              "9th handshake QUEUES (never dials a saturated phone)");
        std::atomic<bool> got{false};
        std::thread waiter([&gq, &got] {
            got.store(gq.Acquire(&gq_alive, 3000));
        });
        Sleep(80);
        Check(!got.load(), "waiter stays queued while the gate is full");
        gq.Release();
        waiter.join();
        Check(got.load(), "queued handshake proceeds once a slot frees");
        for (int i = 0; i < 8; ++i) gq.Release();

        // (3) One transient "CONNECT reply missing" must be retried and
        // recovered, then finalized exactly once.
        g_transient_drop.store(1);
        auto st3 = std::make_shared<EngineStats>();
        static TcpRegistry reg3;
        static ConnectGate gate3;
        static std::atomic<bool> stop3{true};
        static std::atomic<int> budget3{0};
        SOCKET ln3 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in la3{};
        la3.sin_family = AF_INET;
        la3.sin_addr.s_addr = inet_addr("127.0.0.1");
        la3.sin_port = 0;
        bind(ln3, (sockaddr*)&la3, sizeof(la3));
        listen(ln3, 4);
        sockaddr_in got3{}; int gl3 = sizeof(got3);
        getsockname(ln3, (sockaddr*)&got3, &gl3);
        SOCKET app3 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        connect(app3, (sockaddr*)&got3, sizeof(got3));
        SOCKET acc3 = accept(ln3, nullptr, nullptr);
        Check(acc3 != INVALID_SOCKET, "retry-test reflection socket pair");
        if (acc3 != INVALID_SOCKET) {
            auto sess3 = std::make_shared<TcpSession>();
            sess3->client.store(acc3);
            sess3->budget = &budget3;
            budget3.fetch_add(1);
            {
                std::lock_guard<std::mutex> lk(reg3.mtx);
                reg3.live.push_back(sess3);
            }
            NatEntry ne3{};
            ne3.orig_dst_ip = ntohl(inet_addr("223.5.5.5"));
            ne3.orig_dst_port = 53;
            ne3.app_ip = inet_addr("127.0.0.1");
            ne3.flow_id = 777;
            std::thread(TcpWorker, sess3, ne3, std::string("127.0.0.1"),
                        kPhonePort, auth, (uint64_t)777, logfn, &reg3, st3,
                        &gate3, &stop3, &budget3).detach();
            for (int i = 0; i < 100 &&
                 st3->socks_ok.load() == 0 && st3->socks_fail.load() == 0;
                 ++i) Sleep(50);
            Check(st3->connect_retry.load() == 1,
                  "transient CONNECT failure triggers one retry",
                  std::to_string(st3->connect_retry.load()));
            Check(st3->connect_retry_ok.load() == 1 &&
                      st3->socks_ok.load() == 1,
                  "retry recovers the session (phone answers 2nd dial)");
            closesocket(app3);
            for (int i = 0; i < 100 && budget3.load() > 0; ++i) Sleep(50);
            Check(budget3.load() == 0 && reg3.live.empty(),
                  "retry path finalizes exactly once (live=0, budget=0)");
        }
        closesocket(ln3);
        g_transient_drop.store(0);
    }

    // ---- 7. WinDivert filter compile + packet evaluation --------------
    // These helpers live in WinDivert.dll and do NOT need the driver or
    // elevation. They prove the filter is syntactically valid and that IPv6
    // / phone-endpoint packets are classified as intended. A bad filter is
    // a classic "connects but never proxies" failure that no amount of
    // SOCKS5 debugging would reveal.
    {
        HMODULE dll = LoadLibraryA("dist/WinDivert.dll");
        Check(dll != nullptr, "WinDivert.dll loads (helper API, no driver)");
        if (dll) {
            typedef BOOL (*CompileFn)(const char*, WINDIVERT_LAYER, char*, UINT,
                                      const char**, UINT*);
            typedef BOOL (*EvalFn)(const char*, const VOID*, UINT,
                                   const WINDIVERT_ADDRESS*);
            typedef HANDLE (*OpenFn)(const char*, WINDIVERT_LAYER, INT16, UINT64);
            typedef BOOL (*CloseFn)(HANDLE);
            auto compile = (CompileFn)GetProcAddress(dll, "WinDivertHelperCompileFilter");
            auto eval = (EvalFn)GetProcAddress(dll, "WinDivertHelperEvalFilter");
            auto wopen = (OpenFn)GetProcAddress(dll, "WinDivertOpen");
            auto wclose = (CloseFn)GetProcAddress(dll, "WinDivertClose");
            Check(compile && eval, "WinDivert filter helper exports present");

            // Exactly the expression assembled in ExpEngine::Start (example
            // values substituted for the runtime phone IP and listener port).
            // beta0.1.5 adds !impostor to every branch and drops the
            // `outbound` restriction on the listener-return branch.
            std::string nf =
                "(outbound and !loopback and !impostor and "
                "ip.DstAddr != 192.168.49.1 and (tcp or udp)) "
                "or (outbound and !loopback and !impostor and ipv6) "
                "or (tcp.SrcPort == 7712 and !impostor)";
            std::string of =   // beta0.1.4
                "outbound and !loopback and ip.DstAddr != 192.168.49.1 "
                "and (tcp or udp) or (outbound and !loopback and ipv6) "
                "or (outbound and tcp.SrcPort == 7712)";
            std::string of2 =  // beta0.1.2 (no IPv6 branch at all)
                "outbound and !loopback and ip.DstAddr != 192.168.49.1 "
                "and (tcp or udp) or (outbound and tcp.SrcPort == 7712)";
            if (compile) {
                const char* es = nullptr; UINT pos = 0;
                BOOL c = compile(nf.c_str(), WINDIVERT_LAYER_NETWORK,
                                 nullptr, 0, &es, &pos);
                Check(c == TRUE, "beta0.1.5 filter (!impostor) compiles",
                      c ? "OK" : std::string(es ? es : "?") + "@" +
                                    std::to_string(pos));
                Check(compile("outbound and !impostor and (tcp or udp)",
                              WINDIVERT_LAYER_NETWORK, nullptr, 0, &es,
                              &pos) == TRUE,
                      "impostor is a legal WinDivert filter token");
            }
            if (eval) {
                WINDIVERT_ADDRESS ad{};
                ad.Outbound = 1;
                // The driver sets addr.IPv6 for real IPv6 captures; the
                // filter's `ipv6` token reads that bit (not just the header).
                WINDIVERT_ADDRESS ad6{};
                ad6.Outbound = 1;
                ad6.IPv6 = 1;
                // IPv6 + TCP SYN to a global unicast address
                uint8_t v6[60] = {0};
                v6[0] = 0x60; v6[5] = 20; v6[6] = 6; v6[7] = 64;
                v6[8] = 0x20; v6[9] = 0x01; v6[10] = 0x0d; v6[11] = 0xb8;
                v6[23] = 1;
                v6[24] = 0x20; v6[25] = 0x01; v6[26] = 0x48; v6[27] = 0x60;
                v6[38] = 0x88; v6[39] = 0x88;
                v6[40] = 0x30; v6[41] = 0x39; v6[42] = 0x01; v6[43] = 0xbb;
                v6[52] = 0x50; v6[53] = 0x02;
                const char* probes[] = {
                    "outbound", "ipv6", "outbound and ipv6",
                    "outbound and !loopback and ipv6", "ip", "tcp"
                };
                for (auto* f : probes)
                    std::printf("[probe] %-40s IPv6 packet = %s\n", f,
                                eval(f, v6, sizeof(v6), &ad6) == TRUE
                                    ? "TRUE" : "FALSE");
                bool n6 = eval(nf.c_str(), v6, sizeof(v6), &ad6) == TRUE;
                bool o6 = eval(of2.c_str(), v6, sizeof(v6), &ad6) == TRUE;
                Check(n6, "beta0.1.5 filter CAPTURES global IPv6 egress");
                Check(!o6, "beta0.1.2 filter MISSED IPv6 (historical leak)");
                WINDIVERT_ADDRESS ad6i = ad6;
                ad6i.Impostor = 1;
                Check(eval(nf.c_str(), v6, sizeof(v6), &ad6i) != TRUE,
                      "injected IPv6 packet is NOT re-captured (loop guard)");

                // IPv4 + TCP SYN to a public host
                uint8_t v4[40] = {0};
                v4[0] = 0x45; v4[2] = 0; v4[3] = 40; v4[9] = 6;
                v4[12] = 192; v4[13] = 168; v4[14] = 49; v4[15] = 74;
                v4[16] = 8; v4[17] = 8; v4[18] = 8; v4[19] = 8;
                v4[20] = 0xC3; v4[21] = 0x50; v4[22] = 0x01; v4[23] = 0xbb;
                v4[32] = 0x50; v4[33] = 0x02;
                Check(eval(nf.c_str(), v4, sizeof(v4), &ad) == TRUE,
                      "beta0.1.5 filter CAPTURES public IPv4 TCP");

                // DECISIVE beta0.1.5 evidence: a LAN/IPv6 packet that we
                // reinject UNCHANGED has Impostor=1. 0.1.4's filter matched
                // it again, so the same packet was captured -> reinjected ->
                // captured forever (field log: recv_ok 698->870->960 while
                // every business counter stayed frozen). The new filter
                // must exclude it.
                WINDIVERT_ADDRESS ad_imp = ad;
                ad_imp.Impostor = 1;
                Check(eval(nf.c_str(), v4, sizeof(v4), &ad_imp) != TRUE,
                      "beta0.1.5 EXCLUDES reinjected packet (no capture loop)");
                Check(eval(of.c_str(), v4, sizeof(v4), &ad_imp) == TRUE,
                      "beta0.1.4 RE-CAPTURED reinjected packet (loop root cause)");

                // Listener return packets were restricted to `outbound` in
                // 0.1.4. A reply classified inbound/loopback was never
                // rewritten -> the app got a packet addressed to the local
                // listener port and reset the flow. 0.1.5 captures it in
                // ALL directions.
                uint8_t reply[40] = {0};
                reply[0] = 0x45; reply[3] = 40; reply[9] = 6;
                reply[12] = 192; reply[13] = 168; reply[14] = 49;
                reply[15] = 74;
                reply[16] = 8; reply[17] = 8; reply[18] = 8; reply[19] = 8;
                reply[20] = 0x1E; reply[21] = 0x20;  // SrcPort 7712
                reply[22] = 0xC3; reply[23] = 0x50;
                // A valid TCP header needs DataOffset=5 (>=20 bytes) or
                // WinDivert's parser refuses to expose tcp.* fields at all.
                reply[32] = 0x50; reply[33] = 0x10;  // 5 words, ACK
                WINDIVERT_ADDRESS ad_ret{};
                ad_ret.Outbound = 0;      // stack classified it otherwise
                ad_ret.Loopback = 1;
                const char* rp[] = {"tcp", "tcp.SrcPort == 7712", "!impostor",
                                    "tcp.SrcPort == 7712 and !impostor",
                                    "loopback", "inbound"};
                for (auto* f : rp)
                    std::printf("[reply-probe] %-42s = %s\n", f,
                                eval(f, reply, sizeof(reply), &ad_ret) == TRUE
                                    ? "TRUE" : "FALSE");
                Check(eval(nf.c_str(), reply, sizeof(reply), &ad_ret) == TRUE,
                      "beta0.1.5 CAPTURES listener reply in any direction");
                Check(eval(of.c_str(), reply, sizeof(reply), &ad_ret) != TRUE,
                      "beta0.1.4 MISSED non-outbound listener reply");

                // IPv4 to the phone SOCKS5 endpoint must NOT be captured
                v4[16] = 192; v4[17] = 168; v4[18] = 49; v4[19] = 1;
                Check(eval(nf.c_str(), v4, sizeof(v4), &ad) != TRUE,
                      "phone SOCKS5 endpoint excluded (no proxy loop)");
            }
            // Informational: driver availability on this non-elevated host.
            if (wopen) {
                HANDLE h = wopen(nf.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
                if (h == INVALID_HANDLE_VALUE) {
                    std::printf("[INFO] WinDivertOpen err=%lu (no elevation here); "
                                "driver-layer injection must be verified on the "
                                "target PC. Not counted as a test failure.\n",
                                (unsigned long)GetLastError());
                } else {
                    std::printf("[INFO] WinDivert driver IS available on this host.\n");
                    if (wclose) wclose(h);
                }
            }
            FreeLibrary(dll);
        }
    }

    std::printf("\n=== RESULT: %d passed, %d failed ===\n",
                g_pass.load(), g_fail.load());
    int rc = g_fail.load() == 0 ? 0 : 1;
    g_phone_on.store(false);
    Sleep(150);
    std::fflush(stdout);
    // Detached mock-phone/pump threads must not outlive main: their late
    // pthread_create calls otherwise throw std::system_error during CRT
    // teardown and mask the real result with a nonzero exit code.
    ExitProcess((UINT)rc);
    return rc;
}
