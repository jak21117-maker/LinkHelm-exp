// LinkHelm-exp — SOCKS5 client implementation. See exp_socks5.h.
#include "exp_socks5.h"

#include <ws2tcpip.h>

#include <chrono>
#include <cstring>
#include <vector>

namespace linkhelm {

namespace {

bool SendAll(SOCKET s, const uint8_t* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, reinterpret_cast<const char*>(buf + sent), len - sent, 0);
        if (n == SOCKET_ERROR) return false;
        sent += n;
    }
    return true;
}

bool RecvAll(SOCKET s, uint8_t* buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(s, reinterpret_cast<char*>(buf + got), len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

// Connect with a hard timeout so a phone that half-dropped Wi-Fi Direct
// cannot stall the engine for a full TCP SYN timeout.
//
// beta0.1.8 (report §04): the previous version collapsed every negative
// select() outcome into "phone SOCKS5 unreachable (timeout)". The field log
// therefore reported a timeout at 532ms with a 3000ms budget — the exception
// set means "the connection FAILED", not "the timer expired". The three
// cases are now distinguished so the log states WHICH domain failed:
//   * SELECT_TIMEOUT  — the phone really did not answer in time
//   * SELECT_ERROR    — select() itself failed (rare)
//   * TCP_CONNECT_FAILED — the phone REFUSED/RESET the TCP connection
SOCKET DialWithTimeout(const std::string& phone_ip, uint16_t phone_port,
                       int timeout_ms, std::string* err,
                       int* elapsed_ms = nullptr,
                       uint32_t* local_ip_net = nullptr) {
    auto t0 = std::chrono::steady_clock::now();
    auto ms_since = [&]() {
        return static_cast<int>(std::chrono::duration_cast<
            std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count());
    };
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        if (err) *err = "socket() failed";
        return INVALID_SOCKET;
    }
    // Remember which local address the kernel picked for this dial — the
    // report asks for it to tell a Wi-Fi Direct path from a native one.
    if (local_ip_net) {
        sockaddr_in loc{};
        int ll = sizeof(loc);
        if (getsockname(s, reinterpret_cast<sockaddr*>(&loc), &ll) == 0)
            *local_ip_net = loc.sin_addr.s_addr;
        else
            *local_ip_net = 0;
    }
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(phone_port);
    inet_pton(AF_INET, phone_ip.c_str(), &a.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK) {
            if (err) *err = "TCP_CONNECT_FAILED (WSA " + std::to_string(e) +
                            ") to " + phone_ip + ":" +
                            std::to_string(phone_port);
            if (elapsed_ms) *elapsed_ms = ms_since();
            closesocket(s);
            return INVALID_SOCKET;
        }
        fd_set w, x;
        FD_ZERO(&w);
        FD_SET(s, &w);
        FD_ZERO(&x);
        FD_SET(s, &x);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        int r = select(0, nullptr, &w, &x, &tv);
        if (r == 0) {
            if (err) *err = "SELECT_TIMEOUT (" + std::to_string(ms_since()) +
                            "ms) to " + phone_ip + ":" +
                            std::to_string(phone_port);
            if (elapsed_ms) *elapsed_ms = ms_since();
            closesocket(s);
            return INVALID_SOCKET;
        }
        if (r < 0) {
            int se = WSAGetLastError();
            if (err) *err = "SELECT_ERROR (WSA " + std::to_string(se) + ")";
            if (elapsed_ms) *elapsed_ms = ms_since();
            closesocket(s);
            return INVALID_SOCKET;
        }
        if (FD_ISSET(s, &x)) {
            // The socket reported an error condition — read the real reason
            // instead of calling it a timeout.
            int so = 0, sl = sizeof(so);
            int g = getsockopt(s, SOL_SOCKET, SO_ERROR,
                                reinterpret_cast<char*>(&so), &sl);
            if (g != 0)
                so = WSAGetLastError();
            if (err) *err = "TCP_CONNECT_FAILED (WSA " + std::to_string(so) +
                            ", " + std::to_string(ms_since()) + "ms) to " +
                            phone_ip + ":" + std::to_string(phone_port);
            if (elapsed_ms) *elapsed_ms = ms_since();
            closesocket(s);
            return INVALID_SOCKET;
        }
        int so = 0, sl = sizeof(so);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so), &sl);
        if (so != 0) {
            if (err) *err = "TCP_CONNECT_FAILED (WSA " + std::to_string(so) +
                            ") to " + phone_ip + ":" +
                            std::to_string(phone_port);
            if (elapsed_ms) *elapsed_ms = ms_since();
            closesocket(s);
            return INVALID_SOCKET;
        }
    }
    if (elapsed_ms) *elapsed_ms = ms_since();
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);  // back to blocking for the handshake
    // beta0.1.5: the SOCKS5 CONTROL plane had no recv/send timeout at all.
    // DialWithTimeout only bounded connect(); HandshakeAuth() and the
    // CONNECT reply RecvAll() could block FOREVER when the phone accepted
    // TCP but never answered (exactly the "CONNECT reply missing" rows in
    // the field log). Such a worker holds a ConnectGate slot forever, so
    // later flows are starved and the app sees "connected, then dropped".
    // Bound every byte of the handshake. Data-plane sockets override this
    // with their own SO_RCVTIMEO, so this does not change stream behaviour.
    // beta0.1.8 (report §04): the field log's worst line was
    //   "CONNECT reply missing, 18552ms" = 3 attempts x 6s.
    // That flow occupied one ConnectGate slot for 18.5 SECONDS; with cap 2
    // two such flows starved the whole engine. The gate is gone in 0.2.x,
    // so a slow dial now costs only its own thread.
    // beta0.2.1: 4000 -> 6000. beta0.4.0: 6000 -> 15000. Root cause of
    // "occasionally kills a good link": the phone side targets its upstream
    // with connectTimeoutMs = 15000 (ProxyServer.kt), so a slow cellular
    // dial that WOULD succeed in 6-15 s was being RST by the PC at 6 s
    // (CONNECT_REPLY_MISSING / WSA 10060). Aligning the control-plane recv
    // timeout with the phone's dial budget lets the phone's real answer
    // (SUCCEEDED or REFUSED) arrive instead of a false timeout. A truly
    // dead target is still bounded: the phone returns REPLY_CONNECTION_
    // REFUSED at ~15 s, which the PC now receives rather than racing.
    DWORD tmo = 15000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    return s;
}

// beta0.4.9 "A++": build the RFC1929 username/password subnegotiation bytes.
// Factored out of HandshakeAuth so the fast (pipelined) path can coalesce them
// with the greeting and CONNECT into ONE send.
static bool BuildUserPassBytes(const ExpAuth& auth, std::vector<uint8_t>* out,
                               std::string* err) {
    if (auth.user.empty() || auth.user.size() > 255 ||
        auth.pass.size() > 255) {
        if (err) *err = "credentials missing or too long";
        return false;
    }
    out->push_back(0x01);
    out->push_back(static_cast<uint8_t>(auth.user.size()));
    out->insert(out->end(), auth.user.begin(), auth.user.end());
    out->push_back(static_cast<uint8_t>(auth.pass.size()));
    out->insert(out->end(), auth.pass.begin(), auth.pass.end());
    return true;
}

// Greeting (offer no-auth + userpass, prefer no-auth if the server allows it)
// plus RFC1929 subnegotiation when the server picks 0x02.
bool HandshakeAuth(SOCKET s, const ExpAuth& auth, std::string* err) {
    uint8_t greet[] = {0x05, 0x02, 0x00, 0x02};
    if (!SendAll(s, greet, sizeof(greet))) {
        if (err) *err = "greeting send failed";
        return false;
    }
    uint8_t resp[2];
    if (!RecvAll(s, resp, 2)) {
        if (err) *err = "greeting reply missing";
        return false;
    }
    if (resp[0] != 0x05) {
        if (err) *err = "not a SOCKS5 server";
        return false;
    }
    if (resp[1] == 0x00) return true;               // server allows no-auth
    if (resp[1] != 0x02) {
        if (err) *err = "server wants an auth method we do not offer (0x" +
                        std::to_string(resp[1]) + ")";
        return false;
    }
    // RFC 1929: ver=1, ulen, uname, plen, passwd
    std::vector<uint8_t> req;
    if (!BuildUserPassBytes(auth, &req, err)) return false;
    if (!SendAll(s, req.data(), static_cast<int>(req.size()))) {
        if (err) *err = "auth send failed";
        return false;
    }
    uint8_t ar[2];
    if (!RecvAll(s, ar, 2)) {
        if (err) *err = "auth reply missing";
        return false;
    }
    if (ar[1] != 0x00) {
        if (err) *err = "username/password rejected by phone";
        return false;
    }
    return true;
}

}  // namespace

bool ExpSocks5Precheck(const std::string& phone_ip, uint16_t phone_port,
                       const ExpAuth& auth, std::string* err) {
    SOCKET s = DialWithTimeout(phone_ip, phone_port, 3000, err);
    if (s == INVALID_SOCKET) return false;
    bool ok = HandshakeAuth(s, auth, err);
    closesocket(s);
    return ok;
}

bool ExpSocks5Liveness(const std::string& phone_ip, uint16_t phone_port,
                       const ExpAuth& auth, std::string* err) {
    // Short dial so a phone that is powered off / out of range fails fast.
    SOCKET s = DialWithTimeout(phone_ip, phone_port, 3000, err);
    if (s == INVALID_SOCKET) {
        if (err) *err = "phone TCP:8080 unreachable - " + *err;
        return false;
    }
    // DialWithTimeout set SO_RCVTIMEO=15000 for data-plane use; the watchdog
    // must answer quickly, so clamp every handshake stage to a short budget.
    DWORD tmo = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));

    if (!HandshakeAuth(s, auth, err)) {
        if (err) *err = "phone SOCKS5 auth failed - " + *err;
        closesocket(s);
        return false;
    }
    // Full CONNECT to a public resolver: proves the phone's CELLULAR uplink
    // still reaches the Internet, not just that its app is listening.
    // 223.5.5.5:53, IPv4 network-order bytes written explicitly (no cross-TU
    // helper dependency).
    uint8_t req[10] = {0x05, 0x01, 0x00, 0x01, 223, 5, 5, 5, 0, 53};
    if (!SendAll(s, req, sizeof(req))) {
        if (err) *err = "liveness CONNECT send failed";
        closesocket(s);
        return false;
    }
    uint8_t head[4];
    if (!RecvAll(s, head, 4)) {
        if (err) *err = "liveness CONNECT reply missing (phone uplink down?)";
        closesocket(s);
        return false;
    }
    closesocket(s);
    if (head[0] != 0x05 || head[1] != 0x00) {
        if (err) *err = "liveness CONNECT rejected (REP=0x" +
                        std::to_string(head[1]) + ")";
        return false;
    }
    return true;
}

SOCKET ExpSocks5TcpConnect(const std::string& phone_ip, uint16_t phone_port,
                           const ExpAuth& auth, uint32_t dst_ip_net,
                           uint16_t dst_port_net, std::string* err,
                           ExpSocks5Timing* timing,
                           uint32_t* local_ip_net) {
    auto t0 = std::chrono::steady_clock::now();
    auto stage_ms = [&](std::chrono::steady_clock::time_point since) {
        return static_cast<int>(std::chrono::duration_cast<
            std::chrono::milliseconds>(std::chrono::steady_clock::now() - since)
            .count());
    };
    int tcp_ms = 0;
    SOCKET s = DialWithTimeout(phone_ip, phone_port, 3000, err, &tcp_ms,
                                local_ip_net);
    if (s == INVALID_SOCKET) {
        if (timing) {
            timing->tcp_ms = tcp_ms;
            timing->total_ms = tcp_ms;
        }
        return INVALID_SOCKET;
    }
    auto t_auth = std::chrono::steady_clock::now();
    if (!HandshakeAuth(s, auth, err)) {
        if (timing) {
            timing->tcp_ms = tcp_ms;
            timing->auth_ms = stage_ms(t_auth);
            timing->total_ms = stage_ms(t0);
        }
        closesocket(s);
        return INVALID_SOCKET;
    }
    int auth_ms = stage_ms(t_auth);
    auto t_conn = std::chrono::steady_clock::now();
    // CONNECT request: VER CMD=CONNECT RSV=0 ATYP=IPv4 DST.ADDR DST.PORT
    uint8_t req[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    std::memcpy(req + 4, &dst_ip_net, 4);
    std::memcpy(req + 8, &dst_port_net, 2);
    if (!SendAll(s, req, sizeof(req))) {
        if (err) *err = "CONNECT_SEND_FAILED";
        if (timing) {
            timing->tcp_ms = tcp_ms;
            timing->auth_ms = auth_ms;
            timing->total_ms = stage_ms(t0);
        }
        closesocket(s);
        return INVALID_SOCKET;
    }
    uint8_t head[4];
    if (!RecvAll(s, head, 4)) {
        // The phone ACCEPTED the TCP connection but never answered CONNECT.
        // That is the field log's "CONNECT reply missing" — a saturated
        // phone thread pool, NOT a routing problem. Say so explicitly.
        int e = WSAGetLastError();
        if (err) *err = "CONNECT_REPLY_MISSING (WSA " + std::to_string(e) +
                        ", " + std::to_string(stage_ms(t_conn)) + "ms)";
        if (timing) {
            timing->tcp_ms = tcp_ms;
            timing->auth_ms = auth_ms;
            timing->connect_ms = stage_ms(t_conn);
            timing->total_ms = stage_ms(t0);
        }
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (head[0] != 0x05 || head[1] != 0x00) {
        // 0x01 fault, 0x02 not allowed, 0x03 net unreachable, 0x05 refused...
        if (err) *err = "CONNECT_REJECTED (REP=0x" + std::to_string(head[1]) +
                        ")";
        if (timing) {
            timing->tcp_ms = tcp_ms;
            timing->auth_ms = auth_ms;
            timing->connect_ms = stage_ms(t_conn);
            timing->total_ms = stage_ms(t0);
        }
        closesocket(s);
        return INVALID_SOCKET;
    }
    // drain BND.ADDR/BND.PORT (variable by ATYP)
    if (head[3] == 0x01) {
        uint8_t b[6];
        if (!RecvAll(s, b, 6)) { closesocket(s); return INVALID_SOCKET; }
    } else if (head[3] == 0x03) {
        uint8_t len = 0;
        if (!RecvAll(s, &len, 1)) { closesocket(s); return INVALID_SOCKET; }
        std::vector<uint8_t> b(len + 2);
        if (!RecvAll(s, b.data(), len + 2)) { closesocket(s); return INVALID_SOCKET; }
    } else if (head[3] == 0x04) {
        uint8_t b[18];
        if (!RecvAll(s, b, 18)) { closesocket(s); return INVALID_SOCKET; }
    } else {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (timing) {
        timing->tcp_ms = tcp_ms;
        timing->auth_ms = auth_ms;
        timing->connect_ms = stage_ms(t_conn);
        timing->total_ms = stage_ms(t0);
    }
    return s;
}

// beta0.4.9 "A++" — pipelined SOCKS5 CONNECT.
//
// The Android peer (Socks5Parser.kt / ProxyServer.kt) reads a FIXED byte count
// per stage from ONE blocking InputStream:
//   readGreeting  : VER(1) NMETHODS(1) METHODS(N)
//   readUserPass  : VER(1) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)
//   readRequest   : VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(4) DST.PORT(2)
// and flushes each reply independently. TCP is a byte stream, so the client
// may send all THREE request blocks in one write; the server simply consumes
// them stage by stage. This collapses greeting + auth + CONNECT from three
// serial round trips (~3 RTT on the phone's cellular link) into ONE, cutting
// ~2 RTT (~60-120ms) off every flow's setup — the "shortened reflection arc".
//
// Safety: we only pipeline when the peer picks method 0x02 (userpass), which
// is the only method this server offers (it rejects 0x00 / no-auth). We send
// greeting advertising ONLY 0x02, so the server's choice is deterministic.
// If any reply is malformed we fail cleanly; the caller may retry with the
// serial ExpSocks5TcpConnect via FastHandshake=0.
SOCKET ExpSocks5TcpConnectFast(const std::string& phone_ip, uint16_t phone_port,
                               const ExpAuth& auth, uint32_t dst_ip_net,
                               uint16_t dst_port_net, std::string* err,
                               ExpSocks5Timing* timing,
                               uint32_t* local_ip_net) {
    auto t0 = std::chrono::steady_clock::now();
    auto stage_ms = [&](std::chrono::steady_clock::time_point since) {
        return static_cast<int>(std::chrono::duration_cast<
            std::chrono::milliseconds>(std::chrono::steady_clock::now() - since)
            .count());
    };
    int tcp_ms = 0;
    SOCKET s = DialWithTimeout(phone_ip, phone_port, 3000, err, &tcp_ms,
                                local_ip_net);
    if (s == INVALID_SOCKET) {
        if (timing) { timing->tcp_ms = tcp_ms; timing->total_ms = tcp_ms; }
        return INVALID_SOCKET;
    }

    // Build all three request blocks up front.
    std::vector<uint8_t> userpass;
    if (!BuildUserPassBytes(auth, &userpass, err)) {
        closesocket(s);
        if (timing) { timing->tcp_ms = tcp_ms; timing->total_ms = stage_ms(t0); }
        return INVALID_SOCKET;
    }
    std::vector<uint8_t> wire;
    wire.reserve(4 + userpass.size() + 10);
    // Greeting: VER=5, NMETHODS=1, METHOD=0x02 (userpass only — deterministic).
    wire.push_back(0x05); wire.push_back(0x01); wire.push_back(0x02);
    // RFC1929 auth bytes.
    wire.insert(wire.end(), userpass.begin(), userpass.end());
    // CONNECT: VER=5 CMD=1 RSV=0 ATYP=1 DST.ADDR DST.PORT.
    wire.push_back(0x05); wire.push_back(0x01); wire.push_back(0x00);
    wire.push_back(0x01);
    const uint8_t ip4[4] = {
        static_cast<uint8_t>(dst_ip_net & 0xFF),
        static_cast<uint8_t>((dst_ip_net >> 8) & 0xFF),
        static_cast<uint8_t>((dst_ip_net >> 16) & 0xFF),
        static_cast<uint8_t>((dst_ip_net >> 24) & 0xFF)};
    wire.insert(wire.end(), ip4, ip4 + 4);
    wire.push_back(static_cast<uint8_t>(dst_port_net & 0xFF));
    wire.push_back(static_cast<uint8_t>((dst_port_net >> 8) & 0xFF));

    auto t_pipe = std::chrono::steady_clock::now();
    // ONE write. The phone reads greeting(3B) -> auth(variable) -> request(10B)
    // in order from its stream buffer.
    if (!SendAll(s, wire.data(), static_cast<int>(wire.size()))) {
        if (err) *err = "pipelined handshake send failed";
        if (timing) { timing->tcp_ms = tcp_ms; timing->total_ms = stage_ms(t0); }
        closesocket(s);
        return INVALID_SOCKET;
    }

    // Now consume the three replies in the same order the server emits them.
    // (1) method selection: VER METHOD
    uint8_t msel[2];
    if (!RecvAll(s, msel, 2)) {
        if (err) *err = "greeting reply missing (pipelined)";
        if (timing) { timing->tcp_ms = tcp_ms; timing->auth_ms = stage_ms(t_pipe);
                      timing->total_ms = stage_ms(t0); }
        closesocket(s); return INVALID_SOCKET;
    }
    if (msel[0] != 0x05 || msel[1] != 0x02) {
        if (err) *err = "server did not select userpass (0x" +
                        std::to_string(msel[1]) + ")";
        if (timing) { timing->tcp_ms = tcp_ms; timing->auth_ms = stage_ms(t_pipe);
                      timing->total_ms = stage_ms(t0); }
        closesocket(s); return INVALID_SOCKET;
    }
    // (2) RFC1929 auth reply: VER STATUS
    uint8_t ar[2];
    if (!RecvAll(s, ar, 2)) {
        if (err) *err = "auth reply missing (pipelined)";
        if (timing) { timing->tcp_ms = tcp_ms; timing->auth_ms = stage_ms(t_pipe);
                      timing->total_ms = stage_ms(t0); }
        closesocket(s); return INVALID_SOCKET;
    }
    if (ar[1] != 0x00) {
        if (err) *err = "username/password rejected by phone";
        if (timing) { timing->tcp_ms = tcp_ms; timing->auth_ms = stage_ms(t_pipe);
                      timing->total_ms = stage_ms(t0); }
        closesocket(s); return INVALID_SOCKET;
    }
    int auth_ms = stage_ms(t_pipe);
    // (3) CONNECT reply: VER REP RSV ATYP + BND.ADDR + BND.PORT
    uint8_t head[4];
    if (!RecvAll(s, head, 4)) {
        if (err) *err = "CONNECT_REPLY_MISSING (pipelined)";
        if (timing) { timing->tcp_ms = tcp_ms; timing->auth_ms = auth_ms;
                      timing->connect_ms = stage_ms(t_pipe);
                      timing->total_ms = stage_ms(t0); }
        closesocket(s); return INVALID_SOCKET;
    }
    if (head[0] != 0x05 || head[1] != 0x00) {
        if (err) *err = "CONNECT_REJECTED (REP=0x" +
                        std::to_string(head[1]) + ")";
        if (timing) { timing->tcp_ms = tcp_ms; timing->auth_ms = auth_ms;
                      timing->connect_ms = stage_ms(t_pipe);
                      timing->total_ms = stage_ms(t0); }
        closesocket(s); return INVALID_SOCKET;
    }
    if (head[3] == 0x01) {
        uint8_t b[6];
        if (!RecvAll(s, b, 6)) { closesocket(s); return INVALID_SOCKET; }
    } else if (head[3] == 0x03) {
        uint8_t len = 0;
        if (!RecvAll(s, &len, 1)) { closesocket(s); return INVALID_SOCKET; }
        std::vector<uint8_t> b(len + 2);
        if (!RecvAll(s, b.data(), len + 2)) { closesocket(s); return INVALID_SOCKET; }
    } else if (head[3] == 0x04) {
        uint8_t b[18];
        if (!RecvAll(s, b, 18)) { closesocket(s); return INVALID_SOCKET; }
    } else {
        closesocket(s); return INVALID_SOCKET;
    }
    if (timing) {
        timing->tcp_ms = tcp_ms;
        timing->auth_ms = auth_ms;
        timing->connect_ms = stage_ms(t_pipe) - auth_ms;
        timing->total_ms = stage_ms(t0);
    }
    return s;
}

bool ExpSocks5UdpAssociate(const std::string& phone_ip, uint16_t phone_port,
                           const ExpAuth& auth, ExpUdpAssoc* out,
                           std::string* err) {
    if (!out) return false;
    out->ctrl = INVALID_SOCKET;
    out->udp = INVALID_SOCKET;
    out->relay_ip = 0;
    out->relay_port = 0;
    out->relay_unspecified = false;
    SOCKET ctrl = DialWithTimeout(phone_ip, phone_port, 5000, err);
    if (ctrl == INVALID_SOCKET) return false;
    if (!HandshakeAuth(ctrl, auth, err)) {
        closesocket(ctrl);
        return false;
    }
    // UDP ASSOCIATE with DST.ADDR=0.0.0.0 DST.PORT=0 (client has no fixed
    // peer — the phone may enforce its own policy).
    uint8_t req[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    if (!SendAll(ctrl, req, sizeof(req))) {
        if (err) *err = "UDP ASSOCIATE send failed";
        closesocket(ctrl);
        return false;
    }
    uint8_t head[4];
    if (!RecvAll(ctrl, head, 4)) {
        if (err) *err = "UDP ASSOCIATE reply missing";
        closesocket(ctrl);
        return false;
    }
    if (head[0] != 0x05 || head[1] != 0x00) {
        if (err) *err = "UDP ASSOCIATE rejected (REP=0x" +
                        std::to_string(head[1]) + ") - phone may not support UDP";
        closesocket(ctrl);
        return false;
    }
    uint32_t rip = 0;
    uint16_t rport = 0;
    if (head[3] == 0x01) {
        uint8_t b[6];
        if (!RecvAll(ctrl, b, 6)) { closesocket(ctrl); return false; }
        std::memcpy(&rip, b, 4);
        std::memcpy(&rport, b + 4, 2);
    } else if (head[3] == 0x03) {
        uint8_t len = 0;
        if (!RecvAll(ctrl, &len, 1)) { closesocket(ctrl); return false; }
        std::vector<uint8_t> b(len + 2);
        if (!RecvAll(ctrl, b.data(), len + 2)) { closesocket(ctrl); return false; }
        std::memcpy(&rport, b.data() + len, 2);
    } else {
        if (err) *err = "UDP ASSOCIATE BND.ADDR is not IPv4 (ATYP=0x" +
                        std::to_string(head[3]) + ")";
        closesocket(ctrl);
        return false;
    }
    // BND.ADDR 0.0.0.0 (or a domain ATYP) -> the relay lives on the phone
    // itself. Mark the endpoint as advisory: such servers frequently reply
    // from a port other than BND.PORT. beta0.1.5 treated that as fatal and
    // killed the receive thread on the first datagram.
    bool unspecified = (rip == 0);
    if (unspecified) {
        inet_pton(AF_INET, phone_ip.c_str(), &rip);
    }
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        closesocket(ctrl);
        if (err) *err = "udp socket() failed";
        return false;
    }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = 0;
    if (bind(udp, reinterpret_cast<sockaddr*>(&local), sizeof(local)) ==
        SOCKET_ERROR) {
        closesocket(ctrl);
        closesocket(udp);
        if (err) *err = "udp bind() failed";
        return false;
    }
    out->ctrl = ctrl;
    out->udp = udp;
    out->relay_ip = rip;
    out->relay_port = rport;
    out->relay_unspecified = unspecified;
    return true;
}

bool ExpSocks5UdpSend(const ExpUdpAssoc& a, uint32_t dst_ip_net,
                      uint16_t dst_port_net, const uint8_t* payload, int len) {
    if (a.udp == INVALID_SOCKET || !payload || len <= 0 ||
        len > 0x10000 - 10)
        return false;
    std::vector<uint8_t> buf(10 + len);
    buf[0] = 0x00;  // RSV
    buf[1] = 0x00;  // RSV
    buf[2] = 0x00;  // FRAG: only 0 supported, fragments rejected
    buf[3] = 0x01;  // ATYP=IPv4
    std::memcpy(buf.data() + 4, &dst_ip_net, 4);
    std::memcpy(buf.data() + 8, &dst_port_net, 2);
    std::memcpy(buf.data() + 10, payload, static_cast<size_t>(len));
    sockaddr_in relay{};
    relay.sin_family = AF_INET;
    relay.sin_addr.s_addr = a.relay_ip;
    relay.sin_port = a.relay_port;
    int n = sendto(a.udp, reinterpret_cast<const char*>(buf.data()),
                   static_cast<int>(buf.size()), 0,
                   reinterpret_cast<sockaddr*>(&relay), sizeof(relay));
    return n == static_cast<int>(buf.size());
}

int ExpSocks5UdpRecv(const ExpUdpAssoc& a, uint32_t* src_ip_net,
                     uint16_t* src_port_net, uint8_t* buf, int buf_len) {
    if (a.udp == INVALID_SOCKET) return -1;
    std::vector<uint8_t> raw(buf_len + 10 + 262);  // room for a domain ATYP
    sockaddr_in from{};
    int fl = sizeof(from);
    int n = recvfrom(a.udp, reinterpret_cast<char*>(raw.data()),
                     static_cast<int>(raw.size()), 0,
                     reinterpret_cast<sockaddr*>(&from), &fl);
    if (n == SOCKET_ERROR) {
        int e = WSAGetLastError();
        // A timeout is NOT an error: the receive thread must keep waiting.
        if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) return 0;
        return -1;  // real socket failure — the only fatal result
    }
    // beta0.1.6: every "unusable datagram" used to return -1, and
    // UdpRecvThread treated n<=0 as "control connection died" and broke out
    // of the loop FOREVER. One non-IPv4 / fragmented / foreign-port reply
    // from the phone therefore killed UDP for that whole session — the field
    // log froze at "回包 8" while "发送 9" kept growing. All of these are now
    // distinct SKIP codes; only -1 may end the thread.
    if (n < 10) return -2;
    // Endpoint validation: the sender IP must be the phone. BND.PORT is
    // advisory — with BND.ADDR=0.0.0.0 many servers reply from a different
    // port, and even with an explicit BND.ADDR some implementations do.
    // The embedded RSV/FRAG/ATYP/DST header already identifies the flow.
    if (a.relay_ip != 0 && from.sin_addr.s_addr != a.relay_ip)
        return -3;
    if (raw[2] != 0x00) return -4;  // FRAG != 0 unsupported by design
    if (raw[3] != 0x01) return -5;  // domain/IPv6 ATYP: skip, do not die
    std::memcpy(src_ip_net, raw.data() + 4, 4);
    std::memcpy(src_port_net, raw.data() + 8, 2);
    int plen = n - 10;
    if (plen <= 0) return -2;
    if (plen > buf_len) plen = buf_len;
    std::memcpy(buf, raw.data() + 10, static_cast<size_t>(plen));
    return plen;
}

bool ExpSocks5UdpCtrlAlive(const ExpUdpAssoc& a) {
    if (a.ctrl == INVALID_SOCKET) return false;
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(a.ctrl, &rd);
    timeval tv{0, 0};
    int r = select(0, &rd, nullptr, nullptr, &tv);
    if (r == 0) return true;           // nothing pending -> still alive
    if (r == SOCKET_ERROR) return true;  // transient: keep a healthy assoc
    char c = 0;
    int n = recv(a.ctrl, &c, 1, MSG_PEEK);
    if (n == 0) return false;          // FIN: RFC 1928 association is over
    if (n == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) return true;
        return false;
    }
    return true;                       // unexpected control data, still open
}

void ExpSocks5UdpClose(ExpUdpAssoc* a) {
    if (!a) return;
    if (a->ctrl != INVALID_SOCKET) {
        closesocket(a->ctrl);
        a->ctrl = INVALID_SOCKET;
    }
    if (a->udp != INVALID_SOCKET) {
        closesocket(a->udp);
        a->udp = INVALID_SOCKET;
    }
}

}  // namespace linkhelm
