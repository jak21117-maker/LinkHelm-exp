// LinkHelm-exp — SOCKS5 client implementation. See exp_socks5.h.
#include "exp_socks5.h"

#include <ws2tcpip.h>

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
SOCKET DialWithTimeout(const std::string& phone_ip, uint16_t phone_port,
                       int timeout_ms, std::string* err) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        if (err) *err = "socket() failed";
        return INVALID_SOCKET;
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
            if (err) *err = "connect to phone failed (WSA " + std::to_string(e) + ")";
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
        if (r <= 0 || FD_ISSET(s, &x)) {
            if (err) *err = "phone SOCKS5 unreachable (timeout)";
            closesocket(s);
            return INVALID_SOCKET;
        }
        int so = 0, sl = sizeof(so);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so), &sl);
        if (so != 0) {
            if (err) *err = "connect refused (WSA " + std::to_string(so) + ")";
            closesocket(s);
            return INVALID_SOCKET;
        }
    }
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
    DWORD tmo = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    return s;
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
    if (auth.user.empty() || auth.user.size() > 255 ||
        auth.pass.size() > 255) {
        if (err) *err = "credentials missing or too long";
        return false;
    }
    std::vector<uint8_t> req;
    req.push_back(0x01);
    req.push_back(static_cast<uint8_t>(auth.user.size()));
    req.insert(req.end(), auth.user.begin(), auth.user.end());
    req.push_back(static_cast<uint8_t>(auth.pass.size()));
    req.insert(req.end(), auth.pass.begin(), auth.pass.end());
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

SOCKET ExpSocks5TcpConnect(const std::string& phone_ip, uint16_t phone_port,
                           const ExpAuth& auth, uint32_t dst_ip_net,
                           uint16_t dst_port_net, std::string* err) {
    SOCKET s = DialWithTimeout(phone_ip, phone_port, 5000, err);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    if (!HandshakeAuth(s, auth, err)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    // CONNECT request: VER CMD=CONNECT RSV=0 ATYP=IPv4 DST.ADDR DST.PORT
    uint8_t req[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    std::memcpy(req + 4, &dst_ip_net, 4);
    std::memcpy(req + 8, &dst_port_net, 2);
    if (!SendAll(s, req, sizeof(req))) {
        if (err) *err = "CONNECT send failed";
        closesocket(s);
        return INVALID_SOCKET;
    }
    uint8_t head[4];
    if (!RecvAll(s, head, 4)) {
        if (err) *err = "CONNECT reply missing";
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (head[0] != 0x05 || head[1] != 0x00) {
        // 0x01 fault, 0x02 not allowed, 0x03 net unreachable, 0x05 refused...
        if (err) *err = "CONNECT rejected (REP=0x" + std::to_string(head[1]) + ")";
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
    // BND.ADDR 0.0.0.0 -> the relay lives on the phone itself
    if (rip == 0) {
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
    if (n < 10) return -1;
    // endpoint validation: only accept datagrams from the relay we chose
    if (from.sin_addr.s_addr != a.relay_ip ||
        from.sin_port != a.relay_port)
        return -1;
    if (raw[2] != 0x00) return -1;  // FRAG != 0 unsupported by design
    if (raw[3] != 0x01) return -1;  // relay must answer with IPv4
    std::memcpy(src_ip_net, raw.data() + 4, 4);
    std::memcpy(src_port_net, raw.data() + 8, 2);
    int plen = n - 10;
    if (plen <= 0) return 0;
    if (plen > buf_len) plen = buf_len;
    std::memcpy(buf, raw.data() + 10, static_cast<size_t>(plen));
    return plen;
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
