// LinkHelm-exp beta0.1.6 — read-only SOCKS5 capability probe.
//
// Run this on the Windows PC while LinkHelm Android Host is up and the PC is
// joined to the phone's Wi-Fi Direct network. It does NOT modify routes,
// adapters, DNS, the registry or any firewall rule, and it does NOT load the
// WinDivert driver (no admin rights needed).
//
// It answers the three questions the architecture review says must be
// settled by measurement, not assumption:
//   1. Does the phone accept username/password auth and TCP CONNECT?
//   2. Does UDP ASSOCIATE succeed, and what BND.ADDR/BND.PORT does it return?
//   3. Does a real UDP datagram come back, from WHICH source port, with
//      WHICH ATYP/FRAG — i.e. is the phone's relay behaviour compatible?
//
// Usage: socks5_probe.exe <phone_ip> <phone_port> [user] [pass]
// Credentials are supplied on the command line and are NEVER printed.
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "exp_socks5.h"

namespace {

const char* IpStr(uint32_t net) {
    static char b[64];
    in_addr a;
    a.s_addr = net;
    inet_ntop(AF_INET, &a, b, sizeof(b));
    return b;
}

// Minimal DNS A query for www.example.com (RFC 1035).
std::vector<uint8_t> MakeDnsQuery(uint16_t id) {
    const uint8_t name[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm',
                            'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    std::vector<uint8_t> q;
    q.push_back((uint8_t)(id >> 8));
    q.push_back((uint8_t)id);
    q.push_back(0x01); q.push_back(0x00);  // RD
    q.push_back(0x00); q.push_back(0x01);  // QDCOUNT=1
    q.push_back(0x00); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x00);
    q.insert(q.end(), name, name + sizeof(name));
    q.push_back(0x00); q.push_back(0x01);  // QTYPE=A
    q.push_back(0x00); q.push_back(0x01);  // QCLASS=IN
    return q;
}

}  // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    if (argc < 3) {
        std::printf("usage: socks5_probe.exe <phone_ip> <phone_port> [user] [pass]\n");
        std::printf("example: socks5_probe.exe 192.168.49.1 8080\n");
        return 2;
    }
    std::string ip = argv[1];
    uint16_t port = (uint16_t)std::atoi(argv[2]);
    linkhelm::ExpAuth auth;
    if (argc >= 5) { auth.user = argv[3]; auth.pass = argv[4]; }

    std::printf("=== LinkHelm SOCKS5 capability probe (read-only) ===\n");
    std::printf("endpoint: %s:%u  auth: %s\n\n", ip.c_str(), port,
                auth.user.empty() ? "none" : "username/password");

    // ---- 1. auth + TCP CONNECT -------------------------------------------
    std::string err;
    if (!linkhelm::ExpSocks5Precheck(ip, port, auth, &err)) {
        std::printf("[1] AUTH/CONNECT PRECHECK: FAIL — %s\n", err.c_str());
        std::printf("    => Wi-Fi Direct link, port or credentials are wrong.\n");
        WSACleanup();
        return 1;
    }
    std::printf("[1] AUTH/CONNECT PRECHECK: OK\n");
    uint32_t dns_net = inet_addr("223.5.5.5");
    uint16_t dport_net = htons(53);
    SOCKET tcp = linkhelm::ExpSocks5TcpConnect(ip, port, auth, dns_net,
                                               dport_net, &err);
    if (tcp == INVALID_SOCKET) {
        std::printf("    TCP CONNECT 223.5.5.5:53: FAIL — %s\n", err.c_str());
    } else {
        std::printf("    TCP CONNECT 223.5.5.5:53: OK\n");
        closesocket(tcp);
    }

    // ---- 2. UDP ASSOCIATE -------------------------------------------------
    linkhelm::ExpUdpAssoc a{};
    if (!linkhelm::ExpSocks5UdpAssociate(ip, port, auth, &a, &err)) {
        std::printf("[2] UDP ASSOCIATE: FAIL — %s\n", err.c_str());
        std::printf("    => The phone does NOT offer UDP relay. UDP games/QUIC\n");
        std::printf("       cannot work with this Host build; TCP can.\n");
        WSACleanup();
        return 1;
    }
    std::printf("[2] UDP ASSOCIATE: OK\n");
    std::printf("    relay_ip=%s  BND.PORT=%u  BND.ADDR was %s\n",
                IpStr(a.relay_ip), ntohs(a.relay_port),
                a.relay_unspecified ? "0.0.0.0 / domain (unspecified)"
                                    : "an explicit IPv4 address");

    // ---- 3. real UDP round trip ------------------------------------------
    // Two queries: the first is read RAW to expose the phone's actual reply
    // source port / ATYP / FRAG; the second goes through the production
    // ExpSocks5UdpRecv path that LinkHelmExp.exe uses.
    DWORD tmo = 4000;
    setsockopt(a.udp, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    auto q1 = MakeDnsQuery(0x1234);
    bool sent1 = linkhelm::ExpSocks5UdpSend(a, dns_net, dport_net,
                                            q1.data(), (int)q1.size());
    std::printf("[3] UDP datagram #1 sent: %s\n", sent1 ? "OK" : "FAIL");
    if (sent1) {
        char raw[2048];
        sockaddr_in from{};
        int fl = sizeof(from);
        int n = recvfrom(a.udp, raw, (int)sizeof(raw), 0,
                         reinterpret_cast<sockaddr*>(&from), &fl);
        if (n <= 0) {
            std::printf("    RAW reply: NONE within 4s (WSA %d)\n",
                        WSAGetLastError());
            std::printf("    => The phone accepted ASSOCIATE but forwards no\n");
            std::printf("       UDP reply. This is the 'UDP 没通' root cause.\n");
        } else {
            std::printf("    RAW reply: %d bytes from %s:%u\n", n,
                        IpStr(from.sin_addr.s_addr), ntohs(from.sin_port));
            // SOCKS5 UDP request header: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT
            if (n >= 10) {
                std::printf("    header: RSV=%u,%u FRAG=%u ATYP=%u\n",
                            (unsigned char)raw[0], (unsigned char)raw[1],
                            (unsigned char)raw[2], (unsigned char)raw[3]);
                std::printf("    actual source port %s BND.PORT (%u)\n",
                            from.sin_port == a.relay_port
                                ? "MATCHES" : "DIFFERS FROM",
                            ntohs(a.relay_port));
            }
        }
    }
    auto q2 = MakeDnsQuery(0x5678);
    bool sent2 = linkhelm::ExpSocks5UdpSend(a, dns_net, dport_net,
                                            q2.data(), (int)q2.size());
    if (sent2) {
        uint8_t back[2048];
        uint32_t sip = 0;
        uint16_t sport = 0;
        int n = linkhelm::ExpSocks5UdpRecv(a, &sip, &sport, back,
                                          (int)sizeof(back));
        std::printf("[4] production ExpSocks5UdpRecv: rc=%d\n", n);
        if (n > 0) {
            std::printf("    payload=%d bytes, claimed remote=%s:%u\n", n,
                        IpStr(sip), ntohs(sport));
            std::printf("    => UDP relay is usable by LinkHelmExp.exe.\n");
        } else if (n == -1) {
            std::printf("    socket error — association is dead.\n");
        } else if (n == 0) {
            std::printf("    no reply (timeout).\n");
        } else {
            std::printf("    skipped datagram code %d (thread stays alive).\n", n);
        }
    }
    std::printf("\n[5] control connection alive: %s\n",
                linkhelm::ExpSocks5UdpCtrlAlive(a) ? "YES" : "NO (assoc dead)");
    linkhelm::ExpSocks5UdpClose(&a);
    WSACleanup();
    std::printf("\n=== probe finished. No system settings were changed. ===\n");
    return 0;
}
