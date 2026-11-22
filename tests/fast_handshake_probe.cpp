// beta0.4.9 — REAL-PHONE A/B measurement of the pipelined SOCKS5 handshake.
//
// Not a mock. Connects to the actual phone SOCKS5 (192.168.49.1:8080), does a
// CONNECT to a public DNS IP, then verifies a real request/response round trip
// on the resulting stream. Compares the serial 3-RTT handshake against the new
// 1-RTT pipelined one and prints per-stage timings.
//
// Usage: fast_handshake_probe.exe <phone_ip> <phone_port> <user> <pass> [rounds]
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "exp_socks5.h"

using namespace linkhelm;

static const uint8_t kDnsQuery[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01};

static bool RecvExact(SOCKET s, char* buf, int len) {
    int got = 0;
    while (got < len) {
        int n = ::recv(s, buf + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

static bool RoundTrip(SOCKET s, int* rtt_ms) {
    DWORD tmo = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    // DNS over TCP (RFC 1035 §4.2.1): 2-byte big-endian length prefix.
    char wire[2 + sizeof(kDnsQuery)];
    wire[0] = (char)(sizeof(kDnsQuery) >> 8);
    wire[1] = (char)(sizeof(kDnsQuery) & 0xFF);
    std::memcpy(wire + 2, kDnsQuery, sizeof(kDnsQuery));
    auto t0 = std::chrono::steady_clock::now();
    int sent = ::send(s, wire, sizeof(wire), 0);
    if (sent != (int)sizeof(wire)) return false;
    char lenbuf[2];
    if (!RecvExact(s, lenbuf, 2)) return false;
    int dns_len = ((unsigned char)lenbuf[0] << 8) | (unsigned char)lenbuf[1];
    if (dns_len < 12 || dns_len > 1500) return false;
    std::vector<char> dns(dns_len);
    if (!RecvExact(s, dns.data(), dns_len)) return false;
    if ((dns[2] & 0x80) == 0) return false;  // QR must be 1 (a reply)
    *rtt_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    return true;
}

struct Result {
    int ok = 0, fail = 0;
    std::vector<int> dial_ms, tcp_ms, auth_ms, conn_ms;
};

static void RunMode(const char* label, bool fast, const std::string& ip,
                    uint16_t port, const ExpAuth& auth, int rounds, Result* out) {
    std::printf("\n--- %s ---\n", label);
    for (int i = 0; i < rounds; ++i) {
        std::string err;
        ExpSocks5Timing tm{};
        uint32_t local = 0;
        uint32_t dst = inet_addr("223.5.5.5");
        uint16_t dport = htons(53);
        SOCKET s = fast
            ? ExpSocks5TcpConnectFast(ip, port, auth, dst, dport, &err, &tm, &local)
            : ExpSocks5TcpConnect(ip, port, auth, dst, dport, &err, &tm, &local);
        if (s == INVALID_SOCKET) {
            std::printf("  round %d: CONNECT FAIL - %s\n", i + 1, err.c_str());
            out->fail++;
            continue;
        }
        // Record handshake timing regardless of the data phase.
        out->dial_ms.push_back(tm.total_ms);
        out->tcp_ms.push_back(tm.tcp_ms);
        out->auth_ms.push_back(tm.auth_ms);
        out->conn_ms.push_back(tm.connect_ms);
        int rtt = 0;
        bool data_ok = RoundTrip(s, &rtt);
        closesocket(s);
        if (!data_ok) {
            std::printf("  round %d: CONNECT ok dial=%dms but DATA round-trip FAILED\n",
                        i + 1, tm.total_ms);
            out->fail++;
            continue;
        }
        out->ok++;
        std::printf("  round %d: OK  dial=%dms (tcp=%d auth=%d connect=%d)  data_rtt=%dms\n",
                    i + 1, tm.total_ms, tm.tcp_ms, tm.auth_ms, tm.connect_ms, rtt);
    }
}

static double Avg(const std::vector<int>& v) {
    if (v.empty()) return -1;
    int sum = 0; for (int x : v) sum += x;
    return (double)sum / v.size();
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    if (argc < 5) {
        std::printf("usage: fast_handshake_probe.exe <ip> <port> <user> <pass> [rounds]\n");
        return 2;
    }
    std::string ip = argv[1];
    uint16_t port = (uint16_t)atoi(argv[2]);
    ExpAuth auth{argv[3], argv[4]};
    int rounds = argc >= 6 ? atoi(argv[5]) : 5;

    std::printf("=== A++ fast-handshake REAL-PHONE A/B test ===\n");
    std::printf("endpoint=%s:%u rounds=%d target=223.5.5.5:53 (real DNS query)\n",
                ip.c_str(), port, rounds);

    Result serial, fast;
    RunMode("SERIAL 3-RTT (ExpSocks5TcpConnect)", false, ip, port, auth, rounds, &serial);
    RunMode("PIPELINED 1-RTT (ExpSocks5TcpConnectFast)", true, ip, port, auth, rounds, &fast);

    std::printf("\n=== SUMMARY ===\n");
    std::printf("serial : ok=%d fail=%d  avg_dial=%.0fms (tcp=%.0f auth=%.0f connect=%.0f)\n",
                serial.ok, serial.fail, Avg(serial.dial_ms), Avg(serial.tcp_ms),
                Avg(serial.auth_ms), Avg(serial.conn_ms));
    std::printf("fast   : ok=%d fail=%d  avg_dial=%.0fms (tcp=%.0f auth=%.0f connect=%.0f)\n",
                fast.ok, fast.fail, Avg(fast.dial_ms), Avg(fast.tcp_ms),
                Avg(fast.auth_ms), Avg(fast.conn_ms));
    if (serial.dial_ms.size() && fast.dial_ms.size())
        std::printf("handshake saving: %.0fms per flow\n",
                    Avg(serial.dial_ms) - Avg(fast.dial_ms));

    // Decision: fast must be at least as reliable AND not slower.
    bool pass = (fast.fail == 0) && (fast.ok == rounds) &&
                (Avg(fast.dial_ms) <= Avg(serial.dial_ms) + 5);
    std::printf("\n=== RESULT: %s ===\n", pass ? "PASS" : "FAIL");
    WSACleanup();
    return pass ? 0 : 1;
}
