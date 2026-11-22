// beta0.5.0 phone-liveness watchdog - real-phone probe test.
// Usage: liveness_probe.exe <phone_ip> <phone_port> <user> <pass>
// Proves ExpSocks5Liveness() returns true for a live phone and false for a
// dead/unreachable endpoint (the path the auto-disconnect watchdog relies on).
#include <cstdio>
#include <string>
#include <winsock2.h>
#include "../src/exp_socks5.h"

int main(int argc, char** argv) {
    using namespace linkhelm;
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    if (argc < 5) {
        std::printf("usage: liveness_probe <phone_ip> <port> <user> <pass>\n");
        return 2;
    }
    ExpAuth auth{argv[3], argv[4]};
    int port = atoi(argv[2]);
    int pass = 0, fail = 0;

    // 1) Live phone -> must succeed.
    std::string err;
    bool live = ExpSocks5Liveness(argv[1], (uint16_t)port, auth, &err);
    std::printf("[%s] live phone %s:%d -> %s %s\n",
                live ? "PASS" : "FAIL", argv[1], port,
                live ? "ONLINE" : "OFFLINE", live ? "" : err.c_str());
    live ? ++pass : ++fail;

    // 2) Unreachable endpoint -> must fail (this is the auto-disconnect path).
    // 192.0.2.1 is TEST-NET-1 (RFC5737), guaranteed non-routable.
    std::string err2;
    bool dead = ExpSocks5Liveness("192.0.2.1", (uint16_t)port, auth, &err2);
    bool detected = !dead;
    std::printf("[%s] dead phone 192.0.2.1:%d -> %s (%s)\n",
                detected ? "PASS" : "FAIL", port,
                detected ? "OFFLINE DETECTED" : "WRONGLY ONLINE", err2.c_str());
    detected ? ++pass : ++fail;

    std::printf("\n=== RESULT: %d passed, %d failed ===\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
