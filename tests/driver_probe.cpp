// LinkHelm-exp — REAL WinDivert driver-layer acceptance probe.
//
// Why this exists: all mock-phone self-tests cover only the code ABOVE and
// BELOW the driver. They cannot answer the question that actually matters on
// the target PC: can WinDivert (a) capture a real outbound packet and
// (b) inject a real inbound packet so an ordinary UDP socket receives it?
// That second half is the UDP "回包闭环" the engine depends on.
//
// Run as Administrator, from the release folder (WinDivert.dll + .sys next
// to this exe). It uses a TEST-NET-3 address (203.0.113.7, RFC 5737, never
// routable) and a narrow filter; it makes NO change to routes, DNS, firewall
// or registry. Exit code 0 = driver layer proven, 1 = proven broken,
// 2 = not testable (no elevation / driver unavailable).
//
//   driver_probe.exe
// libstdc++ headers MUST precede the Windows/SAL headers: sal.h defines
// __out and friends, which otherwise poison STL templates.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include "windivert.h"

typedef HANDLE (*WD_Open)(const char*, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL   (*WD_Close)(HANDLE);
typedef BOOL   (*WD_Recv)(HANDLE, PVOID, UINT, UINT*, WINDIVERT_ADDRESS*);
typedef BOOL   (*WD_Send)(HANDLE, const PVOID, UINT, UINT*,
                          const WINDIVERT_ADDRESS*);
typedef UINT   (*WD_Checksums)(PVOID, UINT, WINDIVERT_ADDRESS*, UINT64);

static const uint16_t kProbePort = 45999;   // only our own packet matches
static const uint32_t kDocAddr  = 0xCB007107;  // 203.0.113.7, network order

static int Result(const char* label, bool ok, const std::string& detail) {
    std::printf("[%s] %-46s %s\n", ok ? "PASS" : "FAIL", label,
                detail.c_str());
    return ok ? 0 : 1;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    std::printf("=== LinkHelm-exp WinDivert DRIVER probe ===\n");

    // 0. Elevation is required to load WinDivert64.sys.
    BOOL elevated = FALSE;
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te{}; DWORD n = 0;
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &n))
            elevated = te.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    if (!elevated) {
        std::printf("[SKIP] not elevated - WinDivert64.sys cannot load.\n"
                    "       Re-run this tool as Administrator. Nothing was "
                    "verified; this is NOT a pass.\n");
        WSACleanup();
        return 2;
    }

    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring dir(self);
    size_t sl = dir.rfind(L'\\');
    if (sl != std::wstring::npos) dir = dir.substr(0, sl);
    if (sl == std::wstring::npos) dir = L".";
    // Support running from tests/ subfolder too.
    for (const wchar_t* candidate : {L"", L"\\.."}) {
        std::wstring p = dir + candidate + L"\\WinDivert.dll";
        HMODULE d = LoadLibraryW(p.c_str());
        if (d) { dir = dir + candidate; FreeLibrary(d); break; }
    }
    HMODULE dll = LoadLibraryW((dir + L"\\WinDivert.dll").c_str());
    if (!dll) {
        std::printf("[SKIP] WinDivert.dll not found next to the exe.\n");
        WSACleanup();
        return 2;
    }
    WD_Open      wopen = (WD_Open)GetProcAddress(dll, "WinDivertOpen");
    WD_Close     wclose = (WD_Close)GetProcAddress(dll, "WinDivertClose");
    WD_Recv      wrecv = (WD_Recv)GetProcAddress(dll, "WinDivertRecv");
    WD_Send      wsend = (WD_Send)GetProcAddress(dll, "WinDivertSend");
    WD_Checksums wsum = (WD_Checksums)GetProcAddress(
        dll, "WinDivertHelperCalcChecksums");
    if (!wopen || !wclose || !wrecv || !wsend || !wsum) {
        std::printf("[FAIL] WinDivert.dll missing required exports.\n");
        FreeLibrary(dll); WSACleanup(); return 1;
    }

    // Narrow filter: only our probe datagram, outbound, no impostor.
    char filter[256];
    _snprintf_s(filter, sizeof(filter), _TRUNCATE,
                "outbound and !loopback and !impostor and udp.DstPort == %u",
                (unsigned)kProbePort);
    HANDLE h = wopen(filter, WINDIVERT_LAYER_NETWORK, 1000, 0);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        std::printf("[FAIL] WinDivertOpen err=%lu : %s\n", (unsigned long)e,
                    e == ERROR_ACCESS_DENIED ? "still not elevated / blocked"
                    : e == 2 ? "WinDivert64.sys not found next to the exe"
                    : e == 5 ? "access denied (service/driver state)"
                    : "driver or service error");
        FreeLibrary(dll); WSACleanup();
        return 1;
    }
    std::printf("[INFO] WinDivert driver loaded, filter: %s\n", filter);

    // A watchdog closes the handle after 8 s so a machine with no usable
    // route cannot hang the probe forever.
    std::atomic<bool> done{false}, timed_out{false};
    std::thread watchdog([&] {
        for (int i = 0; i < 80 && !done.load(); ++i) Sleep(100);
        if (!done.load()) { timed_out.store(true); wclose(h); }
    });
    watchdog.detach();

    int rc = 0;
    SOCKET app = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in la{}; la.sin_family = AF_INET;
    la.sin_addr.s_addr = INADDR_ANY; la.sin_port = 0;
    bind(app, (sockaddr*)&la, sizeof(la));
    sockaddr_in bound{}; int bl = sizeof(bound);
    getsockname(app, (sockaddr*)&bound, &bl);
    uint16_t app_port = bound.sin_port;   // network order
    DWORD tmo = 3000;
    setsockopt(app, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));

    sockaddr_in dst{}; dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = kDocAddr;
    dst.sin_port = htons(kProbePort);
    const char* payload = "LH-PROBE";
    sendto(app, (const char*)payload, (int)strlen(payload), 0,
           (sockaddr*)&dst, sizeof(dst));

    // ---- A. real outbound capture --------------------------------------
    uint8_t pkt[2048]{}; UINT len = 0;
    WINDIVERT_ADDRESS addr{};
    bool captured = wrecv(h, pkt, sizeof(pkt), &len, &addr);
    WINDIVERT_IPHDR* iph = (WINDIVERT_IPHDR*)pkt;
    bool right = captured && len >= sizeof(WINDIVERT_IPHDR) &&
                 iph->Protocol == IPPROTO_UDP && addr.Outbound;
    uint32_t local_ip = right ? iph->SrcAddr : 0;   // network order
    rc |= Result("A. real outbound packet captured by WinDivert",
                 right, captured ? "len=" + std::to_string(len) +
                     " ifIdx=" + std::to_string(addr.Network.IfIdx)
                     : "WinDivertRecv failed (see watchdog)");

    // The captured packet is DROPPED (not reinjected): nothing leaves the
    // machine toward the documentation address.

    // ---- B. real inbound injection reaches an ordinary UDP socket ------
    // This is the exact path UdpRecvThread uses for SOCKS5 replies.
    bool delivered = false;
    if (right) {
        size_t plen = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + 4;
        std::vector<uint8_t> ib(plen, 0);
        auto* i4 = (WINDIVERT_IPHDR*)ib.data();
        auto* u4 = (WINDIVERT_UDPHDR*)(ib.data() + sizeof(WINDIVERT_IPHDR));
        i4->Version = 4;
        i4->HdrLength = sizeof(WINDIVERT_IPHDR) / 4;
        i4->Length = htons((uint16_t)plen);
        i4->Id = 0x4C48;
        i4->TTL = 64;
        i4->Protocol = IPPROTO_UDP;
        i4->SrcAddr = kDocAddr;      // pretend to be the remote server
        i4->DstAddr = local_ip;      // this PC's own address
        u4->SrcPort = htons(kProbePort);
        u4->DstPort = app_port;
        u4->Length = htons((uint16_t)(sizeof(WINDIVERT_UDPHDR) + 4));
        memcpy(ib.data() + sizeof(WINDIVERT_IPHDR) +
               sizeof(WINDIVERT_UDPHDR), "PONG", 4);
        WINDIVERT_ADDRESS ia{};
        ia.Outbound = FALSE;
        ia.Loopback = FALSE;
        ia.Network.IfIdx = addr.Network.IfIdx;
        ia.Network.SubIfIdx = addr.Network.SubIfIdx;
        wsum(ib.data(), (UINT)plen, &ia, 0);
        UINT sent = 0;
        BOOL ok = wsend(h, ib.data(), (UINT)plen, &sent, &ia);
        bool sent_ok = ok && sent == plen;
        rc |= Result("B1. WinDivertSend accepts inbound packet",
                     sent_ok, sent_ok
                         ? "sent=" + std::to_string(sent)
                         : "BOOL=" + std::to_string((int)ok) +
                               " sent=" + std::to_string(sent) +
                               " err=" + std::to_string(GetLastError()));
        if (sent_ok) {
            char rb[128];
            sockaddr_in from{}; int fl = sizeof(from);
            int n = recvfrom(app, rb, sizeof(rb), 0, (sockaddr*)&from, &fl);
            delivered = (n == 4 && memcmp(rb, "PONG", 4) == 0 &&
                         from.sin_addr.s_addr == kDocAddr &&
                         from.sin_port == htons(kProbePort));
            rc |= Result("B2. injected reply DELIVERED to app UDP socket",
                         delivered, "recv=" + std::to_string(n) +
                             " (this is the UDP reply close-loop)");
        } else {
            rc |= Result("B2. injected reply DELIVERED to app UDP socket",
                         false, "skipped: send failed");
        }
    } else {
        rc |= Result("B1. WinDivertSend accepts inbound packet", false,
                     "skipped: no capture");
        rc |= Result("B2. injected reply DELIVERED to app UDP socket", false,
                     "skipped: no capture");
    }

    closesocket(app);
    done.store(true);
    if (!timed_out.load()) wclose(h);
    FreeLibrary(dll);
    WSACleanup();
    std::printf("\n=== DRIVER VERDICT: %s ===\n",
                rc == 0 ? "WORKING" : "BROKEN / NOT PROVEN");
    std::printf("B2 FAIL is the decisive symptom: if WinDivertSend succeeds "
                "but the socket never receives, the engine's UDP reply "
                "injection (UdpRecvThread) cannot work on this host - "
                "check addr.IfIdx / firewall / network profile first.\n");
    std::fflush(stdout);
    ExitProcess((UINT)(rc == 0 ? 0 : 1));
    return rc;
}
