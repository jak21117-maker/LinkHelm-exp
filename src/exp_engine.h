// LinkHelm-exp — WinDivert + SOCKS5 transparent data plane.
//
// Replaces v1.1.x's Wintun + lwIP (hev-socks5-tunnel) data plane:
//   App -> Windows native TCP/IP -> WinDivert (NETWORK layer, selective
//   capture) -> TCP local reflection bridge / SOCKS5 UDP ASSOCIATE relay
//   -> phone Android Host (RFC 1929) -> phone uplink.
//
// No virtual adapter is created and the system default route is never
// replaced. Half-routes (0.0.0.0/1 + 128.0.0.0/1 via the phone) are added
// ONLY when Windows has no usable route for Internet traffic (ROUTE-00
// gate) so that packets exist for WinDivert to capture; they are removed on
// Stop. NCSI probes ride the same capture path, so the real Wi-Fi Direct
// adapter shows "Internet access".
//
// Interface mirrors the old TunnelManager so the UI wiring stays minimal:
//   Start(cfg, &err) / Stop().
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace linkhelm {

struct ExpConfig {
    std::wstring phone_ip;       // e.g. 192.168.49.1 (Wi-Fi Direct GO)
    int phone_port = 8080;       // SOCKS5 on the phone
    std::wstring socks_user;     // RFC 1929
    std::wstring socks_pass;
};

class ExpEngine {
public:
    using LogFn = std::function<void(const std::wstring&)>;
    using StateFn = std::function<void(const std::wstring&)>;

    ExpEngine(LogFn log, StateFn status);
    ~ExpEngine();

    // Blocking until the data plane is up (or failed). Safe to call once;
    // further Start calls without Stop return false.
    bool Start(const ExpConfig& cfg, std::wstring* error);
    // Stops capture, closes all sessions, removes routes we added.
    void Stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace linkhelm
