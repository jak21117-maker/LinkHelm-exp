// LinkHelm-exp — WinDivert + SOCKS5 transparent data plane.
//
// Replaces v1.1.x's Wintun + lwIP (hev-socks5-tunnel) data plane:
//   App -> Windows native TCP/IP -> WinDivert (NETWORK layer, selective
//   capture) -> TCP local reflection bridge / SOCKS5 UDP ASSOCIATE relay
//   -> phone Android Host (RFC 1929) -> phone uplink.
//
// No virtual adapter is created and the system route table is NEVER touched
// (beta0.1.2 installed 0.0.0.0/1 + 128.0.0.0/1 half-routes; they failed to
// install yet WinDivert still captured 30+ flows, so they were both useless
// and a source of route pollution). WinDivert's NETWORK layer observes every
// packet Windows routes, and the engine consumes EVERY public-destination
// packet: TCP reflection, DNS relay, or UDP relay. Nothing is ever passed
// through unproxied (fail-closed), because on a host with two default routes
// a passthrough is an unproxied egress that makes the public IP flap.
//
// Name resolution is served by an in-process loopback DNS proxy on
// 127.0.0.1:53: the phone's Wi-Fi Direct DHCP offers its OWN address as the
// DNS server, but the phone is a SOCKS5 proxy, not a resolver. We repoint
// the phone adapter's DNS at 127.0.0.1 and relay every query over SOCKS5
// (TCP DNS, RFC 7766) to a public resolver. Loopback is excluded from the
// WinDivert filter, so there is no packet-injection race for DNS.
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
