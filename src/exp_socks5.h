// LinkHelm-exp — SOCKS5 client (RFC 1928/1929).
//
// The Android Host on the phone is the SOCKS5 server (unchanged from
// v1.1.x). wfp-divert only speaks method=0x00 (no auth), which the phone
// rejects — this client implements method=0x02 (username/password) per the
// plan document's P0 requirement.
//
// No exceptions (build uses -fno-exceptions): every failure path returns a
// code and fills the error string.
#pragma once

#include <winsock2.h>

#include <cstdint>
#include <string>

namespace linkhelm {

struct ExpAuth {
    std::string user;
    std::string pass;
};

// Quick reachability + auth probe (greeting + RFC1929 subnegotiation only,
// no CONNECT). Returns false and fills *err on failure.
bool ExpSocks5Precheck(const std::string& phone_ip, uint16_t phone_port,
                       const ExpAuth& auth, std::string* err);

// beta0.5.0 phone-liveness watchdog probe: full SOCKS5 CONNECT to a public
// resolver (223.5.5.5:53) with a SHORT overall budget — proves both that the
// phone app is listening (TCP:8080) AND that its cellular uplink actually
// reaches the Internet. Unlike ExpSocks5Precheck (auth only) this catches
// "app alive but no signal / out of range / uplink down". Returns true only
// on a successful CONNECT reply; fills *err with the failing stage otherwise.
// Intended to be called from a dedicated watchdog thread, never the data plane.
bool ExpSocks5Liveness(const std::string& phone_ip, uint16_t phone_port,
                       const ExpAuth& auth, std::string* err);

// Per-stage timing of one SOCKS5 dial. All values in milliseconds.
// beta0.1.8 (report §04): the field log showed "phone SOCKS5 unreachable
// (timeout)" at 532ms while the dial budget was 3000ms — the exception set
// of select() was lumped together with a genuine timeout, so a refused or
// reset connection was reported as an unreachable phone. The stage timings
// tell the three failure domains apart:
//   * tcp_ms    — establishing the TCP connection to the phone
//   * auth_ms   — SOCKS5 greeting + RFC1929 subnegotiation
//   * connect_ms— the CONNECT request/reply round trip
struct ExpSocks5Timing {
    int tcp_ms = 0;
    int auth_ms = 0;
    int connect_ms = 0;
    int total_ms = 0;
};

// Dial the phone SOCKS5 and CONNECT to dst (network-order ip:port).
// Returns a valid SOCKET or INVALID_SOCKET (err filled).
// *timing (optional) receives the per-stage durations; *local_ip_net
// (optional) receives the local source address used for the dial.
SOCKET ExpSocks5TcpConnect(const std::string& phone_ip, uint16_t phone_port,
                           const ExpAuth& auth, uint32_t dst_ip_net,
                           uint16_t dst_port_net, std::string* err,
                           ExpSocks5Timing* timing = nullptr,
                           uint32_t* local_ip_net = nullptr);

// beta0.4.9 "A++" short-reflection handshake: pipeline greeting + RFC1929
// auth + CONNECT into a single send, collapsing ~3 RTT to ~1 RTT. Protocol-safe
// because the Android Socks5Parser reads fixed byte counts per stage from one
// InputStream and the server only accepts method 0x02 (deterministic choice).
// Fall back to ExpSocks5TcpConnect (FastHandshake=0) if a peer misbehaves.
SOCKET ExpSocks5TcpConnectFast(const std::string& phone_ip, uint16_t phone_port,
                               const ExpAuth& auth, uint32_t dst_ip_net,
                               uint16_t dst_port_net, std::string* err,
                               ExpSocks5Timing* timing = nullptr,
                               uint32_t* local_ip_net = nullptr);

struct ExpUdpAssoc {
    SOCKET ctrl = INVALID_SOCKET;   // TCP control connection (owns the assoc)
    SOCKET udp = INVALID_SOCKET;    // UDP socket used to talk to the relay
    uint32_t relay_ip = 0;          // network order (phone ip when BND.IP==0)
    uint16_t relay_port = 0;        // network order
    // Many SOCKS5 servers (including simple Kotlin implementations) answer
    // UDP ASSOCIATE with BND.ADDR=0.0.0.0 and then send relay datagrams from
    // a port OTHER than BND.PORT. beta0.1.5 validated both IP and PORT and
    // treated any mismatch as a fatal error, which PERMANENTLY killed the
    // session's receive thread on the first such datagram — the field log
    // froze at "发送 9 回包 8". Port is therefore advisory only.
    bool relay_unspecified = false;
};

// Open a UDP ASSOCIATE: TCP control conn + auth + UDP ASSOCIATE request +
// a bound UDP socket for relay traffic. Closing the control connection ends
// the association (RFC 1928).
bool ExpSocks5UdpAssociate(const std::string& phone_ip, uint16_t phone_port,
                           const ExpAuth& auth, ExpUdpAssoc* out,
                           std::string* err);

// Wrap payload in a SOCKS5 UDP datagram (RSV/FRAG=0, ATYP=IPv4) and send to
// the relay endpoint.
bool ExpSocks5UdpSend(const ExpUdpAssoc& a, uint32_t dst_ip_net,
                      uint16_t dst_port_net, const uint8_t* payload, int len);

// Receive one relay datagram and unwrap it. Three-state result so a single
// malformed datagram can NEVER terminate the session's receive thread:
//   > 0 : valid payload length (src_ip_net/src_port_net filled)
//    0  : recv timeout / no data yet — caller keeps waiting
//   -1  : real socket error — caller may exit the thread
//   -2  : short/empty datagram         } skipped, thread MUST continue
//   -3  : foreign sender IP            } skipped, thread MUST continue
//   -4  : FRAG != 0 (unsupported)     } skipped, thread MUST continue
//   -5  : ATYP != IPv4                } skipped, thread MUST continue
// Only the sender IP is validated (never the port). FRAG!=0 datagrams are
// dropped per the plan (never silently reassembled).
int ExpSocks5UdpRecv(const ExpUdpAssoc& a, uint32_t* src_ip_net,
                     uint16_t* src_port_net, uint8_t* buf, int buf_len);

// Non-blocking liveness probe for the ASSOCIATE control connection. RFC 1928:
// closing the TCP control connection terminates the UDP association. Without
// this check a session silently degrades into send-only (field log: replies
// freeze while sent datagrams keep increasing).
bool ExpSocks5UdpCtrlAlive(const ExpUdpAssoc& a);

void ExpSocks5UdpClose(ExpUdpAssoc* a);

}  // namespace linkhelm
