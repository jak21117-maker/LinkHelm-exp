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

// Dial the phone SOCKS5 and CONNECT to dst (network-order ip:port).
// Returns a valid SOCKET or INVALID_SOCKET (err filled).
SOCKET ExpSocks5TcpConnect(const std::string& phone_ip, uint16_t phone_port,
                           const ExpAuth& auth, uint32_t dst_ip_net,
                           uint16_t dst_port_net, std::string* err);

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
