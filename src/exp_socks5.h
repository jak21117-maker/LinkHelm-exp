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

// Receive one relay datagram and unwrap it. Validates that the sender is the
// expected relay endpoint. Returns payload length, or -1 on error/foreign
// sender. FRAG!=0 datagrams are rejected (dropped) per the plan (never
// silently reassembled).
int ExpSocks5UdpRecv(const ExpUdpAssoc& a, uint32_t* src_ip_net,
                     uint16_t* src_port_net, uint8_t* buf, int buf_len);

void ExpSocks5UdpClose(ExpUdpAssoc* a);

}  // namespace linkhelm
