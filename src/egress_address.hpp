#pragma once

#include <boost/corosio/endpoint.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <span>
#include <stdexcept>
#include <string_view>

namespace zetta_tunnel::egress {

namespace net = boost::corosio;

struct DeniedCidr {
  net::endpoint network;
  unsigned bits;
  bool operator==(const DeniedCidr &) const = default;

  bool contains(const net::endpoint &address) const {
    if (network.is_v4() != address.is_v4()) {
      return false;
    }
    auto matches = [this](const auto &prefix, const auto &value) {
      for (unsigned bit = 0; bit < bits; ++bit) {
        const auto mask = 0x80U >> (bit % 8);
        if ((prefix[bit / 8] & mask) != (value[bit / 8] & mask)) {
          return false;
        }
      }
      return true;
    };
    return network.is_v4()
               ? matches(network.v4_address().to_bytes(), address.v4_address().to_bytes())
               : matches(network.v6_address().to_bytes(), address.v6_address().to_bytes());
  }
};

inline DeniedCidr parse_denied_cidr(std::string_view value) {
  const auto slash = value.find('/');
  if (slash == std::string_view::npos) {
    throw std::invalid_argument("denied CIDR requires a prefix length");
  }
  const auto host = value.substr(0, slash);
  net::ipv4_address v4;
  net::ipv6_address v6;
  net::endpoint network;
  if (!net::parse_ipv4_address(host, v4)) {
    network = net::endpoint(v4, 0);
  } else if (!net::parse_ipv6_address(host, v6)) {
    network = net::endpoint(v6, 0);
  } else {
    throw std::invalid_argument("invalid denied CIDR address");
  }
  unsigned bits = 0;
  const auto length = value.substr(slash + 1);
  const auto [end, error] = std::from_chars(length.data(), length.data() + length.size(), bits);
  if (error != std::errc{} || end != length.data() + length.size() ||
      bits > (network.is_v4() ? 32U : 128U)) {
    throw std::invalid_argument("invalid denied CIDR prefix length");
  }
  // Reject host bits so the operator's projection has one unambiguous network.
  auto canonical = [bits](const auto &bytes) {
    for (unsigned bit = bits; bit < bytes.size() * 8; ++bit) {
      if (bytes[bit / 8] & (0x80U >> (bit % 8))) {
        return false;
      }
    }
    return true;
  };
  if (!(network.is_v4() ? canonical(network.v4_address().to_bytes())
                        : canonical(network.v6_address().to_bytes()))) {
    throw std::invalid_argument("denied CIDR has host bits set");
  }
  if (network.is_v6() && network.v6_address().is_v4_mapped() && bits >= 96) {
    const auto bytes = network.v6_address().to_bytes();
    network = net::endpoint(net::ipv4_address({bytes[12], bytes[13], bytes[14], bytes[15]}), 0);
    bits -= 96;
  }
  return {network, bits};
}

// The DNS gateway accepts public unicast only; projected exclusions can narrow it further.
inline bool allowed_destination(net::endpoint address, std::span<const DeniedCidr> denied = {}) {
  if (std::ranges::any_of(denied, [&address](const auto &cidr) {
        return cidr.contains(address);
      })) {
    return false;
  }
  if (address.is_v6() && address.v6_address().is_v4_mapped()) {
    const auto bytes = address.v6_address().to_bytes();
    address = net::endpoint(net::ipv4_address({bytes[12], bytes[13], bytes[14], bytes[15]}), 0);
    if (std::ranges::any_of(denied, [&address](const auto &cidr) {
          return cidr.contains(address);
        })) {
      return false;
    }
  }
  if (address.is_v4()) {
    // IANA special-use ranges plus Azure's platform virtual address.
    static const auto excluded = [] {
      constexpr std::string_view values[] = {
          "0.0.0.0/8",      "10.0.0.0/8",     "100.64.0.0/10",   "127.0.0.0/8",
          "169.254.0.0/16", "172.16.0.0/12",  "192.0.0.0/24",    "192.0.2.0/24",
          "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",   "198.51.100.0/24",
          "203.0.113.0/24", "224.0.0.0/3",    "168.63.129.16/32"};
      std::array<DeniedCidr, std::size(values)> result{};
      std::ranges::transform(values, result.begin(), parse_denied_cidr);
      return result;
    }();
    return std::ranges::none_of(excluded, [&address](const auto &cidr) {
      return cidr.contains(address);
    });
  }
  // Only global unicast 2000::/3. Exclude special protocol assignments, documentation,
  // and 6to4 (which can encode a private IPv4 destination); NAT64 is outside this range.
  static const auto global = parse_denied_cidr("2000::/3");
  static const auto protocol = parse_denied_cidr("2001::/23");
  static const auto documentation = parse_denied_cidr("2001:db8::/32");
  static const auto six_to_four = parse_denied_cidr("2002::/16");
  static const auto documentation2 = parse_denied_cidr("3fff::/20");
  return global.contains(address) && !protocol.contains(address) &&
         !documentation.contains(address) && !six_to_four.contains(address) &&
         !documentation2.contains(address);
}

} // namespace zetta_tunnel::egress
