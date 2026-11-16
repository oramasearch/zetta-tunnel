// SPDX-License-Identifier: MIT

#include "egress_address.hpp"

#include <iostream>
#include <vector>

namespace egress = zetta_tunnel::egress;
namespace net = boost::corosio;

net::endpoint endpoint(std::string_view value) {
  net::ipv4_address v4;
  if (!net::parse_ipv4_address(value, v4)) {
    return net::endpoint(v4, 443);
  }
  return net::endpoint(net::ipv6_address(value), 443);
}

int main() {
  try {
    for (const auto *value : {"0.0.0.0",
                              "0.255.255.255",
                              "10.0.0.0",
                              "10.255.255.255",
                              "100.64.0.0",
                              "100.127.255.255",
                              "127.0.0.1",
                              "127.255.255.255",
                              "169.254.0.0",
                              "169.254.169.254",
                              "172.16.0.0",
                              "172.31.255.255",
                              "192.0.0.9",
                              "192.0.2.1",
                              "192.88.99.1",
                              "192.168.0.0",
                              "192.168.255.255",
                              "198.18.0.0",
                              "198.19.255.255",
                              "198.51.100.1",
                              "203.0.113.1",
                              "224.0.0.0",
                              "239.255.255.255",
                              "240.0.0.0",
                              "255.255.255.255",
                              "168.63.129.16",
                              "::",
                              "::1",
                              "::127.0.0.1",
                              "::ffff:127.0.0.1",
                              "::ffff:a00:1",
                              "::ffff:168.63.129.16",
                              "fc00::1",
                              "fdff::1",
                              "fe80::1",
                              "febf::1",
                              "fec0::1",
                              "ff02::1",
                              "64:ff9b::a00:1",
                              "64:ff9b:1::1",
                              "100::1",
                              "2001::1",
                              "2001:2::1",
                              "2001:db8::1",
                              "2002:7f00:1::1",
                              "3fff::1"}) {
      if (egress::allowed_destination(endpoint(value))) {
        throw std::runtime_error(std::string("unexpected allowed address: ") + value);
      }
    }
    for (const auto *value :
         {"1.1.1.1", "8.8.8.8", "93.184.216.34", "100.63.255.255", "100.128.0.0", "172.15.255.255",
          "172.32.0.0", "198.17.255.255", "198.20.0.0", "168.63.129.15", "168.63.129.17",
          "::ffff:8.8.8.8", "2001:4860:4860::8888", "2606:4700:4700::1111"}) {
      if (!egress::allowed_destination(endpoint(value))) {
        throw std::runtime_error(std::string("unexpected refused address: ") + value);
      }
    }
    const std::vector denied = {egress::parse_denied_cidr("93.184.216.0/24"),
                                egress::parse_denied_cidr("2606:4700:4700::/48")};
    for (const auto *value : {"93.184.216.34", "::ffff:93.184.216.34", "2606:4700:4700::1111"}) {
      if (egress::allowed_destination(endpoint(value), denied)) {
        throw std::runtime_error("projected cluster exclusion was ignored");
      }
    }
    const std::vector mapped = {egress::parse_denied_cidr("::ffff:808:808/128")};
    if (egress::allowed_destination(endpoint("::ffff:8.8.8.8"), mapped) ||
        egress::allowed_destination(endpoint("8.8.8.8"), mapped)) {
      throw std::runtime_error("mapped exclusion was ignored");
    }
    for (const auto *value : {"", "host/24", "10.0.0.1/8", "::1/64", "0.0.0.0/33", "::/129",
                              "::/-1", "::/", "::/1x", "1.1.1.1", "fe80::%eth0/10"}) {
      bool rejected = false;
      try {
        static_cast<void>(egress::parse_denied_cidr(value));
      } catch (const std::invalid_argument &) {
        rejected = true;
      }
      if (!rejected) {
        throw std::runtime_error(std::string("unexpected accepted CIDR: ") + value);
      }
    }
    std::cout << "egress address classification passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
