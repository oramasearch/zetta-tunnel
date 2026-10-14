#include "egress.hpp"
#include "peer.hpp"
#include "tunnel.hpp"
#include <zetta_tunnel/version.hpp>

#include <cstdio>
#include <iostream>
#include <span>
#include <string_view>

int main(int argc, char **argv) {
  const std::span args(argv + 1, static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  try {
    if (args.size() == 1 && std::string_view(args[0]) == "--version") {
      std::printf("zetta-tunnel %s\n", zetta_tunnel::version);
      return 0;
    }
    if ((args.size() == 1 && std::string_view(args[0]) == "--help") ||
        (args.size() == 2 && std::string_view(args[1]) == "--help")) {
      if (!args.empty() && std::string_view(args[0]) == "egress") {
        zetta_tunnel::egress::print_help(std::cout);
      } else if (!args.empty() && std::string_view(args[0]) == "peer") {
        zetta_tunnel::peer::print_help(std::cout);
      } else {
        zetta_tunnel::tunnel::print_help(std::cout);
      }
      return 0;
    }
    if (!args.empty() && std::string_view(args[0]) == "egress") {
      return zetta_tunnel::egress::run(zetta_tunnel::egress::parse_options(args));
    }
    if (!args.empty() && std::string_view(args[0]) == "peer") {
      return zetta_tunnel::peer::run(zetta_tunnel::peer::parse_options(args));
    }
    return zetta_tunnel::tunnel::run(zetta_tunnel::tunnel::parse_options(args));
  } catch (const std::exception &) {
    std::fprintf(stderr, "zetta-tunnel: configuration or startup failed; see --help\n");
    return 2;
  }
}
