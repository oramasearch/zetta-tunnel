#include "egress.hpp"
#include "ingress.hpp"
#include "mesh.hpp"
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
    if (args.empty()) {
      // A role is required: with none, say how to use it rather than failing.
      zetta_tunnel::tunnel::print_help(std::cerr);
      return 2;
    }
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
      } else if (!args.empty() && std::string_view(args[0]) == "ingress") {
        zetta_tunnel::ingress::print_help(std::cout);
      } else if (!args.empty() && std::string_view(args[0]) == "mesh") {
        zetta_tunnel::mesh::print_help(std::cout);
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
    if (!args.empty() && std::string_view(args[0]) == "ingress") {
      return zetta_tunnel::ingress::run(zetta_tunnel::ingress::parse_options(args));
    }
    if (!args.empty() && std::string_view(args[0]) == "mesh") {
      return zetta_tunnel::mesh::run(zetta_tunnel::mesh::parse_options(args));
    }
    return zetta_tunnel::tunnel::run(zetta_tunnel::tunnel::parse_options(args));
  } catch (const std::exception &error) {
    // Every error names the failed option or operation and never holds key or certificate
    // contents (docs/transport.md), so it is safe to print.
    std::fprintf(stderr, "zetta-tunnel: %s\nsee zetta-tunnel --help\n", error.what());
    return 2;
  }
}
