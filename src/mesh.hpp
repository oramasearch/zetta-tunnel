#pragma once

#include "zetta_tunnel/transport.hpp"

#include <cstdint>
#include <exception>
#include <filesystem>
#include <ostream>
#include <span>
#include <string>
#include <vector>

namespace zetta_tunnel::mesh {

struct Route {
  std::string destination;
  std::string mesh;
  std::string identity;
  bool operator==(const Route &) const = default;
};

struct Port {
  std::uint16_t port = 0;
  std::string target;
  std::vector<std::string> sources;
  bool operator==(const Port &) const = default;
};

struct Workload {
  std::string identity;
  std::filesystem::path network_namespace;
  std::string pod_uid;
  std::uint64_t network_namespace_inode = 0;
  transport::TlsFiles tls;
  std::vector<Route> routes;
  std::vector<Port> ports;
};

struct Configuration {
  std::string node;
  std::vector<Workload> workloads;
};

struct Options {
  std::filesystem::path configuration;
  std::string health_listen = "127.0.0.1:8080";
  std::string audit = "-";
  std::size_t max_sessions = 128;
  unsigned setup_timeout = 10;
};

Configuration read_configuration(const std::filesystem::path &path);
Options parse_options(std::span<char *> args);
void print_help(std::ostream &output);
std::string failure_detail(const std::exception &error);
int run(const Options &options);

} // namespace zetta_tunnel::mesh
