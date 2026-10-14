#pragma once

#include "tunnel.hpp"

#include <filesystem>
#include <ostream>
#include <span>
#include <vector>

namespace zetta_tunnel::peer {

struct Import {
  std::string name;
  std::uint16_t port = 0;
  std::string listen;
  bool operator==(const Import &) const = default;
};

struct Export {
  std::string name;
  std::uint16_t port = 0;
  std::string target;
  bool operator==(const Export &) const = default;
};

struct Configuration {
  std::string id;
  std::string workspace;
  std::string remote;
  std::vector<Import> imports;
  std::vector<Export> exports;
  bool operator==(const Configuration &) const = default;
};

struct Options {
  transport::TlsFiles tls;
  std::string peer_name;
  std::string listen = "0.0.0.0:7446";
  std::string health_listen = "127.0.0.1:8080";
  std::filesystem::path configuration;
  std::string audit = "-";
  std::size_t max_sessions = 128;
};

std::string normalize_service_name(std::string_view value);
Configuration read_configuration(const std::filesystem::path &path);
Options parse_options(std::span<char *> args);
void print_help(std::ostream &output);
int run(const Options &options);

} // namespace zetta_tunnel::peer
