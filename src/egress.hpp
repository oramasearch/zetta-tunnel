#pragma once

#include "tunnel.hpp"

#include <filesystem>
#include <map>
#include <span>
#include <vector>

namespace zetta_tunnel::egress {

struct Rule {
  std::string id;
  std::string workspace;
  std::vector<std::string> source_ips;
  std::string dns_name;
  std::vector<std::uint16_t> ports;
  bool operator==(const Rule &) const = default;
};

struct Options {
  std::string listen = "0.0.0.0:7445";
  std::string health_listen = "127.0.0.1:8080";
  std::filesystem::path rules;
  std::string audit = "-";
  std::size_t max_sessions = 128;
  std::size_t max_pending_sessions = 128;
  std::size_t max_pending_per_source = 32;
  std::uint16_t sni_port = 443;
};

std::string normalize_dns_name(std::string_view value);
std::string normalize_ip(std::string_view value);
std::map<std::string, Rule> read_rules(const std::filesystem::path &path);
Options parse_options(std::span<char *> args);
void print_help(std::ostream &output);
int run(const Options &options);

} // namespace zetta_tunnel::egress
