#pragma once

#include "tunnel_io.hpp"

#include <filesystem>
#include <map>
#include <ostream>
#include <span>

namespace zetta_tunnel::tunnel {

struct Grant {
  std::string id;
  std::string workspace;
  std::string endpoint;
  Time expires;
  bool operator==(const Grant &) const = default;
};

struct Options {
  std::string role;
  transport::TlsFiles tls;
  transport::TlsFiles endpoint_tls;
  std::string listen;
  std::string health_listen;
  std::string relay;
  std::string peer_name;
  std::string target;
  std::filesystem::path grants;
  std::string audit = "-";
  std::size_t max_sessions = 128;
};

struct AuditRecord {
  std::string event;
  std::string role;
  std::string session_id;
  std::string grant_id;
  std::string workspace;
  std::string peer;
  std::string endpoint;
  std::string reason;
  std::uint64_t bytes_up = 0;
  std::uint64_t bytes_down = 0;
  Time started_at{};
};

class AuditSink {
public:
  virtual ~AuditSink() = default;
  virtual void write(const AuditRecord &record) = 0;
};

std::unique_ptr<AuditSink> json_lines_sink(const std::string &path);
Address parse_address(std::string_view value);
Time parse_time(std::string_view value);
std::string format_time(Time value);
std::map<std::string, Grant> read_grants(const std::filesystem::path &path);
Options parse_options(std::span<char *> args);
void print_help(std::ostream &output);
int run(const Options &options);

} // namespace zetta_tunnel::tunnel
