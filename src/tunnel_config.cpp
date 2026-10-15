#include "tunnel.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>

namespace zetta_tunnel::tunnel {
namespace {

[[noreturn]] void invalid(std::string_view reason) {
  throw std::invalid_argument(std::string(reason));
}

unsigned number(std::string_view value) {
  unsigned result = 0;
  const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), result);
  if (error != std::errc{} || end != value.data() + value.size()) {
    invalid("invalid number");
  }
  return result;
}

bool safe_name(std::string_view value) {
  return !value.empty() && value.size() <= 253 &&
         std::all_of(value.begin(), value.end(), [](unsigned char c) {
           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '.' || c == ':';
         });
}

bool workspace_name(std::string_view value) {
  if (value.empty() || value.size() > 63 || value.front() == '-' || value.back() == '-') {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
  });
}

class JsonLinesSink final : public AuditSink {
public:
  explicit JsonLinesSink(const std::string &path) {
    if (path != "-") {
      file_.open(path, std::ios::app | std::ios::binary);
      if (!file_) {
        invalid("cannot open audit sink");
      }
      output_ = &file_;
    }
  }

  void write(const AuditRecord &record) override {
    const nlohmann::json value = {{"schema", 1},
                                  {"event", record.event},
                                  {"role", record.role},
                                  {"timestamp", format_time(std::chrono::system_clock::now())},
                                  {"started_at", format_time(record.started_at)},
                                  {"session_id", record.session_id},
                                  {"grant_id", record.grant_id},
                                  {"workspace", record.workspace},
                                  {"peer", record.peer},
                                  {"endpoint", record.endpoint},
                                  {"reason", record.reason},
                                  {"bytes_up", record.bytes_up},
                                  {"bytes_down", record.bytes_down}};
    write_json(value);
  }

  void write(const EgressDecision &record) override {
    const nlohmann::json value = {{"schema", 1},
                                  {"event", "egress_decision"},
                                  {"role", "egress"},
                                  {"timestamp", format_time(std::chrono::system_clock::now())},
                                  {"started_at", format_time(record.started_at)},
                                  {"decision", record.decision},
                                  {"reason", record.reason},
                                  {"rule_id", record.rule_id},
                                  {"workspace", record.workspace},
                                  {"source", record.source},
                                  {"dns_name", record.dns_name},
                                  {"port", record.port},
                                  {"protocol", record.protocol},
                                  {"resolved_address", record.resolved_address}};
    write_json(value);
  }

private:
  void write_json(const nlohmann::json &value) {
    *output_ << value.dump() << '\n';
    output_->flush();
    if (!*output_) {
      throw std::runtime_error("audit_write");
    }
  }

  std::ofstream file_;
  std::ostream *output_ = &std::cout;
};

} // namespace

std::unique_ptr<AuditSink> json_lines_sink(const std::string &path) {
  return std::make_unique<JsonLinesSink>(path);
}

Address parse_address(std::string_view value) {
  const auto separator = value.rfind(':');
  if (separator == std::string_view::npos || separator == 0) {
    invalid("address must be host:port (IPv6 requires brackets)");
  }
  auto host = value.substr(0, separator);
  if (host.starts_with('[') && host.ends_with(']')) {
    host = host.substr(1, host.size() - 2);
  } else if (host.find(':') != std::string_view::npos) {
    invalid("IPv6 requires brackets");
  }
  const auto port = number(value.substr(separator + 1));
  if (!safe_name(host) || port == 0 || port > 65535) {
    invalid("invalid host or port");
  }
  return {std::string(host), static_cast<std::uint16_t>(port)};
}

Time parse_time(std::string_view value) {
  if (value.size() < 20 || value[4] != '-' || value[7] != '-' ||
      (value[10] != 'T' && value[10] != 't') || value[13] != ':' || value[16] != ':') {
    invalid("expires_at must be RFC3339");
  }
  const auto year = number(value.substr(0, 4));
  const auto month = number(value.substr(5, 2));
  const auto day = number(value.substr(8, 2));
  const auto hour = number(value.substr(11, 2));
  const auto minute = number(value.substr(14, 2));
  const auto second = number(value.substr(17, 2));
  const auto date =
      std::chrono::year(static_cast<int>(year)) / std::chrono::month(month) / std::chrono::day(day);
  if (!date.ok() || year < 1970 || year > 2200 || hour > 23 || minute > 59 || second > 59) {
    invalid("invalid expires_at date");
  }
  std::size_t offset = 19;
  std::chrono::nanoseconds fraction{};
  if (value[offset] == '.') {
    ++offset;
    const auto first = offset;
    long scale = 100000000;
    while (offset < value.size() && value[offset] >= '0' && value[offset] <= '9') {
      fraction += std::chrono::nanoseconds((value[offset] - '0') * scale);
      scale /= 10;
      ++offset;
    }
    if (offset == first) {
      invalid("invalid expires_at fraction");
    }
  }
  int zone_minutes = 0;
  const auto zone = value.substr(offset);
  if (zone != "Z" && zone != "z") {
    if (zone.size() != 6 || (zone[0] != '+' && zone[0] != '-') || zone[3] != ':') {
      invalid("invalid expires_at timezone");
    }
    const auto hours = number(zone.substr(1, 2));
    const auto minutes = number(zone.substr(4, 2));
    if (hours > 23 || minutes > 59) {
      invalid("invalid expires_at timezone");
    }
    zone_minutes = static_cast<int>(hours * 60 + minutes) * (zone[0] == '+' ? 1 : -1);
  }
  return std::chrono::time_point_cast<Time::duration>(
      std::chrono::sys_days(date) + std::chrono::hours(hour) + std::chrono::minutes(minute) +
      std::chrono::seconds(second) + fraction - std::chrono::minutes(zone_minutes));
}

std::string format_time(Time value) {
  const auto days = std::chrono::floor<std::chrono::days>(value);
  const std::chrono::year_month_day date(days);
  const std::chrono::hh_mm_ss clock(value - days);
  std::ostringstream output;
  output << std::setfill('0') << std::setw(4) << static_cast<int>(date.year()) << '-'
         << std::setw(2) << static_cast<unsigned>(date.month()) << '-' << std::setw(2)
         << static_cast<unsigned>(date.day()) << 'T' << std::setw(2) << clock.hours().count() << ':'
         << std::setw(2) << clock.minutes().count() << ':' << std::setw(2)
         << clock.seconds().count() << 'Z';
  return output.str();
}

std::map<std::string, Grant> read_grants(const std::filesystem::path &path) {
  constexpr std::size_t limit = 1024 * 1024;
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    invalid("grant file unavailable");
  }
  std::string data(limit + 1, '\0');
  input.read(data.data(), data.size());
  data.resize(static_cast<std::size_t>(input.gcount()));
  if (data.size() > limit || input.bad()) {
    invalid("grant file exceeds limit or read failed");
  }
  std::vector<std::set<std::string>> keys;
  const auto callback = [&keys](int depth, nlohmann::json::parse_event_t event,
                                nlohmann::json &value) {
    if (depth > 8) {
      invalid("grant file nesting exceeds limit");
    }
    if (event == nlohmann::json::parse_event_t::object_start) {
      keys.emplace_back();
    } else if (event == nlohmann::json::parse_event_t::object_end) {
      keys.pop_back();
    } else if (event == nlohmann::json::parse_event_t::key &&
               !keys.back().insert(value.get<std::string>()).second) {
      invalid("duplicate grant file key");
    }
    return true;
  };
  const auto document = nlohmann::json::parse(data, callback);
  if (!document.is_object() || document.size() != 1 || !document.contains("grants") ||
      !document.at("grants").is_array() || document.at("grants").size() > 10000) {
    invalid("invalid grant document");
  }
  std::map<std::string, Grant> grants;
  for (const auto &value : document.at("grants")) {
    if (!value.is_object() || value.size() != 4) {
      invalid("invalid grant fields");
    }
    Grant grant{value.at("id").get<std::string>(), value.at("workspace").get<std::string>(),
                value.at("endpoint").get<std::string>(),
                parse_time(value.at("expires_at").get<std::string>())};
    if (!valid_uuid(grant.id) || !workspace_name(grant.workspace)) {
      invalid("invalid grant identity or workspace");
    }
    static_cast<void>(parse_address(grant.endpoint));
    if (!grants.emplace(grant.id, grant).second) {
      invalid("duplicate grant id");
    }
  }
  return grants;
}

Options parse_options(std::span<char *> args) {
  if (args.empty()) {
    invalid("a role is required");
  }
  Options options;
  options.role = args[0];
  if (options.role != "client" && options.role != "relay" && options.role != "endpoint") {
    invalid("unknown role");
  }
  std::map<std::string, std::string> flags;
  for (std::size_t index = 1; index < args.size(); index += 2) {
    if (index + 1 >= args.size() || !std::string_view(args[index]).starts_with("--") ||
        !flags.emplace(args[index], args[index + 1]).second) {
      invalid("flags require one value and may not repeat");
    }
  }
  auto take = [&flags](const std::string &name, std::string fallback = "") {
    const auto found = flags.find(name);
    if (found == flags.end()) {
      return fallback;
    }
    auto value = found->second;
    flags.erase(found);
    if (value.empty()) {
      invalid("empty flag value");
    }
    return value;
  };
  options.tls = {take("--cert"), take("--key"), take("--ca")};
  options.max_sessions = number(take("--max-sessions", "128"));
  if (options.max_sessions < 1 || options.max_sessions > 4096 || options.tls.certificate.empty() ||
      options.tls.private_key.empty() || options.tls.certificate_authority.empty()) {
    invalid("cert, key, ca and a session limit in 1..4096 are required");
  }
  if (options.role == "client") {
    options.listen = take("--listen", "127.0.0.1:5433");
    options.relay = take("--relay");
    options.peer_name = take("--server-name", parse_address(options.relay).host);
    const auto local = parse_address(options.listen);
    corosio::ipv4_address address;
    if ((corosio::parse_ipv4_address(local.host, address) || !address.is_loopback()) &&
        local.host != "::1") {
      invalid("client listener must be a loopback IP");
    }
  } else {
    options.listen = take("--listen", options.role == "relay" ? "0.0.0.0:7443" : "0.0.0.0:7444");
    options.health_listen = take("--health-listen", "127.0.0.1:8080");
    static_cast<void>(parse_address(options.health_listen));
    options.audit = take("--audit", "-");
    if (options.role == "relay") {
      options.grants = take("--grants");
      options.endpoint_tls = {take("--endpoint-cert"), take("--endpoint-key"),
                              take("--endpoint-ca")};
      if (options.grants.empty() || options.endpoint_tls.certificate.empty() ||
          options.endpoint_tls.private_key.empty() ||
          options.endpoint_tls.certificate_authority.empty()) {
        invalid("relay requires grants and endpoint TLS credentials");
      }
    } else {
      options.target = take("--target");
      options.peer_name = take("--peer-name");
      static_cast<void>(parse_address(options.target));
      if (options.peer_name.empty()) {
        invalid("endpoint requires peer-name");
      }
    }
  }
  static_cast<void>(parse_address(options.listen));
  if (!options.peer_name.empty() && !safe_name(options.peer_name)) {
    invalid("invalid peer name");
  }
  if (!flags.empty()) {
    invalid("unknown flag for role");
  }
  return options;
}

void print_help(std::ostream &output) {
  output << "usage: zetta-tunnel client|relay|endpoint|egress|peer|ingress|mesh [flags]\n"
         << "client/relay/endpoint: --cert FILE --key FILE --ca FILE [--listen IP:PORT] "
            "[--max-sessions 128]\n"
         << "client: --relay HOST:PORT [--server-name DNS_OR_IP]\n"
         << "relay: --grants FILE --endpoint-cert FILE --endpoint-key FILE --endpoint-ca FILE\n"
         << "endpoint: --target HOST:PORT --peer-name DNS_OR_IP\n"
         << "relay/endpoint: [--health-listen IP:PORT] [--audit FILE|-]\n"
         << "egress: see zetta-tunnel egress --help and docs/egress.md\n"
         << "peer: see zetta-tunnel peer --help and docs/peer.md\n"
         << "ingress: see zetta-tunnel ingress --help and docs/ingress.md\n"
         << "mesh: see zetta-tunnel mesh --help and docs/mesh.md\n"
         << "See docs/tunnel.md for identity, grant, and audit contracts.\n";
}

} // namespace zetta_tunnel::tunnel
