#include "egress.hpp"

#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <set>
#include <tuple>

namespace zetta_tunnel::egress {
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

bool workspace_name(std::string_view value) {
  if (value.empty() || value.size() > 63 || value.front() == '-' || value.back() == '-') {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
           character == '-';
  });
}

bool dns_label(std::string_view value) {
  if (value.empty() || value.size() > 63 || value.front() == '-' || value.back() == '-') {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
           character == '-';
  });
}

void validate_listener(std::string_view value) {
  const auto address = tunnel::parse_address(value);
  static_cast<void>(normalize_ip(address.host));
}

} // namespace

std::string normalize_ip(std::string_view value) {
  tunnel::corosio::ipv4_address ipv4;
  if (!tunnel::corosio::parse_ipv4_address(value, ipv4)) {
    return ipv4.to_string();
  }
  tunnel::corosio::ipv6_address ipv6;
  if (!tunnel::corosio::parse_ipv6_address(value, ipv6)) {
    return ipv6.to_string();
  }
  invalid("expected a numeric IP address");
}

std::string normalize_dns_name(std::string_view value) {
  if (value.empty() || value.size() > 254) {
    invalid("invalid DNS name");
  }
  tunnel::corosio::ipv4_address ipv4;
  tunnel::corosio::ipv6_address ipv6;
  if (!tunnel::corosio::parse_ipv4_address(value, ipv4) ||
      !tunnel::corosio::parse_ipv6_address(value, ipv6)) {
    invalid("IP literals are not DNS names");
  }
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
    return static_cast<char>(std::tolower(character));
  });
  if (result.ends_with('.')) {
    result.pop_back();
  }
  if (result.empty() || result.size() > 253) {
    invalid("invalid DNS name");
  }
  std::size_t start = 0;
  while (start < result.size()) {
    const auto end = result.find('.', start);
    const auto length = end == std::string::npos ? result.size() - start : end - start;
    if (!dns_label(std::string_view(result).substr(start, length))) {
      invalid("invalid DNS name");
    }
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  return result;
}

std::map<std::string, Rule> read_rules(const std::filesystem::path &path) {
  constexpr std::size_t file_limit = 1024 * 1024;
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    invalid("rule file unavailable");
  }
  std::string data(file_limit + 1, '\0');
  input.read(data.data(), data.size());
  data.resize(static_cast<std::size_t>(input.gcount()));
  if (data.size() > file_limit || input.bad()) {
    invalid("rule file exceeds limit or read failed");
  }
  std::vector<std::set<std::string>> keys;
  const auto callback = [&keys](int depth, nlohmann::json::parse_event_t event,
                                nlohmann::json &value) {
    if (depth > 8) {
      invalid("rule file nesting exceeds limit");
    }
    if (event == nlohmann::json::parse_event_t::object_start) {
      keys.emplace_back();
    } else if (event == nlohmann::json::parse_event_t::object_end) {
      keys.pop_back();
    } else if (event == nlohmann::json::parse_event_t::key &&
               !keys.back().insert(value.get<std::string>()).second) {
      invalid("duplicate rule file key");
    }
    return true;
  };
  const auto document = nlohmann::json::parse(data, callback);
  if (!document.is_object() || document.size() != 1 || !document.contains("rules") ||
      !document.at("rules").is_array() || document.at("rules").size() > 10000) {
    invalid("invalid rule document");
  }
  std::map<std::string, Rule> rules;
  std::set<std::tuple<std::string, std::string, std::uint16_t>> routes;
  for (const auto &value : document.at("rules")) {
    if (!value.is_object() || value.size() != 5 || !value.contains("id") ||
        !value.contains("workspace") || !value.contains("source_ips") ||
        !value.contains("dns_name") || !value.contains("ports")) {
      invalid("invalid rule fields");
    }
    Rule rule;
    rule.id = value.at("id").get<std::string>();
    rule.workspace = value.at("workspace").get<std::string>();
    rule.dns_name = normalize_dns_name(value.at("dns_name").get<std::string>());
    if (!tunnel::valid_uuid(rule.id) || !workspace_name(rule.workspace) ||
        !value.at("source_ips").is_array() || value.at("source_ips").empty() ||
        value.at("source_ips").size() > 256 || !value.at("ports").is_array() ||
        value.at("ports").empty() || value.at("ports").size() > 64) {
      invalid("invalid rule identity, workspace, sources or ports");
    }
    std::set<std::string> sources;
    for (const auto &source : value.at("source_ips")) {
      if (!source.is_string()) {
        invalid("invalid rule source");
      }
      const auto normalized = normalize_ip(source.get<std::string>());
      if (!sources.insert(normalized).second) {
        invalid("duplicate rule source");
      }
      rule.source_ips.push_back(normalized);
    }
    std::set<std::uint16_t> ports;
    for (const auto &port_value : value.at("ports")) {
      if (!port_value.is_number_unsigned()) {
        invalid("invalid rule port");
      }
      const auto port = port_value.get<unsigned>();
      if (port == 0 || port > 65535 || !ports.insert(static_cast<std::uint16_t>(port)).second) {
        invalid("invalid or duplicate rule port");
      }
      rule.ports.push_back(static_cast<std::uint16_t>(port));
    }
    for (const auto &source : rule.source_ips) {
      for (const auto port : rule.ports) {
        if (!routes.emplace(source, rule.dns_name, port).second) {
          invalid("duplicate authorized route");
        }
      }
    }
    if (!rules.emplace(rule.id, std::move(rule)).second) {
      invalid("duplicate rule id");
    }
  }
  return rules;
}

Options parse_options(std::span<char *> args) {
  if (args.empty() || std::string_view(args[0]) != "egress") {
    invalid("egress role required");
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
  Options options;
  options.listen = take("--listen", options.listen);
  options.health_listen = take("--health-listen", options.health_listen);
  options.rules = take("--rules");
  options.audit = take("--audit", options.audit);
  options.max_sessions = number(take("--max-sessions", "128"));
  options.max_pending_sessions = number(take("--max-pending-sessions", "128"));
  options.max_pending_per_source = number(take("--max-pending-per-source", "32"));
  if (options.max_pending_sessions < 1 || options.max_pending_sessions > 4096 ||
      options.max_pending_per_source < 1 || options.max_pending_per_source > 4096) {
    throw std::invalid_argument("pending limits must be in 1..4096");
  }
  const auto sni_port = number(take("--sni-port", "443"));
  if (options.rules.empty() || options.max_sessions < 1 || options.max_sessions > 4096 ||
      sni_port == 0 || sni_port > 65535) {
    invalid("rules, a session limit in 1..4096 and a valid SNI port are required");
  }
  options.sni_port = static_cast<std::uint16_t>(sni_port);
  validate_listener(options.listen);
  validate_listener(options.health_listen);
  if (!flags.empty()) {
    invalid("unknown flag for egress role");
  }
  return options;
}

void print_help(std::ostream &output) {
  output << "usage: zetta-tunnel egress --rules FILE [flags]\n"
         << "egress: [--listen IP:PORT] [--health-listen IP:PORT] [--audit FILE|-]\n"
         << "        [--max-sessions 128] [--sni-port 443]\n"
         << "[--max-pending-sessions 128] [--max-pending-per-source 32]\n"
         << "See docs/egress.md for the rule, routing, and audit contracts.\n";
}

} // namespace zetta_tunnel::egress
