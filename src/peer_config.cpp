#include "peer.hpp"

#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <map>
#include <set>
#include <tuple>

namespace zetta_tunnel::peer {
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

bool service_label(std::string_view value) {
  if (value.empty() || value.size() > 63 || value.front() == '-' || value.back() == '-') {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
           character == '-';
  });
}

void validate_address(std::string_view value, bool numeric_host) {
  const auto address = tunnel::parse_address(value);
  if (!numeric_host) {
    return;
  }
  tunnel::corosio::ipv4_address ipv4;
  tunnel::corosio::ipv6_address ipv6;
  if (tunnel::corosio::parse_ipv4_address(address.host, ipv4) &&
      tunnel::corosio::parse_ipv6_address(address.host, ipv6)) {
    invalid("listener host must be a numeric IP address");
  }
}

void validate_peer_name(std::string_view value) {
  tunnel::corosio::ipv4_address ipv4;
  tunnel::corosio::ipv6_address ipv6;
  if (!tunnel::corosio::parse_ipv4_address(value, ipv4) ||
      !tunnel::corosio::parse_ipv6_address(value, ipv6)) {
    return;
  }
  static_cast<void>(normalize_service_name(value));
}

std::uint16_t port(const nlohmann::json &value) {
  if (!value.is_number_unsigned()) {
    invalid("service port must be an unsigned integer");
  }
  const auto result = value.get<unsigned>();
  if (result == 0 || result > 65535) {
    invalid("service port is outside 1..65535");
  }
  return static_cast<std::uint16_t>(result);
}

void exact_fields(const nlohmann::json &value, const std::set<std::string> &expected) {
  if (!value.is_object() || value.size() != expected.size()) {
    invalid("invalid configuration fields");
  }
  for (const auto &name : expected) {
    if (!value.contains(name)) {
      invalid("missing configuration field");
    }
  }
}

} // namespace

std::string normalize_service_name(std::string_view value) {
  if (value.empty() || value.size() > 253) {
    invalid("invalid service name");
  }
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
    return static_cast<char>(std::tolower(character));
  });
  if (result != value) {
    invalid("service name must be lowercase");
  }
  std::size_t start = 0;
  while (start < result.size()) {
    const auto end = result.find('.', start);
    const auto length = end == std::string::npos ? result.size() - start : end - start;
    if (!service_label(std::string_view(result).substr(start, length))) {
      invalid("invalid service name");
    }
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  return result;
}

Configuration read_configuration(const std::filesystem::path &path) {
  constexpr std::size_t file_limit = 1024 * 1024;
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    invalid("peer configuration unavailable");
  }
  std::string data(file_limit + 1, '\0');
  input.read(data.data(), data.size());
  data.resize(static_cast<std::size_t>(input.gcount()));
  if (data.size() > file_limit || input.bad()) {
    invalid("peer configuration exceeds limit or read failed");
  }
  std::vector<std::set<std::string>> keys;
  const auto callback = [&keys](int depth, nlohmann::json::parse_event_t event,
                                nlohmann::json &value) {
    if (depth > 8) {
      invalid("peer configuration nesting exceeds limit");
    }
    if (event == nlohmann::json::parse_event_t::object_start) {
      keys.emplace_back();
    } else if (event == nlohmann::json::parse_event_t::object_end) {
      keys.pop_back();
    } else if (event == nlohmann::json::parse_event_t::key &&
               !keys.back().insert(value.get<std::string>()).second) {
      invalid("duplicate peer configuration key");
    }
    return true;
  };
  const auto document = nlohmann::json::parse(data, callback);
  exact_fields(document, {"peer"});
  const auto &peer = document.at("peer");
  exact_fields(peer, {"exports", "id", "imports", "remote", "workspace"});
  Configuration result;
  result.id = peer.at("id").get<std::string>();
  result.workspace = peer.at("workspace").get<std::string>();
  result.remote = peer.at("remote").get<std::string>();
  if (!tunnel::valid_uuid(result.id) || !workspace_name(result.workspace)) {
    invalid("invalid peer identity or workspace");
  }
  validate_address(result.remote, false);
  if (!peer.at("imports").is_array() || peer.at("imports").size() > 256 ||
      !peer.at("exports").is_array() || peer.at("exports").size() > 256) {
    invalid("invalid peer services");
  }
  std::set<std::tuple<std::string, std::uint16_t>> imports;
  std::set<std::string> listeners;
  for (const auto &value : peer.at("imports")) {
    exact_fields(value, {"listen", "name", "port"});
    Import service{normalize_service_name(value.at("name").get<std::string>()),
                   port(value.at("port")), value.at("listen").get<std::string>()};
    validate_address(service.listen, true);
    if (!imports.emplace(service.name, service.port).second ||
        !listeners.insert(service.listen).second) {
      invalid("duplicate imported service or listener");
    }
    result.imports.push_back(std::move(service));
  }
  std::set<std::tuple<std::string, std::uint16_t>> exports;
  for (const auto &value : peer.at("exports")) {
    exact_fields(value, {"name", "port", "target"});
    Export service{normalize_service_name(value.at("name").get<std::string>()),
                   port(value.at("port")), value.at("target").get<std::string>()};
    validate_address(service.target, false);
    if (!exports.emplace(service.name, service.port).second) {
      invalid("duplicate exported service");
    }
    result.exports.push_back(std::move(service));
  }
  return result;
}

Options parse_options(std::span<char *> args) {
  if (args.empty() || std::string_view(args[0]) != "peer") {
    invalid("peer role required");
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
  options.tls = {take("--cert"), take("--key"), take("--ca")};
  options.peer_name = take("--peer-name");
  options.listen = take("--listen", options.listen);
  options.health_listen = take("--health-listen", options.health_listen);
  options.configuration = take("--configuration");
  options.audit = take("--audit", options.audit);
  options.max_sessions = number(take("--max-sessions", "128"));
  options.max_pending_sessions = number(take("--max-pending-sessions", "128"));
  options.max_pending_per_source = number(take("--max-pending-per-source", "32"));
  if (options.max_pending_sessions < 1 || options.max_pending_sessions > 4096 ||
      options.max_pending_per_source < 1 || options.max_pending_per_source > 4096) {
    throw std::invalid_argument("pending limits must be in 1..4096");
  }
  if (options.tls.certificate.empty() || options.tls.private_key.empty() ||
      options.tls.certificate_authority.empty() || options.peer_name.empty() ||
      options.configuration.empty() || options.max_sessions < 1 || options.max_sessions > 4096) {
    invalid("peer TLS, identity, configuration and a session limit in 1..4096 are required");
  }
  validate_address(options.listen, true);
  validate_address(options.health_listen, true);
  validate_peer_name(options.peer_name);
  if (!flags.empty()) {
    invalid("unknown flag for peer role");
  }
  return options;
}

void print_help(std::ostream &output) {
  output << "usage: zetta-tunnel peer --configuration FILE --cert FILE --key FILE --ca FILE "
            "--peer-name DNS_OR_IP [flags]\n"
         << "peer: [--listen IP:PORT] [--health-listen IP:PORT] [--audit FILE|-]\n"
         << "      [--max-sessions 128]\n"
         << "[--max-pending-sessions 128] [--max-pending-per-source 32]\n"
         << "See docs/peer.md for the service, TLS, reload, and audit contracts.\n";
}

} // namespace zetta_tunnel::peer
