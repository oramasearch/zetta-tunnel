#include "mesh.hpp"

#include "peer.hpp"
#include "tunnel.hpp"

#include <boost/corosio/ipv4_address.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fstream>
#include <map>
#include <set>
#include <system_error>

namespace zetta_tunnel::mesh {
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

void exact_fields(const nlohmann::json &value, const std::set<std::string> &expected) {
  if (!value.is_object() || value.size() != expected.size()) {
    invalid("invalid mesh configuration fields");
  }
  for (const auto &name : expected) {
    if (!value.contains(name)) {
      invalid("missing mesh configuration field");
    }
  }
}

std::uint16_t port(const nlohmann::json &value) {
  if (!value.is_number_unsigned()) {
    invalid("mesh port must be an unsigned integer");
  }
  const auto result = value.get<unsigned>();
  if (result == 0 || result > 65535) {
    invalid("mesh port is outside 1..65535");
  }
  return static_cast<std::uint16_t>(result);
}

void numeric_address(std::string_view value) {
  const auto address = tunnel::parse_address(value);
  tunnel::corosio::ipv4_address ipv4;
  if (tunnel::corosio::parse_ipv4_address(address.host, ipv4)) {
    invalid("mesh addresses must use numeric IPv4 addresses");
  }
}

std::string identity(const nlohmann::json &value) {
  return peer::normalize_service_name(value.get<std::string>());
}

std::filesystem::path path(const std::filesystem::path &base, const nlohmann::json &value) {
  const auto text = value.get<std::string>();
  if (text.empty() || text.find('\0') != std::string::npos) {
    invalid("mesh path is empty or contains NUL");
  }
  const std::filesystem::path result(text);
  return result.is_absolute() ? result.lexically_normal() : (base / result).lexically_normal();
}

transport::TlsFiles tls_files(const std::filesystem::path &base, const nlohmann::json &value) {
  exact_fields(value, {"ca", "certificate", "key"});
  return {path(base, value.at("certificate")), path(base, value.at("key")),
          path(base, value.at("ca"))};
}

Workload workload(const std::filesystem::path &base, const nlohmann::json &value) {
  exact_fields(value, {"identity", "network_namespace", "ports", "routes", "tls"});
  Workload result;
  result.identity = identity(value.at("identity"));
  result.network_namespace = path(base, value.at("network_namespace"));
  result.tls = tls_files(base, value.at("tls"));
  const auto &routes = value.at("routes");
  const auto &ports = value.at("ports");
  if (!routes.is_array() || routes.size() > 256 || !ports.is_array() || ports.size() > 256) {
    invalid("mesh route or port count exceeds limit");
  }
  std::set<std::string> destinations;
  for (const auto &entry : routes) {
    exact_fields(entry, {"destination", "identity", "mesh"});
    Route route{entry.at("destination").get<std::string>(), entry.at("mesh").get<std::string>(),
                identity(entry.at("identity"))};
    numeric_address(route.destination);
    numeric_address(route.mesh);
    if (!destinations.insert(route.destination).second) {
      invalid("duplicate mesh destination");
    }
    result.routes.push_back(std::move(route));
  }
  std::set<std::uint16_t> target_ports;
  for (const auto &entry : ports) {
    exact_fields(entry, {"port", "sources", "target"});
    Port allowed;
    allowed.port = port(entry.at("port"));
    allowed.target = entry.at("target").get<std::string>();
    numeric_address(allowed.target);
    const auto parsed_target = tunnel::parse_address(allowed.target);
    if (parsed_target.port != allowed.port || !target_ports.insert(allowed.port).second) {
      invalid("mesh target must preserve a unique declared port");
    }
    const auto &sources = entry.at("sources");
    if (!sources.is_array() || sources.empty() || sources.size() > 256) {
      invalid("mesh sources must contain 1..256 identities");
    }
    std::set<std::string> unique_sources;
    for (const auto &source : sources) {
      auto name = identity(source);
      if (!unique_sources.insert(name).second) {
        invalid("duplicate mesh source identity");
      }
      allowed.sources.push_back(std::move(name));
    }
    result.ports.push_back(std::move(allowed));
  }
  return result;
}

} // namespace

Configuration read_configuration(const std::filesystem::path &file) {
  constexpr std::size_t file_limit = 1024 * 1024;
  errno = 0;
  std::ifstream input(file, std::ios::binary);
  if (!input) {
    throw std::system_error(errno != 0 ? errno : EIO, std::generic_category(),
                            "open mesh projection");
  }
  std::string data(file_limit + 1, '\0');
  errno = 0;
  input.read(data.data(), static_cast<std::streamsize>(data.size()));
  data.resize(static_cast<std::size_t>(input.gcount()));
  if (input.bad()) {
    throw std::system_error(errno != 0 ? errno : EIO, std::generic_category(),
                            "read mesh projection");
  }
  if (data.size() > file_limit) {
    invalid("mesh configuration exceeds limit");
  }
  std::vector<std::set<std::string>> keys;
  auto callback = [&keys](int depth, nlohmann::json::parse_event_t event, nlohmann::json &value) {
    if (depth > 10) {
      invalid("mesh configuration nesting exceeds limit");
    }
    if (event == nlohmann::json::parse_event_t::object_start) {
      keys.emplace_back();
    } else if (event == nlohmann::json::parse_event_t::object_end) {
      keys.pop_back();
    } else if (event == nlohmann::json::parse_event_t::key &&
               !keys.back().insert(value.get<std::string>()).second) {
      invalid("duplicate mesh configuration key");
    }
    return true;
  };
  const auto document = nlohmann::json::parse(data, callback);
  exact_fields(document, {"mesh"});
  const auto &mesh = document.at("mesh");
  exact_fields(mesh, {"node", "workloads"});
  Configuration result;
  result.node = peer::normalize_service_name(mesh.at("node").get<std::string>());
  const auto &workloads = mesh.at("workloads");
  if (!workloads.is_array() || workloads.size() > 128) {
    invalid("mesh workload count exceeds limit");
  }
  const auto base = file.parent_path();
  std::set<std::string> identities;
  std::set<std::filesystem::path> namespaces;
  for (const auto &entry : workloads) {
    auto value = workload(base, entry);
    if (!identities.insert(value.identity).second ||
        !namespaces.insert(value.network_namespace).second) {
      invalid("duplicate mesh workload identity or network namespace");
    }
    result.workloads.push_back(std::move(value));
  }
  return result;
}

bool same_workload(const Workload &left, const Workload &right) {
  return left.identity == right.identity && left.network_namespace == right.network_namespace &&
         left.tls.certificate == right.tls.certificate &&
         left.tls.private_key == right.tls.private_key &&
         left.tls.certificate_authority == right.tls.certificate_authority &&
         left.routes == right.routes && left.ports == right.ports;
}

Options parse_options(std::span<char *> args) {
  if (args.empty() || std::string_view(args[0]) != "mesh") {
    invalid("mesh role required");
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
      invalid("empty mesh flag value");
    }
    return value;
  };
  Options options;
  options.configuration = take("--configuration");
  options.health_listen = take("--health-listen", options.health_listen);
  options.audit = take("--audit", options.audit);
  options.max_sessions = number(take("--max-sessions", "128"));
  const auto workload_sessions = take("--max-workload-sessions");
  options.max_workload_sessions =
      workload_sessions.empty() ? options.max_sessions : number(workload_sessions);
  options.setup_timeout = number(take("--setup-timeout", "10"));
  options.idle_timeout = number(take("--idle-timeout", "900"));
  if (options.configuration.empty() || options.max_sessions < 1 || options.max_sessions > 4096 ||
      options.max_workload_sessions < 1 || options.max_workload_sessions > options.max_sessions ||
      options.setup_timeout < 1 || options.setup_timeout > 60 || options.idle_timeout < 1 ||
      options.idle_timeout > 86400) {
    invalid("mesh configuration and bounded session/setup/idle limits are required");
  }
  numeric_address(options.health_listen);
  if (!flags.empty()) {
    invalid("unknown flag for mesh role");
  }
  return options;
}

void print_help(std::ostream &output) {
  output << "usage: zetta-tunnel mesh --configuration FILE [flags]\n"
         << "mesh: [--health-listen IP:PORT] [--audit FILE|-] [--max-sessions 128]\n"
         << "      [--max-workload-sessions N] [--setup-timeout 10] [--idle-timeout 900]\n"
         << "See docs/mesh.md for projection, capture, TLS, probes and metrics.\n";
}

} // namespace zetta_tunnel::mesh
