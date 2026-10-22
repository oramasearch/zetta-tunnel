#include "egress.hpp"
#include "ingress.hpp"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <charconv>
#include <fstream>
#include <set>

namespace zetta_tunnel::ingress {
namespace {

void require(bool condition) {
  if (!condition) {
    throw std::invalid_argument("invalid ingress configuration");
  }
}

std::string contents(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary);
  require(static_cast<bool>(input));
  std::string data(1024 * 1024 + 1, '\0');
  input.read(data.data(), static_cast<std::streamsize>(data.size()));
  data.resize(static_cast<std::size_t>(input.gcount()));
  require(!input.bad() && data.size() <= 1024 * 1024);
  return data;
}

void fields(const nlohmann::json &value, const std::set<std::string> &required,
            const std::set<std::string> &optional = {}) {
  require(value.is_object());
  for (const auto &name : required) {
    require(value.contains(name));
  }
  for (const auto &[name, unused] : value.items()) {
    require(required.contains(name) || optional.contains(name));
  }
}

std::uint64_t number(std::string_view text) {
  std::uint64_t value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  require(error == std::errc{} && end == text.data() + text.size());
  return value;
}

std::string file_path(const std::filesystem::path &base, const nlohmann::json &value) {
  const auto name = value.get<std::string>();
  require(!name.empty() && name.find('\0') == std::string::npos);
  return (base / name).lexically_normal().string();
}

} // namespace

Configuration read_configuration(const std::filesystem::path &path) {
  std::vector<std::set<std::string>> keys;
  auto callback = [&keys](int depth, nlohmann::json::parse_event_t event, nlohmann::json &value) {
    require(depth <= 12);
    if (event == nlohmann::json::parse_event_t::object_start) {
      keys.emplace_back();
    } else if (event == nlohmann::json::parse_event_t::object_end) {
      keys.pop_back();
    } else if (event == nlohmann::json::parse_event_t::key) {
      require(keys.back().insert(value.get<std::string>()).second);
    }
    return true;
  };
  const auto data = contents(path);
  const auto document = nlohmann::json::parse(data, callback);
  fields(document, {"hosts"});
  require(document["hosts"].is_array() && !document["hosts"].empty() &&
          document["hosts"].size() <= 256);
  Configuration result;
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest_context(EVP_MD_CTX_new(),
                                                                         EVP_MD_CTX_free);
  require(digest_context && EVP_DigestInit_ex(digest_context.get(), EVP_sha256(), nullptr) == 1);
  auto fingerprint = [&digest_context](const std::string &bytes) {
    require(EVP_DigestUpdate(digest_context.get(), bytes.data(), bytes.size()) == 1);
  };
  fingerprint(data);
  const auto base = path.parent_path();
  std::set<std::string> ids;
  for (const auto &value : document["hosts"]) {
    fields(value, {"name", "certificate", "key", "routes"});
    Host host;
    host.name = value["name"].get<std::string>();
    require(egress::normalize_dns_name(host.name) == host.name);
    host.certificate = file_path(base, value["certificate"]);
    host.key = file_path(base, value["key"]);
    fingerprint(contents(host.certificate));
    fingerprint(contents(host.key));
    require(value["routes"].is_array() && !value["routes"].empty() &&
            value["routes"].size() <= 256);
    std::set<std::pair<std::string, bool>> paths;
    for (const auto &entry : value["routes"]) {
      fields(entry, {"id", "path", "path_type", "target", "max_body_bytes"}, {"ca", "server_name"});
      Route route;
      route.id = entry["id"].get<std::string>();
      require(!route.id.empty() && route.id.size() <= 63 &&
              std::all_of(route.id.begin(), route.id.end(),
                          [](unsigned char c) {
                            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                          }) &&
              ids.insert(route.id).second);
      route.path = entry["path"].get<std::string>();
      require(route.path == routing_path(route.path) && route.path.find('?') == std::string::npos);
      const auto type = entry["path_type"].get<std::string>();
      require(type == "Prefix" || type == "Exact");
      route.exact = type == "Exact";
      if (!route.exact && route.path.size() > 1 && route.path.ends_with('/')) {
        route.path.pop_back();
      }
      require(paths.emplace(route.path, route.exact).second);
      route.target = entry["target"].get<std::string>();
      const bool secure = route.target.starts_with("https://");
      require(secure || route.target.starts_with("http://"));
      const auto address =
          tunnel::parse_address(std::string_view(route.target).substr(secure ? 8 : 7));
      require(address.host.find_first_of("/\\?#@ \r\n\t") == std::string::npos &&
              address.host.find('\0') == std::string::npos);
      require(entry["max_body_bytes"].is_number_unsigned());
      route.max_body_bytes = entry["max_body_bytes"].get<std::uint64_t>();
      if (secure) {
        require(entry.contains("ca") && entry.contains("server_name"));
        route.ca = file_path(base, entry["ca"]);
        route.server_name = entry["server_name"].get<std::string>();
        require(egress::normalize_dns_name(route.server_name) == route.server_name);
        fingerprint(contents(route.ca));
        static_cast<void>(client_context(route));
      } else {
        require(!entry.contains("ca") && !entry.contains("server_name"));
      }
      host.routes.push_back(std::move(route));
    }
    host.context = server_context(host);
    require(result.hosts.emplace(host.name, std::move(host)).second);
  }
  unsigned char digest[EVP_MAX_MD_SIZE]{};
  unsigned length = 0;
  require(EVP_DigestFinal_ex(digest_context.get(), digest, &length) == 1);
  result.fingerprint.assign(reinterpret_cast<const char *>(digest), length);
  return result;
}

const Route *match_route(const Host &host, std::string_view target) {
  const auto path = routing_path(target);
  const Route *best = nullptr;
  for (const auto &route : host.routes) {
    const bool match = route.exact
                           ? path == route.path
                           : path == route.path || route.path == "/" ||
                                 (path.starts_with(route.path) && path[route.path.size()] == '/');
    if (match && (!best || route.path.size() > best->path.size() ||
                  (route.path.size() == best->path.size() && route.exact))) {
      best = &route;
    }
  }
  return best;
}

Options parse_options(std::span<char *> args) {
  require(!args.empty() && std::string_view(args[0]) == "ingress");
  std::map<std::string, std::string> flags;
  for (std::size_t index = 1; index < args.size(); index += 2) {
    require(index + 1 < args.size() && std::string_view(args[index]).starts_with("--"));
    require(flags.emplace(args[index], args[index + 1]).second);
  }
  auto take = [&flags](const std::string &key, std::string fallback) {
    const auto found = flags.find(key);
    if (found == flags.end()) {
      return fallback;
    }
    const auto result = found->second;
    flags.erase(found);
    require(!result.empty());
    return result;
  };
  Options options;
  options.configuration = take("--configuration", "");
  options.listen = take("--listen", options.listen);
  options.health_listen = take("--health-listen", options.health_listen);
  options.audit = take("--audit", options.audit);
  options.max_sessions = number(take("--max-sessions", "128"));
  options.max_pending_sessions = number(take("--max-pending-sessions", "128"));
  options.max_pending_per_source = number(take("--max-pending-per-source", "32"));
  if (options.max_pending_sessions < 1 || options.max_pending_sessions > 4096 ||
      options.max_pending_per_source < 1 || options.max_pending_per_source > 4096) {
    throw std::invalid_argument("pending limits must be in 1..4096");
  }
  options.max_sessions_per_source = number(take("--max-sessions-per-source", "0"));
  options.max_requests_per_source = number(take("--max-requests-per-source", "0"));
  require(options.max_sessions_per_source <= 4096 && options.max_requests_per_source <= 4096);
  options.max_requests = number(take("--max-requests", "256"));
  const auto idle = number(take("--idle-timeout-seconds", "60"));
  const auto setup = number(take("--setup-timeout-seconds", "10"));
  require(idle >= 1 && idle <= 86400 && setup >= 1 && setup <= 300);
  options.idle_timeout = static_cast<unsigned>(idle);
  options.setup_timeout = static_cast<unsigned>(setup);
  require(flags.empty() && !options.configuration.empty() && options.max_sessions >= 1 &&
          options.max_sessions <= 4096 && options.max_requests >= 1 &&
          options.max_requests <= 4096);
  static_cast<void>(egress::normalize_ip(tunnel::parse_address(options.listen).host));
  static_cast<void>(egress::normalize_ip(tunnel::parse_address(options.health_listen).host));
  require(options.listen != options.health_listen);
  return options;
}

void print_help(std::ostream &output) {
  output << "usage: zetta-tunnel ingress --configuration FILE [flags]\n"
         << "  --listen IP:PORT (0.0.0.0:8443) --health-listen IP:PORT (127.0.0.1:8080)\n"
         << "  --audit FILE|- --max-sessions 128 --max-requests 256\n"
         << "  --max-sessions-per-source 0 --max-requests-per-source 0 (automatic shares)\n"
         << "  --idle-timeout-seconds 60 --setup-timeout-seconds 10\n"
         << "[--max-pending-sessions 128] [--max-pending-per-source 32]\n"
         << "See docs/ingress.md for TLS, routes, reload, metrics and limits.\n";
}

} // namespace zetta_tunnel::ingress
