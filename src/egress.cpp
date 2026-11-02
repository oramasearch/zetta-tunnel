#include "egress.hpp"
#include "admission.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_any.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/timer.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <csignal>
#include <iostream>
#include <optional>
#include <sstream>
#include <stop_token>
#include <vector>

namespace zetta_tunnel::egress {
namespace {

using namespace std::chrono_literals;
namespace capy = tunnel::capy;
namespace corosio = tunnel::corosio;

constexpr std::size_t explicit_header_limit = 512;
constexpr std::size_t client_hello_limit = 65535;
constexpr std::size_t routing_buffer_limit = 70 * 1024;
volatile std::sig_atomic_t stopping = 0;
volatile std::sig_atomic_t reloading = 0;

class GatewayError final : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

void signal_stop(int) {
  stopping = 1;
}

#ifndef _WIN32
void signal_reload(int) {
  reloading = 1;
}
#endif

void listen(corosio::tcp_acceptor &acceptor, const std::string &value) {
  const corosio::endpoint endpoint(value);
  acceptor.open(endpoint.is_v4() ? corosio::tcp::v4() : corosio::tcp::v6());
  if (acceptor.bind(endpoint) || acceptor.listen()) {
    throw std::runtime_error("listener failed");
  }
}

std::string source_ip(const corosio::tcp_socket &socket) {
  const auto endpoint = socket.remote_endpoint();
  return endpoint.is_v4() ? endpoint.v4_address().to_string() : endpoint.v6_address().to_string();
}

bool numeric_ip(std::string_view value) {
  try {
    static_cast<void>(normalize_ip(value));
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

std::string request_name(std::string_view value) {
  if (numeric_ip(value)) {
    throw GatewayError("ip_literal");
  }
  try {
    return normalize_dns_name(value);
  } catch (const std::exception &) {
    throw GatewayError("invalid_request");
  }
}

struct Route {
  std::string dns_name;
  std::string protocol;
  std::uint16_t port = 0;
  std::size_t payload_offset = 0;
};

enum class ParseStatus { incomplete, complete };

unsigned byte_at(std::span<const std::byte> bytes, std::size_t offset) {
  if (offset >= bytes.size()) {
    throw GatewayError("invalid_request");
  }
  return std::to_integer<unsigned>(bytes[offset]);
}

std::size_t uint16_at(std::span<const std::byte> bytes, std::size_t offset) {
  return (byte_at(bytes, offset) << 8U) | byte_at(bytes, offset + 1);
}

std::string parse_server_name(std::span<const std::byte> hello) {
  std::size_t offset = 0;
  auto advance = [&offset, hello](std::size_t size) {
    if (size > hello.size() - std::min(offset, hello.size())) {
      throw GatewayError("invalid_request");
    }
    offset += size;
  };
  advance(2 + 32);
  const auto session_id_size = byte_at(hello, offset);
  advance(1 + session_id_size);
  const auto cipher_size = uint16_at(hello, offset);
  if (cipher_size < 2 || cipher_size % 2 != 0) {
    throw GatewayError("invalid_request");
  }
  advance(2 + cipher_size);
  const auto compression_size = byte_at(hello, offset);
  if (compression_size == 0) {
    throw GatewayError("invalid_request");
  }
  advance(1 + compression_size);
  const auto extensions_size = uint16_at(hello, offset);
  advance(2);
  if (extensions_size != hello.size() - offset) {
    throw GatewayError("invalid_request");
  }
  const auto extensions_end = offset + extensions_size;
  std::string server_name;
  while (offset < extensions_end) {
    const auto type = uint16_at(hello, offset);
    const auto size = uint16_at(hello, offset + 2);
    advance(4);
    if (size > extensions_end - offset) {
      throw GatewayError("invalid_request");
    }
    if (type != 0) {
      advance(size);
      continue;
    }
    if (!server_name.empty() || size < 5) {
      throw GatewayError("invalid_request");
    }
    const auto names_end = offset + size;
    const auto names_size = uint16_at(hello, offset);
    advance(2);
    if (names_size != names_end - offset) {
      throw GatewayError("invalid_request");
    }
    while (offset < names_end) {
      const auto name_type = byte_at(hello, offset);
      const auto name_size = uint16_at(hello, offset + 1);
      advance(3);
      if (name_type != 0 || name_size == 0 || name_size > names_end - offset ||
          !server_name.empty()) {
        throw GatewayError("invalid_request");
      }
      server_name.assign(reinterpret_cast<const char *>(hello.data() + offset), name_size);
      advance(name_size);
    }
  }
  if (server_name.empty()) {
    throw GatewayError("sni_required");
  }
  return request_name(server_name);
}

ParseStatus parse_client_hello(std::span<const std::byte> input, std::uint16_t port, Route &route) {
  std::vector<std::byte> handshake;
  std::size_t record_offset = 0;
  while (true) {
    if (input.size() - record_offset < 5) {
      return ParseStatus::incomplete;
    }
    if (byte_at(input, record_offset) != 22 || byte_at(input, record_offset + 1) != 3) {
      throw GatewayError("invalid_request");
    }
    const auto record_size = uint16_at(input, record_offset + 3);
    if (record_size == 0 || record_size > 18432) {
      throw GatewayError("invalid_request");
    }
    if (input.size() - record_offset - 5 < record_size) {
      return ParseStatus::incomplete;
    }
    const auto payload = input.subspan(record_offset + 5, record_size);
    handshake.insert(handshake.end(), payload.begin(), payload.end());
    if (handshake.size() > client_hello_limit + 4) {
      throw GatewayError("invalid_request");
    }
    if (handshake.size() >= 4) {
      if (byte_at(handshake, 0) != 1) {
        throw GatewayError("invalid_request");
      }
      const auto hello_size =
          (byte_at(handshake, 1) << 16U) | (byte_at(handshake, 2) << 8U) | byte_at(handshake, 3);
      if (hello_size == 0 || hello_size > client_hello_limit) {
        throw GatewayError("invalid_request");
      }
      if (handshake.size() >= hello_size + 4) {
        route.dns_name =
            parse_server_name(std::span<const std::byte>(handshake).subspan(4, hello_size));
        route.protocol = "https_sni";
        route.port = port;
        route.payload_offset = 0;
        return ParseStatus::complete;
      }
    }
    record_offset += 5 + record_size;
  }
}

ParseStatus parse_explicit(std::span<const std::byte> input, Route &route) {
  const auto newline = std::find(input.begin(), input.end(), static_cast<std::byte>('\n'));
  if (newline == input.end()) {
    if (input.size() >= explicit_header_limit) {
      throw GatewayError("invalid_request");
    }
    return ParseStatus::incomplete;
  }
  const auto header_size = static_cast<std::size_t>(newline - input.begin());
  if (header_size == 0 || header_size >= explicit_header_limit) {
    throw GatewayError("invalid_request");
  }
  std::string header(reinterpret_cast<const char *>(input.data()), header_size);
  if (header.ends_with('\r')) {
    header.pop_back();
  }
  std::istringstream fields(header);
  std::string magic;
  std::string dns_name;
  std::string port_text;
  std::string extra;
  if (!(fields >> magic >> dns_name >> port_text) || fields >> extra || magic != "ZTEG1") {
    throw GatewayError("invalid_request");
  }
  unsigned port = 0;
  const auto [end, error] =
      std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
  if (error != std::errc{} || end != port_text.data() + port_text.size() || port == 0 ||
      port > 65535) {
    throw GatewayError("invalid_request");
  }
  route.dns_name = request_name(dns_name);
  route.protocol = "explicit";
  route.port = static_cast<std::uint16_t>(port);
  route.payload_offset = header_size + 1;
  return ParseStatus::complete;
}

struct Session {
  Session(corosio::io_context &context, std::uint64_t value)
      : incoming(context), outgoing(context), id(value) {
    decision.started_at = std::chrono::system_clock::now();
  }

  corosio::tcp_socket incoming;
  corosio::tcp_socket outgoing;
  std::stop_source stop;
  std::uint64_t id;
  std::string source_ip;
  Route route;
  std::vector<std::byte> buffered;
  std::optional<Rule> rule;
  tunnel::EgressDecision decision;
  std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + 10s;
  std::unique_ptr<Admission::Ticket> admission;
  bool decision_written = false;
  std::string forced_reason;

  void close() {
    stop.request_stop();
    incoming.close();
    outgoing.close();
  }
};

struct Yield {
  capy::continuation continuation;

  bool await_ready() const noexcept {
    return false;
  }

  void await_suspend(std::coroutine_handle<> handle, const capy::io_env *environment) {
    continuation.h = handle;
    environment->executor.post(continuation);
  }

  void await_resume() const noexcept {
  }
};

capy::io_task<> write_all(corosio::tcp_socket &socket, capy::const_buffer buffer) {
  std::size_t offset = 0;
  while (offset < buffer.size()) {
    auto [error, size] = co_await socket.write_some(capy::const_buffer(
        static_cast<const std::byte *>(buffer.data()) + offset, buffer.size() - offset));
    if (error || size == 0) {
      co_return {std::make_error_code(std::errc::connection_aborted)};
    }
    offset += size;
  }
  co_return {};
}

capy::io_task<> forward(Session &session, bool upstream) {
  std::array<std::byte, 16384> buffer{};
  auto &source = upstream ? session.incoming : session.outgoing;
  auto &destination = upstream ? session.outgoing : session.incoming;
  while (!session.stop.stop_requested()) {
    auto [read_error, size] =
        co_await source.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
    if (read_error || size == 0) {
      break;
    }
    auto [write_error] = co_await write_all(destination, capy::const_buffer(buffer.data(), size));
    if (write_error) {
      break;
    }
    co_await Yield{};
  }
  co_return {};
}

class Runtime {
public:
  explicit Runtime(const Options &options)
      : options_(options), listener_(context_), health_(context_),
        audit_(tunnel::json_lines_sink(options.audit)),
        admission_(options.max_sessions, options.max_pending_sessions,
                   options.max_pending_per_source) {
    reload(true);
    listen(listener_, options_.listen);
    listen(health_, options_.health_listen);
  }

  int run() {
    launch(accept_sessions());
    launch(accept_health());
    launch(watch());
    context_.run();
    return failed_ || !audit_ok_ ? 1 : 0;
  }

private:
  void launch(capy::task<> task) {
    capy::run_async(
        context_.get_executor(),
        [] {
        },
        [this](std::exception_ptr) {
          failed_ = true;
          stopping = 1;
        })(std::move(task));
  }

  bool ready() const {
    return !stopping && audit_ok_ && rules_ok_;
  }

  bool emit(const tunnel::EgressDecision &decision) {
    try {
      audit_->write(decision);
      return true;
    } catch (...) {
      audit_ok_ = false;
      std::cerr << "zetta-tunnel: audit unavailable; refusing traffic\n";
      return false;
    }
  }

  void reload(bool force) {
    try {
      const auto modified = std::filesystem::last_write_time(options_.rules);
      const auto size = std::filesystem::file_size(options_.rules);
      if (!force && rules_ok_ && modified == modified_ && size == file_size_) {
        return;
      }
      auto replacement = read_rules(options_.rules);
      rules_ = std::move(replacement);
      modified_ = modified;
      file_size_ = size;
      rules_ok_ = true;
    } catch (...) {
      rules_.clear();
      if (rules_ok_ || force) {
        std::cerr << "zetta-tunnel: rule file unavailable or invalid; refusing traffic\n";
      }
      rules_ok_ = false;
    }
  }

  const Rule *authorize(const Session &session) {
    reload(false);
    if (!ready()) {
      throw GatewayError("rules_unavailable");
    }
    for (const auto &[id, rule] : rules_) {
      const bool source_allowed = std::find(rule.source_ips.begin(), rule.source_ips.end(),
                                            session.source_ip) != rule.source_ips.end();
      const bool port_allowed =
          std::find(rule.ports.begin(), rule.ports.end(), session.route.port) != rule.ports.end();
      if (source_allowed && port_allowed && rule.dns_name == session.route.dns_name) {
        return &rule;
      }
    }
    throw GatewayError("rule_absent");
  }

  capy::task<> identify(Session &session) {
    std::array<std::byte, 4096> buffer{};
    while (!session.stop.stop_requested()) {
      auto [error, size] =
          co_await session.incoming.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
      if (error || size == 0 || session.buffered.size() + size > routing_buffer_limit) {
        throw GatewayError("invalid_request");
      }
      session.buffered.insert(session.buffered.end(), buffer.begin(), buffer.begin() + size);
      const auto input = std::span<const std::byte>(session.buffered);
      const auto status = byte_at(input, 0) == 22
                              ? parse_client_hello(input, options_.sni_port, session.route)
                              : parse_explicit(input, session.route);
      if (status == ParseStatus::complete) {
        co_return;
      }
    }
    throw GatewayError("invalid_request");
  }

  capy::task<> connect(Session &session) {
    corosio::resolver resolver(context_);
    auto [resolve_error, results] =
        co_await resolver.resolve(session.route.dns_name, std::to_string(session.route.port));
    if (resolve_error) {
      throw GatewayError("dns_resolution");
    }
    for (const auto &result : results) {
      auto [connect_error] = co_await session.outgoing.connect(result.get_endpoint());
      if (!connect_error) {
        session.decision.resolved_address = tunnel::peer_address(session.outgoing);
        co_return;
      }
      session.outgoing.close();
    }
    throw GatewayError("upstream_connect");
  }

  capy::task<> serve(std::shared_ptr<Session> session) {
    std::string reason;
    try {
      co_await identify(*session);
      session->decision.dns_name = session->route.dns_name;
      session->decision.port = session->route.port;
      session->decision.protocol = session->route.protocol;
      session->rule = *authorize(*session);
      session->decision.rule_id = session->rule->id;
      session->decision.workspace = session->rule->workspace;
      if (!session->admission->promote()) {
        throw GatewayError("capacity");
      }
      co_await connect(*session);
      const auto current = rules_.find(session->rule->id);
      if (!ready() || current == rules_.end() || current->second != *session->rule) {
        throw GatewayError("rule_changed");
      }
      session->decision.decision = "allow";
      session->decision.reason = "rule_allowed";
      if (!emit(session->decision)) {
        throw GatewayError("audit_unavailable");
      }
      session->decision_written = true;
      const auto payload =
          std::span<const std::byte>(session->buffered).subspan(session->route.payload_offset);
      auto [write_error] =
          co_await write_all(session->outgoing, capy::const_buffer(payload.data(), payload.size()));
      if (write_error) {
        throw GatewayError("upstream_connect");
      }
      static_cast<void>(co_await capy::when_any(forward(*session, true), forward(*session, false)));
    } catch (const GatewayError &error) {
      reason = error.what();
    } catch (...) {
      reason = "session_error";
    }
    if (!session->forced_reason.empty()) {
      reason = session->forced_reason;
    }
    session->close();
    if (!session->decision_written && reason != "audit_unavailable") {
      session->decision.decision = "deny";
      session->decision.reason = reason.empty() ? "peer_closed" : reason;
      static_cast<void>(emit(session->decision));
    }
    session->admission.reset();
    sessions_.erase(session->id);
  }

  capy::task<> accept_sessions() {
    while (!stopping) {
      auto session = std::make_shared<Session>(context_, next_id_++);
      auto [error] = co_await listener_.accept(session->incoming);
      if (error) {
        if (stopping) {
          co_return;
        }
        throw GatewayError("accept failed");
      }
      session->deadline = std::chrono::steady_clock::now() + 10s;
      session->decision.started_at = std::chrono::system_clock::now();
      session->decision.source = tunnel::peer_address(session->incoming);
      session->source_ip = source_ip(session->incoming);
      session->admission = admission_.acquire(tunnel::source_address(session->incoming));
      if (!ready() || !session->admission) {
        session->decision.decision = "deny";
        session->decision.reason =
            ready() ? "capacity" : (audit_ok_ ? "rules_unavailable" : "audit_unavailable");
        static_cast<void>(emit(session->decision));
        session->close();
        continue;
      }
      sessions_.emplace(session->id, session);
      capy::run_async(
          context_.get_executor(), session->stop.get_token(),
          [] {
          },
          [this, session](std::exception_ptr) {
            session->close();
            session->admission.reset();
            sessions_.erase(session->id);
            failed_ = true;
          })(serve(session));
    }
  }

  capy::task<> serve_health(std::shared_ptr<Session> session) {
    std::array<char, 4096> buffer{};
    std::size_t used = 0;
    while (used < buffer.size()) {
      auto [error, size] = co_await session->incoming.read_some(
          capy::mutable_buffer(buffer.data() + used, buffer.size() - used));
      if (error || size == 0) {
        break;
      }
      used += size;
      const std::string_view request(buffer.data(), used);
      if (request.find("\r\n\r\n") == std::string_view::npos) {
        continue;
      }
      std::string status = "404 Not Found";
      if (request.starts_with("GET /healthz HTTP/1.")) {
        status = "200 OK";
      } else if (request.starts_with("GET /readyz HTTP/1.")) {
        status = ready() ? "200 OK" : "503 Service Unavailable";
      }
      const std::string response =
          "HTTP/1.1 " + status + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
      auto [write_error] = co_await write_all(session->incoming,
                                              capy::const_buffer(response.data(), response.size()));
      static_cast<void>(write_error);
      break;
    }
    session->close();
    health_sessions_.erase(session->id);
  }

  capy::task<> accept_health() {
    while (!stopping) {
      auto session = std::make_shared<Session>(context_, next_id_++);
      auto [error] = co_await health_.accept(session->incoming);
      if (error) {
        co_return;
      }
      if (health_sessions_.size() >= 16) {
        session->close();
        continue;
      }
      session->deadline = std::chrono::steady_clock::now() + 5s;
      health_sessions_.emplace(session->id, session);
      launch(serve_health(session));
    }
  }

  void check_sessions() {
    std::vector<std::shared_ptr<Session>> current;
    for (const auto &[id, session] : sessions_) {
      current.push_back(session);
    }
    for (const auto &session : current) {
      if (stopping || !audit_ok_ || !rules_ok_) {
        session->close();
      } else if (std::chrono::steady_clock::now() >= session->deadline &&
                 !session->decision_written) {
        session->forced_reason = "setup_timeout";
        session->close();
      } else if (session->rule) {
        const auto found = rules_.find(session->rule->id);
        if (found == rules_.end() || found->second != *session->rule) {
          session->close();
        }
      }
    }
    current.clear();
    for (const auto &[id, session] : health_sessions_) {
      current.push_back(session);
    }
    for (const auto &session : current) {
      if (stopping || std::chrono::steady_clock::now() >= session->deadline) {
        session->close();
      }
    }
  }

  capy::task<> watch() {
    corosio::timer timer(context_);
    auto next_reload = std::chrono::steady_clock::now() + 2s;
    while (!stopping) {
      timer.expires_after(100ms);
      auto [error] = co_await timer.wait();
      if (error) {
        break;
      }
      const auto now = std::chrono::steady_clock::now();
      if (reloading || now >= next_reload) {
        const bool force = reloading != 0;
        reloading = 0;
        reload(force);
        next_reload = now + 2s;
      }
      check_sessions();
    }
    stopping = 1;
    listener_.close();
    health_.close();
    check_sessions();
  }

  const Options &options_;
  corosio::io_context context_;
  corosio::tcp_acceptor listener_;
  corosio::tcp_acceptor health_;
  std::unique_ptr<tunnel::AuditSink> audit_;
  Admission admission_;
  std::map<std::string, Rule> rules_;
  std::filesystem::file_time_type modified_{};
  std::uintmax_t file_size_ = 0;
  std::map<std::uint64_t, std::shared_ptr<Session>> sessions_;
  std::map<std::uint64_t, std::shared_ptr<Session>> health_sessions_;
  std::uint64_t next_id_ = 1;
  bool rules_ok_ = false;
  bool audit_ok_ = true;
  bool failed_ = false;
};

} // namespace

int run(const Options &options) {
  stopping = 0;
  reloading = 0;
  std::signal(SIGINT, signal_stop);
  std::signal(SIGTERM, signal_stop);
#ifndef _WIN32
  std::signal(SIGHUP, signal_reload);
  std::signal(SIGPIPE, SIG_IGN);
#endif
  Runtime runtime(options);
  return runtime.run();
}

} // namespace zetta_tunnel::egress
