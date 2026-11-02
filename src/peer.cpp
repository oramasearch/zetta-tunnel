#include "peer.hpp"
#include "admission.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_any.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/timer.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <csignal>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stop_token>
#include <vector>

namespace zetta_tunnel::peer {
namespace {

using namespace std::chrono_literals;
namespace capy = tunnel::capy;
namespace corosio = tunnel::corosio;

constexpr std::size_t request_limit = 512;
volatile std::sig_atomic_t stopping = 0;
volatile std::sig_atomic_t reloading = 0;

class PeerError final : public std::runtime_error {
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

struct Decision {
  std::uint64_t session_id = 0;
  std::string decision;
  std::string reason;
  std::string peer_id;
  std::string workspace;
  std::string direction;
  std::string service;
  std::uint16_t port = 0;
  std::string peer;
  std::string target;
  tunnel::Time started_at{};
};

class AuditSink {
public:
  explicit AuditSink(const std::string &path) {
    if (path != "-") {
      file_.open(path, std::ios::app | std::ios::binary);
      if (!file_) {
        throw std::invalid_argument("cannot open audit sink");
      }
      output_ = &file_;
    }
  }

  void write(const Decision &record) {
    const nlohmann::json value = {
        {"schema", 1},
        {"event", "peer_decision"},
        {"role", "peer"},
        {"timestamp", tunnel::format_time(std::chrono::system_clock::now())},
        {"started_at", tunnel::format_time(record.started_at)},
        {"session_id", record.session_id},
        {"decision", record.decision},
        {"reason", record.reason},
        {"peer_id", record.peer_id},
        {"workspace", record.workspace},
        {"direction", record.direction},
        {"service", record.service},
        {"port", record.port},
        {"peer", record.peer},
        {"target", record.target}};
    *output_ << value.dump() << '\n';
    output_->flush();
    if (!*output_) {
      throw std::runtime_error("audit write failed");
    }
  }

private:
  std::ofstream file_;
  std::ostream *output_ = &std::cout;
};

struct Session {
  Session(corosio::io_context &context, std::uint64_t value)
      : incoming(context), outgoing(context), id(value) {
    decision.session_id = value;
    decision.started_at = std::chrono::system_clock::now();
  }

  corosio::tcp_socket incoming;
  corosio::tcp_socket outgoing;
  std::unique_ptr<tunnel::SecureStream> secure;
  std::stop_source stop;
  std::uint64_t id;
  std::optional<Configuration> configuration;
  std::optional<Import> imported;
  std::optional<Export> exported;
  Decision decision;
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

struct HealthSession {
  HealthSession(corosio::io_context &context, std::uint64_t value) : socket(context), id(value) {
  }

  corosio::tcp_socket socket;
  std::uint64_t id;
  std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + 5s;
};

struct ImportListener {
  ImportListener(corosio::io_context &context, Import value)
      : acceptor(context), service(std::move(value)) {
  }

  corosio::tcp_acceptor acceptor;
  Import service;
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

capy::io_task<> write_all(tunnel::SecureStream &stream, capy::const_buffer buffer) {
  std::size_t offset = 0;
  while (offset < buffer.size()) {
    auto [error, size] = co_await stream.write_some(capy::const_buffer(
        static_cast<const std::byte *>(buffer.data()) + offset, buffer.size() - offset));
    if (error || size == 0) {
      co_return {std::make_error_code(std::errc::connection_aborted)};
    }
    offset += size;
  }
  co_return {};
}

capy::io_task<> forward_plain_to_secure(Session &session) {
  std::array<std::byte, 16384> buffer{};
  while (!session.stop.stop_requested()) {
    auto [read_error, size] =
        co_await session.incoming.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
    if (read_error || size == 0) {
      break;
    }
    auto [write_error] =
        co_await write_all(*session.secure, capy::const_buffer(buffer.data(), size));
    if (write_error) {
      break;
    }
    co_await Yield{};
  }
  co_return {};
}

capy::io_task<> forward_secure_to_plain(Session &session) {
  std::array<std::byte, 16384> buffer{};
  while (!session.stop.stop_requested()) {
    auto [read_error, size] =
        co_await session.secure->read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
    if (read_error || size == 0) {
      break;
    }
    auto [write_error] =
        co_await write_all(session.incoming, capy::const_buffer(buffer.data(), size));
    if (write_error) {
      break;
    }
    co_await Yield{};
  }
  co_return {};
}

capy::io_task<> forward_secure_to_target(Session &session) {
  std::array<std::byte, 16384> buffer{};
  while (!session.stop.stop_requested()) {
    auto [read_error, size] =
        co_await session.secure->read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
    if (read_error || size == 0) {
      break;
    }
    auto [write_error] =
        co_await write_all(session.outgoing, capy::const_buffer(buffer.data(), size));
    if (write_error) {
      break;
    }
    co_await Yield{};
  }
  co_return {};
}

capy::io_task<> forward_target_to_secure(Session &session) {
  std::array<std::byte, 16384> buffer{};
  while (!session.stop.stop_requested()) {
    auto [read_error, size] =
        co_await session.outgoing.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
    if (read_error || size == 0) {
      break;
    }
    auto [write_error] =
        co_await write_all(*session.secure, capy::const_buffer(buffer.data(), size));
    if (write_error) {
      break;
    }
    co_await Yield{};
  }
  co_return {};
}

struct Request {
  std::string peer_id;
  std::string service;
  std::uint16_t port = 0;
  std::vector<std::byte> payload;
};

Request parse_request(std::span<const std::byte> bytes, std::size_t newline) {
  std::string header(reinterpret_cast<const char *>(bytes.data()), newline);
  if (header.ends_with('\r')) {
    header.pop_back();
  }
  std::istringstream fields(header);
  std::string magic;
  std::string port_text;
  std::string extra;
  Request request;
  if (!(fields >> magic >> request.peer_id >> request.service >> port_text) || fields >> extra ||
      magic != "ZTPR1" || !tunnel::valid_uuid(request.peer_id)) {
    throw PeerError("invalid_request");
  }
  try {
    request.service = normalize_service_name(request.service);
  } catch (const std::exception &) {
    throw PeerError("invalid_request");
  }
  unsigned parsed_port = 0;
  const auto [end, error] =
      std::from_chars(port_text.data(), port_text.data() + port_text.size(), parsed_port);
  if (error != std::errc{} || end != port_text.data() + port_text.size() || parsed_port == 0 ||
      parsed_port > 65535) {
    throw PeerError("invalid_request");
  }
  request.port = static_cast<std::uint16_t>(parsed_port);
  request.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(newline + 1), bytes.end());
  return request;
}

capy::task<Request> read_request(tunnel::SecureStream &stream) {
  std::vector<std::byte> bytes;
  while (bytes.size() <= request_limit) {
    std::array<std::byte, request_limit + 1> buffer{};
    auto [error, size] =
        co_await stream.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
    if (error || size == 0) {
      throw PeerError("invalid_request");
    }
    bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(size));
    const auto newline = std::find(bytes.begin(), bytes.end(), static_cast<std::byte>('\n'));
    if (newline != bytes.end()) {
      const auto offset = static_cast<std::size_t>(newline - bytes.begin());
      if (offset == 0 || offset >= request_limit) {
        throw PeerError("invalid_request");
      }
      co_return parse_request(bytes, offset);
    }
  }
  throw PeerError("invalid_request");
}

capy::task<> expect_acknowledgement(tunnel::SecureStream &stream) {
  std::array<char, 6> acknowledgement{};
  std::size_t used = 0;
  while (used < acknowledgement.size()) {
    auto [error, size] = co_await stream.read_some(
        capy::mutable_buffer(acknowledgement.data() + used, acknowledgement.size() - used));
    if (error || size == 0) {
      throw PeerError("remote_denied");
    }
    used += size;
  }
  if (std::string_view(acknowledgement.data(), acknowledgement.size()) != "ZTPA1\n") {
    throw PeerError("remote_denied");
  }
  co_return;
}

class Runtime {
public:
  explicit Runtime(const Options &options)
      : options_(options), peer_listener_(context_), health_listener_(context_),
        audit_(options.audit), admission_(options.max_sessions, options.max_pending_sessions,
                                          options.max_pending_per_source) {
    tls_ = tunnel::load_credentials(options_.tls);
    listen(peer_listener_, options_.listen);
    listen(health_listener_, options_.health_listen);
    reload(true);
  }

  int run() {
    launch(accept_peers());
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
    return !stopping && tls_ && audit_ok_ && configuration_ok_;
  }

  bool emit(const Decision &decision) {
    try {
      audit_.write(decision);
      return true;
    } catch (...) {
      audit_ok_ = false;
      std::cerr << "zetta-tunnel: audit unavailable; refusing peer traffic\n";
      return false;
    }
  }

  void close_imports() {
    for (const auto &[address, listener] : import_listeners_) {
      listener->acceptor.close();
    }
    import_listeners_.clear();
  }

  void close_sessions() {
    std::vector<std::shared_ptr<Session>> current;
    for (const auto &[id, session] : sessions_) {
      current.push_back(session);
    }
    for (const auto &session : current) {
      session->forced_reason = "configuration_changed";
      session->close();
    }
  }

  void apply_imports(const Configuration &replacement) {
    std::map<std::string, Import> desired;
    for (const auto &service : replacement.imports) {
      desired.emplace(service.listen, service);
    }
    std::vector<std::shared_ptr<ImportListener>> staged;
    for (const auto &[address, service] : desired) {
      if (import_listeners_.contains(address)) {
        continue;
      }
      auto listener = std::make_shared<ImportListener>(context_, service);
      listen(listener->acceptor, address);
      staged.push_back(listener);
    }
    for (auto current = import_listeners_.begin(); current != import_listeners_.end();) {
      const auto desired_service = desired.find(current->first);
      if (desired_service == desired.end()) {
        current->second->acceptor.close();
        current = import_listeners_.erase(current);
      } else {
        current->second->service = desired_service->second;
        ++current;
      }
    }
    for (const auto &listener : staged) {
      import_listeners_.emplace(listener->service.listen, listener);
      launch(accept_imports(listener));
    }
  }

  void reload(bool force) {
    try {
      const auto modified = std::filesystem::last_write_time(options_.configuration);
      const auto size = std::filesystem::file_size(options_.configuration);
      if (!force && configuration_ok_ && modified == modified_ && size == file_size_) {
        return;
      }
      auto replacement = read_configuration(options_.configuration);
      const bool changed = !configuration_ || *configuration_ != replacement;
      if (changed) {
        apply_imports(replacement);
        close_sessions();
      }
      configuration_ = std::move(replacement);
      modified_ = modified;
      file_size_ = size;
      configuration_ok_ = true;
    } catch (...) {
      configuration_.reset();
      close_imports();
      close_sessions();
      if (configuration_ok_ || force) {
        std::cerr << "zetta-tunnel: peer configuration unavailable or invalid; refusing traffic\n";
      }
      configuration_ok_ = false;
    }
  }

  std::optional<Export> authorize(const Request &request) {
    reload(false);
    if (!ready() || !configuration_ || request.peer_id != configuration_->id) {
      return std::nullopt;
    }
    const auto found =
        std::find_if(configuration_->exports.begin(), configuration_->exports.end(),
                     [&request](const auto &item) {
                       return item.name == request.service && item.port == request.port;
                     });
    if (found == configuration_->exports.end()) {
      return std::nullopt;
    }
    return *found;
  }

  bool current(const Session &session) const {
    return ready() && configuration_ && session.configuration &&
           *configuration_ == *session.configuration;
  }

  capy::task<> serve_import(std::shared_ptr<Session> session) {
    std::string reason;
    try {
      reload(false);
      if (!current(*session) || !session->imported) {
        throw PeerError("configuration_unavailable");
      }
      const auto remote = tunnel::parse_address(session->configuration->remote);
      try {
        co_await tunnel::connect(context_, session->outgoing, remote);
      } catch (const std::exception &) {
        throw PeerError("remote_connect");
      }
      session->secure = std::make_unique<tunnel::SecureStream>(session->outgoing, tls_, false,
                                                               options_.peer_name);
      auto [handshake_error] = co_await session->secure->handshake();
      if (handshake_error) {
        throw PeerError("tls_authentication");
      }
      const auto request = "ZTPR1 " + session->configuration->id + " " + session->imported->name +
                           " " + std::to_string(session->imported->port) + "\n";
      auto [write_error] =
          co_await write_all(*session->secure, capy::const_buffer(request.data(), request.size()));
      if (write_error) {
        throw PeerError("remote_connect");
      }
      co_await expect_acknowledgement(*session->secure);
      reload(false);
      if (!current(*session)) {
        throw PeerError("configuration_changed");
      }
      if (!session->admission->promote()) {
        throw PeerError("capacity");
      }
      session->decision.decision = "allow";
      session->decision.reason = "service_allowed";
      if (!emit(session->decision)) {
        throw PeerError("audit_unavailable");
      }
      session->decision_written = true;
      static_cast<void>(co_await capy::when_any(forward_plain_to_secure(*session),
                                                forward_secure_to_plain(*session)));
    } catch (const PeerError &error) {
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

  capy::task<> serve_export(std::shared_ptr<Session> session) {
    std::string reason;
    try {
      session->secure =
          std::make_unique<tunnel::SecureStream>(session->incoming, tls_, true, options_.peer_name);
      auto [handshake_error] = co_await session->secure->handshake();
      if (handshake_error) {
        throw PeerError("tls_authentication");
      }
      auto request = co_await read_request(*session->secure);
      session->decision.peer_id = request.peer_id;
      session->decision.service = request.service;
      session->decision.port = request.port;
      const auto service = authorize(request);
      if (!service || !configuration_) {
        throw PeerError("service_absent");
      }
      session->configuration = *configuration_;
      session->exported = *service;
      if (!session->admission->promote()) {
        throw PeerError("capacity");
      }
      session->decision.workspace = configuration_->workspace;
      session->decision.target = service->target;
      try {
        co_await tunnel::connect(context_, session->outgoing,
                                 tunnel::parse_address(service->target));
      } catch (const std::exception &) {
        throw PeerError("target_connect");
      }
      reload(false);
      if (!current(*session)) {
        throw PeerError("configuration_changed");
      }
      session->decision.decision = "allow";
      session->decision.reason = "service_allowed";
      if (!emit(session->decision)) {
        throw PeerError("audit_unavailable");
      }
      session->decision_written = true;
      constexpr std::string_view acknowledgement = "ZTPA1\n";
      auto [acknowledgement_error] = co_await write_all(
          *session->secure, capy::const_buffer(acknowledgement.data(), acknowledgement.size()));
      if (acknowledgement_error) {
        throw PeerError("peer_closed");
      }
      if (!request.payload.empty()) {
        auto [payload_error] = co_await write_all(
            session->outgoing, capy::const_buffer(request.payload.data(), request.payload.size()));
        if (payload_error) {
          throw PeerError("target_connect");
        }
      }
      static_cast<void>(co_await capy::when_any(forward_secure_to_target(*session),
                                                forward_target_to_secure(*session)));
    } catch (const PeerError &error) {
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

  capy::task<> accept_imports(std::shared_ptr<ImportListener> listener) {
    while (!stopping && listener->acceptor.is_open()) {
      auto session = std::make_shared<Session>(context_, next_id_++);
      auto [error] = co_await listener->acceptor.accept(session->incoming);
      if (error) {
        co_return;
      }
      session->decision.direction = "import";
      session->decision.service = listener->service.name;
      session->decision.port = listener->service.port;
      session->decision.target = listener->service.listen;
      session->decision.peer = tunnel::peer_address(session->incoming);
      if (configuration_) {
        session->configuration = *configuration_;
        session->decision.peer_id = configuration_->id;
        session->decision.workspace = configuration_->workspace;
      }
      session->imported = listener->service;
      session->deadline = std::chrono::steady_clock::now() + 10s;
      session->admission = admission_.acquire(tunnel::source_address(session->incoming));
      if (!ready() || !session->admission) {
        session->decision.decision = "deny";
        session->decision.reason = ready() ? "capacity" : "configuration_unavailable";
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
          })(serve_import(session));
    }
  }

  capy::task<> accept_peers() {
    while (!stopping) {
      auto session = std::make_shared<Session>(context_, next_id_++);
      auto [error] = co_await peer_listener_.accept(session->incoming);
      if (error) {
        if (stopping) {
          co_return;
        }
        throw PeerError("accept failed");
      }
      session->decision.direction = "export";
      session->decision.peer = tunnel::peer_address(session->incoming);
      if (configuration_) {
        session->configuration = *configuration_;
        session->decision.peer_id = configuration_->id;
        session->decision.workspace = configuration_->workspace;
      }
      session->deadline = std::chrono::steady_clock::now() + 10s;
      session->admission = admission_.acquire(tunnel::source_address(session->incoming));
      if (!ready() || !session->admission) {
        session->decision.decision = "deny";
        session->decision.reason = ready() ? "capacity" : "configuration_unavailable";
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
          })(serve_export(session));
    }
  }

  capy::task<> serve_health(std::shared_ptr<HealthSession> session) {
    std::array<char, 4096> buffer{};
    std::size_t used = 0;
    while (used < buffer.size()) {
      auto [error, size] = co_await session->socket.read_some(
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
      auto [write_error] =
          co_await write_all(session->socket, capy::const_buffer(response.data(), response.size()));
      static_cast<void>(write_error);
      break;
    }
    session->socket.close();
    health_sessions_.erase(session->id);
  }

  capy::task<> accept_health() {
    while (!stopping) {
      auto session = std::make_shared<HealthSession>(context_, next_id_++);
      auto [error] = co_await health_listener_.accept(session->socket);
      if (error) {
        co_return;
      }
      if (health_sessions_.size() >= 16) {
        session->socket.close();
        continue;
      }
      health_sessions_.emplace(session->id, session);
      launch(serve_health(session));
    }
  }

  void check_sessions() {
    std::vector<std::shared_ptr<Session>> current_sessions;
    for (const auto &[id, session] : sessions_) {
      current_sessions.push_back(session);
    }
    for (const auto &session : current_sessions) {
      if (stopping || !audit_ok_ || !current(*session)) {
        session->close();
      } else if (std::chrono::steady_clock::now() >= session->deadline &&
                 !session->decision_written) {
        session->forced_reason = "setup_timeout";
        session->close();
      }
    }
    std::vector<std::shared_ptr<HealthSession>> current_health;
    for (const auto &[id, session] : health_sessions_) {
      current_health.push_back(session);
    }
    for (const auto &session : current_health) {
      if (stopping || std::chrono::steady_clock::now() >= session->deadline) {
        session->socket.close();
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
        try {
          tls_ = tunnel::load_credentials(options_.tls);
        } catch (...) {
          tls_.reset();
        }
        reload(force);
        next_reload = now + 2s;
      }
      check_sessions();
    }
    stopping = 1;
    peer_listener_.close();
    health_listener_.close();
    close_imports();
    check_sessions();
  }

  const Options &options_;
  corosio::io_context context_;
  corosio::tcp_acceptor peer_listener_;
  corosio::tcp_acceptor health_listener_;
  AuditSink audit_;
  Admission admission_;
  tunnel::TlsContext tls_;
  std::optional<Configuration> configuration_;
  std::filesystem::file_time_type modified_{};
  std::uintmax_t file_size_ = 0;
  std::map<std::string, std::shared_ptr<ImportListener>> import_listeners_;
  std::map<std::uint64_t, std::shared_ptr<Session>> sessions_;
  std::map<std::uint64_t, std::shared_ptr<HealthSession>> health_sessions_;
  std::uint64_t next_id_ = 1;
  bool configuration_ok_ = false;
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

} // namespace zetta_tunnel::peer
