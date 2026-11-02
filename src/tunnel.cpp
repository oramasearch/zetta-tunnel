#include "tunnel.hpp"
#include "admission.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_any.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/timer.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <csignal>
#include <iostream>
#include <optional>
#include <stop_token>
#include <vector>

namespace zetta_tunnel::tunnel {
namespace {

using namespace std::chrono_literals;
volatile std::sig_atomic_t stopping = 0;
volatile std::sig_atomic_t reloading = 0;

void signal_stop(int) {
  stopping = 1;
}

#ifndef _WIN32
void signal_reload(int) {
  reloading = 1;
}
#endif

std::string session_id() {
  std::array<unsigned char, 16> bytes{};
  if (RAND_bytes(bytes.data(), bytes.size()) != 1) {
    throw std::runtime_error("session id generation failed");
  }
  constexpr char hex[] = "0123456789abcdef";
  std::string value;
  for (const auto byte : bytes) {
    value += hex[byte >> 4];
    value += hex[byte & 15];
  }
  return value;
}

void listen(corosio::tcp_acceptor &acceptor, const std::string &value) {
  const corosio::endpoint endpoint(value);
  acceptor.open(endpoint.is_v4() ? corosio::tcp::v4() : corosio::tcp::v6());
  if (acceptor.bind(endpoint) || acceptor.listen()) {
    throw std::runtime_error("listener failed");
  }
}

struct Session {
  explicit Session(corosio::io_context &context) : incoming(context), outgoing(context) {
    record.session_id = session_id();
    record.started_at = std::chrono::system_clock::now();
  }

  corosio::tcp_socket incoming;
  corosio::tcp_socket outgoing;
  std::stop_source stop;
  std::unique_ptr<SecureStream> incoming_tls;
  std::unique_ptr<SecureStream> outgoing_tls;
  std::optional<Grant> grant;
  Time certificate_expires = Time::max();
  std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + 10s;
  AuditRecord record;
  std::unique_ptr<Admission::Ticket> admission;
  bool started = false;
  std::string reason;

  void close(std::string_view why) {
    if (reason.empty()) {
      reason = why;
    }
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

capy::io_task<std::size_t> read(Session &session, bool incoming, capy::mutable_buffer buffer) {
  auto &tls = incoming ? session.incoming_tls : session.outgoing_tls;
  if (tls) {
    co_return co_await tls->read_some(buffer);
  }
  auto &socket = incoming ? session.incoming : session.outgoing;
  co_return co_await socket.read_some(buffer);
}

capy::io_task<std::size_t> write(Session &session, bool incoming, capy::const_buffer buffer) {
  auto &tls = incoming ? session.incoming_tls : session.outgoing_tls;
  if (tls) {
    co_return co_await tls->write_some(buffer);
  }
  auto &socket = incoming ? session.incoming : session.outgoing;
  co_return co_await socket.write_some(buffer);
}

capy::io_task<> forward(Session &session, bool upstream) {
  std::array<std::byte, 16384> buffer{};
  while (!session.stop.stop_requested()) {
    auto [read_error, size] =
        co_await read(session, upstream, capy::mutable_buffer(buffer.data(), buffer.size()));
    if (read_error || size == 0) {
      break;
    }
    std::size_t offset = 0;
    while (offset < size) {
      auto [write_error, written] = co_await write(
          session, !upstream, capy::const_buffer(buffer.data() + offset, size - offset));
      auto &count = upstream ? session.record.bytes_up : session.record.bytes_down;
      count += written;
      if (write_error || written == 0) {
        co_return {};
      }
      offset += written;
    }
    // Buffered TLS must not monopolize the event loop during continuous traffic.
    co_await Yield{};
  }
  // First completed direction cancels the other, including blocked writes.
  co_return {};
}

class Runtime {
public:
  explicit Runtime(const Options &options)
      : options_(options), listener_(context_), health_(context_),
        audit_(json_lines_sink(options.audit)),
        admission_(options.max_sessions, options.max_pending_sessions,
                   options.max_pending_per_source) {
    tls_ = load_credentials(options_.tls);
    if (options_.role == "relay") {
      endpoint_tls_ = load_credentials(options_.endpoint_tls);
      reload(true);
    }
    listen(listener_, options_.listen);
    if (!options_.health_listen.empty()) {
      listen(health_, options_.health_listen);
    }
  }

  int run() {
    launch(accept_sessions());
    launch(watch());
    if (health_.is_open()) {
      launch(accept_health());
    }
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
    return !stopping && tls_ && (options_.role != "relay" || endpoint_tls_) && audit_ok_ &&
           (options_.role != "relay" || grants_ok_);
  }

  void emit(AuditRecord record) {
    if (options_.role == "client") {
      return;
    }
    try {
      audit_->write(record);
    } catch (...) {
      audit_ok_ = false;
      // Do not echo the sink path, payloads, or library error text.
      std::cerr << "zetta-tunnel: audit unavailable; refusing traffic\n";
    }
  }

  void reload(bool force) {
    if (options_.role != "relay") {
      return;
    }
    try {
      const auto modified = std::filesystem::last_write_time(options_.grants);
      const auto size = std::filesystem::file_size(options_.grants);
      if (!force && grants_ok_ && modified == modified_ && size == file_size_) {
        return;
      }
      auto replacement = read_grants(options_.grants);
      grants_ = std::move(replacement);
      modified_ = modified;
      file_size_ = size;
      grants_ok_ = true;
    } catch (...) {
      grants_.clear();
      if (grants_ok_ || force) {
        std::cerr << "zetta-tunnel: grant file unavailable or invalid; refusing traffic\n";
      }
      grants_ok_ = false;
    }
  }

  void authorize(Session &session) {
    const auto certificate = session.incoming_tls->grant();
    session.record.grant_id = certificate.id;
    session.certificate_expires = certificate.expires;
    reload(false);
    const auto grant = grants_.find(certificate.id);
    if (!ready() || grant == grants_.end()) {
      throw transport::Error("grant_absent");
    }
    if (grant->second.expires <= std::chrono::system_clock::now()) {
      throw transport::Error("grant_expired");
    }
    if (certificate.expires > grant->second.expires) {
      throw transport::Error("certificate_exceeds_grant");
    }
    // The relay's --ca trusts every customer's CA. A grant is authorized only by a certificate
    // whose verified chain runs through one of the CAs bound to that grant, so a customer that
    // holds its own CA key cannot sign for another customer's grant (LSR-074).
    const auto &allowed = grant->second.client_ca_sha256;
    if (std::none_of(certificate.issuer_sha256.begin(), certificate.issuer_sha256.end(),
                     [&allowed](const std::string &issuer) {
                       return std::find(allowed.begin(), allowed.end(), issuer) != allowed.end();
                     })) {
      throw transport::Error("grant_issuer");
    }
    session.grant = grant->second;
    session.record.workspace = grant->second.workspace;
    session.record.endpoint = grant->second.endpoint;
  }

  capy::task<> prepare(Session &session) {
    if (options_.role != "client") {
      session.incoming_tls =
          std::make_unique<SecureStream>(session.incoming, tls_, true, options_.peer_name);
      auto [error] = co_await session.incoming_tls->handshake();
      if (error) {
        throw transport::Error("tls_peer_refused");
      }
    }
    std::string upstream;
    if (options_.role == "relay") {
      authorize(session);
      upstream = session.grant->endpoint;
    } else {
      upstream = options_.role == "client" ? options_.relay : options_.target;
      session.record.endpoint = upstream;
    }
    if (!session.admission->promote()) {
      throw transport::Error("capacity");
    }
    co_await connect(context_, session.outgoing, parse_address(upstream));
    if (options_.role != "endpoint") {
      const auto &credentials = options_.role == "client" ? tls_ : endpoint_tls_;
      const auto identity =
          options_.role == "client" ? options_.peer_name : "endpoint." + session.grant->id;
      session.outgoing_tls =
          std::make_unique<SecureStream>(session.outgoing, credentials, false, identity);
      auto [error] = co_await session.outgoing_tls->handshake();
      if (error) {
        throw transport::Error("upstream_tls_refused");
      }
      if (options_.role == "relay") {
        // TLS 1.3 clients can finish before the server verifies their certificate.
        // Require the authenticated endpoint to confirm setup before any payload.
        std::array<char, 5> ready{};
        std::size_t used = 0;
        while (used < ready.size()) {
          auto [read_error, size] = co_await session.outgoing_tls->read_some(
              capy::mutable_buffer(ready.data() + used, ready.size() - used));
          if (read_error || size == 0) {
            throw transport::Error("upstream_tls_refused");
          }
          used += size;
        }
        if (std::string_view(ready.data(), ready.size()) != "ZTUN1") {
          throw transport::Error("upstream_tls_refused");
        }
      }
    }
  }

  capy::task<> serve(std::shared_ptr<Session> session) {
    try {
      co_await prepare(*session);
      if (!ready() || session->stop.stop_requested()) {
        throw transport::Error("unavailable");
      }
      session->record.event = "session_start";
      emit(session->record);
      if (!audit_ok_) {
        throw transport::Error("audit_unavailable");
      }
      session->started = true;
      if (options_.role == "endpoint") {
        constexpr std::string_view ready = "ZTUN1";
        auto [error, size] = co_await session->incoming_tls->write_some(
            capy::const_buffer(ready.data(), ready.size()));
        if (error || size != ready.size()) {
          throw transport::Error("unavailable");
        }
      }
      static_cast<void>(co_await capy::when_any(forward(*session, true), forward(*session, false)));
    } catch (const transport::Error &error) {
      if (session->reason.empty()) {
        // Only fixed internal reasons from the transport path reach this field.
        const std::string_view reason(error.what());
        constexpr std::array reasons = {
            "grant_absent",     "grant_expired",        "certificate_exceeds_grant",
            "grant_issuer",     "certificate_identity", "certificate_lifetime",
            "tls_peer_refused", "upstream_connect",     "upstream_tls_refused",
            "unavailable",      "audit_unavailable",    "capacity"};
        session->reason = std::find(reasons.begin(), reasons.end(), reason) != reasons.end()
                              ? reason
                              : "tls_configuration";
      }
    } catch (...) {
      if (session->reason.empty()) {
        session->reason = "session_error";
      }
    }
    session->close("peer_closed");
    session->record.event = session->started ? "session_end" : "refusal";
    session->record.reason = session->reason;
    emit(session->record);
    session->admission.reset();
    sessions_.erase(session->record.session_id);
  }

  capy::task<> accept_sessions() {
    while (!stopping) {
      auto session = std::make_shared<Session>(context_);
      auto [error] = co_await listener_.accept(session->incoming);
      if (error) {
        if (stopping) {
          co_return;
        }
        throw transport::Error("accept failed");
      }
      // Setup deadlines start after acceptance, not while waiting for a peer.
      session->deadline = std::chrono::steady_clock::now() + 10s;
      session->record.started_at = std::chrono::system_clock::now();
      session->record.role = options_.role;
      session->record.peer = peer_address(session->incoming);
      session->admission = admission_.acquire(source_address(session->incoming));
      if (!ready() || !session->admission) {
        session->record.event = "refusal";
        session->record.reason = ready() ? "capacity" : "unavailable";
        emit(session->record);
        session->close(session->record.reason);
        continue;
      }
      sessions_.emplace(session->record.session_id, session);
      capy::run_async(
          context_.get_executor(), session->stop.get_token(),
          [] {
          },
          [this, session](std::exception_ptr) {
            session->close("session_error");
            session->admission.reset();
            sessions_.erase(session->record.session_id);
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
      std::size_t sent = 0;
      while (sent < response.size()) {
        auto [write_error, written] = co_await session->incoming.write_some(
            capy::const_buffer(response.data() + sent, response.size() - sent));
        if (write_error || written == 0) {
          break;
        }
        sent += written;
      }
      break;
    }
    session->incoming.close();
    health_sessions_.erase(session->record.session_id);
  }

  capy::task<> accept_health() {
    while (!stopping) {
      auto session = std::make_shared<Session>(context_);
      auto [error] = co_await health_.accept(session->incoming);
      if (error) {
        co_return;
      }
      if (health_sessions_.size() >= 16) {
        session->incoming.close();
        continue;
      }
      session->deadline = std::chrono::steady_clock::now() + 5s;
      health_sessions_.emplace(session->record.session_id, session);
      launch(serve_health(session));
    }
  }

  void check_sessions() {
    std::vector<std::shared_ptr<Session>> current;
    for (const auto &[id, session] : sessions_) {
      current.push_back(session);
    }
    const auto now = std::chrono::system_clock::now();
    for (const auto &session : current) {
      if (stopping || !audit_ok_) {
        session->close(stopping ? "shutdown" : "audit_unavailable");
      } else if (!session->started && std::chrono::steady_clock::now() >= session->deadline) {
        session->close("setup_timeout");
      } else if (session->grant) {
        const auto found = grants_.find(session->grant->id);
        if (!grants_ok_ || found == grants_.end()) {
          session->close("grant_removed");
        } else if (found->second.expires <= now || session->certificate_expires <= now) {
          session->close("grant_expired");
        } else if (found->second != *session->grant) {
          session->close("grant_changed");
        }
      }
    }
    current.clear();
    for (const auto &[id, session] : health_sessions_) {
      current.push_back(session);
    }
    for (const auto &session : current) {
      if (stopping || std::chrono::steady_clock::now() >= session->deadline) {
        session->close("health_timeout");
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
          auto next = load_credentials(options_.tls);
          auto endpoint =
              options_.role == "relay" ? load_credentials(options_.endpoint_tls) : TlsContext{};
          tls_ = std::move(next);
          endpoint_tls_ = std::move(endpoint);
        } catch (...) {
          tls_.reset();
          endpoint_tls_.reset();
        }
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
  std::unique_ptr<AuditSink> audit_;
  Admission admission_;
  TlsContext tls_, endpoint_tls_;
  std::map<std::string, Grant> grants_;
  std::filesystem::file_time_type modified_{};
  std::uintmax_t file_size_ = 0;
  std::map<std::string, std::shared_ptr<Session>> sessions_;
  std::map<std::string, std::shared_ptr<Session>> health_sessions_;
  bool grants_ok_ = false;
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

} // namespace zetta_tunnel::tunnel
