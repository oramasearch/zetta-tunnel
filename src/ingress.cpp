#include "ingress.hpp"
#include "admission.hpp"

#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_any.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/timer.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <array>
#include <charconv>
#include <csignal>
#include <fstream>
#include <iostream>

namespace zetta_tunnel::ingress {
namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
volatile std::sig_atomic_t stopping = 0;
volatile std::sig_atomic_t reloading = 0;

void stop_signal(int) {
  stopping = 1;
}

#ifndef _WIN32
void reload_signal(int) {
  reloading = 1;
}
#endif

std::string serialize(unsigned status, const Headers &headers) {
  std::string result = "HTTP/1.1 " + std::to_string(status) + " Response\r\n";
  for (const auto &[name, value] : headers) {
    result += name + ": " + value + "\r\n";
  }
  return result + "\r\n";
}

std::string websocket_accept(std::string key) {
  key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  unsigned char digest[EVP_MAX_MD_SIZE]{};
  unsigned length = 0;
  if (EVP_Digest(key.data(), key.size(), digest, &length, EVP_sha1(), nullptr) != 1 ||
      length != 20) {
    throw Error(502);
  }
  std::array<unsigned char, 29> encoded{};
  if (EVP_EncodeBlock(encoded.data(), digest, static_cast<int>(length)) != 28) {
    throw Error(502);
  }
  return std::string(reinterpret_cast<const char *>(encoded.data()), 28);
}

capy::task<> chunk(Wire &wire, std::string_view data) {
  std::array<char, 32> size{};
  const auto [end, error] = std::to_chars(size.data(), size.data() + size.size(), data.size(), 16);
  if (error != std::errc{}) {
    throw Error(502);
  }
  const std::string framed = std::string(size.data(), end) + "\r\n" + std::string(data) + "\r\n";
  co_await wire.write(framed);
}

class Http1 final : public Exchange {
public:
  Http1(corosio::tcp_socket &socket, Reader &reader, Message message)
      : socket_(socket), reader_(reader), body_(reader, message) {
    request = std::move(message);
  }

  capy::task<std::string> read_body() override {
    co_return co_await body_.read();
  }

  capy::task<> send_head(unsigned status, Headers headers) override {
    if (status >= 200) {
      chunked_ = field(headers, "content-length").empty() && request.method != "HEAD" &&
                 status != 204 && status != 304;
      if (chunked_) {
        headers.emplace_back("transfer-encoding", "chunked");
      }
      headers.emplace_back("connection", request.close ? "close" : "keep-alive");
    }
    co_await reader_.wire.write(serialize(status, headers));
  }

  capy::task<> send_body(std::string data) override {
    if (chunked_) {
      co_await chunk(reader_.wire, data);
    } else {
      co_await reader_.wire.write(data);
    }
  }

  capy::task<> finish() override {
    if (chunked_) {
      co_await reader_.wire.write("0\r\n\r\n");
    }
  }

  void abort() override {
    socket_.close();
  }

private:
  corosio::tcp_socket &socket_;
  Reader &reader_;
  Body body_;
  bool chunked_ = false;
};

struct Session {
  Session(corosio::io_context &context, std::uint64_t value) : socket(context), id(value) {
  }
  corosio::tcp_socket socket;
  std::uint64_t id;
  Clock::time_point deadline;
  std::shared_ptr<const Configuration> configuration;
  std::string sni;
  std::string source;
  std::unique_ptr<Admission::Ticket> admission;
  bool established = false;
  bool reading_headers = false;
};

struct RequestState {
  RequestState(corosio::io_context &context, std::uint64_t value, std::shared_ptr<Exchange> item)
      : upstream(context), id(value), exchange(std::move(item)) {
  }
  corosio::tcp_socket upstream;
  std::uint64_t id;
  std::shared_ptr<Exchange> exchange;
  Clock::time_point deadline;
  std::string source;
  bool connected = false;
  bool response_started = false;
  bool upload_done = false;
  bool finished = false;
  std::uint64_t received = 0;
};

class Runtime {
public:
  explicit Runtime(const Options &options)
      : options_(options), listener_(context_), health_listener_(context_),
        admission_(options.max_sessions, options.max_pending_sessions,
                   options.max_pending_per_source,
                   options.max_sessions_per_source ? options.max_sessions_per_source
                                                   : source_share(options.max_sessions)) {
    if (options.audit != "-") {
      audit_file_.open(options.audit, std::ios::app | std::ios::binary);
      if (!audit_file_) {
        throw Error(503);
      }
      audit_ = &audit_file_;
    }
    reload();
    listen(listener_, options.listen);
    listen(health_listener_, options.health_listen);
  }

  int run() {
    launch(accept(false));
    launch(accept(true));
    launch(watch());
    context_.run();
    return failed_ || !audit_ok_ ? 1 : 0;
  }

private:
  void listen(corosio::tcp_acceptor &acceptor, const std::string &address) {
    const corosio::endpoint endpoint(address);
    acceptor.open(endpoint.is_v4() ? corosio::tcp::v4() : corosio::tcp::v6());
    if (acceptor.bind(endpoint) || acceptor.listen()) {
      throw Error(503);
    }
  }

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
    return !stopping && configuration_ && audit_ok_;
  }

  void close_traffic() {
    for (const auto &[id, session] : sessions_) {
      session->socket.close();
    }
    for (const auto &[id, request] : requests_) {
      request->upstream.close();
      request->exchange->abort();
    }
  }

  void reload() {
    try {
      auto next = std::make_shared<Configuration>(read_configuration(options_.configuration));
      if (!configuration_ || configuration_->fingerprint != next->fingerprint || reloading) {
        close_traffic();
        configuration_ = std::move(next);
        ++reloads_;
      }
    } catch (...) {
      if (configuration_) {
        std::cerr << "zetta-tunnel: ingress configuration unavailable; refusing traffic\n";
      }
      configuration_.reset();
      ++reload_failures_;
      close_traffic();
    }
    reloading = 0;
  }

  void record(const Session &session, const RequestState &state, const Route &route) {
    const nlohmann::json value = {
        {"schema", 1},
        {"event", "ingress_request"},
        {"role", "ingress"},
        {"timestamp", tunnel::format_time(std::chrono::system_clock::now())},
        {"request_id", state.id},
        {"host", session.sni},
        {"route", route.id},
        {"source", session.source},
        {"decision", "allow"}};
    *audit_ << value.dump() << '\n';
    audit_->flush();
    if (!*audit_) {
      audit_ok_ = false;
      close_traffic();
      throw Error(503);
    }
  }

  void touch(RequestState &request) {
    request.deadline = Clock::now() + std::chrono::seconds(options_.idle_timeout);
  }

  capy::task<> setup_deadline(Clock::time_point deadline) {
    corosio::timer timer(context_);
    timer.expires_at(deadline);
    auto [error] = co_await timer.wait();
    if (!error) {
      ++timeouts_;
      throw Error(504);
    }
  }

  Headers upstream_headers(const Session &session, const Message &request) {
    auto headers = end_to_end(request.headers);
    std::erase_if(headers, [](const auto &item) {
      return item.first == "host" || item.first == "forwarded" ||
             item.first.starts_with("x-forwarded-") || item.first == "x-real-ip" ||
             item.first == "expect" || item.first == "content-length";
    });
    headers.emplace_back("host", field(request.headers, "host").empty()
                                     ? request.host
                                     : field(request.headers, "host"));
    headers.emplace_back("x-forwarded-for", session.source);
    headers.emplace_back("x-real-ip", session.source);
    headers.emplace_back("x-forwarded-proto", "https");
    headers.emplace_back("x-forwarded-host", request.host);
    if (request.length) {
      headers.emplace_back("content-length", std::to_string(*request.length));
    } else if (request.chunked || !request.websocket) {
      headers.emplace_back("transfer-encoding", "chunked");
    }
    headers.emplace_back("connection", request.websocket ? "upgrade" : "close");
    if (request.websocket) {
      headers.emplace_back("upgrade", "websocket");
    }
    return headers;
  }

  capy::task<> upload(RequestState &state, Wire &upstream, const Route &route) {
    while (true) {
      const auto data = co_await state.exchange->read_body();
      if (data.empty()) {
        break;
      }
      if (data.size() > UINT64_MAX - state.received) {
        throw Error(413);
      }
      state.received += data.size();
      if (route.max_body_bytes && state.received > route.max_body_bytes) {
        throw Error(413);
      }
      if (state.exchange->request.length && state.received > *state.exchange->request.length) {
        throw Error(400);
      }
      touch(state);
      bytes_received_ += data.size();
      if (state.exchange->request.length) {
        co_await upstream.write(data);
      } else {
        co_await chunk(upstream, data);
      }
    }
    if (state.exchange->request.length && state.received != *state.exchange->request.length) {
      throw Error(400);
    }
    if (!state.exchange->request.length) {
      co_await upstream.write("0\r\n\r\n");
    }
    state.upload_done = true;
    capy::async_event response_finished;
    // The response task completes the exchange, including an early upstream rejection.
    static_cast<void>(co_await response_finished.wait());
  }

  capy::task<Message> response_head(Reader &reader) {
    for (unsigned count = 0; count < 8; ++count) {
      try {
        auto response = parse_head(co_await reader.head(), false);
        if (response.status >= 200 || response.status == 101) {
          co_return response;
        }
      } catch (...) {
        throw Error(502);
      }
    }
    throw Error(502);
  }

  capy::task<> download(RequestState &state, Reader &reader) {
    auto response = co_await response_head(reader);
    if (response.status == 101) {
      throw Error(502);
    }
    state.exchange->request.close = state.exchange->request.close || !state.upload_done;
    auto headers = end_to_end(response.headers);
    state.response_started = true;
    ++responses_[response.status / 100];
    co_await state.exchange->send_head(response.status, std::move(headers));
    if (state.exchange->request.method != "HEAD" && response.status != 204 &&
        response.status != 304) {
      Body body(reader, response, true);
      while (true) {
        auto data = co_await body.read();
        if (data.empty()) {
          break;
        }
        bytes_sent_ += data.size();
        touch(state);
        co_await state.exchange->send_body(std::move(data));
      }
    }
    co_await state.exchange->finish();
    state.finished = true;
  }

  capy::task<> copy(Reader &reader, Wire &writer, bool incoming) {
    while (true) {
      const auto data = co_await reader.read(16384);
      if (data.empty()) {
        co_return;
      }
      if (incoming) {
        bytes_received_ += data.size();
      } else {
        bytes_sent_ += data.size();
      }
      co_await writer.write(data);
    }
  }

  capy::task<> websocket(RequestState &state, Reader &client, Reader &upstream) {
    const auto response = co_await response_head(upstream);
    if (response.status != 101 || !response.websocket ||
        field(response.headers, "sec-websocket-accept") !=
            websocket_accept(field(state.exchange->request.headers, "sec-websocket-key"))) {
      throw Error(502);
    }
    auto headers = end_to_end(response.headers);
    headers.emplace_back("connection", "upgrade");
    headers.emplace_back("upgrade", "websocket");
    state.response_started = true;
    ++responses_[1];
    co_await client.wire.write(serialize(101, headers));
    co_await race(copy(client, upstream.wire, true), copy(upstream, client.wire, false));
    state.finished = true;
    state.exchange->request.close = true;
  }

  capy::task<> proxy(std::shared_ptr<Session> session, std::shared_ptr<Exchange> exchange,
                     Reader *http1_reader) {
    auto state = std::make_shared<RequestState>(context_, next_id_++, exchange);
    state->source = session->source;
    unsigned error_status = 0;
    ++request_count_;
    try {
      validate_request(exchange->request, http1_reader == nullptr);
      state->upload_done = exchange->request.length == 0;
      if (!ready() || session->configuration != configuration_ ||
          requests_.size() >= options_.max_requests ||
          static_cast<std::size_t>(std::count_if(requests_.begin(), requests_.end(),
                                                 [&session](const auto &item) {
                                                   return item.second->source == session->source;
                                                 })) >=
              (options_.max_requests_per_source ? options_.max_requests_per_source
                                                : source_share(options_.max_requests))) {
        throw Error(503);
      }
      if (exchange->request.host != session->sni) {
        throw Error(421);
      }
      const auto &host = session->configuration->hosts.at(session->sni);
      const auto *route = match_route(host, exchange->request.target);
      if (!route) {
        throw Error(404);
      }
      if (route->max_body_bytes && exchange->request.length.value_or(0) > route->max_body_bytes) {
        throw Error(413);
      }
      state->deadline = Clock::now() + std::chrono::seconds(options_.setup_timeout);
      requests_.emplace(state->id, state);
      record(*session, *state, *route);
      const bool secure = route->target.starts_with("https://");
      const auto address =
          tunnel::parse_address(std::string_view(route->target).substr(secure ? 8 : 7));
      co_await race(tunnel::connect(context_, state->upstream, address),
                    setup_deadline(state->deadline));
      if (!ready() || session->configuration != configuration_ || !session->socket.is_open()) {
        throw Error(503);
      }
      Wire upstream(state->upstream, [this, state] {
        if (state->connected) {
          touch(*state);
        }
      });
      if (secure) {
        upstream.client_tls(*route);
        co_await upstream.handshake();
      }
      state->connected = true;
      touch(*state);
      const auto headers = upstream_headers(*session, exchange->request);
      std::string head =
          exchange->request.method + " " + exchange->request.target + " HTTP/1.1\r\n";
      for (const auto &[name, value] : headers) {
        head += name + ": " + value + "\r\n";
      }
      head += "\r\n";
      co_await upstream.write(head);
      Reader reader(upstream);
      if (exchange->request.websocket) {
        if (!http1_reader) {
          throw Error(400);
        }
        co_await websocket(*state, *http1_reader, reader);
      } else {
        if (exchange->request.expect_continue) {
          co_await exchange->send_head(100, {});
        }
        co_await race(upload(*state, upstream, *route), download(*state, reader));
      }
    } catch (const Error &error) {
      error_status = error.status;
    } catch (...) {
      error_status = 502;
    }
    state->upstream.close();
    requests_.erase(state->id);
    if (error_status) {
      ++errors_;
      exchange->request.close = true;
      if (!state->response_started) {
        ++responses_[error_status / 100];
        try {
          co_await exchange->send_head(error_status, {{"content-length", "0"}});
          co_await exchange->finish();
        } catch (...) {
          exchange->abort();
        }
      } else {
        exchange->abort();
      }
    } else if (!state->finished) {
      exchange->abort();
    }
  }

  capy::task<> serve(std::shared_ptr<Session> session) {
    try {
      Wire wire(session->socket, [this, session] {
        if (session->established && !session->reading_headers) {
          session->deadline = Clock::now() + std::chrono::seconds(options_.idle_timeout);
        }
      });
      wire.server_tls(session->configuration);
      co_await wire.handshake();
      if (!session->admission->promote()) {
        ++rejected_;
        throw Error(503);
      }
      session->sni = wire.sni();
      session->established = true;
      session->deadline = Clock::now() + std::chrono::seconds(options_.idle_timeout);
      if (wire.http2()) {
        Http2 h2(wire, context_, [this, session](std::shared_ptr<Exchange> exchange) {
          return proxy(session, std::move(exchange), nullptr);
        });
        co_await h2.run();
      } else {
        Reader reader(wire);
        for (unsigned count = 0; count < 1000 && ready() && session->socket.is_open(); ++count) {
          session->reading_headers = true;
          session->deadline = Clock::now() + std::chrono::seconds(options_.setup_timeout);
          std::optional<Message> message;
          unsigned status = 0;
          try {
            message = parse_head(co_await reader.head(), true);
          } catch (const Error &error) {
            status = error.status;
          }
          if (!message) {
            co_await wire.write(
                serialize(status, {{"content-length", "0"}, {"connection", "close"}}));
            break;
          }
          session->reading_headers = false;
          session->deadline = Clock::now() + std::chrono::seconds(options_.idle_timeout);
          auto exchange = std::make_shared<Http1>(session->socket, reader, std::move(*message));
          co_await proxy(session, exchange, &reader);
          if (exchange->request.close) {
            break;
          }
        }
      }
    } catch (...) {
      ++connection_errors_;
    }
    session->socket.close();
    session->admission.reset();
    sessions_.erase(session->id);
  }

  std::string metrics() const {
    std::string result;
    auto add = [&result](std::string_view name, std::string_view type, std::uint64_t value) {
      const auto key = "zetta_ingress_" + std::string(name);
      result += "# TYPE " + key + " " + std::string(type) + "\n" + key + " " +
                std::to_string(value) + "\n";
    };
    add("ready", "gauge", ready());
    add("connections_active", "gauge", sessions_.size());
    add("requests_active", "gauge", requests_.size());
    add("connections_total", "counter", connections_);
    add("requests_total", "counter", request_count_);
    add("request_errors_total", "counter", errors_);
    add("connection_errors_total", "counter", connection_errors_);
    add("capacity_rejections_total", "counter", rejected_);
    add("timeouts_total", "counter", timeouts_);
    add("request_body_bytes_total", "counter", bytes_received_);
    add("response_body_bytes_total", "counter", bytes_sent_);
    add("reloads_total", "counter", reloads_);
    add("reload_failures_total", "counter", reload_failures_);
    result += "# TYPE zetta_ingress_responses_total counter\n";
    for (unsigned group = 1; group <= 5; ++group) {
      result += "zetta_ingress_responses_total{class=\"" + std::to_string(group) + "xx\"} " +
                std::to_string(responses_[group]) + "\n";
    }
    return result;
  }

  capy::task<> health(std::shared_ptr<Session> session) {
    try {
      Wire wire(session->socket);
      Reader reader(wire);
      const auto request = co_await reader.head();
      unsigned status = 404;
      std::string body;
      if (request.starts_with("GET /healthz HTTP/1.1\r\n")) {
        status = 200;
      } else if (request.starts_with("GET /readyz HTTP/1.1\r\n")) {
        status = ready() ? 200 : 503;
      } else if (request.starts_with("GET /metrics HTTP/1.1\r\n")) {
        status = 200;
        body = metrics();
      }
      co_await wire.write(serialize(status, {{"content-length", std::to_string(body.size())},
                                             {"content-type", "text/plain; version=0.0.4"},
                                             {"connection", "close"}}) +
                          body);
    } catch (...) {
    }
    session->socket.close();
    health_.erase(session->id);
  }

  capy::task<> accept(bool probe) {
    auto &listener = probe ? health_listener_ : listener_;
    while (!stopping) {
      auto session = std::make_shared<Session>(context_, next_id_++);
      auto [error] = co_await listener.accept(session->socket);
      if (error) {
        co_return;
      }
      if (probe) {
        if (health_.size() >= 16) {
          session->socket.close();
          continue;
        }
        session->deadline = Clock::now() + 5s;
        health_.emplace(session->id, session);
        launch(health(session));
      } else {
        ++connections_;
        session->source = tunnel::source_address(session->socket);
        session->admission = admission_.acquire(session->source);
        if (!ready() || !session->admission) {
          ++rejected_;
          session->socket.close();
          continue;
        }
        session->configuration = configuration_;
        session->deadline = Clock::now() + std::chrono::seconds(options_.setup_timeout);
        sessions_.emplace(session->id, session);
        launch(serve(session));
      }
    }
  }

  capy::task<> watch() {
    corosio::timer timer(context_);
    auto next_reload = Clock::now() + 2s;
    while (!stopping) {
      timer.expires_after(100ms);
      auto [error] = co_await timer.wait();
      if (error) {
        break;
      }
      const auto now = Clock::now();
      if (reloading || now >= next_reload) {
        reload();
        next_reload = now + 2s;
      }
      for (const auto &[id, session] : sessions_) {
        if (now >= session->deadline) {
          ++timeouts_;
          session->socket.close();
        }
      }
      for (const auto &[id, request] : requests_) {
        if (now >= request->deadline) {
          ++timeouts_;
          request->upstream.close();
          request->exchange->abort();
        }
      }
      for (const auto &[id, session] : health_) {
        if (now >= session->deadline) {
          session->socket.close();
        }
      }
    }
    stopping = 1;
    listener_.close();
    health_listener_.close();
    close_traffic();
    for (const auto &[id, session] : health_) {
      session->socket.close();
    }
  }

  const Options &options_;
  corosio::io_context context_;
  corosio::tcp_acceptor listener_;
  corosio::tcp_acceptor health_listener_;
  Admission admission_;
  std::shared_ptr<const Configuration> configuration_;
  std::map<std::uint64_t, std::shared_ptr<Session>> sessions_;
  std::map<std::uint64_t, std::shared_ptr<Session>> health_;
  std::map<std::uint64_t, std::shared_ptr<RequestState>> requests_;
  std::ofstream audit_file_;
  std::ostream *audit_ = &std::cout;
  bool audit_ok_ = true;
  bool failed_ = false;
  std::uint64_t next_id_ = 1;
  std::uint64_t connections_ = 0;
  std::uint64_t request_count_ = 0;
  std::uint64_t connection_errors_ = 0;
  std::uint64_t errors_ = 0;
  std::uint64_t rejected_ = 0;
  std::uint64_t timeouts_ = 0;
  std::uint64_t bytes_received_ = 0;
  std::uint64_t bytes_sent_ = 0;
  std::uint64_t reloads_ = 0;
  std::uint64_t reload_failures_ = 0;
  std::array<std::uint64_t, 6> responses_{};
};

} // namespace

int run(const Options &options) {
  stopping = 0;
  reloading = 0;
  std::signal(SIGINT, stop_signal);
  std::signal(SIGTERM, stop_signal);
#ifndef _WIN32
  std::signal(SIGHUP, reload_signal);
  std::signal(SIGPIPE, SIG_IGN);
#endif
  Runtime runtime(options);
  return runtime.run();
}

} // namespace zetta_tunnel::ingress
