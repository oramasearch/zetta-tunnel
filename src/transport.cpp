// SPDX-License-Identifier: MIT

#include "zetta_tunnel/transport.hpp"

#include <array>
#include <exception>
#include <limits>
#include <mutex>
#include <optional>
#include <system_error>
#include <utility>

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/read.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/write.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

namespace zetta_tunnel::transport {
namespace {

namespace capy = boost::capy;
namespace corosio = boost::corosio;

[[noreturn]] void throw_error(std::string_view operation,
                              const std::error_code &error) {
  throw Error(std::string(operation) + ": " + error.message());
}

void check_tls_setting(std::string_view operation,
                       const std::error_code &error) {
  if (error) {
    throw_error(operation, error);
  }
}

struct Runtime {
  corosio::io_context context;
  std::mutex mutex;

  template <typename T> T run(capy::task<T> task) {
    const std::lock_guard lock(mutex);
    std::optional<T> result;
    std::exception_ptr exception;
    context.restart();
    capy::run_async(
        context.get_executor(),
        [&result](T value) { result.emplace(std::move(value)); },
        [&exception](std::exception_ptr value) { exception = value; })(
        std::move(task));
    context.run();
    if (exception) {
      std::rethrow_exception(exception);
    }
    if (!result) {
      throw Error("transport operation did not complete");
    }
    return std::move(*result);
  }
};

corosio::tls_context make_backend_context(const TlsFiles &files,
                                          std::string_view expected_peer) {
  corosio::tls_context context;
  check_tls_setting("load certificate", context.use_certificate_file(
                                            files.certificate.string(),
                                            corosio::tls_file_format::pem));
  check_tls_setting("load private key", context.use_private_key_file(
                                            files.private_key.string(),
                                            corosio::tls_file_format::pem));
  check_tls_setting(
      "load certificate authority",
      context.load_verify_file(files.certificate_authority.string()));
  check_tls_setting(
      "require peer certificate",
      context.set_verify_mode(corosio::tls_verify_mode::require_peer));
  check_tls_setting(
      "set minimum TLS version",
      context.set_min_protocol_version(corosio::tls_version::tls_1_3));
  check_tls_setting(
      "set maximum TLS version",
      context.set_max_protocol_version(corosio::tls_version::tls_1_3));
  context.set_hostname(expected_peer);
  return context;
}

std::array<std::byte, 4> encode_size(std::size_t size) {
  const auto value = static_cast<std::uint32_t>(size);
  return {
      static_cast<std::byte>((value >> 24U) & 0xffU),
      static_cast<std::byte>((value >> 16U) & 0xffU),
      static_cast<std::byte>((value >> 8U) & 0xffU),
      static_cast<std::byte>(value & 0xffU),
  };
}

std::size_t decode_size(const std::array<std::byte, 4> &bytes) {
  const auto byte_value = [](std::byte value) {
    return static_cast<std::uint32_t>(std::to_integer<unsigned char>(value));
  };
  return (byte_value(bytes[0]) << 24U) | (byte_value(bytes[1]) << 16U) |
         (byte_value(bytes[2]) << 8U) | byte_value(bytes[3]);
}

} // namespace

struct TlsContext::Impl {
  explicit Impl(TlsFiles value) : files(std::move(value)) {}

  TlsFiles files;
};

TlsContext::TlsContext(TlsFiles files)
    : impl_(std::make_shared<Impl>(std::move(files))) {
  static_cast<void>(make_backend_context(impl_->files, "validation.invalid"));
}

TlsContext::~TlsContext() = default;
TlsContext::TlsContext(const TlsContext &) = default;
TlsContext &TlsContext::operator=(const TlsContext &) = default;
TlsContext::TlsContext(TlsContext &&) noexcept = default;
TlsContext &TlsContext::operator=(TlsContext &&) noexcept = default;

struct Connection::Impl {
  Impl(std::shared_ptr<Runtime> runtime_value,
       std::shared_ptr<corosio::tcp_socket> socket_value,
       std::unique_ptr<corosio::openssl_stream> stream_value)
      : runtime(std::move(runtime_value)), socket(std::move(socket_value)),
        stream(std::move(stream_value)) {}

  std::shared_ptr<Runtime> runtime;
  std::shared_ptr<corosio::tcp_socket> socket;
  std::unique_ptr<corosio::openssl_stream> stream;
  bool open = true;
};

Connection::Connection(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Connection::~Connection() {
  if (impl_ && impl_->socket) {
    impl_->socket->close();
  }
}

Connection::Connection(Connection &&) noexcept = default;
Connection &Connection::operator=(Connection &&) noexcept = default;

void Connection::write_frame(std::span<const std::byte> payload) {
  if (!is_open()) {
    throw Error("write on closed connection");
  }
  if (payload.size() > max_frame_size) {
    throw Error("frame exceeds maximum size");
  }
  const auto header = encode_size(payload.size());
  auto write_task = [this, &header, payload]() -> capy::task<std::error_code> {
    auto [header_error, header_size] = co_await capy::write(
        *impl_->stream, capy::const_buffer(header.data(), header.size()));
    if (header_error) {
      co_return header_error;
    }
    if (header_size != header.size()) {
      co_return std::make_error_code(std::errc::io_error);
    }
    auto [payload_error, payload_size] = co_await capy::write(
        *impl_->stream, capy::const_buffer(payload.data(), payload.size()));
    if (payload_error) {
      co_return payload_error;
    }
    if (payload_size != payload.size()) {
      co_return std::make_error_code(std::errc::io_error);
    }
    co_return std::error_code{};
  };
  const auto error = impl_->runtime->run(write_task());
  if (error) {
    impl_->open = false;
    throw_error("write frame", error);
  }
}

std::vector<std::byte> Connection::read_frame() {
  if (!is_open()) {
    throw Error("read on closed connection");
  }
  std::array<std::byte, 4> header{};
  auto read_header_task = [this, &header]() -> capy::task<std::error_code> {
    auto [error, size] = co_await capy::read(
        *impl_->stream, capy::mutable_buffer(header.data(), header.size()));
    if (error) {
      co_return error;
    }
    if (size != header.size()) {
      co_return std::make_error_code(std::errc::io_error);
    }
    co_return std::error_code{};
  };
  auto error = impl_->runtime->run(read_header_task());
  if (error) {
    impl_->open = false;
    throw_error("read frame header", error);
  }
  const auto size = decode_size(header);
  if (size > max_frame_size) {
    impl_->open = false;
    impl_->socket->close();
    throw Error("peer frame exceeds maximum size");
  }
  std::vector<std::byte> payload(size);
  if (payload.empty()) {
    return payload;
  }
  auto read_payload_task = [this, &payload]() -> capy::task<std::error_code> {
    auto [payload_error, payload_size] = co_await capy::read(
        *impl_->stream, capy::mutable_buffer(payload.data(), payload.size()));
    if (payload_error) {
      co_return payload_error;
    }
    if (payload_size != payload.size()) {
      co_return std::make_error_code(std::errc::io_error);
    }
    co_return std::error_code{};
  };
  error = impl_->runtime->run(read_payload_task());
  if (error) {
    impl_->open = false;
    throw_error("read frame payload", error);
  }
  return payload;
}

void Connection::shutdown() {
  if (!is_open()) {
    return;
  }
  auto shutdown_task = [this]() -> capy::task<std::error_code> {
    auto [error] = co_await impl_->stream->shutdown();
    co_return error;
  };
  const auto error = impl_->runtime->run(shutdown_task());
  impl_->open = false;
  impl_->socket->close();
  if (error && error != capy::cond::stream_truncated) {
    throw_error("TLS shutdown", error);
  }
}

bool Connection::is_open() const noexcept {
  return impl_ && impl_->open && impl_->socket && impl_->socket->is_open();
}

struct Client::Impl {
  Impl(TlsContext value, std::string identity)
      : context(std::move(value)),
        expected_server_identity(std::move(identity)),
        runtime(std::make_shared<Runtime>()) {}

  TlsContext context;
  std::string expected_server_identity;
  std::shared_ptr<Runtime> runtime;
};

Client::Client(TlsContext context, std::string expected_server_identity)
    : impl_(std::make_unique<Impl>(std::move(context),
                                   std::move(expected_server_identity))) {
  if (impl_->expected_server_identity.empty()) {
    throw Error("expected server identity is required");
  }
}

Client::~Client() = default;
Client::Client(Client &&) noexcept = default;
Client &Client::operator=(Client &&) noexcept = default;

Connection Client::connect(std::string_view host, std::uint16_t port) {
  if (host.empty() || port == 0) {
    throw Error("host and port are required");
  }
  auto socket = std::make_shared<corosio::tcp_socket>(impl_->runtime->context);
  auto backend = make_backend_context(impl_->context.impl_->files,
                                      impl_->expected_server_identity);
  std::unique_ptr<corosio::openssl_stream> stream;
  auto connect_task = [this, host = std::string(host), port, &socket, &backend,
                       &stream]() -> capy::task<std::error_code> {
    corosio::resolver resolver(impl_->runtime->context);
    auto [resolve_error, results] =
        co_await resolver.resolve(host, std::to_string(port));
    if (resolve_error) {
      co_return resolve_error;
    }
    std::error_code connect_error =
        std::make_error_code(std::errc::host_unreachable);
    for (const auto &result : results) {
      socket = std::make_shared<corosio::tcp_socket>(impl_->runtime->context);
      auto [error] = co_await socket->connect(result.get_endpoint());
      connect_error = error;
      if (!error) {
        break;
      }
    }
    if (connect_error) {
      co_return connect_error;
    }
    stream = std::make_unique<corosio::openssl_stream>(socket.get(), backend);
    auto [handshake_error] =
        co_await stream->handshake(corosio::tls_stream::client);
    co_return handshake_error;
  };
  const auto error = impl_->runtime->run(connect_task());
  if (error) {
    socket->close();
    throw_error("connect with mutual TLS", error);
  }
  return Connection(std::make_unique<Connection::Impl>(
      impl_->runtime, std::move(socket), std::move(stream)));
}

struct Server::Impl {
  Impl(TlsContext value, std::string identity)
      : context(std::move(value)),
        expected_client_identity(std::move(identity)),
        runtime(std::make_shared<Runtime>()) {}

  TlsContext context;
  std::string expected_client_identity;
  std::shared_ptr<Runtime> runtime;
  std::optional<corosio::tcp_acceptor> acceptor;
};

Server::Server(TlsContext context, std::string expected_client_identity)
    : impl_(std::make_unique<Impl>(std::move(context),
                                   std::move(expected_client_identity))) {
  if (impl_->expected_client_identity.empty()) {
    throw Error("expected client identity is required");
  }
}

Server::~Server() { close(); }

Server::Server(Server &&) noexcept = default;
Server &Server::operator=(Server &&) noexcept = default;

void Server::listen(std::string_view host, std::uint16_t port) {
  corosio::ipv4_address address;
  const auto parse_error = corosio::parse_ipv4_address(host, address);
  if (parse_error) {
    throw_error("parse listen address", parse_error);
  }
  const std::lock_guard lock(impl_->runtime->mutex);
  impl_->acceptor.emplace(impl_->runtime->context);
  impl_->acceptor->open();
  const auto bind_error =
      impl_->acceptor->bind(corosio::endpoint(address, port));
  if (bind_error) {
    impl_->acceptor.reset();
    throw_error("bind listener", bind_error);
  }
  const auto listen_error = impl_->acceptor->listen();
  if (listen_error) {
    impl_->acceptor.reset();
    throw_error("listen", listen_error);
  }
}

std::uint16_t Server::port() const {
  if (!impl_->acceptor || !impl_->acceptor->is_open()) {
    throw Error("server is not listening");
  }
  return impl_->acceptor->local_endpoint().port();
}

Connection Server::accept() {
  if (!impl_->acceptor || !impl_->acceptor->is_open()) {
    throw Error("server is not listening");
  }
  auto socket = std::make_shared<corosio::tcp_socket>(impl_->runtime->context);
  auto backend = make_backend_context(impl_->context.impl_->files,
                                      impl_->expected_client_identity);
  auto stream =
      std::make_unique<corosio::openssl_stream>(socket.get(), backend);
  auto accept_task = [this, &socket, &stream]() -> capy::task<std::error_code> {
    auto [accept_error] = co_await impl_->acceptor->accept(*socket);
    if (accept_error) {
      co_return accept_error;
    }
    auto [handshake_error] =
        co_await stream->handshake(corosio::tls_stream::server);
    co_return handshake_error;
  };
  const auto error = impl_->runtime->run(accept_task());
  if (error) {
    socket->close();
    throw_error("accept with mutual TLS", error);
  }
  return Connection(std::make_unique<Connection::Impl>(
      impl_->runtime, std::move(socket), std::move(stream)));
}

void Server::close() noexcept {
  if (impl_ && impl_->acceptor) {
    impl_->acceptor->close();
    impl_->acceptor.reset();
  }
}

} // namespace zetta_tunnel::transport
