// SPDX-License-Identifier: MIT

#include "ingress.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/corosio/wait_type.hpp>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <fcntl.h>
#endif

namespace zetta_tunnel::ingress {
namespace {

void require(bool condition) {
  if (!condition) {
    ERR_clear_error();
    throw Error(502);
  }
}

int select_host(SSL *ssl, int *alert, void *) noexcept {
  try {
    const auto *configuration = static_cast<const Configuration *>(SSL_get_app_data(ssl));
    const auto *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (configuration && name) {
      const auto found = configuration->hosts.find(lower(name));
      if (found != configuration->hosts.end() &&
          SSL_set_SSL_CTX(ssl, found->second.context.get())) {
        // The connection was made from another host's context: take this host's client
        // certificate requirement too (zetta-tunnel#34).
        auto *selected = found->second.context.get();
        SSL_set_verify(ssl, SSL_CTX_get_verify_mode(selected), nullptr);
        SSL_set_verify_depth(ssl, SSL_CTX_get_verify_depth(selected));
        return SSL_TLSEXT_ERR_OK;
      }
    }
  } catch (...) {
  }
  *alert = SSL_AD_UNRECOGNIZED_NAME;
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int select_protocol(SSL *, const unsigned char **out, unsigned char *out_length,
                    const unsigned char *input, unsigned input_length, void *) noexcept {
  static constexpr unsigned char protocols[] = {2,   'h', '2', 8,   'h', 't',
                                                't', 'p', '/', '1', '.', '1'};
  unsigned char *selected = nullptr;
  if (SSL_select_next_proto(&selected, out_length, protocols, sizeof(protocols), input,
                            input_length) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  *out = selected;
  return SSL_TLSEXT_ERR_OK;
}

TlsContext context() {
  TlsContext result(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  require(result != nullptr);
  require(SSL_CTX_set_min_proto_version(result.get(), TLS1_3_VERSION) == 1);
  require(SSL_CTX_set_max_proto_version(result.get(), TLS1_3_VERSION) == 1);
  SSL_CTX_set_options(result.get(), SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  SSL_CTX_set_session_cache_mode(result.get(), SSL_SESS_CACHE_OFF);
  SSL_CTX_set_num_tickets(result.get(), 0);
  SSL_CTX_set_max_early_data(result.get(), 0);
  return result;
}

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

} // namespace

TlsContext server_context(const Host &host) {
  auto result = context();
  require(SSL_CTX_use_certificate_chain_file(result.get(), host.certificate.c_str()) == 1);
  require(SSL_CTX_use_PrivateKey_file(result.get(), host.key.c_str(), SSL_FILETYPE_PEM) == 1);
  require(SSL_CTX_check_private_key(result.get()) == 1);
  auto *certificate = SSL_CTX_get0_certificate(result.get());
  require(certificate && X509_cmp_current_time(X509_get0_notBefore(certificate)) < 0 &&
          X509_cmp_current_time(X509_get0_notAfter(certificate)) > 0);
  require(
      X509_check_host(certificate, host.name.c_str(), host.name.size(),
                      X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
                      nullptr) == 1);
  require(X509_check_purpose(certificate, X509_PURPOSE_SSL_SERVER, 0) == 1);
  if (host.client_ca.empty()) {
    // Public ingress authenticates the server; workload mutual TLS remains in the other roles.
    SSL_CTX_set_verify(result.get(), SSL_VERIFY_NONE, nullptr);
  } else {
    // An origin host: only a caller with a certificate from its client CA completes the handshake
    // (zetta-tunnel#34).
    require(SSL_CTX_load_verify_locations(result.get(), host.client_ca.c_str(), nullptr) == 1);
    auto *names = SSL_load_client_CA_file(host.client_ca.c_str());
    require(names != nullptr);
    SSL_CTX_set_client_CA_list(result.get(), names);
    SSL_CTX_set_verify(result.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_set_verify_depth(result.get(), 6);
  }
  SSL_CTX_set_tlsext_servername_callback(result.get(), select_host);
  SSL_CTX_set_alpn_select_cb(result.get(), select_protocol, nullptr);
  return result;
}

TlsContext client_context(const Route &route) {
  auto result = context();
  require(SSL_CTX_load_verify_locations(result.get(), route.ca.c_str(), nullptr) == 1);
  SSL_CTX_set_verify(result.get(), SSL_VERIFY_PEER, nullptr);
  SSL_CTX_set_verify_depth(result.get(), 6);
  return result;
}

Wire::Wire(corosio::tcp_socket &socket, std::function<void()> activity)
    : socket_(socket), activity_(std::move(activity)) {
}

Wire::~Wire() = default;

void Wire::prepare() {
  ssl_.reset(SSL_new(context_.get()));
  require(ssl_ != nullptr);
  const auto handle = socket_.native_handle();
#ifdef _WIN32
  u_long nonblocking = 1;
  require(ioctlsocket(handle, FIONBIO, &nonblocking) == 0);
#else
  const int flags = fcntl(handle, F_GETFL, 0);
  require(flags >= 0 && fcntl(handle, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
  require(SSL_set_fd(ssl_.get(), static_cast<int>(handle)) == 1);
}

void Wire::server_tls(std::shared_ptr<const Configuration> configuration) {
  configuration_ = std::move(configuration);
  context_ = configuration_->hosts.begin()->second.context;
  prepare();
  SSL_set_app_data(ssl_.get(), const_cast<Configuration *>(configuration_.get()));
  SSL_set_accept_state(ssl_.get());
}

void Wire::client_tls(const Route &route) {
  context_ = client_context(route);
  prepare();
  X509_VERIFY_PARAM_set_hostflags(SSL_get0_param(ssl_.get()), X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
  require(SSL_set1_host(ssl_.get(), route.server_name.c_str()) == 1);
  require(SSL_set_tlsext_host_name(ssl_.get(), route.server_name.c_str()) == 1);
  static constexpr unsigned char protocol[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  require(SSL_set_alpn_protos(ssl_.get(), protocol, sizeof(protocol)) == 0);
  SSL_set_connect_state(ssl_.get());
}

capy::task<> Wire::handshake() {
  const auto stop = co_await capy::this_coro::stop_token;
  while (socket_.is_open()) {
    require(!stop.stop_requested());
    ERR_clear_error();
    const int result = SSL_do_handshake(ssl_.get());
    if (result == 1) {
      if (!configuration_) {
        require(SSL_get_verify_result(ssl_.get()) == X509_V_OK &&
                SSL_get0_peer_certificate(ssl_.get()));
      }
      co_return;
    }
    const int error = SSL_get_error(ssl_.get(), result);
    require(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
    auto [wait_error] = co_await socket_.wait(
        error == SSL_ERROR_WANT_READ ? corosio::wait_type::read : corosio::wait_type::write);
    require(!wait_error);
  }
  throw Error(502);
}

capy::task<std::size_t> Wire::read(char *data, std::size_t size) {
  const auto stop = co_await capy::this_coro::stop_token;
  while (socket_.is_open()) {
    require(!stop.stop_requested());
    std::size_t received = 0;
    if (!ssl_) {
      auto [error, count] = co_await socket_.read_some(capy::mutable_buffer(data, size));
      require(!error || error == capy::cond::eof);
      if (count == 0) {
        co_return 0;
      }
      received = count;
    } else {
      ERR_clear_error();
      const int result = SSL_read_ex(ssl_.get(), data, size, &received);
      if (result != 1) {
        const int error = SSL_get_error(ssl_.get(), result);
        if (error == SSL_ERROR_ZERO_RETURN) {
          co_return 0;
        }
        require(error == SSL_ERROR_WANT_READ);
        auto [wait_error] = co_await socket_.wait(corosio::wait_type::read);
        require(!wait_error);
        continue;
      }
    }
    if (activity_) {
      activity_();
    }
    co_await Yield{};
    co_return received;
  }
  throw Error(502);
}

capy::task<> Wire::write(std::string_view data) {
  const auto stop = co_await capy::this_coro::stop_token;
  while (!data.empty() && socket_.is_open()) {
    require(!stop.stop_requested());
    std::size_t sent = 0;
    if (!ssl_) {
      auto [error, count] =
          co_await socket_.write_some(capy::const_buffer(data.data(), data.size()));
      require(!error && count > 0);
      sent = count;
    } else {
      ERR_clear_error();
      const int result = SSL_write_ex(ssl_.get(), data.data(), data.size(), &sent);
      if (result != 1) {
        const int error = SSL_get_error(ssl_.get(), result);
        require(error == SSL_ERROR_WANT_WRITE);
        auto [wait_error] = co_await socket_.wait(corosio::wait_type::write);
        require(!wait_error);
        continue;
      }
    }
    data.remove_prefix(sent);
    if (activity_) {
      activity_();
    }
    co_await Yield{};
  }
  require(data.empty());
}

std::string Wire::sni() const {
  const auto *name = SSL_get_servername(ssl_.get(), TLSEXT_NAMETYPE_host_name);
  return name ? lower(name) : "";
}

bool Wire::client_verified() const {
  return ssl_ && SSL_get0_peer_certificate(ssl_.get()) != nullptr &&
         SSL_get_verify_result(ssl_.get()) == X509_V_OK;
}

bool Wire::http2() const {
  const unsigned char *protocol = nullptr;
  unsigned size = 0;
  SSL_get0_alpn_selected(ssl_.get(), &protocol, &size);
  return size == 2 && std::string_view(reinterpret_cast<const char *>(protocol), size) == "h2";
}

} // namespace zetta_tunnel::ingress
