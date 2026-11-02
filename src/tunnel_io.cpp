#include "tunnel_io.hpp"

#include <boost/capy/cond.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/wait_type.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <fcntl.h>
#endif

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace zetta_tunnel::tunnel {
namespace {

void require(bool condition) {
  if (!condition) {
    throw transport::Error("TLS configuration failed");
  }
}

Time certificate_time(const ASN1_TIME *value) {
  std::tm result{};
  require(ASN1_TIME_to_tm(value, &result) == 1);
  require(result.tm_year >= 70 && result.tm_year <= 300);
  const auto date = std::chrono::year(result.tm_year + 1900) /
                    std::chrono::month(result.tm_mon + 1) / std::chrono::day(result.tm_mday);
  return std::chrono::sys_days(date) + std::chrono::hours(result.tm_hour) +
         std::chrono::minutes(result.tm_min) + std::chrono::seconds(result.tm_sec);
}

std::error_code tls_error() {
  ERR_clear_error();
  return std::make_error_code(std::errc::protocol_error);
}

using Context = TlsContext;

Context make_context(const transport::TlsFiles &files) {
  Context owner(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  auto *context = owner.get();
  require(context != nullptr);
  require(SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) == 1);
  require(SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) == 1);
  require(SSL_CTX_use_certificate_chain_file(context, files.certificate.string().c_str()) == 1);
  require(SSL_CTX_use_PrivateKey_file(context, files.private_key.string().c_str(),
                                      SSL_FILETYPE_PEM) == 1);
  require(SSL_CTX_check_private_key(context) == 1);
  require(SSL_CTX_load_verify_locations(context, files.certificate_authority.string().c_str(),
                                        nullptr) == 1);
  SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  SSL_CTX_set_verify_depth(context, 6);
  SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_num_tickets(context, 0);
  SSL_CTX_set_options(context, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
  return owner;
}

} // namespace

struct SecureStream::Impl {
  corosio::tcp_socket &socket;
  TlsContext context;
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
  explicit Impl(corosio::tcp_socket &value) : socket(value) {
  }
};

SecureStream::SecureStream(corosio::tcp_socket &socket, TlsContext context, bool server,
                           const std::string &peer_name)
    : impl_(std::make_unique<Impl>(socket)) {
  impl_->context = std::move(context);
  require(impl_->context != nullptr);
  impl_->ssl.reset(SSL_new(impl_->context.get()));
  require(impl_->ssl != nullptr);
  auto *ssl = impl_->ssl.get();
  if (!peer_name.empty()) {
    auto *parameters = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT |
                                                    X509_CHECK_FLAG_NO_WILDCARDS);
    corosio::ipv4_address v4;
    corosio::ipv6_address v6;
    if (!corosio::parse_ipv4_address(peer_name, v4) ||
        !corosio::parse_ipv6_address(peer_name, v6)) {
      require(X509_VERIFY_PARAM_set1_ip_asc(parameters, peer_name.c_str()) == 1);
    } else {
      require(SSL_set1_host(ssl, peer_name.c_str()) == 1);
      if (!server) {
        require(SSL_set_tlsext_host_name(ssl, peer_name.c_str()) == 1);
      }
    }
  } else {
    require(server);
  }
  const auto handle = socket.native_handle();
#ifdef _WIN32
  u_long nonblocking = 1;
  require(ioctlsocket(handle, FIONBIO, &nonblocking) == 0);
#else
  const int flags = fcntl(handle, F_GETFL, 0);
  require(flags >= 0 && fcntl(handle, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
  require(SSL_set_fd(ssl, static_cast<int>(handle)) == 1);
  if (server) {
    SSL_set_accept_state(ssl);
  } else {
    SSL_set_connect_state(ssl);
  }
}

SecureStream::~SecureStream() = default;

capy::io_task<> SecureStream::handshake() {
  while (impl_->socket.is_open()) {
    ERR_clear_error();
    const int result = SSL_do_handshake(impl_->ssl.get());
    if (result == 1) {
      if (SSL_get_verify_result(impl_->ssl.get()) != X509_V_OK ||
          SSL_get0_peer_certificate(impl_->ssl.get()) == nullptr) {
        co_return {tls_error()};
      }
      co_return {};
    }
    const int error = SSL_get_error(impl_->ssl.get(), result);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
      co_return {tls_error()};
    }
    auto [wait_error] = co_await impl_->socket.wait(
        error == SSL_ERROR_WANT_READ ? corosio::wait_type::read : corosio::wait_type::write);
    if (wait_error) {
      co_return {wait_error};
    }
  }
  co_return {std::make_error_code(std::errc::operation_canceled)};
}

capy::io_task<std::size_t> SecureStream::read_some(capy::mutable_buffer buffer) {
  while (impl_->socket.is_open()) {
    ERR_clear_error();
    std::size_t size = 0;
    const int result = SSL_read_ex(impl_->ssl.get(), buffer.data(), buffer.size(), &size);
    if (result == 1) {
      co_return {{}, size};
    }
    const int error = SSL_get_error(impl_->ssl.get(), result);
    if (error == SSL_ERROR_ZERO_RETURN) {
      co_return {{}, 0};
    }
    if (error != SSL_ERROR_WANT_READ) {
      co_return {tls_error(), 0};
    }
    auto [wait_error] = co_await impl_->socket.wait(corosio::wait_type::read);
    if (wait_error) {
      co_return {wait_error, 0};
    }
  }
  co_return {std::make_error_code(std::errc::operation_canceled), 0};
}

capy::io_task<std::size_t> SecureStream::write_some(capy::const_buffer buffer) {
  while (impl_->socket.is_open()) {
    ERR_clear_error();
    std::size_t size = 0;
    const int result = SSL_write_ex(impl_->ssl.get(), buffer.data(), buffer.size(), &size);
    if (result == 1) {
      co_return {{}, size};
    }
    const int error = SSL_get_error(impl_->ssl.get(), result);
    if (error != SSL_ERROR_WANT_WRITE) {
      co_return {tls_error(), 0};
    }
    auto [wait_error] = co_await impl_->socket.wait(corosio::wait_type::write);
    if (wait_error) {
      co_return {wait_error, 0};
    }
  }
  co_return {std::make_error_code(std::errc::operation_canceled), 0};
}

CertificateGrant SecureStream::grant() const {
  auto *certificate = SSL_get0_peer_certificate(impl_->ssl.get());
  require(certificate != nullptr && SSL_get_verify_result(impl_->ssl.get()) == X509_V_OK);
  std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
      static_cast<GENERAL_NAMES *>(
          X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr)),
      GENERAL_NAMES_free);
  if (!names) {
    throw transport::Error("certificate_identity");
  }
  constexpr std::string_view prefix = "urn:orama:tunnel-grant:";
  std::string id;
  for (int index = 0; index < sk_GENERAL_NAME_num(names.get()); ++index) {
    const auto *name = sk_GENERAL_NAME_value(names.get(), index);
    if (name->type != GEN_URI) {
      continue;
    }
    const auto *uri = name->d.uniformResourceIdentifier;
    const std::string_view value(reinterpret_cast<const char *>(ASN1_STRING_get0_data(uri)),
                                 ASN1_STRING_length(uri));
    if (!id.empty() || !value.starts_with(prefix) || !valid_uuid(value.substr(prefix.size()))) {
      throw transport::Error("certificate_identity");
    }
    id = value.substr(prefix.size());
  }
  if (id.empty()) {
    throw transport::Error("certificate_identity");
  }
  const auto expires = certificate_time(X509_get0_notAfter(certificate));
  const auto starts = certificate_time(X509_get0_notBefore(certificate));
  if (expires <= starts || expires - starts > std::chrono::hours(12)) {
    throw transport::Error("certificate_lifetime");
  }
  // The chain OpenSSL verified, leaf first. Only the CAs above the leaf name the issuer; a
  // certificate presented by the peer but not part of the verified path is never considered.
  const auto *chain = SSL_get0_verified_chain(impl_->ssl.get());
  require(chain != nullptr && sk_X509_num(chain) >= 2);
  std::vector<std::string> issuers;
  for (int index = 1; index < sk_X509_num(chain); ++index) {
    issuers.push_back(certificate_sha256(sk_X509_value(chain, index)));
  }
  return {id, expires, std::move(issuers)};
}

std::string certificate_sha256(const X509 *certificate) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int size = 0;
  require(X509_digest(certificate, EVP_sha256(), digest.data(), &size) == 1 && size == 32);
  constexpr char hex[] = "0123456789abcdef";
  std::string value;
  for (unsigned int index = 0; index < size; ++index) {
    value += hex[digest[index] >> 4];
    value += hex[digest[index] & 15];
  }
  return value;
}

bool valid_sha256(std::string_view value) {
  return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}

capy::task<> connect(corosio::io_context &context, corosio::tcp_socket &socket,
                     const Address &address) {
  corosio::resolver resolver(context);
  auto [error, results] = co_await resolver.resolve(address.host, std::to_string(address.port));
  if (error) {
    throw transport::Error("upstream_connect");
  }
  for (const auto &result : results) {
    auto [connect_error] = co_await socket.connect(result.get_endpoint());
    if (!connect_error) {
      co_return;
    }
    socket.close();
  }
  throw transport::Error("upstream_connect");
}

std::string peer_address(const corosio::tcp_socket &socket) {
  const auto endpoint = socket.remote_endpoint();
  const auto host = endpoint.is_v4() ? endpoint.v4_address().to_string()
                                     : "[" + endpoint.v6_address().to_string() + "]";
  return host + ":" + std::to_string(endpoint.port());
}

bool valid_uuid(std::string_view value) {
  if (value.size() != 36) {
    return false;
  }
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (value[index] != '-') {
        return false;
      }
    } else if (!((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return true;
}

TlsContext load_credentials(const transport::TlsFiles &files) {
  return make_context(files);
}

std::string source_address(const corosio::tcp_socket &socket) {
  const auto endpoint = socket.remote_endpoint();
  if (endpoint.is_v4()) {
    return endpoint.v4_address().to_string();
  }
  const auto address = endpoint.v6_address();
  if (address.is_v4_mapped()) {
    const auto bytes = address.to_bytes();
    return corosio::ipv4_address(
               corosio::ipv4_address::bytes_type{bytes[12], bytes[13], bytes[14], bytes[15]})
        .to_string();
  }
  return address.to_string();
}

void validate_credentials(const transport::TlsFiles &files) {
  static_cast<void>(make_context(files));
}

} // namespace zetta_tunnel::tunnel
