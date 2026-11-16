// SPDX-License-Identifier: MIT

#include "zetta_tunnel/transport.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <future>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <chrono>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

namespace {

namespace transport = zetta_tunnel::transport;
namespace capy = boost::capy;
namespace corosio = boost::corosio;

template <typename T, auto Deleter> using OpenSslPtr = std::unique_ptr<T, decltype(Deleter)>;

using Key = OpenSslPtr<EVP_PKEY, EVP_PKEY_free>;
using Certificate = OpenSslPtr<X509, X509_free>;
using Extension = OpenSslPtr<X509_EXTENSION, X509_EXTENSION_free>;
using Bio = OpenSslPtr<BIO, BIO_free>;

[[noreturn]] void fail(std::string_view message) {
  throw std::runtime_error(std::string(message));
}

void require(bool condition, std::string_view message) {
  if (!condition) {
    fail(message);
  }
}

Key make_key() {
  OpenSslPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(
      EVP_PKEY_CTX_new_from_name(nullptr, "ED25519", nullptr), EVP_PKEY_CTX_free);
  require(static_cast<bool>(context), "create key context");
  require(EVP_PKEY_keygen_init(context.get()) == 1, "initialize key generation");
  EVP_PKEY *raw_key = nullptr;
  require(EVP_PKEY_generate(context.get(), &raw_key) == 1, "generate key");
  return Key(raw_key, EVP_PKEY_free);
}

void set_name(X509_NAME *name, std::string_view common_name) {
  require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                     reinterpret_cast<const unsigned char *>(common_name.data()),
                                     static_cast<int>(common_name.size()), -1, 0) == 1,
          "set certificate common name");
}

void add_extension(X509 *certificate, X509 *issuer, int identifier, std::string value) {
  X509V3_CTX context{};
  X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
  Extension extension(X509V3_EXT_conf_nid(nullptr, &context, identifier, value.data()),
                      X509_EXTENSION_free);
  require(static_cast<bool>(extension), "create certificate extension");
  require(X509_add_ext(certificate, extension.get(), -1) == 1, "add certificate extension");
}

Certificate make_ca(EVP_PKEY *key, long serial) {
  Certificate certificate(X509_new(), X509_free);
  require(static_cast<bool>(certificate), "create CA certificate");
  require(X509_set_version(certificate.get(), 2) == 1, "set CA version");
  require(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) == 1, "set CA serial");
  require(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) != nullptr,
          "set CA start time");
  require(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400) != nullptr,
          "set CA end time");
  require(X509_set_pubkey(certificate.get(), key) == 1, "set CA public key");
  set_name(X509_get_subject_name(certificate.get()), "zetta-tunnel-test-ca");
  require(X509_set_issuer_name(certificate.get(), X509_get_subject_name(certificate.get())) == 1,
          "set CA issuer");
  add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
  add_extension(certificate.get(), certificate.get(), NID_key_usage,
                "critical,keyCertSign,cRLSign");
  require(X509_sign(certificate.get(), key, nullptr) > 0, "sign CA certificate");
  return certificate;
}

Certificate make_identity(EVP_PKEY *key, X509 *ca, EVP_PKEY *ca_key, std::string_view identity,
                          long serial, bool expired = false) {
  Certificate certificate(X509_new(), X509_free);
  require(static_cast<bool>(certificate), "create identity certificate");
  require(X509_set_version(certificate.get(), 2) == 1, "set identity version");
  require(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) == 1,
          "set identity serial");
  const long start = expired ? -7200 : -60;
  const long end = expired ? -3600 : 86400;
  require(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), start) != nullptr,
          "set identity start time");
  require(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), end) != nullptr,
          "set identity end time");
  require(X509_set_pubkey(certificate.get(), key) == 1, "set identity public key");
  set_name(X509_get_subject_name(certificate.get()), identity);
  require(X509_set_issuer_name(certificate.get(), X509_get_subject_name(ca)) == 1,
          "set identity issuer");
  add_extension(certificate.get(), ca, NID_basic_constraints, "critical,CA:FALSE");
  add_extension(certificate.get(), ca, NID_key_usage, "critical,digitalSignature");
  add_extension(certificate.get(), ca, NID_ext_key_usage, "serverAuth,clientAuth");
  add_extension(certificate.get(), ca, NID_subject_alt_name, "DNS:" + std::string(identity));
  require(X509_sign(certificate.get(), ca_key, nullptr) > 0, "sign identity certificate");
  return certificate;
}

void write_key(const std::filesystem::path &path, EVP_PKEY *key) {
  Bio output(BIO_new_file(path.string().c_str(), "w"), BIO_free);
  require(static_cast<bool>(output), "open private key output");
  require(PEM_write_bio_PrivateKey(output.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
          "write private key");
}

void write_certificate(const std::filesystem::path &path, X509 *certificate) {
  Bio output(BIO_new_file(path.string().c_str(), "w"), BIO_free);
  require(static_cast<bool>(output), "open certificate output");
  require(PEM_write_bio_X509(output.get(), certificate) == 1, "write certificate");
}

struct Credentials {
  std::filesystem::path certificate;
  std::filesystem::path key;
};

class Fixture {
public:
  Fixture() {
    // Keep fixtures inside the build directory on every supported platform.
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    directory_ = std::filesystem::current_path() / ("transport-test-" + std::to_string(nonce));
    require(std::filesystem::create_directory(directory_), "create temporary directory");

    ca_key_ = make_key();
    ca_ = make_ca(ca_key_.get(), 1);
    other_ca_key_ = make_key();
    other_ca_ = make_ca(other_ca_key_.get(), 2);

    ca_path_ = directory_ / "ca.pem";
    other_ca_path_ = directory_ / "other-ca.pem";
    write_certificate(ca_path_, ca_.get());
    write_certificate(other_ca_path_, other_ca_.get());
    server_ = make_credentials("server", "server.zetta", ca_.get(), ca_key_.get(), 10, false);
    client_ = make_credentials("client", "client.zetta", ca_.get(), ca_key_.get(), 11, false);
    other_client_ = make_credentials("other-client", "client.zetta", other_ca_.get(),
                                     other_ca_key_.get(), 12, false);
    expired_client_ =
        make_credentials("expired-client", "client.zetta", ca_.get(), ca_key_.get(), 13, true);
  }

  ~Fixture() {
    std::error_code ignored;
    std::filesystem::remove_all(directory_, ignored);
  }

  transport::TlsContext server_context() const {
    return transport::TlsContext({server_.certificate, server_.key, ca_path_});
  }

  transport::TlsContext client_context() const {
    return transport::TlsContext({client_.certificate, client_.key, ca_path_});
  }

  transport::TlsContext other_ca_client_context() const {
    return transport::TlsContext({other_client_.certificate, other_client_.key, ca_path_});
  }

  transport::TlsContext expired_client_context() const {
    return transport::TlsContext({expired_client_.certificate, expired_client_.key, ca_path_});
  }

  const std::filesystem::path &ca_path() const {
    return ca_path_;
  }

private:
  Credentials make_credentials(std::string_view prefix, std::string_view identity, X509 *ca,
                               EVP_PKEY *ca_key, long serial, bool expired) {
    auto key = make_key();
    auto certificate = make_identity(key.get(), ca, ca_key, identity, serial, expired);
    Credentials result{
        .certificate = directory_ / (std::string(prefix) + "-cert.pem"),
        .key = directory_ / (std::string(prefix) + "-key.pem"),
    };
    write_certificate(result.certificate, certificate.get());
    write_key(result.key, key.get());
    return result;
  }

  std::filesystem::path directory_;
  Key ca_key_{nullptr, EVP_PKEY_free};
  Certificate ca_{nullptr, X509_free};
  Key other_ca_key_{nullptr, EVP_PKEY_free};
  Certificate other_ca_{nullptr, X509_free};
  std::filesystem::path ca_path_;
  std::filesystem::path other_ca_path_;
  Credentials server_;
  Credentials client_;
  Credentials other_client_;
  Credentials expired_client_;
};

std::vector<std::byte> bytes(std::string_view value) {
  const auto *first = reinterpret_cast<const std::byte *>(value.data());
  return std::vector<std::byte>(first, first + value.size());
}

bool server_refuses(transport::Server &server) {
  try {
    static_cast<void>(server.accept());
    return false;
  } catch (const transport::Error &) {
    return true;
  }
}

void attempt_client_data(transport::Client &client, std::uint16_t port) {
  try {
    auto connection = client.connect("127.0.0.1", port);
    connection.write_frame(bytes("must not cross"));
  } catch (const transport::Error &) {
  }
}

void test_exchange(const Fixture &fixture) {
  transport::Server server(fixture.server_context(), "client.zetta");
  server.listen("127.0.0.1");
  const std::vector<std::byte> request = {
      std::byte{'z'},
      std::byte{0},
      std::byte{0xff},
      std::byte{'t'},
  };
  constexpr char response_data[] = "arbitrary response\0with zero";
  const auto response = bytes(std::string_view(response_data, sizeof(response_data) - 1));
  auto server_result = std::async(std::launch::async, [&]() {
    auto connection = server.accept();
    require(connection.read_frame() == request, "server received request");
    connection.write_frame(response);
    connection.shutdown();
  });

  transport::Client client(fixture.client_context(), "server.zetta");
  auto connection = client.connect("127.0.0.1", server.port());
  connection.write_frame(request);
  require(connection.read_frame() == response, "client received response");
  connection.shutdown();
  server_result.get();
}

void test_refused_client(transport::Server &server, transport::Client &client) {
  server.listen("127.0.0.1");
  auto server_result = std::async(std::launch::async, [&]() {
    return server_refuses(server);
  });
  attempt_client_data(client, server.port());
  require(server_result.get(), "server refused peer before application data");
}

void test_other_ca(const Fixture &fixture) {
  transport::Server server(fixture.server_context(), "client.zetta");
  transport::Client client(fixture.other_ca_client_context(), "server.zetta");
  test_refused_client(server, client);
}

void test_expired_certificate(const Fixture &fixture) {
  transport::Server server(fixture.server_context(), "client.zetta");
  transport::Client client(fixture.expired_client_context(), "server.zetta");
  test_refused_client(server, client);
}

void test_wrong_identity(const Fixture &fixture) {
  transport::Server server(fixture.server_context(), "another-client.zetta");
  transport::Client client(fixture.client_context(), "server.zetta");
  test_refused_client(server, client);
}

void connect_without_certificate(const std::filesystem::path &ca_path, std::uint16_t port) {
  corosio::io_context context;
  corosio::tcp_socket socket(context);
  corosio::tls_context tls;
  require(!tls.load_verify_file(ca_path.string()), "load attacker CA");
  require(!tls.set_verify_mode(corosio::tls_verify_mode::require_peer),
          "set attacker verification");
  require(!tls.set_min_protocol_version(corosio::tls_version::tls_1_3), "set attacker TLS minimum");
  require(!tls.set_max_protocol_version(corosio::tls_version::tls_1_3), "set attacker TLS maximum");
  tls.set_hostname("server.zetta");
  corosio::openssl_stream stream(&socket, tls);
  std::exception_ptr exception;
  auto task = [&]() -> capy::task<> {
    auto [connect_error] =
        co_await socket.connect(corosio::endpoint(corosio::ipv4_address::loopback(), port));
    if (connect_error) {
      co_return;
    }
    auto [handshake_error] = co_await stream.handshake(corosio::tls_stream::client);
    static_cast<void>(handshake_error);
    socket.close();
  };
  capy::run_async(
      context.get_executor(),
      []() {
      },
      [&exception](std::exception_ptr value) {
        exception = value;
      })(task());
  context.run();
  if (exception) {
    std::rethrow_exception(exception);
  }
}

void test_no_certificate(const Fixture &fixture) {
  transport::Server server(fixture.server_context(), "client.zetta");
  server.listen("127.0.0.1");
  auto server_result = std::async(std::launch::async, [&]() {
    return server_refuses(server);
  });
  connect_without_certificate(fixture.ca_path(), server.port());
  require(server_result.get(), "server refused certificate-less peer");
}

} // namespace

int main(int argc, char **argv) {
  try {
    require(argc == 2, "one test case argument is required");
    Fixture fixture;
    const std::string_view test_case(argv[1]);
    if (test_case == "exchange") {
      test_exchange(fixture);
    } else if (test_case == "no_certificate") {
      test_no_certificate(fixture);
    } else if (test_case == "other_ca") {
      test_other_ca(fixture);
    } else if (test_case == "expired_certificate") {
      test_expired_certificate(fixture);
    } else if (test_case == "wrong_identity") {
      test_wrong_identity(fixture);
    } else {
      fail("unknown test case");
    }
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "transport test failed: " << error.what() << '\n';
    return 1;
  }
}
