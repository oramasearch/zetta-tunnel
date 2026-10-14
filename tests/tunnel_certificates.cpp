#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

template <typename T, auto Free> using Handle = std::unique_ptr<T, decltype(Free)>;
using Key = Handle<EVP_PKEY, EVP_PKEY_free>;
using Cert = Handle<X509, X509_free>;

void require(bool result) {
  if (!result) {
    throw std::runtime_error("certificate fixture failed");
  }
}

void extension(X509 *cert, X509 *issuer, int kind, const std::string &value) {
  X509V3_CTX context{};
  X509V3_set_ctx(&context, issuer, cert, nullptr, nullptr, 0);
  Handle<X509_EXTENSION, X509_EXTENSION_free> entry(
      X509V3_EXT_conf_nid(nullptr, &context, kind, value.c_str()), X509_EXTENSION_free);
  require(entry != nullptr && X509_add_ext(cert, entry.get(), -1) == 1);
}

struct Identity {
  Key key{nullptr, EVP_PKEY_free};
  Cert cert{nullptr, X509_free};
};

Identity issue(const std::filesystem::path &directory, const std::string &name, const Identity *ca,
               const std::string &san, long seconds = 300) {
  Identity identity;
  identity.key.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
  identity.cert.reset(X509_new());
  require(identity.key != nullptr && identity.cert != nullptr);
  auto *cert = identity.cert.get();
  static long serial = 1;
  require(X509_set_version(cert, 2) == 1);
  require(ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++) == 1);
  require(X509_gmtime_adj(X509_getm_notBefore(cert), seconds < 0 ? -7200 : -60) != nullptr);
  require(X509_gmtime_adj(X509_getm_notAfter(cert), seconds) != nullptr);
  require(X509_set_pubkey(cert, identity.key.get()) == 1);
  require(X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                                     reinterpret_cast<const unsigned char *>(name.c_str()), -1, -1,
                                     0) == 1);
  auto *issuer = ca ? ca->cert.get() : cert;
  require(X509_set_issuer_name(cert, X509_get_subject_name(issuer)) == 1);
  extension(cert, issuer, NID_basic_constraints, ca ? "critical,CA:FALSE" : "critical,CA:TRUE");
  extension(cert, issuer, NID_key_usage,
            ca ? "critical,digitalSignature" : "critical,keyCertSign,cRLSign");
  if (ca) {
    extension(cert, issuer, NID_ext_key_usage, "serverAuth,clientAuth");
    extension(cert, issuer, NID_subject_alt_name, san);
  }
  require(X509_sign(cert, ca ? ca->key.get() : identity.key.get(), nullptr) > 0);
  const auto cert_path = (directory / (name + ".pem")).string();
  const auto key_path = (directory / (name + ".key")).string();
  Handle<BIO, BIO_free> cert_file(BIO_new_file(cert_path.c_str(), "w"), BIO_free);
  Handle<BIO, BIO_free> key_file(BIO_new_file(key_path.c_str(), "w"), BIO_free);
  require(cert_file != nullptr && key_file != nullptr);
  require(PEM_write_bio_X509(cert_file.get(), cert) == 1);
  require(PEM_write_bio_PrivateKey(key_file.get(), identity.key.get(), nullptr, nullptr, 0, nullptr,
                                   nullptr) == 1);
  return identity;
}

} // namespace

int main(int argc, char **argv) {
  try {
    require(argc == 3);
    const std::filesystem::path directory(argv[1]);
    const long lifetime = std::stol(argv[2]);
    const std::string id = "11111111-1111-4111-8111-111111111111";
    const auto uri = "URI:urn:orama:tunnel-grant:" + id;
    const auto tunnel_ca = issue(directory, "tunnel-ca", nullptr, "", 86400);
    const auto server_ca = issue(directory, "server-ca", nullptr, "", 86400);
    const auto workload_ca = issue(directory, "workload-ca", nullptr, "", 86400);
    const auto other_ca = issue(directory, "other-ca", nullptr, "", 86400);
    issue(directory, "relay", &server_ca, "DNS:relay.test");
    issue(directory, "relay-workload", &workload_ca, "DNS:relay.workload");
    issue(directory, "endpoint", &workload_ca, "DNS:endpoint." + id);
    issue(directory, "wrong-endpoint", &workload_ca, "DNS:endpoint.other");
    issue(directory, "wrong-workload", &workload_ca, "DNS:untrusted.workload");
    issue(directory, "developer", &tunnel_ca, uri, lifetime);
    issue(directory, "expired", &tunnel_ca, uri, -60);
    issue(directory, "unknown", &tunnel_ca,
          "URI:urn:orama:tunnel-grant:22222222-2222-4222-8222-222222222222");
    issue(directory, "other", &other_ca, uri);
    issue(directory, "no-uri", &tunnel_ca, "DNS:developer.test");
    issue(directory, "multiple-uri", &tunnel_ca, uri + "," + uri);
    issue(directory, "long-lived", &tunnel_ca, uri, 86400);
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
