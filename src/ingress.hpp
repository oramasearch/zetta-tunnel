#pragma once

#include "tunnel.hpp"

#include <openssl/ssl.h>

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace zetta_tunnel::ingress {

namespace capy = tunnel::capy;
namespace corosio = tunnel::corosio;
using Headers = std::vector<std::pair<std::string, std::string>>;
using TlsContext = std::shared_ptr<SSL_CTX>;
constexpr std::size_t header_limit = 32768;
constexpr std::size_t buffer_limit = 65535;

struct Error : std::runtime_error {
  explicit Error(unsigned value);
  unsigned status;
};

struct Route {
  std::string id;
  std::string path;
  bool exact = false;
  std::string target;
  std::string ca;
  std::string server_name;
  std::uint64_t max_body_bytes = 1048576;
};

struct Host {
  std::string name;
  std::string certificate;
  std::string key;
  std::vector<Route> routes;
  TlsContext context;
};

struct Configuration {
  std::map<std::string, Host> hosts;
  std::string fingerprint;
};

struct Options {
  std::filesystem::path configuration;
  std::string listen = "0.0.0.0:8443";
  std::string health_listen = "127.0.0.1:8080";
  std::string audit = "-";
  std::size_t max_sessions = 128;
  std::size_t max_pending_sessions = 128;
  std::size_t max_pending_per_source = 32;
  std::size_t max_requests = 256;
  std::size_t max_sessions_per_source = 0;
  std::size_t max_requests_per_source = 0;
  unsigned idle_timeout = 60;
  unsigned setup_timeout = 10;
};

struct Message {
  std::string method;
  std::string target;
  std::string host;
  Headers headers;
  unsigned status = 0;
  std::optional<std::uint64_t> length;
  bool chunked = false;
  bool websocket = false;
  bool close = false;
  bool expect_continue = false;
};

std::string lower(std::string_view value);
std::string authority(std::string_view value);
std::string routing_path(std::string_view value);
std::string field(const Headers &headers, std::string_view name);
bool has_token(std::string_view value, std::string_view token);
Message parse_head(std::string_view head, bool request);
void validate_request(Message &message, bool http2);
Headers end_to_end(const Headers &headers);
const Route *match_route(const Host &host, std::string_view target);
Configuration read_configuration(const std::filesystem::path &path);
Options parse_options(std::span<char *> args);
void print_help(std::ostream &output);
int run(const Options &options);
capy::task<> race(capy::task<> first, capy::task<> second);

TlsContext server_context(const Host &host);
TlsContext client_context(const Route &route);

class Wire {
public:
  explicit Wire(corosio::tcp_socket &socket, std::function<void()> activity = {});
  ~Wire();
  void server_tls(std::shared_ptr<const Configuration> configuration);
  void client_tls(const Route &route);
  capy::task<> handshake();
  capy::task<std::size_t> read(char *data, std::size_t size);
  capy::task<> write(std::string_view data);
  std::string sni() const;
  bool http2() const;

private:
  corosio::tcp_socket &socket_;
  std::function<void()> activity_;
  std::shared_ptr<const Configuration> configuration_;
  TlsContext context_;
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl_{nullptr, SSL_free};
  void prepare();
};

class Reader {
public:
  explicit Reader(Wire &wire);
  capy::task<std::string> head();
  capy::task<std::string> line();
  capy::task<std::string> read(std::size_t maximum);
  capy::task<std::string> exact(std::size_t size);
  Wire &wire;

private:
  std::string pending_;
  capy::task<std::string> until(std::string_view delimiter, std::size_t limit);
};

// Decodes one HTTP/1 message incrementally; never stores the whole body.
class Body {
public:
  Body(Reader &reader, const Message &message, bool response = false);
  capy::task<std::string> read();

private:
  Reader &reader_;
  std::uint64_t remaining_ = 0;
  bool chunked_ = false;
  bool eof_delimited_ = false;
  bool chunk_end_ = false;
  bool done_ = false;
};

class Exchange {
public:
  virtual ~Exchange() = default;
  Message request;
  virtual capy::task<std::string> read_body() = 0;
  virtual capy::task<> send_head(unsigned status, Headers headers) = 0;
  virtual capy::task<> send_body(std::string data) = 0;
  virtual capy::task<> finish() = 0;
  virtual void abort() = 0;
};

// The H2 engine owns protocol state; request coroutines own individual exchanges.
class Http2 {
public:
  using Handler = std::function<capy::task<>(std::shared_ptr<Exchange>)>;
  Http2(Wire &wire, corosio::io_context &context, Handler handler);
  ~Http2();
  capy::task<> run();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace zetta_tunnel::ingress
