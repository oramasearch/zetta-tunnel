#pragma once

#include "zetta_tunnel/transport.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <chrono>
#include <memory>
#include <string>

namespace zetta_tunnel::tunnel {

namespace capy = boost::capy;
namespace corosio = boost::corosio;
using Time = std::chrono::system_clock::time_point;

struct Address {
  std::string host;
  std::uint16_t port;
};

struct CertificateGrant {
  std::string id;
  Time expires;
};

// Streaming TLS uses the same TLS 1.3/Corosio stack as the framed API.
// All operations run on one io_context thread, with one reader and one writer.
class SecureStream {
public:
  SecureStream(corosio::tcp_socket &socket, const transport::TlsFiles &files, bool server,
               const std::string &peer_name);
  ~SecureStream();
  SecureStream(const SecureStream &) = delete;
  SecureStream &operator=(const SecureStream &) = delete;

  capy::io_task<> handshake();
  capy::io_task<std::size_t> read_some(capy::mutable_buffer buffer);
  capy::io_task<std::size_t> write_some(capy::const_buffer buffer);
  [[nodiscard]] CertificateGrant grant() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

capy::task<> connect(corosio::io_context &context, corosio::tcp_socket &socket,
                     const Address &address);
std::string peer_address(const corosio::tcp_socket &socket);
bool valid_uuid(std::string_view value);
void validate_credentials(const transport::TlsFiles &files);

} // namespace zetta_tunnel::tunnel
