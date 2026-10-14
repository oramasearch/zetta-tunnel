#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#if defined(zetta_tunnel_transport_EXPORTS)
#define ZETTA_TUNNEL_TRANSPORT_EXPORT __declspec(dllexport)
#else
#define ZETTA_TUNNEL_TRANSPORT_EXPORT __declspec(dllimport)
#endif
#else
#define ZETTA_TUNNEL_TRANSPORT_EXPORT __attribute__((visibility("default")))
#endif

namespace zetta_tunnel::transport {

inline constexpr std::size_t max_frame_size = 16U * 1024U * 1024U;

struct TlsFiles {
  std::filesystem::path certificate;
  std::filesystem::path private_key;
  std::filesystem::path certificate_authority;
};

class ZETTA_TUNNEL_TRANSPORT_EXPORT Error : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class ZETTA_TUNNEL_TRANSPORT_EXPORT TlsContext final {
public:
  explicit TlsContext(TlsFiles files);
  ~TlsContext();

  TlsContext(const TlsContext &);
  TlsContext &operator=(const TlsContext &);
  TlsContext(TlsContext &&) noexcept;
  TlsContext &operator=(TlsContext &&) noexcept;

private:
  struct Impl;
  std::shared_ptr<const Impl> impl_;

  friend class Client;
  friend class Server;
};

class ZETTA_TUNNEL_TRANSPORT_EXPORT Connection final {
public:
  ~Connection();

  Connection(Connection &&) noexcept;
  Connection &operator=(Connection &&) noexcept;
  Connection(const Connection &) = delete;
  Connection &operator=(const Connection &) = delete;

  void write_frame(std::span<const std::byte> payload);
  [[nodiscard]] std::vector<std::byte> read_frame();
  void shutdown();
  [[nodiscard]] bool is_open() const noexcept;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  explicit Connection(std::unique_ptr<Impl> impl);

  friend class Client;
  friend class Server;
};

class ZETTA_TUNNEL_TRANSPORT_EXPORT Client final {
public:
  Client(TlsContext context, std::string expected_server_identity);
  ~Client();

  Client(Client &&) noexcept;
  Client &operator=(Client &&) noexcept;
  Client(const Client &) = delete;
  Client &operator=(const Client &) = delete;

  [[nodiscard]] Connection connect(std::string_view host, std::uint16_t port);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class ZETTA_TUNNEL_TRANSPORT_EXPORT Server final {
public:
  Server(TlsContext context, std::string expected_client_identity);
  ~Server();

  Server(Server &&) noexcept;
  Server &operator=(Server &&) noexcept;
  Server(const Server &) = delete;
  Server &operator=(const Server &) = delete;

  void listen(std::string_view host, std::uint16_t port = 0);
  [[nodiscard]] std::uint16_t port() const;
  [[nodiscard]] Connection accept();
  void close() noexcept;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace zetta_tunnel::transport
