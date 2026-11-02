#include "mesh.hpp"
#include "mesh_netlink.hpp"

#include "peer.hpp"
#include "tunnel.hpp"

#include <nlohmann/json.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/nsfs.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace zetta_tunnel::mesh {
namespace {

using namespace std::chrono_literals;
using netlink::bypass_mark;
using netlink::inbound_port;
using netlink::outbound_port;
constexpr std::size_t preface_limit = 512;
volatile std::sig_atomic_t stopping = 0;
volatile std::sig_atomic_t reloading = 0;

class FileDescriptor {
public:
  explicit FileDescriptor(int value = -1) : value_(value) {
  }

  ~FileDescriptor() {
    reset();
  }

  FileDescriptor(const FileDescriptor &) = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;

  FileDescriptor(FileDescriptor &&other) noexcept : value_(other.release()) {
  }

  FileDescriptor &operator=(FileDescriptor &&other) noexcept {
    reset(other.release());
    return *this;
  }

  int get() const {
    return value_;
  }

  explicit operator bool() const {
    return value_ >= 0;
  }

  int release() {
    const int result = value_;
    value_ = -1;
    return result;
  }

  void reset(int value = -1) {
    if (value_ >= 0) {
      ::close(value_);
    }
    value_ = value;
  }

private:
  int value_;
};

[[noreturn]] void system_error(std::string_view operation) {
  const auto code = errno;
  throw std::runtime_error(std::string(operation) + ": errno=" + std::to_string(code) + " (" +
                           std::strerror(code) + ")");
}

void signal_stop(int) {
  stopping = 1;
}

void signal_reload(int) {
  reloading = 1;
}

// A generation owns one verified descriptor; process paths are never used by sessions.
class PinnedNamespace {
public:
  explicit PinnedNamespace(const Workload &workload) {
    const auto &path = workload.network_namespace;
    const auto process_path = path.parent_path().parent_path();
    const auto pid = process_path.filename().string();
    if (path.filename() != "net" || path.parent_path().filename() != "ns" || pid.empty() ||
        pid.front() == '0' || pid.find_first_not_of("0123456789") != std::string::npos) {
      throw std::runtime_error("workload namespace must name a numeric process ns/net");
    }
    FileDescriptor process(
        ::open(process_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!process) {
      system_error("open workload process directory");
    }
    verify_pod(process.get(), workload.pod_uid);
    target_.reset(::openat(process.get(), "ns/net", O_RDONLY | O_CLOEXEC));
    if (!target_) {
      system_error("open workload network namespace");
    }
    struct stat status{};
    if (::fstat(target_.get(), &status) != 0) {
      system_error("stat workload network namespace");
    }
    if (static_cast<std::uint64_t>(status.st_ino) != workload.network_namespace_inode ||
        ::ioctl(target_.get(), NS_GET_NSTYPE) != CLONE_NEWNET) {
      throw std::runtime_error("workload network namespace identity changed or is not a netns");
    }
    verify_pod(process.get(), workload.pod_uid);
  }

  int get() const {
    return target_.get();
  }

private:
  static void verify_pod(int process, const std::string &uid) {
    FileDescriptor cgroup(::openat(process, "cgroup", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (!cgroup) {
      system_error("open workload process cgroup");
    }
    constexpr std::size_t limit = 65536;
    std::string data;
    std::array<char, 4096> buffer{};
    while (true) {
      const auto size = ::read(cgroup.get(), buffer.data(), buffer.size());
      if (size < 0) {
        if (errno == EINTR) {
          continue;
        }
        system_error("read workload process cgroup");
      }
      if (size == 0) {
        break;
      }
      data.append(buffer.data(), static_cast<std::size_t>(size));
      if (data.size() > limit) {
        throw std::runtime_error("workload process cgroup exceeds limit");
      }
    }
    auto systemd_uid = uid;
    std::ranges::replace(systemd_uid, '-', '_');
    std::istringstream lines(data);
    std::string line;
    bool matched = false;
    while (std::getline(lines, line)) {
      const auto first = line.find(':');
      const auto second = first == std::string::npos ? first : line.find(':', first + 1);
      if (second == std::string::npos || second + 1 == line.size() || line[second + 1] != '/') {
        throw std::runtime_error("invalid workload process cgroup");
      }
      std::istringstream components(line.substr(second + 1));
      std::string component;
      while (std::getline(components, component, '/')) {
        const bool pod_component =
            component.starts_with("pod") || component.find("-pod") != std::string::npos;
        if (!pod_component) {
          continue;
        }
        if (component == "pod" + uid || component == "kubepods-pod" + systemd_uid + ".slice" ||
            component == "kubepods-burstable-pod" + systemd_uid + ".slice" ||
            component == "kubepods-besteffort-pod" + systemd_uid + ".slice") {
          matched = true;
        } else {
          // A different pod marker, including a UID prefix, is never membership proof.
          throw std::runtime_error("workload process pod identity changed");
        }
      }
    }
    if (!matched) {
      throw std::runtime_error("workload process pod identity changed");
    }
  }

  FileDescriptor target_;
};

class NetworkNamespace {
public:
  explicit NetworkNamespace(const PinnedNamespace &target) {
    original_.reset(::open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC));
    if (!original_) {
      system_error("open current thread network namespace");
    }
    if (::setns(target.get(), CLONE_NEWNET) != 0) {
      system_error("enter workload network namespace");
    }
  }

  ~NetworkNamespace() {
    if (original_ && ::setns(original_.get(), CLONE_NEWNET) != 0) {
      const auto code = errno;
      std::fprintf(stderr,
                   "zetta-tunnel: restore thread network namespace: errno=%d (%s); terminating\n",
                   code, std::strerror(code));
      std::terminate();
    }
  }

  NetworkNamespace(const NetworkNamespace &) = delete;
  NetworkNamespace &operator=(const NetworkNamespace &) = delete;

private:
  FileDescriptor original_;
};

void send_request(int socket, std::span<const std::byte> bytes, std::string_view operation) {
  sockaddr_nl kernel{};
  kernel.nl_family = AF_NETLINK;
  const auto sent = ::sendto(socket, bytes.data(), bytes.size(), 0,
                             reinterpret_cast<const sockaddr *>(&kernel), sizeof(kernel));
  if (sent < 0) {
    system_error(operation);
  }
  if (static_cast<std::size_t>(sent) != bytes.size()) {
    throw std::runtime_error(std::string(operation) + ": short netlink datagram");
  }
}

void receive_replies(int socket, netlink::Replies &replies) {
  const auto deadline = std::chrono::steady_clock::now() + 3s;
  std::array<std::byte, 16384> buffer{};
  while (!replies.complete()) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) {
      throw std::runtime_error(
          "nftables acknowledgement timeout: errno=" + std::to_string(ETIMEDOUT) + " (" +
          std::strerror(ETIMEDOUT) + "); pending: " + replies.pending());
    }
    pollfd event{socket, POLLIN, 0};
    const auto ready = ::poll(&event, 1, static_cast<int>(remaining.count()));
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      system_error("poll nftables acknowledgement");
    }
    if (ready == 0) {
      continue;
    }
    sockaddr_nl sender{};
    iovec iov{buffer.data(), buffer.size()};
    msghdr message{};
    message.msg_name = &sender;
    message.msg_namelen = sizeof(sender);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    const auto size = ::recvmsg(socket, &message, MSG_DONTWAIT);
    if (size < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        continue;
      }
      system_error("receive nftables acknowledgement");
    }
    if ((message.msg_flags & MSG_TRUNC) != 0) {
      throw std::runtime_error("truncated nftables acknowledgement datagram");
    }
    if (message.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK ||
        sender.nl_pid != 0) {
      throw std::runtime_error("nftables acknowledgement did not come from the kernel");
    }
    replies.consume(std::span(buffer).first(static_cast<std::size_t>(size)));
  }
}

bool table_exists(int socket) {
  const auto query = netlink::table_query();
  netlink::Replies replies(std::span(&query, 1), true);
  send_request(socket, query.bytes, "send nftables table lookup");
  receive_replies(socket, replies);
  return replies.table_present();
}

void install_capture(const PinnedNamespace &path) {
  NetworkNamespace network_namespace(path);
  FileDescriptor socket(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER));
  if (!socket) {
    system_error("open nftables netlink socket");
  }
  sockaddr_nl local{};
  local.nl_family = AF_NETLINK;
  if (::bind(socket.get(), reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
    system_error("bind nftables netlink socket");
  }
  const int enabled = 1;
  if (::setsockopt(socket.get(), SOL_NETLINK, NETLINK_EXT_ACK, &enabled, sizeof(enabled)) != 0 &&
      errno != ENOPROTOOPT) {
    system_error("enable nftables extended acknowledgements");
  }
  if (table_exists(socket.get())) {
    return;
  }
  const auto batch = netlink::capture_batch();
  netlink::Replies replies(batch.requests);
  // NFNL_MSG_BATCH_BEGIN, every mutation and NFNL_MSG_BATCH_END must share one datagram.
  send_request(socket.get(), batch.bytes, "send nftables capture batch");
  receive_replies(socket.get(), replies);
}

sockaddr_in parse_ipv4(std::string_view value) {
  const auto address = tunnel::parse_address(value);
  sockaddr_in result{};
  result.sin_family = AF_INET;
  result.sin_port = htons(address.port);
  if (::inet_pton(AF_INET, address.host.c_str(), &result.sin_addr) != 1) {
    throw std::invalid_argument("mesh Linux capture currently requires IPv4 addresses");
  }
  return result;
}

void socket_timeout(int socket, unsigned seconds) {
  timeval value{static_cast<time_t>(seconds), 0};
  if (::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) != 0 ||
      ::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value)) != 0) {
    system_error("set mesh socket timeout");
  }
}

int listener(const PinnedNamespace &path, std::string_view host, std::uint16_t port) {
  NetworkNamespace network_namespace(path);
  FileDescriptor socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!socket) {
    system_error("open mesh listener");
  }
  int enabled = 1;
  if (::setsockopt(socket.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
    system_error("configure mesh listener");
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) != 1) {
    throw std::invalid_argument("invalid mesh listener IPv4 address");
  }
  if (::bind(socket.get(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
    system_error("bind mesh listener");
  }
  if (::listen(socket.get(), 128) != 0) {
    system_error("listen on mesh capture socket");
  }
  return socket.release();
}

int connect_marked(const PinnedNamespace &path, std::string_view target, unsigned timeout) {
  const auto address = parse_ipv4(target);
  FileDescriptor socket;
  {
    NetworkNamespace network_namespace(path);
    socket.reset(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!socket) {
      system_error("open mesh upstream socket");
    }
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_MARK, &bypass_mark, sizeof(bypass_mark)) != 0) {
      system_error("mark mesh upstream socket");
    }
  }
  socket_timeout(socket.get(), timeout);
  if (::connect(socket.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
    system_error("connect mesh upstream");
  }
  return socket.release();
}

std::string original_destination(int socket) {
  constexpr int original_destination_option = 80;
  sockaddr_in address{};
  socklen_t size = sizeof(address);
  if (::getsockopt(socket, SOL_IP, original_destination_option, &address, &size) != 0 ||
      size != sizeof(address)) {
    system_error("read original mesh destination");
  }
  std::array<char, INET_ADDRSTRLEN> host{};
  if (::inet_ntop(AF_INET, &address.sin_addr, host.data(), host.size()) == nullptr) {
    system_error("format original mesh destination");
  }
  return std::string(host.data()) + ":" + std::to_string(ntohs(address.sin_port));
}

using SslContext = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using Ssl = std::unique_ptr<SSL, decltype(&SSL_free)>;

[[noreturn]] void tls_error(std::string_view operation) {
  const auto system_code = errno;
  const auto code = ERR_get_error();
  const auto *reason = ERR_reason_error_string(code);
  throw std::runtime_error(std::string(operation) + ": openssl_error=" + std::to_string(code) +
                           " (" + (reason != nullptr ? reason : "no OpenSSL error queued") +
                           ") errno=" + std::to_string(system_code) + " (" +
                           std::strerror(system_code) + ")");
}

template <typename Function> void tls_setting(std::string_view operation, Function apply) {
  ERR_clear_error();
  errno = 0;
  if (apply() != 1) {
    tls_error(operation);
  }
}

SslContext tls_context(const transport::TlsFiles &files) {
  ERR_clear_error();
  errno = 0;
  SslContext context(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  if (!context) {
    tls_error("create mesh TLS context");
  }
  tls_setting("set mesh TLS minimum version", [&] {
    return SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION);
  });
  tls_setting("set mesh TLS maximum version", [&] {
    return SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION);
  });
  tls_setting("load mesh certificate chain", [&] {
    return SSL_CTX_use_certificate_chain_file(context.get(), files.certificate.c_str());
  });
  tls_setting("load mesh private key", [&] {
    return SSL_CTX_use_PrivateKey_file(context.get(), files.private_key.c_str(), SSL_FILETYPE_PEM);
  });
  tls_setting("match mesh certificate and private key", [&] {
    return SSL_CTX_check_private_key(context.get());
  });
  tls_setting("load mesh certificate authority", [&] {
    return SSL_CTX_load_verify_locations(context.get(), files.certificate_authority.c_str(),
                                         nullptr);
  });
  SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  SSL_CTX_set_verify_depth(context.get(), 6);
  SSL_CTX_set_session_cache_mode(context.get(), SSL_SESS_CACHE_OFF);
  SSL_CTX_set_num_tickets(context.get(), 0);
  SSL_CTX_set_options(context.get(), SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
  return context;
}

Ssl client_tls(int socket, const transport::TlsFiles &files, const std::string &identity) {
  auto context = tls_context(files);
  Ssl ssl(SSL_new(context.get()), SSL_free);
  if (!ssl) {
    throw std::runtime_error("create mesh TLS client failed");
  }
  auto *parameters = SSL_get0_param(ssl.get());
  X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT |
                                                  X509_CHECK_FLAG_NO_WILDCARDS);
  if (SSL_set1_host(ssl.get(), identity.c_str()) != 1 ||
      SSL_set_tlsext_host_name(ssl.get(), identity.c_str()) != 1 ||
      SSL_set_fd(ssl.get(), socket) != 1 || SSL_connect(ssl.get()) != 1 ||
      SSL_get_verify_result(ssl.get()) != X509_V_OK) {
    throw std::runtime_error("mesh TLS client authentication failed");
  }
  return ssl;
}

Ssl server_tls(int socket, const transport::TlsFiles &files) {
  auto context = tls_context(files);
  Ssl ssl(SSL_new(context.get()), SSL_free);
  if (!ssl || SSL_set_fd(ssl.get(), socket) != 1 || SSL_accept(ssl.get()) != 1 ||
      SSL_get_verify_result(ssl.get()) != X509_V_OK) {
    throw std::runtime_error("mesh TLS server authentication failed");
  }
  return ssl;
}

std::string peer_identity(SSL *ssl) {
  auto *certificate = SSL_get0_peer_certificate(ssl);
  if (certificate == nullptr) {
    throw std::runtime_error("mesh peer certificate missing");
  }
  std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
      static_cast<GENERAL_NAMES *>(
          X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr)),
      GENERAL_NAMES_free);
  std::string result;
  if (names) {
    for (int index = 0; index < sk_GENERAL_NAME_num(names.get()); ++index) {
      const auto *name = sk_GENERAL_NAME_value(names.get(), index);
      if (name->type != GEN_DNS) {
        continue;
      }
      const auto *data = ASN1_STRING_get0_data(name->d.dNSName);
      const auto size = ASN1_STRING_length(name->d.dNSName);
      std::string value(reinterpret_cast<const char *>(data), static_cast<std::size_t>(size));
      if (!result.empty() || value.find('\0') != std::string::npos ||
          peer::normalize_service_name(value) != value) {
        throw std::runtime_error("mesh peer certificate identity is ambiguous");
      }
      result = std::move(value);
    }
  }
  if (result.empty()) {
    throw std::runtime_error("mesh peer certificate identity missing");
  }
  return result;
}

void ssl_write_all(SSL *ssl, std::string_view data) {
  std::size_t offset = 0;
  while (offset < data.size()) {
    std::size_t written = 0;
    if (SSL_write_ex(ssl, data.data() + offset, data.size() - offset, &written) != 1 ||
        written == 0) {
      throw std::runtime_error("mesh TLS write failed");
    }
    offset += written;
  }
}

std::string ssl_line(SSL *ssl) {
  std::string result;
  while (result.size() < preface_limit) {
    char character = '\0';
    std::size_t size = 0;
    if (SSL_read_ex(ssl, &character, 1, &size) != 1 || size != 1) {
      throw std::runtime_error("mesh TLS preface read failed");
    }
    if (character == '\n') {
      return result;
    }
    if (character < 0x20 || character > 0x7e) {
      throw std::runtime_error("mesh TLS preface is not bounded ASCII");
    }
    result.push_back(character);
  }
  throw std::runtime_error("mesh TLS preface exceeds limit");
}

void send_all(int socket, const char *data, std::size_t size) {
  std::size_t offset = 0;
  while (offset < size) {
    const auto written = ::send(socket, data + offset, size - offset, MSG_NOSIGNAL);
    if (written <= 0) {
      throw std::runtime_error("mesh plain write failed");
    }
    offset += static_cast<std::size_t>(written);
  }
}

void forward(int plain, SSL *secure) {
  std::array<char, 16384> buffer{};
  const int tls_socket = SSL_get_fd(secure);
  while (!stopping) {
    std::array<pollfd, 2> descriptors{{{plain, POLLIN, 0}, {tls_socket, POLLIN, 0}}};
    const int result = ::poll(descriptors.data(), descriptors.size(), -1);
    if (result < 0 && errno == EINTR) {
      continue;
    }
    if (result <= 0) {
      break;
    }
    if (descriptors[0].revents & POLLIN) {
      const auto size = ::recv(plain, buffer.data(), buffer.size(), 0);
      if (size <= 0) {
        break;
      }
      ssl_write_all(secure, std::string_view(buffer.data(), static_cast<std::size_t>(size)));
    }
    if (descriptors[1].revents & POLLIN) {
      std::size_t size = 0;
      if (SSL_read_ex(secure, buffer.data(), buffer.size(), &size) != 1 || size == 0) {
        break;
      }
      send_all(plain, buffer.data(), size);
    }
    if ((descriptors[0].revents | descriptors[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
      break;
    }
  }
}

class Agent;

class Audit {
public:
  explicit Audit(const std::string &path) {
    if (path != "-") {
      errno = 0;
      file_.open(path, std::ios::app | std::ios::binary);
      if (!file_) {
        if (errno == 0) {
          errno = EIO;
        }
        system_error("open mesh audit sink");
      }
      output_ = &file_;
    }
  }

  bool write(const nlohmann::json &record) {
    const std::lock_guard lock(mutex_);
    *output_ << record.dump() << '\n';
    output_->flush();
    return static_cast<bool>(*output_);
  }

private:
  std::mutex mutex_;
  std::ofstream file_;
  std::ostream *output_ = &std::cout;
};

struct Runtime {
  explicit Runtime(const Workload &value)
      : workload(value), network_namespace(std::make_shared<PinnedNamespace>(value)) {
  }

  Workload workload;
  std::shared_ptr<const PinnedNamespace> network_namespace;
  FileDescriptor outbound;
  FileDescriptor inbound;
  std::jthread outbound_thread;
  std::jthread inbound_thread;
};

class Agent {
public:
  explicit Agent(Options options) : options_(std::move(options)), audit_(options_.audit) {
  }

  ~Agent() {
    close_runtime();
    close_sessions();
    wait_for_sessions();
    ::shutdown(health_socket_.get(), SHUT_RDWR);
    health_socket_.reset();
    health_thread_.request_stop();
  }

  void run() {
    health_socket_.reset(host_listener(options_.health_listen));
    health_thread_ = std::jthread([this] {
      health_loop();
    });
    reload(true);
    while (!stopping) {
      if (reloading || changed()) {
        reload(true);
      }
      if (!audit_ok_) {
        ready_ = false;
        close_sessions();
      }
      std::this_thread::sleep_for(250ms);
    }
    ready_ = false;
    close_runtime();
    close_sessions();
    wait_for_sessions();
  }

private:
  static int host_listener(std::string_view address) {
    const auto endpoint = parse_ipv4(address);
    FileDescriptor socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!socket) {
      system_error("open mesh health listener");
    }
    int enabled = 1;
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
      system_error("configure mesh health listener");
    }
    if (::bind(socket.get(), reinterpret_cast<const sockaddr *>(&endpoint), sizeof(endpoint)) !=
        0) {
      system_error("bind mesh health listener");
    }
    if (::listen(socket.get(), 16) != 0) {
      system_error("listen on mesh health socket");
    }
    return socket.release();
  }

  bool changed() const {
    try {
      return modified_ != std::filesystem::last_write_time(options_.configuration) ||
             size_ != std::filesystem::file_size(options_.configuration);
    } catch (...) {
      return true;
    }
  }

  void reload(bool) {
    reloading = 0;
    ready_ = false;
    close_runtime();
    close_sessions();
    wait_for_sessions();
    std::string step = "projection read/validation";
    try {
      auto configuration = read_configuration(options_.configuration);
      std::vector<std::shared_ptr<Runtime>> replacement;
      for (const auto &workload : configuration.workloads) {
        const auto context = "workload[" + std::to_string(replacement.size()) + "] ";
        step = context + "TLS validation";
        static_cast<void>(tls_context(workload.tls));
        step = context + "namespace identity validation";
        auto runtime = std::make_shared<Runtime>(workload);
        step = context + "capture installation";
        install_capture(*runtime->network_namespace);
        step = context + "outbound listener 127.0.0.1:15001";
        runtime->outbound.reset(listener(*runtime->network_namespace, "127.0.0.1", outbound_port));
        step = context + "inbound listener 0.0.0.0:15008";
        runtime->inbound.reset(listener(*runtime->network_namespace, "0.0.0.0", inbound_port));
        replacement.push_back(std::move(runtime));
      }
      step = "capture listener threads";
      configuration_ = std::move(configuration);
      runtimes_ = std::move(replacement);
      for (const auto &runtime : runtimes_) {
        auto *value = runtime.get();
        runtime->outbound_thread = std::jthread([this, value] {
          accept_loop(value, true);
        });
        runtime->inbound_thread = std::jthread([this, value] {
          accept_loop(value, false);
        });
      }
      step = "projection modification time";
      modified_ = std::filesystem::last_write_time(options_.configuration);
      step = "projection file size";
      size_ = std::filesystem::file_size(options_.configuration);
      ++reloads_;
      ready_ = audit_ok_.load();
    } catch (const std::exception &error) {
      reload_failed(step, failure_detail(error));
    } catch (...) {
      reload_failed(step, "unknown exception");
    }
  }

  void reload_failed(std::string_view step, std::string_view detail) {
    ready_ = false;
    close_runtime();
    close_sessions();
    wait_for_sessions();
    configuration_.reset();
    ++reload_failures_;
    std::cerr << "zetta-tunnel: mesh stage=" << step << ": " << detail << "; refusing traffic\n";
  }

  void close_runtime() {
    for (const auto &runtime : runtimes_) {
      ::shutdown(runtime->outbound.get(), SHUT_RDWR);
      ::shutdown(runtime->inbound.get(), SHUT_RDWR);
      runtime->outbound.reset();
      runtime->inbound.reset();
      runtime->outbound_thread.request_stop();
      runtime->inbound_thread.request_stop();
    }
    runtimes_.clear();
  }

  bool reserve_session(int socket) {
    auto count = sessions_.load();
    while (count < options_.max_sessions) {
      if (sessions_.compare_exchange_weak(count, count + 1)) {
        const std::lock_guard lock(session_mutex_);
        session_sockets_.insert(socket);
        return true;
      }
    }
    ++capacity_denials_;
    return false;
  }

  void release_session(int socket) {
    {
      const std::lock_guard lock(session_mutex_);
      session_sockets_.erase(socket);
    }
    --sessions_;
  }

  void close_sessions() {
    const std::lock_guard lock(session_mutex_);
    for (const int socket : session_sockets_) {
      ::shutdown(socket, SHUT_RDWR);
    }
  }

  void wait_for_sessions() const {
    while (sessions_.load() != 0) {
      std::this_thread::sleep_for(10ms);
    }
  }

  void accept_loop(Runtime *runtime, bool outbound) {
    const int listener_socket = outbound ? runtime->outbound.get() : runtime->inbound.get();
    while (!stopping && listener_socket >= 0) {
      const int accepted = ::accept4(listener_socket, nullptr, nullptr, SOCK_CLOEXEC);
      if (accepted < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      if (!reserve_session(accepted)) {
        ::close(accepted);
        continue;
      }
      const auto workload = runtime->workload;
      const auto network_namespace = runtime->network_namespace;
      std::thread([this, accepted, workload, network_namespace, outbound] {
        FileDescriptor incoming(accepted);
        try {
          socket_timeout(accepted, options_.setup_timeout);
          if (outbound) {
            outbound_session(workload, *network_namespace, accepted);
          } else {
            inbound_session(workload, *network_namespace, accepted);
          }
        } catch (...) {
          static_cast<void>(record("deny", "session_failure", workload, "", "", 0,
                                   outbound ? "outbound" : "inbound"));
        }
        release_session(accepted);
      }).detach();
    }
  }

  bool record(std::string_view decision, std::string_view reason, const Workload &workload,
              std::string_view peer, std::string_view destination, std::uint16_t port,
              std::string_view direction) {
    const nlohmann::json value = {
        {"schema", 1},
        {"event", "mesh_decision"},
        {"role", "mesh"},
        {"timestamp", tunnel::format_time(std::chrono::system_clock::now())},
        {"node", configuration_ ? configuration_->node : ""},
        {"workload", workload.identity},
        {"peer", peer},
        {"destination", destination},
        {"port", port},
        {"direction", direction},
        {"decision", decision},
        {"reason", reason}};
    if (!audit_.write(value)) {
      audit_ok_ = false;
      return false;
    }
    if (decision == "allow") {
      ++allows_;
    } else {
      ++denials_;
    }
    return true;
  }

  void outbound_session(const Workload &workload, const PinnedNamespace &network_namespace,
                        int incoming) {
    const auto destination = original_destination(incoming);
    const auto route = std::find_if(workload.routes.begin(), workload.routes.end(),
                                    [&destination](const Route &value) {
                                      return value.destination == destination;
                                    });
    if (route == workload.routes.end()) {
      static_cast<void>(
          record("deny", "destination_absent", workload, "", destination, 0, "outbound"));
      return;
    }
    const auto destination_address = tunnel::parse_address(route->destination);
    FileDescriptor remote(connect_marked(network_namespace, route->mesh, options_.setup_timeout));
    auto secure = client_tls(remote.get(), workload.tls, route->identity);
    const auto preface =
        "ZTM1 " + route->identity + " " + std::to_string(destination_address.port) + "\n";
    ssl_write_all(secure.get(), preface);
    if (ssl_line(secure.get()) != "ZTMA1") {
      static_cast<void>(record("deny", "remote_denied", workload, route->identity, destination,
                               destination_address.port, "outbound"));
      return;
    }
    if (!record("allow", "identity_allowed", workload, route->identity, destination,
                destination_address.port, "outbound")) {
      return;
    }
    socket_timeout(incoming, 0);
    socket_timeout(remote.get(), 0);
    forward(incoming, secure.get());
  }

  void inbound_session(const Workload &workload, const PinnedNamespace &network_namespace,
                       int incoming) {
    auto secure = server_tls(incoming, workload.tls);
    const auto source = peer_identity(secure.get());
    const auto preface = ssl_line(secure.get());
    std::istringstream parser(preface);
    std::string protocol;
    std::string destination;
    unsigned requested_port = 0;
    std::string extra;
    parser >> protocol >> destination >> requested_port;
    parser >> extra;
    if (protocol != "ZTM1" || destination != workload.identity || !extra.empty() ||
        requested_port == 0 || requested_port > 65535) {
      static_cast<void>(
          record("deny", "invalid_preface", workload, source, destination, 0, "inbound"));
      return;
    }
    const auto allowed = std::find_if(
        workload.ports.begin(), workload.ports.end(), [requested_port, &source](const Port &value) {
          return value.port == requested_port &&
                 std::ranges::find(value.sources, source) != value.sources.end();
        });
    if (allowed == workload.ports.end()) {
      static_cast<void>(record("deny", "source_absent", workload, source, destination,
                               static_cast<std::uint16_t>(requested_port), "inbound"));
      return;
    }
    FileDescriptor target(
        connect_marked(network_namespace, allowed->target, options_.setup_timeout));
    if (!record("allow", "identity_allowed", workload, source, destination, allowed->port,
                "inbound")) {
      return;
    }
    ssl_write_all(secure.get(), "ZTMA1\n");
    socket_timeout(incoming, 0);
    socket_timeout(target.get(), 0);
    forward(target.get(), secure.get());
  }

  std::string metrics() const {
    return "# TYPE zetta_mesh_sessions gauge\nzetta_mesh_sessions " +
           std::to_string(sessions_.load()) +
           "\n# TYPE zetta_mesh_allows_total counter\nzetta_mesh_allows_total " +
           std::to_string(allows_.load()) +
           "\n# TYPE zetta_mesh_denials_total counter\nzetta_mesh_denials_total " +
           std::to_string(denials_.load()) +
           "\n# TYPE zetta_mesh_capacity_denials_total "
           "counter\nzetta_mesh_capacity_denials_total " +
           std::to_string(capacity_denials_.load()) +
           "\n# TYPE zetta_mesh_reloads_total counter\nzetta_mesh_reloads_total " +
           std::to_string(reloads_.load()) +
           "\n# TYPE zetta_mesh_reload_failures_total counter\nzetta_mesh_reload_failures_total " +
           std::to_string(reload_failures_.load()) + "\n";
  }

  void health_loop() {
    while (!stopping) {
      FileDescriptor connection(::accept4(health_socket_.get(), nullptr, nullptr, SOCK_CLOEXEC));
      if (!connection) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      socket_timeout(connection.get(), 5);
      std::array<char, 4097> request{};
      const auto size = ::recv(connection.get(), request.data(), request.size() - 1, 0);
      std::string_view path;
      if (size > 0) {
        const std::string_view line(request.data(), static_cast<std::size_t>(size));
        const auto first = line.find(' ');
        const auto second = first == std::string_view::npos ? first : line.find(' ', first + 1);
        if (first != std::string_view::npos && second != std::string_view::npos &&
            line.substr(0, first) == "GET") {
          path = line.substr(first + 1, second - first - 1);
        }
      }
      unsigned status = 404;
      std::string body;
      if (path == "/healthz") {
        status = 200;
        body = "ok\n";
      } else if (path == "/readyz") {
        status = ready_ && audit_ok_ ? 200 : 503;
        body = status == 200 ? "ready\n" : "not ready\n";
      } else if (path == "/metrics") {
        status = 200;
        body = metrics();
      }
      const auto response =
          "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK\r\n" : " Unavailable\r\n") +
          "Connection: close\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
      try {
        send_all(connection.get(), response.data(), response.size());
      } catch (...) {
      }
    }
  }

  Options options_;
  Audit audit_;
  std::optional<Configuration> configuration_;
  std::vector<std::shared_ptr<Runtime>> runtimes_;
  std::filesystem::file_time_type modified_{};
  std::uintmax_t size_ = 0;
  FileDescriptor health_socket_;
  std::jthread health_thread_;
  std::mutex session_mutex_;
  std::set<int> session_sockets_;
  std::atomic<std::size_t> sessions_ = 0;
  std::atomic<std::uint64_t> allows_ = 0;
  std::atomic<std::uint64_t> denials_ = 0;
  std::atomic<std::uint64_t> capacity_denials_ = 0;
  std::atomic<std::uint64_t> reloads_ = 0;
  std::atomic<std::uint64_t> reload_failures_ = 0;
  std::atomic<bool> ready_ = false;
  std::atomic<bool> audit_ok_ = true;
};

} // namespace

int run(const Options &options) {
  stopping = 0;
  reloading = 0;
  std::signal(SIGINT, signal_stop);
  std::signal(SIGTERM, signal_stop);
  std::signal(SIGHUP, signal_reload);
  try {
    Agent agent(options);
    agent.run();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "zetta-tunnel: mesh startup: " << failure_detail(error) << "; refusing traffic\n";
    return 2;
  }
}

} // namespace zetta_tunnel::mesh
