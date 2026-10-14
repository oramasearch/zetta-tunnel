#include "mesh.hpp"

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
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
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
constexpr std::uint16_t outbound_port = 15001;
constexpr std::uint16_t inbound_port = 15008;
constexpr std::uint32_t bypass_mark = 0x5a54544d;
constexpr std::string_view table_name = "zetta_mesh";
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
  throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

void signal_stop(int) {
  stopping = 1;
}

void signal_reload(int) {
  reloading = 1;
}

class NetworkNamespace {
public:
  explicit NetworkNamespace(const std::filesystem::path &path)
      : original_(::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC)),
        target_(::open(path.c_str(), O_RDONLY | O_CLOEXEC)) {
    if (!original_ || !target_ || ::setns(target_.get(), CLONE_NEWNET) != 0) {
      system_error("enter workload network namespace");
    }
  }

  ~NetworkNamespace() {
    if (original_ && ::setns(original_.get(), CLONE_NEWNET) != 0) {
      std::terminate();
    }
  }

  NetworkNamespace(const NetworkNamespace &) = delete;
  NetworkNamespace &operator=(const NetworkNamespace &) = delete;

private:
  FileDescriptor original_;
  FileDescriptor target_;
};

std::size_t aligned(std::size_t size) {
  return (size + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1);
}

bool attribute_valid(const nlattr *attribute, int remaining) {
  return remaining >= static_cast<int>(sizeof(nlattr)) && attribute->nla_len >= sizeof(nlattr) &&
         attribute->nla_len <= remaining;
}

nlattr *next_attribute(nlattr *attribute, int &remaining) {
  const auto length = static_cast<int>(aligned(attribute->nla_len));
  remaining -= length;
  return reinterpret_cast<nlattr *>(reinterpret_cast<std::byte *>(attribute) + length);
}

class NetlinkMessage {
public:
  NetlinkMessage(std::uint16_t type, std::uint16_t flags, std::uint32_t sequence,
                 std::uint8_t family = NFPROTO_INET) {
    data_.resize(NLMSG_SPACE(sizeof(nfgenmsg)), std::byte{});
    auto *header = reinterpret_cast<nlmsghdr *>(data_.data());
    header->nlmsg_len = static_cast<std::uint32_t>(data_.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = flags;
    header->nlmsg_seq = sequence;
    auto *generation = reinterpret_cast<nfgenmsg *>(NLMSG_DATA(header));
    generation->nfgen_family = family;
    generation->version = NFNETLINK_V0;
    generation->res_id = htons(NFNL_SUBSYS_NFTABLES);
  }

  void attribute(std::uint16_t type, const void *data, std::size_t size) {
    const auto offset = data_.size();
    const auto length = sizeof(nlattr) + size;
    data_.resize(offset + aligned(length), std::byte{});
    auto *value = reinterpret_cast<nlattr *>(data_.data() + offset);
    value->nla_type = type;
    value->nla_len = static_cast<std::uint16_t>(length);
    std::memcpy(reinterpret_cast<std::byte *>(value) + sizeof(nlattr), data, size);
    header()->nlmsg_len = static_cast<std::uint32_t>(data_.size());
  }

  void string(std::uint16_t type, std::string_view value) {
    attribute(type, value.data(), value.size() + 1);
  }

  void integer(std::uint16_t type, std::uint32_t value) {
    const auto network = htonl(value);
    attribute(type, &network, sizeof(network));
  }

  std::size_t begin(std::uint16_t type) {
    const auto offset = data_.size();
    data_.resize(offset + aligned(sizeof(nlattr)), std::byte{});
    auto *value = reinterpret_cast<nlattr *>(data_.data() + offset);
    value->nla_type = type | NLA_F_NESTED;
    value->nla_len = sizeof(nlattr);
    header()->nlmsg_len = static_cast<std::uint32_t>(data_.size());
    return offset;
  }

  void end(std::size_t offset) {
    auto *value = reinterpret_cast<nlattr *>(data_.data() + offset);
    value->nla_len = static_cast<std::uint16_t>(data_.size() - offset);
  }

  nlmsghdr *header() {
    return reinterpret_cast<nlmsghdr *>(data_.data());
  }

  const std::vector<std::byte> &data() const {
    return data_;
  }

private:
  std::vector<std::byte> data_;
};

void add_expression(NetlinkMessage &message, std::string_view name,
                    const std::function<void(NetlinkMessage &)> &fields) {
  const auto element = message.begin(NFTA_LIST_ELEM);
  message.string(NFTA_EXPR_NAME, name);
  const auto data = message.begin(NFTA_EXPR_DATA);
  fields(message);
  message.end(data);
  message.end(element);
}

void add_meta(NetlinkMessage &message, std::uint32_t key) {
  add_expression(message, "meta", [key](NetlinkMessage &value) {
    value.integer(NFTA_META_KEY, key);
    value.integer(NFTA_META_DREG, NFT_REG_1);
  });
}

void add_payload_port(NetlinkMessage &message) {
  add_expression(message, "payload", [](NetlinkMessage &value) {
    value.integer(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
    value.integer(NFTA_PAYLOAD_OFFSET, 2);
    value.integer(NFTA_PAYLOAD_LEN, 2);
    value.integer(NFTA_PAYLOAD_DREG, NFT_REG_1);
  });
}

void add_compare(NetlinkMessage &message, std::uint32_t operation, const void *data,
                 std::size_t size) {
  add_expression(message, "cmp", [operation, data, size](NetlinkMessage &value) {
    value.integer(NFTA_CMP_SREG, NFT_REG_1);
    value.integer(NFTA_CMP_OP, operation);
    const auto nested = value.begin(NFTA_CMP_DATA);
    value.attribute(NFTA_DATA_VALUE, data, size);
    value.end(nested);
  });
}

void add_redirect(NetlinkMessage &message, std::uint16_t port) {
  add_expression(message, "immediate", [port](NetlinkMessage &value) {
    value.integer(NFTA_IMMEDIATE_DREG, NFT_REG_1);
    const auto nested = value.begin(NFTA_IMMEDIATE_DATA);
    const auto network = htons(port);
    value.attribute(NFTA_DATA_VALUE, &network, sizeof(network));
    value.end(nested);
  });
  add_expression(message, "redir", [](NetlinkMessage &value) {
    value.integer(NFTA_REDIR_REG_PROTO_MIN, NFT_REG_1);
  });
}

NetlinkMessage table_message(std::uint32_t sequence) {
  NetlinkMessage result((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sequence);
  result.string(NFTA_TABLE_NAME, table_name);
  return result;
}

NetlinkMessage chain_message(std::uint32_t sequence, std::string_view name, std::uint32_t hook) {
  NetlinkMessage result((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sequence);
  result.string(NFTA_CHAIN_TABLE, table_name);
  result.string(NFTA_CHAIN_NAME, name);
  result.string(NFTA_CHAIN_TYPE, "nat");
  const auto nested = result.begin(NFTA_CHAIN_HOOK);
  result.integer(NFTA_HOOK_HOOKNUM, hook);
  result.integer(NFTA_HOOK_PRIORITY, static_cast<std::uint32_t>(-100));
  result.end(nested);
  result.integer(NFTA_CHAIN_POLICY, NF_ACCEPT);
  return result;
}

NetlinkMessage rule_message(std::uint32_t sequence, std::string_view chain, std::uint16_t redirect,
                            bool output) {
  NetlinkMessage result((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND, sequence);
  result.string(NFTA_RULE_TABLE, table_name);
  result.string(NFTA_RULE_CHAIN, chain);
  const auto expressions = result.begin(NFTA_RULE_EXPRESSIONS);
  add_meta(result, NFT_META_L4PROTO);
  const std::uint8_t tcp = IPPROTO_TCP;
  add_compare(result, NFT_CMP_EQ, &tcp, sizeof(tcp));
  if (output) {
    add_meta(result, NFT_META_MARK);
    const auto mark = htonl(bypass_mark);
    add_compare(result, NFT_CMP_NEQ, &mark, sizeof(mark));
  }
  add_payload_port(result);
  const auto mesh_port = htons(inbound_port);
  add_compare(result, NFT_CMP_NEQ, &mesh_port, sizeof(mesh_port));
  add_redirect(result, redirect);
  result.end(expressions);
  return result;
}

void send_message(int socket, const NetlinkMessage &message) {
  const auto &bytes = message.data();
  if (::send(socket, bytes.data(), bytes.size(), 0) != static_cast<ssize_t>(bytes.size())) {
    system_error("send nftables request");
  }
}

bool table_exists(int socket) {
  NetlinkMessage request((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE, NLM_F_REQUEST | NLM_F_DUMP,
                         1);
  send_message(socket, request);
  std::array<std::byte, 16384> buffer{};
  while (true) {
    const auto size = ::recv(socket, buffer.data(), buffer.size(), 0);
    if (size < 0) {
      system_error("read nftables table list");
    }
    for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); NLMSG_OK(header, size);
         header = NLMSG_NEXT(header, size)) {
      if (header->nlmsg_type == NLMSG_DONE) {
        return false;
      }
      if (header->nlmsg_type == NLMSG_ERROR) {
        const auto *error = reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
        if (error->error != 0) {
          errno = -error->error;
          system_error("list nftables tables");
        }
        continue;
      }
      const auto *generation = reinterpret_cast<const nfgenmsg *>(NLMSG_DATA(header));
      auto length = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(nfgenmsg)));
      auto *attribute = reinterpret_cast<nlattr *>(
          reinterpret_cast<std::byte *>(const_cast<nfgenmsg *>(generation)) +
          NLMSG_ALIGN(sizeof(nfgenmsg)));
      while (attribute_valid(attribute, length)) {
        if ((attribute->nla_type & NLA_TYPE_MASK) == NFTA_TABLE_NAME) {
          const auto *name = reinterpret_cast<const char *>(attribute) + sizeof(nlattr);
          if (std::string_view(name) == table_name) {
            return true;
          }
        }
        attribute = next_attribute(attribute, length);
      }
    }
  }
}

void receive_acks(int socket, std::size_t expected) {
  std::array<std::byte, 16384> buffer{};
  std::size_t received = 0;
  while (received < expected) {
    auto size = ::recv(socket, buffer.data(), buffer.size(), 0);
    if (size < 0) {
      system_error("read nftables acknowledgement");
    }
    for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); NLMSG_OK(header, size);
         header = NLMSG_NEXT(header, size)) {
      if (header->nlmsg_type != NLMSG_ERROR) {
        continue;
      }
      const auto *error = reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
      if (error->error != 0) {
        errno = -error->error;
        system_error("install nftables capture");
      }
      ++received;
    }
  }
}

void install_capture(const std::filesystem::path &path) {
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
  if (table_exists(socket.get())) {
    return;
  }
  std::vector<NetlinkMessage> messages;
  messages.push_back(table_message(2));
  messages.push_back(chain_message(3, "outbound", NF_INET_LOCAL_OUT));
  messages.push_back(chain_message(4, "inbound", NF_INET_PRE_ROUTING));
  messages.push_back(rule_message(5, "outbound", outbound_port, true));
  messages.push_back(rule_message(6, "inbound", inbound_port, false));
  NetlinkMessage begin(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 7, AF_UNSPEC);
  NetlinkMessage end(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 8, AF_UNSPEC);
  send_message(socket.get(), begin);
  for (const auto &message : messages) {
    send_message(socket.get(), message);
  }
  send_message(socket.get(), end);
  receive_acks(socket.get(), messages.size());
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

int listener(const std::filesystem::path &path, std::string_view host, std::uint16_t port) {
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
  if (::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) != 1 ||
      ::bind(socket.get(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
      ::listen(socket.get(), 128) != 0) {
    system_error("bind mesh listener");
  }
  return socket.release();
}

int connect_marked(const std::filesystem::path &path, std::string_view target, unsigned timeout) {
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

SslContext tls_context(const transport::TlsFiles &files) {
  SslContext context(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  if (!context || SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
      SSL_CTX_use_certificate_chain_file(context.get(), files.certificate.c_str()) != 1 ||
      SSL_CTX_use_PrivateKey_file(context.get(), files.private_key.c_str(), SSL_FILETYPE_PEM) !=
          1 ||
      SSL_CTX_check_private_key(context.get()) != 1 ||
      SSL_CTX_load_verify_locations(context.get(), files.certificate_authority.c_str(), nullptr) !=
          1) {
    throw std::runtime_error("mesh TLS configuration failed");
  }
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
      file_.open(path, std::ios::app | std::ios::binary);
      if (!file_) {
        throw std::invalid_argument("cannot open mesh audit sink");
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
  Workload workload;
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
    ::setsockopt(socket.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    if (::bind(socket.get(), reinterpret_cast<const sockaddr *>(&endpoint), sizeof(endpoint)) !=
            0 ||
        ::listen(socket.get(), 16) != 0) {
      system_error("bind mesh health listener");
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
    try {
      auto configuration = read_configuration(options_.configuration);
      std::vector<std::shared_ptr<Runtime>> replacement;
      for (const auto &workload : configuration.workloads) {
        static_cast<void>(tls_context(workload.tls));
        install_capture(workload.network_namespace);
        auto runtime = std::make_shared<Runtime>();
        runtime->workload = workload;
        runtime->outbound.reset(listener(workload.network_namespace, "127.0.0.1", outbound_port));
        runtime->inbound.reset(listener(workload.network_namespace, "0.0.0.0", inbound_port));
        replacement.push_back(std::move(runtime));
      }
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
      modified_ = std::filesystem::last_write_time(options_.configuration);
      size_ = std::filesystem::file_size(options_.configuration);
      ++reloads_;
      ready_ = audit_ok_;
    } catch (...) {
      configuration_.reset();
      ++reload_failures_;
      std::cerr << "zetta-tunnel: mesh projection or capture unavailable; refusing traffic\n";
    }
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
      std::thread([this, accepted, workload, outbound] {
        FileDescriptor incoming(accepted);
        try {
          socket_timeout(accepted, options_.setup_timeout);
          if (outbound) {
            outbound_session(workload, accepted);
          } else {
            inbound_session(workload, accepted);
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

  void outbound_session(const Workload &workload, int incoming) {
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
    FileDescriptor remote(
        connect_marked(workload.network_namespace, route->mesh, options_.setup_timeout));
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

  void inbound_session(const Workload &workload, int incoming) {
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
        connect_marked(workload.network_namespace, allowed->target, options_.setup_timeout));
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
  Agent agent(options);
  agent.run();
  return 0;
}

} // namespace zetta_tunnel::mesh
