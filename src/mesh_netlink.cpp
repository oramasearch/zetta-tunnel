#include "mesh_netlink.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <stdexcept>

#ifdef __linux__
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#endif

namespace zetta_tunnel::mesh::netlink {
namespace {

// Linux netlink/nftables UAPI wire values. Kept independent of Linux headers so the
// production encoder and reply decoder run in the native macOS regression suite.
constexpr std::uint16_t request_flag = 0x1;
constexpr std::uint16_t ack_flag = 0x4;
constexpr std::uint16_t create_exclusive = 0x600;
constexpr std::uint16_t create_append = 0xc00;
constexpr std::uint16_t nested_flag = 0x8000;
constexpr std::uint16_t batch_begin = 0x10;
constexpr std::uint16_t batch_end = 0x11;
constexpr std::uint16_t new_table = 0xa00;
constexpr std::uint16_t get_table = 0xa01;
constexpr std::uint16_t new_chain = 0xa03;
constexpr std::uint16_t new_rule = 0xa06;
constexpr std::uint8_t inet_family = 1;
constexpr std::uint32_t mark_key = 3;
constexpr std::uint32_t l4proto_key = 16;
constexpr std::size_t header_size = 16;
constexpr std::size_t attribute_header_size = 4;
constexpr std::uint16_t capped_flag = 0x100;
constexpr std::uint16_t ack_tlvs_flag = 0x200;

enum class Table : std::uint16_t { name = 1 };
enum class Chain : std::uint16_t { table = 1, name = 3, hook = 4, policy = 5, type = 7 };
enum class Hook : std::uint16_t { number = 1, priority = 2 };
enum class Rule : std::uint16_t { table = 1, chain = 2, expressions = 4 };
enum class List : std::uint16_t { element = 1 };
enum class Expression : std::uint16_t { name = 1, data = 2 };
enum class Meta : std::uint16_t { destination = 1, key = 2 };
enum class Compare : std::uint16_t { source = 1, operation = 2, data = 3 };
enum class Payload : std::uint16_t { destination = 1, base = 2, offset = 3, length = 4 };
enum class Immediate : std::uint16_t { destination = 1, data = 2 };
enum class Data : std::uint16_t { value = 1 };
enum class Redirect : std::uint16_t { minimum = 1 };

#ifdef __linux__
static_assert(header_size == sizeof(nlmsghdr) && attribute_header_size == sizeof(nlattr));
static_assert(inet_family == NFPROTO_INET && batch_begin == NFNL_MSG_BATCH_BEGIN &&
              batch_end == NFNL_MSG_BATCH_END && NFNL_SUBSYS_NFTABLES == 10);
static_assert(new_table == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE));
static_assert(get_table == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE));
static_assert(new_chain == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN));
static_assert(new_rule == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE));
static_assert(request_flag == NLM_F_REQUEST && ack_flag == NLM_F_ACK);
static_assert(create_exclusive == (NLM_F_CREATE | NLM_F_EXCL));
static_assert(create_append == (NLM_F_CREATE | NLM_F_APPEND));
static_assert(nested_flag == NLA_F_NESTED && capped_flag == NLM_F_CAPPED &&
              ack_tlvs_flag == NLM_F_ACK_TLVS);
static_assert(mark_key == NFT_META_MARK && l4proto_key == NFT_META_L4PROTO);
static_assert(NFT_REG_1 == 1 && NFT_CMP_EQ == 0 && NFT_CMP_NEQ == 1);
static_assert(NFT_PAYLOAD_TRANSPORT_HEADER == 2 && NF_INET_LOCAL_OUT == 3 &&
              NF_INET_PRE_ROUTING == 0 && NF_ACCEPT == 1);
#define CHECK_ATTRIBUTE(type, member, uapi)                                                        \
  static_assert(static_cast<unsigned>(type::member) == uapi)
CHECK_ATTRIBUTE(Table, name, NFTA_TABLE_NAME);
CHECK_ATTRIBUTE(Chain, table, NFTA_CHAIN_TABLE);
CHECK_ATTRIBUTE(Chain, name, NFTA_CHAIN_NAME);
CHECK_ATTRIBUTE(Chain, hook, NFTA_CHAIN_HOOK);
CHECK_ATTRIBUTE(Chain, policy, NFTA_CHAIN_POLICY);
CHECK_ATTRIBUTE(Chain, type, NFTA_CHAIN_TYPE);
CHECK_ATTRIBUTE(Hook, number, NFTA_HOOK_HOOKNUM);
CHECK_ATTRIBUTE(Hook, priority, NFTA_HOOK_PRIORITY);
CHECK_ATTRIBUTE(Rule, table, NFTA_RULE_TABLE);
CHECK_ATTRIBUTE(Rule, chain, NFTA_RULE_CHAIN);
CHECK_ATTRIBUTE(Rule, expressions, NFTA_RULE_EXPRESSIONS);
CHECK_ATTRIBUTE(List, element, NFTA_LIST_ELEM);
CHECK_ATTRIBUTE(Expression, name, NFTA_EXPR_NAME);
CHECK_ATTRIBUTE(Expression, data, NFTA_EXPR_DATA);
CHECK_ATTRIBUTE(Meta, destination, NFTA_META_DREG);
CHECK_ATTRIBUTE(Meta, key, NFTA_META_KEY);
CHECK_ATTRIBUTE(Compare, source, NFTA_CMP_SREG);
CHECK_ATTRIBUTE(Compare, operation, NFTA_CMP_OP);
CHECK_ATTRIBUTE(Compare, data, NFTA_CMP_DATA);
CHECK_ATTRIBUTE(Payload, destination, NFTA_PAYLOAD_DREG);
CHECK_ATTRIBUTE(Payload, base, NFTA_PAYLOAD_BASE);
CHECK_ATTRIBUTE(Payload, offset, NFTA_PAYLOAD_OFFSET);
CHECK_ATTRIBUTE(Payload, length, NFTA_PAYLOAD_LEN);
CHECK_ATTRIBUTE(Immediate, destination, NFTA_IMMEDIATE_DREG);
CHECK_ATTRIBUTE(Immediate, data, NFTA_IMMEDIATE_DATA);
CHECK_ATTRIBUTE(Data, value, NFTA_DATA_VALUE);
CHECK_ATTRIBUTE(Redirect, minimum, NFTA_REDIR_REG_PROTO_MIN);
#undef CHECK_ATTRIBUTE
#endif

constexpr std::size_t aligned(std::size_t size) {
  return (size + 3) & ~std::size_t{3};
}

template <typename T> T read(std::span<const std::byte> bytes, std::size_t offset) {
  if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
    throw std::runtime_error("truncated nftables netlink reply");
  }
  T value;
  std::memcpy(&value, bytes.data() + offset, sizeof(value));
  return value;
}

template <typename T> T network(T value) {
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(value);
  }
  return value;
}

class Message {
public:
  Message(std::uint16_t type, std::uint16_t flags, std::uint32_t sequence, std::string operation,
          bool batch = false)
      : request_{{}, sequence, type, std::move(operation), (flags & ack_flag) != 0} {
    request_.bytes.resize(20, std::byte{});
    put(4, type);
    put(6, flags);
    put(8, sequence);
    put<std::uint8_t>(16, batch ? 0 : inet_family);
    put<std::uint16_t>(18, network<std::uint16_t>(batch ? 10 : 0));
  }

  template <typename Attr> void attribute(Attr type, const void *data, std::size_t size) {
    if (size > std::numeric_limits<std::uint16_t>::max() - attribute_header_size) {
      throw std::length_error("nftables attribute too large");
    }
    const auto offset = request_.bytes.size();
    const auto length = attribute_header_size + size;
    request_.bytes.resize(offset + aligned(length), std::byte{});
    put(offset, static_cast<std::uint16_t>(length));
    put(offset + 2, static_cast<std::uint16_t>(type));
    if (size != 0) {
      std::memcpy(request_.bytes.data() + offset + attribute_header_size, data, size);
    }
  }

  template <typename Attr> void string(Attr type, std::string_view value) {
    // string_view is not guaranteed to include a trailing NUL.
    const std::string terminated(value);
    attribute(type, terminated.c_str(), terminated.size() + 1);
  }

  template <typename Attr> void integer(Attr type, std::uint32_t value) {
    value = network(value);
    attribute(type, &value, sizeof(value));
  }

  template <typename Attr> std::size_t begin(Attr type) {
    const auto offset = request_.bytes.size();
    attribute(static_cast<std::uint16_t>(type) | nested_flag, nullptr, 0);
    return offset;
  }

  void end(std::size_t offset) {
    put(offset, static_cast<std::uint16_t>(request_.bytes.size() - offset));
  }

  Request finish() {
    put<std::uint32_t>(0, static_cast<std::uint32_t>(request_.bytes.size()));
    return std::move(request_);
  }

private:
  template <typename T> void put(std::size_t offset, T value) {
    std::memcpy(request_.bytes.data() + offset, &value, sizeof(value));
  }
  Request request_;
};

template <typename Fields> void expression(Message &message, std::string_view name, Fields fields) {
  const auto element = message.begin(List::element);
  message.string(Expression::name, name);
  const auto data = message.begin(Expression::data);
  fields(message);
  message.end(data);
  message.end(element);
}

void meta(Message &message, std::uint32_t key) {
  expression(message, "meta", [key](Message &value) {
    value.integer(Meta::key, key);
    value.integer(Meta::destination, 1);
  });
}

template <typename T> void compare(Message &message, std::uint32_t operation, T data) {
  expression(message, "cmp", [operation, data](Message &value) {
    value.integer(Compare::source, 1);
    value.integer(Compare::operation, operation);
    const auto nested = value.begin(Compare::data);
    value.attribute(Data::value, &data, sizeof(data));
    value.end(nested);
  });
}

Request chain(std::uint32_t sequence, std::string_view name, std::uint32_t hook) {
  Message result(new_chain, request_flag | ack_flag | create_exclusive, sequence,
                 "create nftables " + std::string(name) + " chain");
  result.string(Chain::table, "zetta_mesh");
  result.string(Chain::name, name);
  result.string(Chain::type, "nat");
  const auto nested = result.begin(Chain::hook);
  result.integer(Hook::number, hook);
  result.integer(Hook::priority, static_cast<std::uint32_t>(-100));
  result.end(nested);
  result.integer(Chain::policy, 1);
  return result.finish();
}

Request rule(std::uint32_t sequence, std::string_view name, std::uint16_t port, bool output) {
  Message result(new_rule, request_flag | ack_flag | create_append, sequence,
                 "create nftables " + std::string(name) + " rule");
  result.string(Rule::table, "zetta_mesh");
  result.string(Rule::chain, name);
  const auto expressions = result.begin(Rule::expressions);
  meta(result, l4proto_key);
  compare(result, 0, std::uint8_t{6}); // IPPROTO_TCP is one byte.
  if (output) {
    meta(result, mark_key);
    compare(result, 1, bypass_mark); // NFT_META_MARK returns a host-order register value.
  }
  expression(result, "payload", [](Message &value) {
    value.integer(Payload::base, 2);
    value.integer(Payload::offset, 2);
    value.integer(Payload::length, 2);
    value.integer(Payload::destination, 1);
  });
  compare(result, 1, network(inbound_port)); // Transport header ports stay in network order.
  expression(result, "immediate", [port](Message &value) {
    value.integer(Immediate::destination, 1);
    const auto nested = value.begin(Immediate::data);
    const auto bytes = network(port);
    value.attribute(Data::value, &bytes, sizeof(bytes));
    value.end(nested);
  });
  expression(result, "redir", [](Message &value) {
    value.integer(Redirect::minimum, 1);
  });
  result.end(expressions);
  return result.finish();
}

std::string extended_error(std::span<const std::byte> message, std::int32_t error) {
  const auto flags = read<std::uint16_t>(message, 6);
  if ((flags & ack_tlvs_flag) == 0) {
    return {};
  }
  std::size_t offset = 36; // nlmsghdr + error + echoed nlmsghdr
  if (error != 0 && (flags & capped_flag) == 0) {
    const auto original_size = read<std::uint32_t>(message, 20);
    if (original_size < header_size || original_size > message.size() - 20) {
      throw std::runtime_error("invalid echoed nftables request length");
    }
    offset = 20 + aligned(original_size);
  }
  std::string result;
  while (offset < message.size()) {
    const auto length = read<std::uint16_t>(message, offset);
    const auto type = read<std::uint16_t>(message, offset + 2) & 0x3fff;
    if (length < attribute_header_size || length > message.size() - offset ||
        aligned(length) > message.size() - offset) {
      throw std::runtime_error("invalid nftables extended acknowledgement attribute");
    }
    if (type == 1) { // NLMSGERR_ATTR_MSG; never log the echoed request payload.
      result += " kernel_message=";
      const auto data = message.subspan(offset + 4, length - 4);
      for (const auto byte : data.first(std::min<std::size_t>(data.size(), 256))) {
        const auto c = std::to_integer<unsigned char>(byte);
        if (c == 0) {
          break;
        }
        result += c >= 32 && c < 127 ? static_cast<char>(c) : '?';
      }
    } else if (type == 2 && length == 8) { // NLMSGERR_ATTR_OFFS is native endian.
      result += " attribute_offset=" + std::to_string(read<std::uint32_t>(message, offset + 4));
    }
    offset += aligned(length);
  }
  return result;
}

} // namespace

Request table_query() {
  Message result(get_table, request_flag | ack_flag, 1, "lookup nftables inet table zetta_mesh");
  result.string(Table::name, "zetta_mesh");
  return result.finish();
}

Batch capture_batch() {
  Batch result;
  result.requests.push_back(
      Message(batch_begin, request_flag, 2, "begin nftables batch", true).finish());
  Message table(new_table, request_flag | ack_flag | create_exclusive, 3,
                "create nftables table zetta_mesh");
  table.string(Table::name, "zetta_mesh");
  result.requests.push_back(table.finish());
  result.requests.push_back(chain(4, "outbound", 3));
  result.requests.push_back(chain(5, "inbound", 0));
  result.requests.push_back(rule(6, "outbound", outbound_port, true));
  result.requests.push_back(rule(7, "inbound", inbound_port, false));
  result.requests.push_back(
      Message(batch_end, request_flag, 8, "end nftables batch", true).finish());
  for (const auto &request : result.requests) {
    result.bytes.insert(result.bytes.end(), request.bytes.begin(), request.bytes.end());
  }
  return result;
}

Replies::Replies(std::span<const Request> requests, bool table_query) : table_query_(table_query) {
  for (const auto &request : requests) {
    requests_.emplace(request.sequence, request);
    remaining_ += request.acknowledgement;
  }
}

void Replies::consume(std::span<const std::byte> datagram) {
  if (datagram.empty()) {
    throw std::runtime_error("empty nftables netlink reply");
  }
  while (!datagram.empty()) {
    const auto size = read<std::uint32_t>(datagram, 0);
    if (size < header_size || size > datagram.size() || aligned(size) > datagram.size()) {
      throw std::runtime_error("invalid nftables netlink message length");
    }
    consume_message(datagram.first(size));
    datagram = datagram.subspan(aligned(size));
  }
}

void Replies::consume_message(std::span<const std::byte> message) {
  const auto sequence = read<std::uint32_t>(message, 8);
  auto found = requests_.find(sequence);
  if (found == requests_.end()) {
    throw std::runtime_error("unexpected nftables reply sequence=" + std::to_string(sequence));
  }
  auto &request = found->second;
  const auto type = read<std::uint16_t>(message, 4);
  if (table_query_ && type == new_table) {
    if (message.size() < 20 || read<std::uint8_t>(message, 16) != inet_family) {
      throw std::runtime_error("unexpected nftables table reply family");
    }
    // The named GETTABLE request is complete only after its matching success ACK.
    return;
  }
  if (type != 2 || message.size() < 36) { // NLMSG_ERROR contains struct nlmsgerr.
    throw std::runtime_error(request.operation + ": malformed nftables acknowledgement");
  }
  if (read<std::uint32_t>(message, 28) != sequence ||
      read<std::uint16_t>(message, 24) != request.type) {
    throw std::runtime_error(request.operation + ": mismatched echoed nftables request");
  }
  const auto error = read<std::int32_t>(message, 16);
  const auto detail = extended_error(message, error);
  if (error > 0 || error < -4095) {
    throw std::runtime_error(request.operation + ": invalid netlink error code");
  }
  // ENOENT is 2 in the Linux UAPI, independent of the host running these tests.
  if (error != 0 && !(table_query_ && error == -2)) {
    throw std::runtime_error(request.operation + ": netlink_error=" + std::to_string(error) + " (" +
                             std::strerror(-error) + ") sequence=" + std::to_string(sequence) +
                             " type=" + std::to_string(request.type) + detail);
  }
  if (!request.acknowledgement) {
    throw std::runtime_error(request.operation + ": duplicate or unrequested acknowledgement");
  }
  request.acknowledgement = false;
  --remaining_;
  if (table_query_) {
    table_present_ = error == 0;
  }
}

bool Replies::complete() const {
  return remaining_ == 0;
}

bool Replies::table_present() const {
  if (!table_query_ || !complete()) {
    throw std::logic_error("incomplete nftables table lookup");
  }
  return table_present_;
}

std::string Replies::pending() const {
  std::string result;
  for (const auto &[sequence, request] : requests_) {
    if (request.acknowledgement) {
      if (!result.empty()) {
        result += ", ";
      }
      result += request.operation + " sequence=" + std::to_string(sequence);
    }
  }
  return result;
}

} // namespace zetta_tunnel::mesh::netlink
