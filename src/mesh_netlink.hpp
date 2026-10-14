#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <vector>

namespace zetta_tunnel::mesh::netlink {

inline constexpr std::uint16_t outbound_port = 15001;
inline constexpr std::uint16_t inbound_port = 15008;
inline constexpr std::uint32_t bypass_mark = 0x5a54544d;

struct Request {
  std::vector<std::byte> bytes;
  std::uint32_t sequence;
  std::uint16_t type;
  std::string operation;
  bool acknowledgement;
};

struct Batch {
  std::vector<std::byte> bytes;
  std::vector<Request> requests;
};

Request table_query();
Batch capture_batch();

// Socket-independent decoding: only an ACK for the matching request advances completion.
// Unknown, duplicate, truncated and malformed replies fail closed.
class Replies {
public:
  explicit Replies(std::span<const Request> requests, bool table_query = false);
  void consume(std::span<const std::byte> datagram);
  bool complete() const;
  bool table_present() const;
  std::string pending() const;

private:
  void consume_message(std::span<const std::byte> message);
  std::map<std::uint32_t, Request> requests_;
  std::size_t remaining_ = 0;
  bool table_query_;
  bool table_present_ = false;
};

} // namespace zetta_tunnel::mesh::netlink
