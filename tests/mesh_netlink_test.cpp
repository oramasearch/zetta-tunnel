// SPDX-License-Identifier: MIT

#include "mesh.hpp"
#include "mesh_netlink.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <bit>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace {
namespace netlink = zetta_tunnel::mesh::netlink;
using Bytes = std::vector<std::byte>;

void require(bool condition, std::string_view description) {
  if (!condition) {
    throw std::runtime_error(std::string(description));
  }
}

template <typename Function> std::string refuses(Function function, std::string_view expected) {
  try {
    function();
  } catch (const std::exception &error) {
    require(std::string_view(error.what()).contains(expected), error.what());
    return error.what();
  }
  throw std::runtime_error("expected refusal: " + std::string(expected));
}

Bytes hex(std::string_view text) {
  std::istringstream input{std::string(text)};
  Bytes bytes;
  std::string word;
  while (input >> word) {
    require(word.size() % 2 == 0, "invalid hex fixture");
    for (std::size_t offset = 0; offset < word.size(); offset += 2) {
      bytes.push_back(static_cast<std::byte>(std::stoul(word.substr(offset, 2), nullptr, 16)));
    }
  }
  return bytes;
}

Bytes fixture(const std::filesystem::path &directory, std::string_view name) {
  std::ifstream input(directory / name);
  require(static_cast<bool>(input), "missing wire fixture");
  std::ostringstream data;
  data << input.rdbuf();
  return hex(data.str());
}

template <typename T> void put(Bytes &bytes, std::size_t offset, T value) {
  require(offset + sizeof(value) <= bytes.size(), "test write out of bounds");
  std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void append(Bytes &target, const Bytes &source) {
  target.insert(target.end(), source.begin(), source.end());
}

void equal_bytes(const Bytes &actual, const Bytes &expected, std::string_view name) {
  for (std::size_t index = 0; index < std::min(actual.size(), expected.size()); ++index) {
    if (actual[index] != expected[index]) {
      throw std::runtime_error(
          std::string(name) + " byte=" + std::to_string(index) +
          " actual=" + std::to_string(std::to_integer<unsigned>(actual[index])) +
          " expected=" + std::to_string(std::to_integer<unsigned>(expected[index])));
    }
  }
  require(actual.size() == expected.size(),
          std::string(name) + " byte count actual=" + std::to_string(actual.size()) +
              " expected=" + std::to_string(expected.size()));
}

Bytes acknowledgement(const netlink::Request &request, std::int32_t error = 0) {
  Bytes bytes(36, std::byte{});
  put<std::uint32_t>(bytes, 0, 36);
  put<std::uint16_t>(bytes, 4, 2);     // NLMSG_ERROR
  put<std::uint16_t>(bytes, 6, 0x100); // NLM_F_CAPPED
  put(bytes, 8, request.sequence);
  put(bytes, 16, error);
  std::copy_n(request.bytes.begin(), 16, bytes.begin() + 20);
  return bytes;
}

void wire_layouts(const std::filesystem::path &directory) {
  // The shipped architecture (amd64) and the macOS proof host are little endian.
  // Native-endian netlink headers and mark data make these fixtures architecture-specific.
  require(std::endian::native == std::endian::little, "wire fixtures require a little-endian host");
  require(netlink::table_query().bytes == fixture(directory, "query.hex"), "table query layout");
  const auto batch = netlink::capture_batch();
  const std::vector<std::string> names = {"begin.hex",
                                          "table.hex",
                                          "outbound-chain.hex",
                                          "inbound-chain.hex",
                                          "outbound-rule.hex",
                                          "inbound-rule.hex",
                                          "end.hex"};
  require(batch.requests.size() == names.size(), "batch request count");
  Bytes expected;
  for (std::size_t index = 0; index < names.size(); ++index) {
    const auto reference = fixture(directory, names[index]);
    equal_bytes(batch.requests[index].bytes, reference, names[index]);
    require(batch.requests[index].acknowledgement == (index > 0 && index < 6), "ACK flags");
    append(expected, reference);
  }
  require(batch.bytes == expected, "begin, mutations and end must share one datagram");
}

void success_replies() {
  const auto batch = netlink::capture_batch();
  netlink::Replies replies(batch.requests);
  require(!replies.complete(), "batch starts pending");
  require(replies.pending().contains("create nftables outbound rule sequence=6"),
          "pending context");
  // Multiple ACKs per datagram, out-of-order arrival, and replies split across datagrams.
  Bytes first = acknowledgement(batch.requests[5]);
  append(first, acknowledgement(batch.requests[2]));
  replies.consume(first);
  require(!replies.complete(), "partial ACKs must not mark capture ready");
  replies.consume(acknowledgement(batch.requests[1]));
  replies.consume(acknowledgement(batch.requests[3]));
  require(!replies.complete(), "one mutation still pending");
  replies.consume(acknowledgement(batch.requests[4]));
  require(replies.complete() && replies.pending().empty(), "all matching ACKs complete");
  refuses(
      [&] {
        replies.consume(acknowledgement(batch.requests[4]));
      },
      "duplicate");
}

void query_replies() {
  const auto query = netlink::table_query();
  netlink::Replies absent(std::span(&query, 1), true);
  absent.consume(acknowledgement(query, -2));
  require(absent.complete() && !absent.table_present(), "only ENOENT means table absent");
  netlink::Replies present(std::span(&query, 1), true);
  auto data = query.bytes;
  put<std::uint16_t>(data, 4, 0xa00);
  present.consume(data);
  require(!present.complete(), "consume lookup ACK after the table data");
  refuses(
      [&] {
        static_cast<void>(present.table_present());
      },
      "incomplete");
  present.consume(acknowledgement(query));
  require(present.complete() && present.table_present(), "existing table consumes matching ACK");
  netlink::Replies denied(std::span(&query, 1), true);
  refuses(
      [&] {
        denied.consume(acknowledgement(query, -1));
      },
      "netlink_error=-1");
  require(!denied.complete(), "lookup permission failure must not create a table");
}

void kernel_errors() {
  const auto batch = netlink::capture_batch();
  for (const auto &request : batch.requests) {
    netlink::Replies replies(batch.requests);
    const auto detail = refuses(
        [&] {
          replies.consume(acknowledgement(request, -22));
        },
        request.operation);
    require(detail.contains("netlink_error=-22 (" + std::string(std::strerror(22)) + ")"),
            "kernel error code and message");
    require(detail.contains("sequence=" + std::to_string(request.sequence)) &&
                detail.contains("type=" + std::to_string(request.type)),
            "failed request correlation");
    require(!replies.complete(), "batch/table/chain/rule errors keep capture unready");
  }
  const auto &request = batch.requests[4];
  auto error = acknowledgement(request, -22);
  put<std::uint16_t>(error, 6, 0x300); // Capped original header + extended ACK attributes.
  append(error, hex("0d000100 6261640a72756c65 00000000")); // "bad\nrule" + NUL/padding
  append(error, hex("08000200 34000000"));
  put<std::uint32_t>(error, 0, static_cast<std::uint32_t>(error.size()));
  netlink::Replies capped(batch.requests);
  refuses(
      [&] {
        capped.consume(error);
      },
      "kernel_message=bad?rule");
  netlink::Replies offset(batch.requests);
  refuses(
      [&] {
        offset.consume(error);
      },
      "attribute_offset=52");

  auto uncapped = acknowledgement(request, -95);
  put<std::uint16_t>(uncapped, 6, 0x200);
  uncapped.insert(uncapped.end(), request.bytes.begin() + 16, request.bytes.end());
  append(uncapped, hex("08000200 34000000"));
  put<std::uint32_t>(uncapped, 0, static_cast<std::uint32_t>(uncapped.size()));
  netlink::Replies full(batch.requests);
  refuses(
      [&] {
        full.consume(uncapped);
      },
      "attribute_offset=52");
}

void malformed_replies() {
  const auto batch = netlink::capture_batch();
  const auto valid = acknowledgement(batch.requests[1]);
  for (std::size_t size = 0; size < valid.size(); ++size) {
    netlink::Replies replies(batch.requests);
    refuses(
        [&] {
          replies.consume(std::span(valid).first(size));
        },
        "nftables");
  }
  auto wrong_sequence = valid;
  put<std::uint32_t>(wrong_sequence, 8, 1);
  netlink::Replies stale(batch.requests);
  refuses(
      [&] {
        stale.consume(wrong_sequence);
      },
      "unexpected nftables reply sequence=1");
  auto wrong_echo = valid;
  put<std::uint32_t>(wrong_echo, 28, 42);
  netlink::Replies echo(batch.requests);
  refuses(
      [&] {
        echo.consume(wrong_echo);
      },
      "mismatched echoed");
  auto wrong_type = valid;
  put<std::uint16_t>(wrong_type, 24, 0xa06);
  netlink::Replies type(batch.requests);
  refuses(
      [&] {
        type.consume(wrong_type);
      },
      "mismatched echoed");
  auto invalid_code = valid;
  put<std::int32_t>(invalid_code, 16, std::numeric_limits<std::int32_t>::min());
  netlink::Replies code(batch.requests);
  refuses(
      [&] {
        code.consume(invalid_code);
      },
      "invalid netlink error");
  auto malformed_attribute = valid;
  put<std::uint16_t>(malformed_attribute, 6, 0x300);
  append(malformed_attribute, hex("ffff0100"));
  put<std::uint32_t>(malformed_attribute, 0,
                     static_cast<std::uint32_t>(malformed_attribute.size()));
  netlink::Replies attribute(batch.requests);
  refuses(
      [&] {
        attribute.consume(malformed_attribute);
      },
      "extended acknowledgement attribute");
}

void safe_diagnostics() {
  namespace mesh = zetta_tunnel::mesh;
  try {
    static_cast<void>(nlohmann::json::parse("{\"secret\":\"DO_NOT_LOG\",BAD_TOKEN}"));
    require(false, "invalid JSON must fail");
  } catch (const nlohmann::json::parse_error &error) {
    const auto detail = mesh::failure_detail(error);
    require(detail.contains("parse error id=") && detail.contains("byte="), "parse location");
    require(!detail.contains("DO_NOT_LOG") && !detail.contains("BAD_TOKEN"), "no input in log");
  }
  try {
    static_cast<void>(nlohmann::json("DO_NOT_LOG").get<unsigned>());
  } catch (const nlohmann::json::exception &error) {
    const auto detail = mesh::failure_detail(error);
    require(detail.contains("schema error id=") && !detail.contains("DO_NOT_LOG"),
            "safe schema error");
  }
  const std::filesystem::filesystem_error error("open", "/DO_NOT_LOG",
                                                std::make_error_code(std::errc::permission_denied));
  const auto detail = mesh::failure_detail(error);
  require(detail.contains("system_error=") && !detail.contains("DO_NOT_LOG"), "safe file error");
  require(mesh::failure_detail(std::runtime_error("fixed\noperation")) == "fixed?operation",
          "one log line");
  require(mesh::failure_detail(std::runtime_error(std::string(3000, 'x'))).size() == 1024,
          "bounded error");
}

} // namespace

int main(int argc, char **argv) {
  try {
    require(argc == 2, "fixture directory required");
    wire_layouts(argv[1]);
    success_replies();
    query_replies();
    kernel_errors();
    malformed_replies();
    safe_diagnostics();
    std::cout << "mesh netlink wire layouts, acknowledgements and safe diagnostics passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
