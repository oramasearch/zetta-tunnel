#include "tunnel.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

namespace tunnel = zetta_tunnel::tunnel;

void require(bool value) {
  if (!value) {
    throw std::runtime_error("configuration assertion failed");
  }
}

template <typename Function> void refuses(Function function) {
  bool refused = false;
  try {
    function();
  } catch (const std::exception &) {
    refused = true;
  }
  require(refused);
}

void test_dates() {
  require(tunnel::parse_time("2026-10-14T12:00:00Z") ==
          tunnel::parse_time("2026-10-14T14:00:00+02:00"));
  require(tunnel::format_time(tunnel::parse_time("2026-10-14T12:00:00.125Z")) ==
          "2026-10-14T12:00:00Z");
  for (const auto *value :
       {"", "2026-02-30T00:00:00Z", "2026-10-14T25:00:00Z", "2026-10-14T00:00:00",
        "2026-10-14T00:00:00.Z", "2026-10-14T00:00:00+24:00", "2026-10-14T00:00:00Zjunk"}) {
    refuses([value] {
      tunnel::parse_time(value);
    });
  }
}

void test_addresses() {
  const auto address = tunnel::parse_address("[::1]:5432");
  require(address.host == "::1" && address.port == 5432);
  for (const auto *value :
       {"", "host", "host:0", "host:65536", "host:123x", "host:1:2", "host name:4", "host\n:5"}) {
    refuses([value] {
      tunnel::parse_address(value);
    });
  }
}

void test_grants(const std::filesystem::path &path) {
  const std::string fingerprint(64, 'a');
  const std::string upper(64, 'A');
  const std::string grant =
      R"({"id":"11111111-1111-4111-8111-111111111111","workspace":"workspace-test","endpoint":"host:1234","expires_at":"2026-10-14T12:00:00Z","client_ca_sha256":[")" +
      fingerprint + R"("]})";
  // A grant must name the customer CAs that may sign for it (LSR-074).
  auto with_cas = [](const std::string &cas) {
    return R"({"grants":[{"id":"11111111-1111-4111-8111-111111111111","workspace":"workspace-test","endpoint":"host:1234","expires_at":"2026-10-14T12:00:00Z")" +
           cas + "}]}";
  };
  auto write = [&path](const std::string &data) {
    std::ofstream file(path);
    file << data;
  };
  write("{\"grants\":[" + grant + "]}");
  const auto grants = tunnel::read_grants(path);
  require(grants.size() == 1 &&
          grants.begin()->second.client_ca_sha256 == std::vector<std::string>{fingerprint});
  write("{\"grants\":[]}");
  require(tunnel::read_grants(path).empty());
  const std::vector<std::string> invalid = {
      "",
      "null",
      "[]",
      "{}",
      "{\"grants\":null}",
      "{\"grants\":[{}]}",
      "{\"grants\":[],\"grants\":[]}",
      "{\"grants\":[],\"extra\":true}",
      "{\"grants\":[" + grant + "," + grant + "]}",
      "{\"grants\":[[[[[[[[[[[[]]]]]]]]]]]]}",
      std::string(1024 * 1024 + 1, ' '),
      with_cas(""),
      with_cas(R"(,"client_ca_sha256":[])"),
      with_cas(R"(,"client_ca_sha256":")" + fingerprint + "\""),
      with_cas(R"(,"client_ca_sha256":[")" + fingerprint.substr(1) + "\"]"),
      with_cas(R"(,"client_ca_sha256":[")" + upper + "\"]"),
      with_cas(R"(,"client_ca_sha256":[")" + fingerprint + "\",\"" + fingerprint + "\"]")};
  for (const auto &data : invalid) {
    write(data);
    refuses([&] {
      tunnel::read_grants(path);
    });
  }
}

void test_flags() {
  auto parse = [](std::vector<std::string> values) {
    std::vector<char *> args;
    for (auto &value : values) {
      args.push_back(value.data());
    }
    return tunnel::parse_options(args);
  };
  const std::vector<std::string> base = {"client", "--cert", "cert",    "--key",     "key",
                                         "--ca",   "ca",     "--relay", "relay:7443"};
  require(parse(base).listen == "127.0.0.1:5433");
  for (const auto &extra :
       std::vector<std::vector<std::string>>{{"--listen", "0.0.0.0:5433"},
                                             {"--target", "other:5432"},
                                             {"--cert", "again"},
                                             {"--listen"},
                                             {"--max-sessions", "0"},
                                             {"--max-sessions", "99999999999999"}}) {
    auto values = base;
    values.insert(values.end(), extra.begin(), extra.end());
    refuses([&] {
      parse(values);
    });
  }
}

} // namespace

int main() {
  // CTest runs this in its build directory; no user configuration is touched.
  const auto path = std::filesystem::current_path() / "tunnel-config-test.json";
  try {
    test_dates();
    test_addresses();
    test_grants(path);
    test_flags();
    std::filesystem::remove(path);
    std::cout << "configuration validation passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::filesystem::remove(path);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
