// SPDX-License-Identifier: MIT

#include "peer.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

namespace peer = zetta_tunnel::peer;

void require(bool value) {
  if (!value) {
    throw std::runtime_error("peer configuration assertion failed");
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

void test_names() {
  require(peer::normalize_service_name("writer.database") == "writer.database");
  for (const auto *name : {"", ".", "Writer", "bad..name", "-bad", "bad_"}) {
    refuses([name] {
      peer::normalize_service_name(name);
    });
  }
}

void test_configuration(const std::filesystem::path &path) {
  const std::string valid =
      R"({"peer":{"id":"11111111-1111-4111-8111-111111111111","workspace":"workspace-test","remote":"127.0.0.1:7446","imports":[{"name":"remote.writer","port":5432,"listen":"127.0.0.1:15432"}],"exports":[{"name":"local.writer","port":5432,"target":"127.0.0.1:5432"}]}})";
  auto write = [&path](const std::string &data) {
    std::ofstream file(path);
    file << data;
  };
  write(valid);
  const auto configuration = peer::read_configuration(path);
  require(configuration.id == "11111111-1111-4111-8111-111111111111");
  require(configuration.imports.size() == 1);
  require(configuration.exports.size() == 1);
  const std::vector<std::string> invalid = {
      "",
      "null",
      "{}",
      R"({"peer":null})",
      R"({"peer":{},"peer":{}})",
      R"({"peer":{"id":"bad","workspace":"workspace-test","remote":"127.0.0.1:7446","imports":[],"exports":[]}})",
      R"({"peer":{"id":"11111111-1111-4111-8111-111111111111","workspace":"workspace-test","remote":"127.0.0.1:7446","imports":[{"name":"writer","port":5432,"listen":"localhost:15432"}],"exports":[]}})",
      R"({"peer":{"id":"11111111-1111-4111-8111-111111111111","workspace":"workspace-test","remote":"127.0.0.1:7446","imports":[{"name":"writer","port":5432,"listen":"127.0.0.1:15432"},{"name":"writer","port":5432,"listen":"127.0.0.1:25432"}],"exports":[]}})",
      R"({"peer":{"id":"11111111-1111-4111-8111-111111111111","workspace":"workspace-test","remote":"127.0.0.1:7446","imports":[],"exports":[{"name":"writer","port":0,"target":"127.0.0.1:5432"}]}})",
      std::string(1024 * 1024 + 1, ' '),
  };
  for (const auto &data : invalid) {
    write(data);
    refuses([&] {
      peer::read_configuration(path);
    });
  }
}

void test_flags() {
  auto parse = [](std::vector<std::string> values) {
    std::vector<char *> args;
    for (auto &value : values) {
      args.push_back(value.data());
    }
    return peer::parse_options(args);
  };
  const std::vector<std::string> base = {
      "peer", "--configuration", "peer.json",   "--cert",      "cert.pem", "--key", "key.pem",
      "--ca", "ca.pem",          "--peer-name", "peer-b.test",
  };
  require(parse(base).listen == "0.0.0.0:7446");
  require(parse(base).max_sessions == 128);
  for (const auto &extra : std::vector<std::vector<std::string>>{{"--listen", "hostname:7446"},
                                                                 {"--configuration", "again"},
                                                                 {"--listen"},
                                                                 {"--max-sessions", "0"},
                                                                 {"--max-pending-sessions", "0"},
                                                                 {"--max-pending-sessions", "4097"},
                                                                 {"--max-pending-per-source", "0"},
                                                                 {"--max-pending-per-source", "-1"},
                                                                 {"--peer-name", "bad_name"}}) {
    auto values = base;
    values.insert(values.end(), extra.begin(), extra.end());
    refuses([&] {
      parse(values);
    });
  }
}

} // namespace

int main() {
  const auto path = std::filesystem::current_path() / "peer-config-test.json";
  try {
    test_names();
    test_configuration(path);
    test_flags();
    std::filesystem::remove(path);
    std::cout << "peer configuration validation passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::filesystem::remove(path);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
