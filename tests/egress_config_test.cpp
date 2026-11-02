#include "egress.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

namespace egress = zetta_tunnel::egress;

void require(bool value) {
  if (!value) {
    throw std::runtime_error("egress configuration assertion failed");
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
  require(egress::normalize_dns_name("API.Example.COM.") == "api.example.com");
  require(egress::normalize_ip("127.0.0.1") == "127.0.0.1");
  for (const auto *name :
       {"", ".", "bad..name", "-bad.example", "bad_.example", "127.0.0.1", "::1"}) {
    refuses([name] {
      egress::normalize_dns_name(name);
    });
  }
  refuses([] {
    egress::normalize_ip("localhost");
  });
}

void test_rules(const std::filesystem::path &path) {
  const std::string rule =
      R"({"id":"11111111-1111-4111-8111-111111111111","workspace":"workspace-test","source_ips":["127.0.0.1","::1"],"dns_name":"LOCALHOST.","ports":[443,5432]})";
  auto write = [&path](const std::string &data) {
    std::ofstream file(path);
    file << data;
  };
  write("{\"rules\":[" + rule + "]}");
  const auto rules = egress::read_rules(path);
  require(rules.size() == 1);
  require(rules.begin()->second.dns_name == "localhost");
  auto with_denied = rule;
  with_denied.insert(with_denied.size() - 1, R"(,"denied_cidrs":["8.8.8.0/24","2606:4700::/32"])");
  write("{\"rules\":[" + with_denied + "]}");
  require(egress::read_rules(path).begin()->second.denied_cidrs.size() == 2);
  require(rules.begin()->second.denied_cidrs.empty());
  for (const auto *denied :
       {R"(null)", R"(["bad"])", R"(["10.0.0.1/8"])", R"(["::/129"])", R"([1])", R"({})"}) {
    auto invalid_rule = rule;
    invalid_rule.insert(invalid_rule.size() - 1, std::string(",\"denied_cidrs\":") + denied);
    write("{\"rules\":[" + invalid_rule + "]}");
    refuses([&] {
      egress::read_rules(path);
    });
  }
  write("{\"rules\":[]}");
  require(egress::read_rules(path).empty());
  auto second_rule = rule;
  second_rule.replace(second_rule.find("11111111-1111-4111-8111-111111111111"), 36,
                      "22222222-2222-4222-8222-222222222222");
  const std::vector<std::string> invalid = {"",
                                            "null",
                                            "[]",
                                            "{}",
                                            "{\"rules\":null}",
                                            "{\"rules\":[],\"rules\":[]}",
                                            "{\"rules\":[],\"extra\":true}",
                                            "{\"rules\":[{}]}",
                                            "{\"rules\":[" + rule + "," + rule + "]}",
                                            "{\"rules\":[" + rule + "," + second_rule + "]}",
                                            "{\"rules\":[[[[[[[[[[[[]]]]]]]]]]]]}",
                                            std::string(1024 * 1024 + 1, ' ')};
  for (const auto &data : invalid) {
    write(data);
    refuses([&] {
      egress::read_rules(path);
    });
  }
}

void test_flags() {
  auto parse = [](std::vector<std::string> values) {
    std::vector<char *> args;
    for (auto &value : values) {
      args.push_back(value.data());
    }
    return egress::parse_options(args);
  };
  const std::vector<std::string> base = {"egress", "--rules", "rules.json"};
  require(parse(base).listen == "0.0.0.0:7445");
  require(parse(base).sni_port == 443);
  for (const auto &extra :
       std::vector<std::vector<std::string>>{{"--listen", "hostname:7445"},
                                             {"--cert", "cert.pem"},
                                             {"--rules", "again"},
                                             {"--listen"},
                                             {"--max-sessions", "0"},
                                             {"--max-pending-sessions", "0"},
                                             {"--max-pending-per-source", "4097"},
                                             {"--sni-port", "65536"}}) {
    auto values = base;
    values.insert(values.end(), extra.begin(), extra.end());
    refuses([&] {
      parse(values);
    });
  }
}

} // namespace

int main() {
  const auto path = std::filesystem::current_path() / "egress-config-test.json";
  try {
    test_names();
    test_rules(path);
    test_flags();
    std::filesystem::remove(path);
    std::cout << "egress configuration validation passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::filesystem::remove(path);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
