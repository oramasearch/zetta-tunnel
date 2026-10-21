#include "mesh.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

namespace mesh = zetta_tunnel::mesh;

void require(bool value) {
  if (!value) {
    throw std::runtime_error("mesh configuration assertion failed");
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

std::string valid_configuration() {
  return R"({"mesh":{"node":"node-a","workloads":[{"identity":"api.workspace.test","network_namespace":"/proc/123/ns/net","tls":{"certificate":"api.pem","key":"api.key","ca":"workload-ca.pem"},"routes":[{"destination":"10.1.0.20:8080","mesh":"10.1.0.20:15008","identity":"worker.workspace.test"}],"ports":[{"port":8080,"target":"127.0.0.1:8080","sources":["frontend.workspace.test"]}]}]}})";
}

void test_configuration(const std::filesystem::path &path) {
  auto write = [&path](const std::string &data) {
    std::ofstream output(path);
    output << data;
  };
  write(valid_configuration());
  const auto configuration = mesh::read_configuration(path);
  require(configuration.node == "node-a");
  require(configuration.workloads.size() == 1);
  require(configuration.workloads.front().identity == "api.workspace.test");
  require(configuration.workloads.front().routes.front().destination == "10.1.0.20:8080");
  require(configuration.workloads.front().ports.front().sources.front() ==
          "frontend.workspace.test");
  // A reload keeps a running workload only when nothing about it changed (LSR-178).
  const auto &workload = configuration.workloads.front();
  require(mesh::same_workload(workload, workload));
  auto changed = workload;
  changed.routes.front().identity = "other.workspace.test";
  require(!mesh::same_workload(workload, changed));
  changed = workload;
  changed.tls.private_key = "rotated.key";
  require(!mesh::same_workload(workload, changed));
  changed = workload;
  changed.network_namespace = "/proc/456/ns/net";
  require(!mesh::same_workload(workload, changed));
  changed = workload;
  changed.ports.front().sources.push_back("extra.workspace.test");
  require(!mesh::same_workload(workload, changed));
  const std::vector<std::string> invalid = {
      "",
      "null",
      "{}",
      R"({"mesh":{"node":"node-a","workloads":[],"extra":true}})",
      R"({"mesh":{"node":"Node_A","workloads":[]}})",
      R"({"mesh":{"node":"node-a","workloads":[{"identity":"api.workspace.test","network_namespace":"/proc/123/ns/net","tls":{"certificate":"api.pem","key":"api.key","ca":"workload-ca.pem"},"routes":[{"destination":"service.test:8080","mesh":"10.1.0.20:15008","identity":"worker.workspace.test"}],"ports":[]}]}})",
      R"({"mesh":{"node":"node-a","workloads":[{"identity":"api.workspace.test","network_namespace":"/proc/123/ns/net","tls":{"certificate":"api.pem","key":"api.key","ca":"workload-ca.pem"},"routes":[],"ports":[{"port":8080,"target":"127.0.0.1:9090","sources":["frontend.workspace.test"]}]}]}})",
      R"({"mesh":{"node":"node-a","workloads":[{"identity":"api.workspace.test","network_namespace":"/proc/123/ns/net","tls":{"certificate":"api.pem","key":"api.key","ca":"workload-ca.pem"},"routes":[],"ports":[{"port":8080,"target":"127.0.0.1:8080","sources":[]}]}]}})",
      std::string(1024 * 1024 + 1, ' '),
  };
  for (const auto &value : invalid) {
    write(value);
    refuses([&] {
      mesh::read_configuration(path);
    });
  }
}

void test_flags() {
  auto parse = [](std::vector<std::string> values) {
    std::vector<char *> arguments;
    for (auto &value : values) {
      arguments.push_back(value.data());
    }
    return mesh::parse_options(arguments);
  };
  const std::vector<std::string> base = {"mesh", "--configuration", "mesh.json"};
  require(parse(base).max_sessions == 128);
  require(parse(base).setup_timeout == 10);
  require(parse(base).idle_timeout == 900);
  require(parse(base).max_workload_sessions == 128);
  {
    auto values = base;
    values.insert(values.end(), {"--max-sessions", "64", "--max-workload-sessions", "16",
                                 "--idle-timeout", "60"});
    const auto options = parse(values);
    require(options.max_sessions == 64 && options.max_workload_sessions == 16 &&
            options.idle_timeout == 60);
    values = base;
    values.insert(values.end(), {"--max-sessions", "64"});
    require(parse(values).max_workload_sessions == 64);
  }
  for (const auto &extra :
       std::vector<std::vector<std::string>>{{"--configuration", "again"},
                                             {"--max-sessions", "0"},
                                             {"--setup-timeout", "61"},
                                             {"--max-workload-sessions", "0"},
                                             {"--max-workload-sessions", "129"},
                                             {"--idle-timeout", "0"},
                                             {"--idle-timeout", "86401"},
                                             {"--health-listen", "health.test:8080"},
                                             {"--unknown", "value"}}) {
    auto values = base;
    values.insert(values.end(), extra.begin(), extra.end());
    refuses([&] {
      parse(values);
    });
  }
}

} // namespace

int main() {
  const auto path = std::filesystem::current_path() / "mesh-config-test.json";
  try {
    test_configuration(path);
    test_flags();
    std::filesystem::remove(path);
    std::cout << "mesh projection and flags validation passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::filesystem::remove(path);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
