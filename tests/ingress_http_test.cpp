#include "ingress.hpp"

#include <iostream>
#include <stdexcept>

namespace {
namespace ingress = zetta_tunnel::ingress;

void require(bool value) {
  if (!value) {
    throw std::runtime_error("ingress HTTP assertion failed");
  }
}

template <typename Function> void refuses(Function function) {
  bool denied = false;
  try {
    function();
  } catch (const std::exception &) {
    denied = true;
  }
  require(denied);
}

void requests() {
  const auto request = ingress::parse_head(
      "POST /api?q=secret HTTP/1.1\r\nHost: Lake.Test:443\r\nContent-Length: 42\r\n\r\n", true);
  require(request.host == "lake.test" && request.length == 42 && request.method == "POST");
  for (const auto *head :
       {"GET / HTTP/1.1\r\n\r\n", "GET / HTTP/1.1\r\nHost: lake.test\r\nHost: apps.test\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: lake.test\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: lake.test\r\nContent-Length: 1\r\nTransfer-Encoding: "
        "chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: lake.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: lake.test\r\n bad: folded\r\n\r\n",
        "GET / HTTP/1.1\r\nHost : lake.test\r\n\r\n",
        "GET https://other.test/ HTTP/1.1\r\nHost: lake.test\r\n\r\n",
        "CONNECT lake.test:443 HTTP/1.1\r\nHost: lake.test\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: lake.test\r\nContent-Length: -1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: lake.test\r\nContent-Length: 18446744073709551616\r\n\r\n"}) {
    refuses([head] {
      ingress::parse_head(head, true);
    });
  }
}

void routes() {
  ingress::Host host;
  for (const auto &[path, exact] : std::vector<std::pair<std::string, bool>>{
           {"/", false}, {"/api", false}, {"/api", true}, {"/api/v1", false}}) {
    ingress::Route route;
    route.path = path;
    route.exact = exact;
    host.routes.push_back(route);
  }
  require(ingress::match_route(host, "/api")->exact);
  require(ingress::match_route(host, "/apiculture")->path == "/");
  require(ingress::match_route(host, "/api/v1/users?x=1")->path == "/api/v1");
  require(ingress::match_route(host, "/%61pi/users")->path == "/api");
  for (const auto *path : {"/../", "/a/./b", "/%2e%2e/", "/api%2fsecret", "/%5c", "/%252f", "/%00",
                           "/a//b", "/%zz", "/a#b", "*"}) {
    refuses([path] {
      ingress::routing_path(path);
    });
  }
  const auto filtered = ingress::end_to_end({{"connection", "keep-alive, secret"},
                                             {"secret", "hidden"},
                                             {"content-type", "text/plain"},
                                             {"te", "trailers"}});
  require(filtered.size() == 1 && filtered[0].first == "content-type");
}

void flags() {
  auto parse = [](std::vector<std::string> values) {
    std::vector<char *> args;
    for (auto &value : values) {
      args.push_back(value.data());
    }
    return ingress::parse_options(args);
  };
  require(parse({"ingress", "--configuration", "routes.json"}).max_requests == 256);
  for (const auto &extra :
       std::vector<std::vector<std::string>>{{"--max-sessions", "0"},
                                             {"--max-requests", "4097"},
                                             {"--idle-timeout-seconds", "0"},
                                             {"--setup-timeout-seconds", "4294967297"},
                                             {"--listen", "localhost:8443"},
                                             {"--configuration", "second"},
                                             {"--unknown", "yes"},
                                             {"--audit"}}) {
    auto values = std::vector<std::string>{"ingress", "--configuration", "routes.json"};
    values.insert(values.end(), extra.begin(), extra.end());
    refuses([&] {
      parse(values);
    });
  }
}
} // namespace

int main() {
  try {
    requests();
    routes();
    flags();
    std::cout << "ingress HTTP, routes and flags validation passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
