// SPDX-License-Identifier: MIT

#include "admission.hpp"
#include "tunnel_io.hpp"

#include <boost/corosio/tcp.hpp>

#include <filesystem>
#include <stdexcept>

using namespace zetta_tunnel;

void check(bool condition) {
  if (!condition) {
    throw std::runtime_error("admission invariant failed");
  }
}

int main(int argc, char **argv) {
  if (argc == 2) {
    const std::filesystem::path directory(argv[1]);
    auto context = tunnel::load_credentials(
        {directory / "relay.pem", directory / "relay.key", directory / "tunnel-ca.pem"});
    // Every stream must reuse the already loaded snapshot, without filesystem reads.
    std::filesystem::remove(directory / "relay.pem");
    std::filesystem::remove(directory / "relay.key");
    std::filesystem::remove(directory / "tunnel-ca.pem");
    tunnel::corosio::io_context io;
    for (int count = 0; count < 2; ++count) {
      tunnel::corosio::tcp_socket socket(io);
      socket.open(tunnel::corosio::tcp::v4());
      tunnel::SecureStream stream(socket, context, true, "");
    }
    bool refused = false;
    try {
      static_cast<void>(tunnel::load_credentials(
          {directory / "relay.pem", directory / "relay.key", directory / "tunnel-ca.pem"}));
    } catch (const std::exception &) {
      refused = true;
    }
    check(refused);
    return 0;
  }
  Admission admission(2, 3, 2, 1);
  auto a = admission.acquire("a");
  auto b = admission.acquire("a");
  check(a && b && !admission.acquire("a"));
  auto c = admission.acquire("b");
  check(c && !admission.acquire("c"));
  check(a->promote());
  check(!b->promote());
  auto d = admission.acquire("c");
  check(d != nullptr);
  check(c->promote());
  // Already pending sockets cannot overbook active capacity during promotion.
  check(!d->promote() && !admission.acquire("d"));
  a.reset();
  check(b->promote());
  c.reset();
  check(d->promote());
  b.reset();
  d.reset();
  for (int count = 0; count < 100; ++count) {
    auto ticket = admission.acquire(std::to_string(count));
    check(ticket && ticket->promote());
  }
}
