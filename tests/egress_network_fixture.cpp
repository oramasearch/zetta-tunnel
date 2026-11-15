// Loaded only into integration-test gateway processes. Synthetic DNS answers stay numeric;
// connect redirects the public fixture address to a local echo server and records every attempt.
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

namespace {
constexpr const char *public_fixture = "93.184.216.34";

int fixture_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
                        addrinfo **result) {
#ifdef __APPLE__
  // dyld does not interpose calls from the interposing image, so this is the real getaddrinfo.
  static auto real = &::getaddrinfo;
#else
  static auto real = reinterpret_cast<decltype(&getaddrinfo)>(dlsym(RTLD_NEXT, "getaddrinfo"));
#endif
  if (!node || std::strcmp(node, "localhost") != 0) {
    return real(node, service, hints, result);
  }
  const auto *configured = std::getenv("EGRESS_TEST_DNS");
  std::string answers = configured ? configured : public_fixture;
  if (const auto *path = std::getenv("EGRESS_TEST_DNS_FILE")) {
    std::ifstream input(path);
    std::getline(input, answers);
  }
  *result = nullptr;
  auto **tail = result;
  std::size_t start = 0;
  while (start < answers.size()) {
    const auto end = answers.find(',', start);
    const auto value = answers.substr(start, end == std::string::npos ? end : end - start);
    addrinfo numeric = hints ? *hints : addrinfo{};
    numeric.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    numeric.ai_family = AF_UNSPEC;
    addrinfo *entry = nullptr;
    const auto error = real(value.c_str(), service, &numeric, &entry);
    if (error) {
      if (*result) {
        freeaddrinfo(*result);
        *result = nullptr;
      }
      return error;
    }
    *tail = entry;
    while (*tail) {
      tail = &(*tail)->ai_next;
    }
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  return *result ? 0 : EAI_NONAME;
}

int fixture_connect(int socket, const sockaddr *address, socklen_t size) {
#ifdef __APPLE__
  // dyld does not interpose calls from the interposing image, so this is the real connect.
  static auto real = &::connect;
#else
  static auto real = reinterpret_cast<decltype(&connect)>(dlsym(RTLD_NEXT, "connect"));
#endif
  if (const auto *path = std::getenv("EGRESS_TEST_CONNECT_LOG")) {
    std::ofstream(path, std::ios::app) << "connect\n";
  }
  if (address->sa_family == AF_INET) {
    auto local = *reinterpret_cast<const sockaddr_in *>(address);
    in_addr fixture{};
    inet_pton(AF_INET, public_fixture, &fixture);
    if (local.sin_addr.s_addr == fixture.s_addr) {
      inet_pton(AF_INET, "127.0.0.1", &local.sin_addr);
      return real(socket, reinterpret_cast<const sockaddr *>(&local), sizeof(local));
    }
    // An unfixed gateway can reach the local echo fixture, but never an external host.
    if ((ntohl(local.sin_addr.s_addr) >> 24) == 127) {
      return real(socket, address, size);
    }
  }
  errno = ECONNREFUSED;
  return -1;
}
} // namespace

#ifdef __APPLE__
__attribute__((used, section("__DATA,__interpose"))) static const struct {
  const void *replacement;
  const void *original;
} interpositions[] = {
    {reinterpret_cast<const void *>(fixture_getaddrinfo),
     reinterpret_cast<const void *>(getaddrinfo)},
    {reinterpret_cast<const void *>(fixture_connect), reinterpret_cast<const void *>(connect)}};
#else
extern "C" int getaddrinfo(const char *node, const char *service, const addrinfo *hints,
                           addrinfo **result) {
  return fixture_getaddrinfo(node, service, hints, result);
}
extern "C" int connect(int socket, const sockaddr *address, socklen_t size) {
  return fixture_connect(socket, address, size);
}
#endif
