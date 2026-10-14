#include <zetta_tunnel/version.hpp>

#include <cstdio>
#include <span>
#include <string_view>

// The CLI reports the build version. Network features consume the transport
// library; later issues add their own commands.
int main(int argc, char** argv) {
    const std::span args(argv + 1, static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (const char* raw : args) {
        const std::string_view arg(raw);
        if (arg == "--version") {
            std::printf("zetta-tunnel %s\n", zetta_tunnel::version);
            return 0;
        }
        std::fprintf(stderr, "zetta-tunnel: unknown argument %s\n", raw);
        return 2;
    }
    std::fprintf(stderr, "usage: zetta-tunnel --version\n");
    return 2;
}
