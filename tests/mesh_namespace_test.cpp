// Exercise the production Linux namespace operations without requiring setns privileges.
#include "../src/mesh_linux.cpp"

#include <cstdarg>
#include <cstdlib>

namespace {

namespace mesh = zetta_tunnel::mesh;
constexpr std::string_view pod_uid = "11111111-2222-3333-4444-555555555555";
std::vector<ino_t> entered;
std::function<void()> namespace_open;

void require(bool value, std::string_view reason) {
  if (!value) {
    throw std::runtime_error(std::string(reason));
  }
}

template <typename Function> void refuses(Function function) {
  bool refused = false;
  try {
    function();
  } catch (const std::exception &) {
    refused = true;
  }
  require(refused, "changed workload identity was accepted");
}

// Also supports the original path-based Runtime for the unfixed-source proof.
template <typename Runtime> auto session_namespace(const Runtime &runtime) {
  if constexpr (requires { runtime.network_namespace; }) {
    return runtime.network_namespace;
  } else {
    return runtime.workload.network_namespace;
  }
}

template <typename Target> decltype(auto) namespace_target(const Target &target) {
  if constexpr (requires { *target; }) {
    return *target;
  } else {
    return (target);
  }
}

class Fixture {
public:
  Fixture() {
    std::string pattern =
        (std::filesystem::temp_directory_path() / "mesh-namespace-XXXXXX").string();
    const auto result = ::mkdtemp(pattern.data());
    require(result != nullptr, "create fixture directory");
    root = result;
    workload.network_namespace = root / "123/ns/net";
    workload.pod_uid = pod_uid;
    struct stat status{};
    require(::stat("/proc/self/ns/net", &status) == 0, "stat fixture namespace");
    workload.network_namespace_inode = status.st_ino;
    create_process(root / "123", "/proc/self/ns/net");
  }

  ~Fixture() {
    std::filesystem::remove_all(root);
  }

  void create_process(const std::filesystem::path &process, const std::filesystem::path &target) {
    std::filesystem::create_directories(process / "ns");
    std::filesystem::create_symlink(target, process / "ns/net");
    std::ofstream(process / "cgroup") << "0::/kubepods/burstable/pod" << pod_uid << "/container\n";
  }

  void cgroup(std::string_view value) {
    std::ofstream(root / "123/cgroup") << value;
  }

  std::filesystem::path root;
  mesh::Workload workload;
};

void identity() {
  Fixture fixture;
  {
    mesh::Runtime valid(fixture.workload);
  }
  fixture.cgroup("0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"
                 "11111111_2222_3333_4444_555555555555.slice/container.scope\n");
  {
    mesh::Runtime systemd(fixture.workload);
  }
  for (const auto &value :
       {"0::/kubepods/pod11111111-2222-3333-4444-555555555555-extra/container\n",
        "0::/kubepods/podaaaaaaaa-2222-3333-4444-555555555555/container\n",
        "0::/unrelated/container\n", "malformed\n", ""}) {
    fixture.cgroup(value);
    refuses([&] {
      mesh::Runtime runtime(fixture.workload);
    });
  }
  fixture.cgroup("0::/kubepods/pod11111111-2222-3333-4444-555555555555/container\n");
  ++fixture.workload.network_namespace_inode;
  refuses([&] {
    mesh::Runtime runtime(fixture.workload);
  });
  --fixture.workload.network_namespace_inode;
  std::filesystem::remove(fixture.workload.network_namespace);
  std::filesystem::create_symlink("/proc/self/ns/user", fixture.workload.network_namespace);
  struct stat status{};
  require(::stat("/proc/self/ns/user", &status) == 0, "stat wrong namespace type");
  fixture.workload.network_namespace_inode = status.st_ino;
  refuses([&] {
    mesh::Runtime runtime(fixture.workload);
  });
  std::filesystem::remove(fixture.workload.network_namespace);
  std::filesystem::create_symlink("/proc/self/ns/net", fixture.workload.network_namespace);
  require(::stat("/proc/self/ns/net", &status) == 0, "stat fixture namespace");
  fixture.workload.network_namespace_inode = status.st_ino;
  // Change membership after the first cgroup check; the second check must fail closed.
  namespace_open = [&] {
    fixture.cgroup("0::/unrelated/container\n");
  };
  refuses([&] {
    mesh::Runtime runtime(fixture.workload);
  });
  namespace_open = {};
  std::filesystem::remove(fixture.root / "123/cgroup");
  refuses([&] {
    mesh::Runtime runtime(fixture.workload);
  });
}

void pinning() {
  Fixture fixture;
  auto runtime = std::make_unique<mesh::Runtime>(fixture.workload);
  auto target = session_namespace(*runtime);
  // Replace the numeric process directory, as when a process path names a different generation.
  std::filesystem::rename(fixture.root / "123", fixture.root / "old-process");
  fixture.create_process(fixture.root / "123", "/proc/self/ns/user");
  // Sessions own their handle even after a runtime is withdrawn.
  runtime.reset();
  auto expect_pinned = [&](auto operation) {
    entered.clear();
    operation();
    require(entered.size() == 2, "operation must enter and restore the namespace");
    require(entered.front() == fixture.workload.network_namespace_inode,
            "stale process path changed the namespace used by an existing workload");
  };
  expect_pinned([&] {
    mesh::FileDescriptor socket(mesh::listener(namespace_target(target), "127.0.0.1", 0));
  });
  expect_pinned([&] {
    // Netlink socket creation is deliberately refused after namespace entry.
    refuses([&] {
      mesh::install_capture(namespace_target(target));
    });
  });
  mesh::FileDescriptor server(mesh::listener(namespace_target(target), "127.0.0.1", 0));
  sockaddr_in address{};
  socklen_t size = sizeof(address);
  require(::getsockname(server.get(), reinterpret_cast<sockaddr *>(&address), &size) == 0,
          "inspect fixture server");
  const auto destination = "127.0.0.1:" + std::to_string(ntohs(address.sin_port));
  expect_pinned([&] {
    mesh::FileDescriptor upstream(mesh::connect_marked(namespace_target(target), destination, 1));
  });
  std::filesystem::remove_all(fixture.root / "123");
  expect_pinned([&] {
    mesh::FileDescriptor socket(mesh::listener(namespace_target(target), "127.0.0.1", 0));
  });
  Fixture initial;
  // Retarget during the initial open: relative lookup must stay on the original directory.
  namespace_open = [&] {
    std::filesystem::rename(initial.root / "123", initial.root / "old-process");
    initial.create_process(initial.root / "123", "/proc/self/ns/user");
  };
  mesh::Runtime anchored(initial.workload);
  namespace_open = {};
  auto anchored_target = session_namespace(anchored);
  entered.clear();
  mesh::FileDescriptor socket(mesh::listener(namespace_target(anchored_target), "127.0.0.1", 0));
  require(entered.size() == 2 && entered.front() == initial.workload.network_namespace_inode,
          "initial namespace open followed a replaced process directory");
}

} // namespace

extern "C" int __wrap_setns(int descriptor, int type) {
  if (type != CLONE_NEWNET) {
    std::abort();
  }
  struct stat status{};
  if (::fstat(descriptor, &status) != 0) {
    return -1;
  }
  entered.push_back(status.st_ino);
  return 0;
}

extern "C" int __real_openat(int, const char *, int, ...);
extern "C" int __wrap_openat(int directory, const char *path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
    va_list arguments;
    va_start(arguments, flags);
    mode = va_arg(arguments, mode_t);
    va_end(arguments);
  }
  if (std::string_view(path) == "ns/net" && namespace_open) {
    namespace_open();
  }
  return __real_openat(directory, path, flags, mode);
}

extern "C" int __real_socket(int, int, int);
extern "C" int __wrap_socket(int domain, int type, int protocol) {
  if (domain == AF_NETLINK) {
    errno = EACCES;
    return -1;
  }
  return __real_socket(domain, type, protocol);
}

extern "C" int __real_setsockopt(int, int, int, const void *, socklen_t);
extern "C" int __wrap_setsockopt(int descriptor, int level, int option, const void *value,
                                 socklen_t size) {
  if (level == SOL_SOCKET && option == SO_MARK) {
    return 0;
  }
  return __real_setsockopt(descriptor, level, option, value, size);
}

int main(int argc, char **argv) {
  try {
    require(argc == 2, "expected identity or pinning");
    if (std::string_view(argv[1]) == "identity") {
      identity();
    } else {
      pinning();
    }
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
