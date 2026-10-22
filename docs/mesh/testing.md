# Mesh verification

The native repository suite validates the exact projection schema, duplicate rejection, file and
collection bounds, numeric-address requirements, target-port preservation, role flags, production
netlink wire layouts/ACK handling, safe failure diagnostics and all
existing transport/tunnel/egress/peer/ingress regressions on macOS and Linux.

The unprivileged Linux cases `mesh_namespace_identity` and `mesh_namespace_pinning` exercise the
production namespace code with real namespace descriptors and a temporary proc-shaped directory.
They replace the numeric process directory during pinning and after runtime installation, remove
it, and check capture, listener and upstream operations after runtime withdrawal. Hooks around
`openat` replace the directory or cgroup at the initial namespace open.
`setns` records the descriptor inode, netlink socket creation is refused before any kernel mutation,
and setting the reserved socket mark is intercepted; ordinary loopback sockets are real.
Identity cases reject wrong or prefixed pod UIDs, changed cgroup membership during the open,
missing cgroup files, inode mismatches and non-network namespace handles. No special capabilities
or live cluster are needed. Run the focused proof with:

```sh
cmake --build build --target mesh_namespace_test mesh_config_test mesh_netlink_test -j 6
ctest --test-dir build -R '^(mesh_namespace_(identity|pinning)|mesh_config_validation|mesh_netlink_wire)$' \
  --timeout 600 --output-on-failure
```

The capture acceptance test needs a Linux node with root privileges, network namespaces, nftables
in the kernel and the `ip` command. It creates only process-unique temporary namespaces, veth links
and a bridge, and removes them at the end. A trusted temporary proc-shaped directory supplies
the pod cgroup records beside links to these real network namespace handles. It uses no container
runtime. Run it after the native build:

```sh
sudo env ZETTA_MESH_PRIVILEGED_TEST=1 \
  ctest --test-dir build -R '^mesh_linux_fail_closed$' --output-on-failure
```

Without that environment variable or root, CTest reports the case skipped. The privileged case
proves:

- malformed and missing projections, a missing namespace, a missing TLS key and an occupied
  capture listener each report their operation/error and keep readiness false; restoring valid
  inputs restores readiness without removing capture;
- capture is installed before the simulated application starts;
- an exact declared source reaches an exact destination through real TLS 1.3;
- inbound and outbound allow records exist before application data passes;
- an unenrolled namespace cannot send plaintext directly to the application port;
- the agent's marked target and mesh sockets do not capture themselves;
- health and metrics remain outside workload capture;
- an invalid atomic replacement closes traffic and readiness until a valid projection returns;
- replacing both numeric process paths with a third real network namespace leaves existing
  runtimes on their pinned namespaces; a forced reload rejects the changed inode until restored;
- killing the agent leaves namespace rules installed and traffic refused;
- restarting the agent reuses those rules and restores only the authorized TLS path;
- stopping both the application and agent leaves the path closed.

The operator-side cluster acceptance must use the same order with its real `NetworkSandbox`
startup gate and Cilium policies. Run the full repository proof natively:

```sh
git submodule update --init --recursive
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
```

The macOS suite intentionally does not pretend to exercise Linux capture. The privileged command
above is the required node proof.

See [netlink and diagnostics](netlink.md) for fixture provenance and interpreting kernel errors.

For the release image path, `tools/prove-mesh-linux.sh` builds the Dockerfile's test-only target on
the cluster BuildKit lane and runs this same Python case inside a privileged Linux pod. See
[Image and releases](../image.md#linux-mesh-proof) for the coordinator command and cleanup model.
