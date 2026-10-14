# Mesh netlink and startup diagnostics

The first AKS proof for `dev-e522b9a` failed before `/readyz` became ready. Its log contained only
`mesh projection or capture unavailable; refusing traffic`, so it did not identify the rejected
operation. The fixes below address wire defects found by source inspection; the coordinator must
rerun `tools/prove-mesh-linux.sh` to establish kernel acceptance and end-to-end traffic behavior.
No successful Linux run is claimed by the native wire tests.

## Transaction contract

The previous implementation sent batch begin, each mutation and batch end as separate datagrams.
Linux processes an nftables batch from one received socket buffer, not across successive sends.
The encoder now concatenates begin, table, both chains, both rules and end into one datagram and
the Linux transport submits it in one `sendto` to the kernel. The
[kernel batch receiver](https://github.com/torvalds/linux/blob/v6.6/net/netfilter/nfnetlink.c)
defines this boundary.

The wire contract is:

| Field | Encoding |
|---|---|
| Netlink and attribute headers | Native endian; four-byte alignment and zero padding |
| Batch envelope | `NFNL_MSG_BATCH_BEGIN` / `NFNL_MSG_BATCH_END`, request flag, family unspecified, version 0, `res_id = htons(NFNL_SUBSYS_NFTABLES)` |
| Ordinary nftables messages | Subsystem 10, family `NFPROTO_INET`, version 0, resource ID 0 |
| Named table query | `NLM_F_REQUEST | NLM_F_ACK`; no multipart dump |
| Table and chains | Request, ACK, create and exclusive flags |
| Rules | Request, ACK, create and append flags |
| Nested attributes | `NLA_F_NESTED` on expression lists, elements, data, hooks and immediate/compare values |
| Integer attributes | Network-order 32-bit values |
| TCP protocol comparison | One raw byte, `6`, from `NFT_META_L4PROTO` |
| Socket mark comparison | Raw native-order `0x5a54544d`, as returned by `NFT_META_MARK` |
| TCP port comparisons and redirect values | Raw network-order 16-bit values |
| Port payload | Transport-header base (`2`), offset `2`, length `2`, register `NFT_REG_1` |

The old mark comparison byte-swapped the socket mark, although the
[kernel meta expression](https://github.com/torvalds/linux/blob/v6.6/net/netfilter/nft_meta.c)
loads `skb->mark` in host order. Correct comparison excludes marked agent sockets from outbound
capture. Chain priorities, ports and capture policy are unchanged.

`src/mesh_netlink.cpp` is the production encoder and reply decoder on Linux and is compiled into
the native test suite on other hosts. On Linux, compile-time assertions verify its wire constants
against the installed Linux UAPI headers. No new runtime dependency or userspace nft executable
is introduced.

## Acknowledgements and namespace handling

The named table lookup consumes its matching ACK; only `ENOENT` means absent. Permission and
other lookup errors fail closed instead of attempting a create. Reusing a table retains the
existing lifecycle contract: the agent does not remove or replace capture in a live namespace.

Each batch mutation requests an ACK. The decoder handles replies across datagrams, multiple
messages per datagram and out-of-order ACKs. Readiness cannot proceed until all five mutation
ACKs match their request sequence and echoed type/sequence. Errors on the begin/end envelopes
also identify those operations. Duplicate or unrelated ACKs, truncated/malformed messages,
non-kernel senders and truncated receive buffers fail closed. Reception has a bounded deadline;
a timeout names the still-pending operations.

`NETLINK_EXT_ACK` is enabled where supported. Both capped and full echoed-request errors are
decoded, including bounded, single-line kernel error text and the offending attribute offset.
The echoed request payload is never logged. Network namespace restoration uses
`/proc/thread-self/ns/net`, preserving the calling thread's namespace. A failed restoration logs
its errno and terminates rather than continuing in the wrong namespace.

## Wire fixtures and tests

`mesh_netlink_wire` compares the complete production requests and concatenated batch against
literal little-endian hex fixtures in `tests/fixtures/mesh/`. They are independently written
protocol layouts, not captures from the failing pod. Their references are the
[Linux nftables UAPI](https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/netfilter/nf_tables.h),
the kernel receiver above and the attribute/batch builders in the
[libnftnl 1.2.6 reference source](https://www.netfilter.org/projects/libnftnl/files/libnftnl-1.2.6.tar.xz)
(`src/common.c`, `src/table.c`, `src/chain.c`, `src/rule.c`, and `src/expr/`). The reference source
is not linked or shipped. Fixture sequence numbers are fixed and the port ID is zero, as in the
production requests; the actual sender is assigned when the netlink socket binds.

The fixtures cover the named lookup, both envelopes, table, both chains, both rules, nested
lengths, alignment, family/resource IDs, flags and value byte order. Separate reply tests cover
partial/multiple ACKs, table absence, every operation's error, extended error text/offsets,
stale or mismatched ACKs and malformed/truncated input. Diagnostics tests ensure malformed JSON
and filesystem exceptions cannot echo secrets or configured paths.

```sh
ctest --test-dir build -R '^(mesh_config_validation|mesh_netlink_wire)$' --output-on-failure
```

## Reading a refusal

Illustrative failures (the code/message comes from the actual failing operation):

```text
zetta-tunnel: mesh stage=workload[0] capture installation: open workload network namespace: errno=2 (No such file or directory); refusing traffic
zetta-tunnel: mesh stage=workload[0] capture installation: create nftables outbound rule: netlink_error=-22 (Invalid argument) sequence=6 type=2566 attribute_offset=52; refusing traffic
zetta-tunnel: mesh stage=workload[0] outbound listener 127.0.0.1:15001: bind mesh listener: errno=98 (Address in use); refusing traffic
```

Use the zero-based workload index to locate the projection entry. A namespace open/enter error
points to its handle or agent permissions. A lookup/create netlink error points to kernel feature
support, capabilities or the specific rejected message; preserve any extended error and offset.
A listener bind failure identifies which reserved address is occupied. TLS failures distinguish
certificate, key, key matching, trust store and context settings. Projection parse errors include
the JSON error ID and byte position without quoting the document.

All failures keep readiness false and close listeners/sessions without deleting installed rules.
Never work around a failure by disabling certificate checks, removing capture or releasing the
application startup gate. Attach the full proof log to the coordinator rerun result. The command
and cleanup model remain unchanged; see [verification](testing.md) and the
[image proof](../image.md#linux-mesh-proof).
