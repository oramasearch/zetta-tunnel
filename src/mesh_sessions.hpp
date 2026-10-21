#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>

namespace zetta_tunnel::mesh {

// The node agent's session budget, shared by every enrolled workload on the node (LSR-177).
//
// `total` caps the node's combined inbound and outbound sessions. Each workload currently in the
// projection is guaranteed `guaranteed()` of them, `min(per_workload, total / workloads)`, which no
// other workload can take: a workload may open a session only while what is left after it still
// covers every other workload's unused guarantee. No workload ever holds more than
// `per_workload`. Sessions of a workload that has left the projection still count until they end,
// but it may open no new ones.
//
// Workloads are named by an opaque key the caller chooses (the agent uses one per runtime).
// Thread-safe.
class SessionPool {
public:
  SessionPool(std::size_t total, std::size_t per_workload);

  // Replace the set of workloads sharing the pool.
  void set_workloads(const std::set<std::uint64_t> &workloads);
  // Take one session for `workload`; false when its quota or the others' guarantees forbid it.
  bool reserve(std::uint64_t workload);
  void release(std::uint64_t workload);

  std::size_t in_use() const;
  std::size_t in_use(std::uint64_t workload) const;
  std::size_t guaranteed() const;

private:
  std::size_t guaranteed_locked() const;

  const std::size_t total_;
  const std::size_t per_workload_;
  mutable std::mutex mutex_;
  std::set<std::uint64_t> workloads_;
  std::map<std::uint64_t, std::size_t> counts_;
  std::size_t in_use_ = 0;
};

} // namespace zetta_tunnel::mesh
