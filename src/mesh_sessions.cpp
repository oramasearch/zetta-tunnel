#include "mesh_sessions.hpp"

#include <algorithm>
#include <stdexcept>

namespace zetta_tunnel::mesh {

SessionPool::SessionPool(std::size_t total, std::size_t per_workload)
    : total_(total), per_workload_(per_workload) {
  if (total_ == 0 || per_workload_ == 0 || per_workload_ > total_) {
    throw std::invalid_argument("mesh session limits must satisfy 1 <= per workload <= total");
  }
}

void SessionPool::set_workloads(const std::set<std::uint64_t> &workloads) {
  const std::lock_guard lock(mutex_);
  workloads_ = workloads;
}

std::size_t SessionPool::guaranteed_locked() const {
  if (workloads_.empty()) {
    return 0;
  }
  return std::min(per_workload_, total_ / workloads_.size());
}

bool SessionPool::reserve(std::uint64_t workload) {
  const std::lock_guard lock(mutex_);
  if (!workloads_.contains(workload)) {
    return false;
  }
  const auto found = counts_.find(workload);
  const std::size_t mine = found == counts_.end() ? 0 : found->second;
  if (mine >= per_workload_) {
    return false;
  }
  const auto guarantee = guaranteed_locked();
  std::size_t others_unused = 0;
  for (const auto other : workloads_) {
    if (other == workload) {
      continue;
    }
    const auto count = counts_.find(other);
    const std::size_t used = count == counts_.end() ? 0 : count->second;
    others_unused += used < guarantee ? guarantee - used : 0;
  }
  if (in_use_ + 1 + others_unused > total_) {
    return false;
  }
  ++counts_[workload];
  ++in_use_;
  return true;
}

void SessionPool::release(std::uint64_t workload) {
  const std::lock_guard lock(mutex_);
  const auto found = counts_.find(workload);
  if (found == counts_.end() || found->second == 0) {
    return;
  }
  if (--found->second == 0) {
    counts_.erase(found);
  }
  --in_use_;
}

std::size_t SessionPool::in_use() const {
  const std::lock_guard lock(mutex_);
  return in_use_;
}

std::size_t SessionPool::in_use(std::uint64_t workload) const {
  const std::lock_guard lock(mutex_);
  const auto found = counts_.find(workload);
  return found == counts_.end() ? 0 : found->second;
}

std::size_t SessionPool::guaranteed() const {
  const std::lock_guard lock(mutex_);
  return guaranteed_locked();
}

} // namespace zetta_tunnel::mesh
