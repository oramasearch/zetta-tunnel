#include "mesh_sessions.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

namespace mesh = zetta_tunnel::mesh;

void require(bool value, const std::string &what) {
  if (!value) {
    throw std::runtime_error("session pool assertion failed: " + what);
  }
}

std::size_t take_all(mesh::SessionPool &pool, std::uint64_t workload) {
  std::size_t taken = 0;
  while (pool.reserve(workload)) {
    ++taken;
  }
  return taken;
}

// LSR-177: one workload holding every session it can must leave each other workload its
// guarantee. A single node-wide counter (the agent before this change) let the first workload take
// all 128 sessions and refused every other workload's connections.
void test_one_workload_cannot_exhaust_another() {
  mesh::SessionPool pool(128, 128);
  pool.set_workloads({1, 2});
  require(pool.guaranteed() == 64, "two workloads share 128 as 64 each");
  require(take_all(pool, 1) == 64, "the attacker stops at the total minus the victim's guarantee");
  require(take_all(pool, 2) == 64, "the victim still opens its whole guarantee");
  require(pool.in_use() == 128, "the node total is never exceeded");
  pool.release(2);
  require(!pool.reserve(1), "a slot the victim frees is still the victim's");
  require(pool.reserve(2), "the victim can use its freed slot again");
}

void test_unused_capacity_is_shared() {
  mesh::SessionPool pool(12, 12);
  pool.set_workloads({1, 2, 3});
  require(pool.guaranteed() == 4, "12 sessions across three workloads guarantee 4 each");
  require(pool.reserve(2) && pool.reserve(2), "workload 2 opens two sessions");
  // Workload 1 may use what is not guaranteed to others: 12 - 2 (workload 2's unused guarantee)
  // - 4 (workload 3's) - 2 (workload 2 already holds).
  require(take_all(pool, 1) == 4 + 0, "workload 1 gets its own guarantee and nothing reserved");
  pool.release(2);
  pool.release(2);
  require(take_all(pool, 1) == 0, "workload 2's released sessions return to its guarantee");
  pool.set_workloads({1});
  require(take_all(pool, 1) == 8, "alone on the node, a workload may use the whole pool");
}

void test_per_workload_cap() {
  mesh::SessionPool pool(128, 16);
  pool.set_workloads({7});
  require(pool.guaranteed() == 16, "the guarantee never exceeds the per-workload cap");
  require(take_all(pool, 7) == 16, "one workload stops at its cap even with the node idle");
  require(pool.in_use(7) == 16 && pool.in_use() == 16, "counts are per workload");
}

void test_removed_workload() {
  mesh::SessionPool pool(8, 8);
  pool.set_workloads({1, 2});
  require(pool.reserve(1), "workload 1 opens a session");
  pool.set_workloads({2});
  require(!pool.reserve(1), "a workload removed from the projection opens no new sessions");
  require(pool.in_use() == 1, "its live session still counts until it ends");
  require(take_all(pool, 2) == 7, "the remaining workload gets what is left");
  pool.release(1);
  require(pool.in_use(1) == 0 && pool.reserve(2), "the ended session frees its slot");
  require(!pool.reserve(99), "an unknown workload opens nothing");
  pool.release(99);
  require(pool.in_use() == 8, "releasing an unknown workload changes nothing");
}

void test_limits() {
  for (const auto [total, per_workload] :
       {std::pair<std::size_t, std::size_t>{0, 0}, {4, 0}, {4, 5}}) {
    bool refused = false;
    try {
      mesh::SessionPool pool(total, per_workload);
    } catch (const std::invalid_argument &) {
      refused = true;
    }
    require(refused, "invalid limits are refused");
  }
  mesh::SessionPool many(4, 4);
  many.set_workloads({1, 2, 3, 4, 5, 6});
  require(many.guaranteed() == 0, "more workloads than sessions guarantee nothing");
  require(take_all(many, 1) == 4, "first come, first served when nothing is guaranteed");
}

} // namespace

int main() {
  try {
    test_one_workload_cannot_exhaust_another();
    test_unused_capacity_is_shared();
    test_per_workload_cap();
    test_removed_workload();
    test_limits();
    std::cout << "mesh session quotas passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
