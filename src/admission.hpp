// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace zetta_tunnel {

// Event-loop-owned admission. Pending sockets never reserve established capacity.
class Admission {
public:
  struct Ticket {
    Admission &owner;
    std::string source;
    bool active = false;

    Ticket(Admission &value, std::string address) : owner(value), source(std::move(address)) {
    }
    Ticket(const Ticket &) = delete;
    Ticket &operator=(const Ticket &) = delete;
    ~Ticket() {
      auto &counts = active ? owner.active_sources_ : owner.pending_sources_;
      if (--counts.at(source) == 0) {
        counts.erase(source);
      }
      --(active ? owner.active_ : owner.pending_);
    }

    bool promote() {
      if (active) {
        return true;
      }
      const auto found = owner.active_sources_.find(source);
      if (owner.active_ >= owner.maximum_ ||
          (owner.source_maximum_ && found != owner.active_sources_.end() &&
           found->second >= owner.source_maximum_)) {
        return false;
      }
      ++owner.active_sources_[source];
      if (--owner.pending_sources_.at(source) == 0) {
        owner.pending_sources_.erase(source);
      }
      --owner.pending_;
      ++owner.active_;
      active = true;
      return true;
    }
  };

  Admission(std::size_t maximum, std::size_t pending_maximum, std::size_t pending_source_maximum,
            std::size_t source_maximum = 0)
      : maximum_(maximum), pending_maximum_(pending_maximum),
        pending_source_maximum_(pending_source_maximum), source_maximum_(source_maximum) {
  }

  std::unique_ptr<Ticket> acquire(std::string source) {
    const auto found = pending_sources_.find(source);
    if (active_ >= maximum_ || pending_ >= pending_maximum_ ||
        (found != pending_sources_.end() && found->second >= pending_source_maximum_)) {
      return {};
    }
    auto ticket = std::make_unique<Ticket>(*this, std::move(source));
    ++pending_sources_[ticket->source];
    ++pending_;
    return ticket;
  }

private:
  std::size_t maximum_, pending_maximum_, pending_source_maximum_, source_maximum_;
  std::size_t pending_ = 0, active_ = 0;
  std::map<std::string, std::size_t> pending_sources_, active_sources_;
};

inline std::size_t source_share(std::size_t maximum) {
  return std::max<std::size_t>(4, maximum / 4);
}

} // namespace zetta_tunnel
