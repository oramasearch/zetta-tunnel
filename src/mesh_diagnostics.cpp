// SPDX-License-Identifier: MIT

#include "mesh.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <system_error>

namespace zetta_tunnel::mesh {

std::string failure_detail(const std::exception &error) {
  // JSON exceptions can quote the input, including invalid secret values. Filesystem
  // exceptions can quote configured paths. Report codes/positions without that text.
  if (const auto *parse = dynamic_cast<const nlohmann::json::parse_error *>(&error)) {
    return "projection JSON parse error id=" + std::to_string(parse->id) +
           " byte=" + std::to_string(parse->byte);
  }
  if (const auto *json = dynamic_cast<const nlohmann::json::exception *>(&error)) {
    return "projection JSON schema error id=" + std::to_string(json->id);
  }
  if (const auto *system = dynamic_cast<const std::system_error *>(&error)) {
    return "system_error=" + std::to_string(system->code().value()) + " (" +
           system->code().message() + ")";
  }
  // Other mesh exceptions contain only fixed operations and numeric kernel/TLS errors.
  std::string result(error.what());
  result.resize(std::min<std::size_t>(result.size(), 1024));
  for (auto &character : result) {
    if (static_cast<unsigned char>(character) < 32 ||
        static_cast<unsigned char>(character) >= 127) {
      character = '?';
    }
  }
  return result;
}

} // namespace zetta_tunnel::mesh
