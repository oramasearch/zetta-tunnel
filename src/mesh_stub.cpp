#include "mesh.hpp"

#include <stdexcept>

namespace zetta_tunnel::mesh {

int run(const Options &) {
  throw std::runtime_error("the mesh node agent requires Linux network namespaces");
}

} // namespace zetta_tunnel::mesh
