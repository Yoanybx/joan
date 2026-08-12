#include "joan.h"

#include <cstddef>
#include <cstdint>
#include <type_traits>

static_assert(sizeof(void *) == 8);
static_assert(std::is_standard_layout_v<joan_program_binding_v1>);
static_assert(std::is_standard_layout_v<joan_span_v1>);
static_assert(std::is_standard_layout_v<joan_lattice_view_v1>);
static_assert(sizeof(joan_program_binding_v1) == 64);
static_assert(alignof(joan_program_binding_v1) == 8);
static_assert(offsetof(joan_program_binding_v1, struct_size) == 0);
static_assert(offsetof(joan_program_binding_v1, abi_version) == 4);
static_assert(offsetof(joan_program_binding_v1, semantic_profile) == 6);
static_assert(offsetof(joan_program_binding_v1, semantic_root) == 8);
static_assert(offsetof(joan_program_binding_v1, reserved) == 40);
static_assert(sizeof(joan_span_v1) == 16);
static_assert(alignof(joan_span_v1) == 8);
static_assert(offsetof(joan_span_v1, offset) == 0);
static_assert(offsetof(joan_span_v1, length) == 8);
static_assert(sizeof(joan_lattice_view_v1) == 224);
static_assert(alignof(joan_lattice_view_v1) == 8);
static_assert(offsetof(joan_lattice_view_v1, struct_size) == 0);
static_assert(offsetof(joan_lattice_view_v1, abi_version) == 4);
static_assert(offsetof(joan_lattice_view_v1, lattice_version) == 6);
static_assert(offsetof(joan_lattice_view_v1, flags) == 7);
static_assert(offsetof(joan_lattice_view_v1, frame_length) == 8);
static_assert(offsetof(joan_lattice_view_v1, schema_digest) == 16);
static_assert(offsetof(joan_lattice_view_v1, intent_digest) == 48);
static_assert(offsetof(joan_lattice_view_v1, semantic_profile) == 80);
static_assert(offsetof(joan_lattice_view_v1, level_count) == 82);
static_assert(offsetof(joan_lattice_view_v1, reserved0) == 84);
static_assert(offsetof(joan_lattice_view_v1, semantic_root) == 88);
static_assert(offsetof(joan_lattice_view_v1, levels) == 120);
static_assert(offsetof(joan_lattice_view_v1, reserved) == 216);
static_assert(JOAN_ABI_VERSION_V1 == UINT32_C(1));

int main() {
  return 0;
}
