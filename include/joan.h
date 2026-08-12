#ifndef JOAN_NATIVE_ABI_V1_H
#define JOAN_NATIVE_ABI_V1_H

#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#  error "JOAN native ABI v1 has not been verified for Windows"
#endif

#define JOAN_ABI_EXPORT __attribute__((visibility("default")))

#ifdef __cplusplus
extern "C" {
#endif

#define JOAN_ABI_VERSION_V1 UINT32_C(1)
#define JOAN_ABI_MAX_BUFFER_LEN_V1 UINT64_C(16777216)
#define JOAN_ABI_SEMANTIC_ROOT_LEN_V1 UINT32_C(32)
#define JOAN_ABI_LEVEL_COUNT_V1 UINT32_C(6)

#define JOAN_SEMANTIC_PROFILE_LEGACY_V1 UINT16_C(1)
#define JOAN_SEMANTIC_PROFILE_LINEAR_V1 UINT16_C(2)
#define JOAN_SEMANTIC_PROFILE_INFORMATION_V1 UINT16_C(3)

typedef uint32_t joan_status_v1;

#define JOAN_STATUS_OK_V1 UINT32_C(0)
#define JOAN_STATUS_NULL_ARGUMENT_V1 UINT32_C(1)
#define JOAN_STATUS_OUTPUT_TOO_SMALL_V1 UINT32_C(2)
#define JOAN_STATUS_UNSUPPORTED_ABI_V1 UINT32_C(3)
#define JOAN_STATUS_INVALID_BINDING_V1 UINT32_C(4)
#define JOAN_STATUS_MISALIGNED_ARGUMENT_V1 UINT32_C(5)
#define JOAN_STATUS_POINTER_RANGE_INVALID_V1 UINT32_C(6)
#define JOAN_STATUS_OUTPUT_OVERLAPS_INPUT_V1 UINT32_C(7)
#define JOAN_STATUS_TRUNCATED_HEADER_V1 UINT32_C(100)
#define JOAN_STATUS_FRAME_TOO_LARGE_V1 UINT32_C(101)
#define JOAN_STATUS_INVALID_MAGIC_V1 UINT32_C(102)
#define JOAN_STATUS_UNSUPPORTED_FRAME_VERSION_V1 UINT32_C(103)
#define JOAN_STATUS_UNSUPPORTED_FLAGS_V1 UINT32_C(104)
#define JOAN_STATUS_RESERVED_BITS_V1 UINT32_C(105)
#define JOAN_STATUS_LENGTH_MISMATCH_V1 UINT32_C(106)
#define JOAN_STATUS_NONCANONICAL_LEVEL_MAP_V1 UINT32_C(107)
#define JOAN_STATUS_INTERNAL_INVARIANT_V1 UINT32_C(255)

typedef struct joan_program_binding_v1 {
  uint32_t struct_size;
  uint16_t abi_version;
  uint16_t semantic_profile;
  uint8_t semantic_root[32];
  uint64_t reserved[3];
} joan_program_binding_v1;

typedef struct joan_span_v1 {
  uint64_t offset;
  uint64_t length;
} joan_span_v1;

typedef struct joan_lattice_view_v1 {
  uint32_t struct_size;
  uint16_t abi_version;
  uint8_t lattice_version;
  uint8_t flags;
  uint64_t frame_length;
  uint8_t schema_digest[32];
  uint8_t intent_digest[32];
  uint16_t semantic_profile;
  uint16_t level_count;
  uint32_t reserved0;
  uint8_t semantic_root[32];
  joan_span_v1 levels[6];
  uint64_t reserved[1];
} joan_lattice_view_v1;

JOAN_ABI_EXPORT uint32_t joan_abi_version_v1(void);
JOAN_ABI_EXPORT uint64_t joan_abi_max_buffer_len_v1(void);
JOAN_ABI_EXPORT uint32_t joan_abi_program_binding_size_v1(void);
JOAN_ABI_EXPORT uint32_t joan_abi_lattice_view_size_v1(void);

/*
 * frame must identify one initialized contiguous allocation, readable for the
 * exact frame_length and immutable for the complete call. The caller owns every
 * byte. Valid spans remain usable only while frame stays alive and unchanged.
 * out_view must be aligned, writable, large enough, and disjoint from frame and
 * binding. A C-built binding is asserted, not compiler-verified. See the spec.
 */
JOAN_ABI_EXPORT joan_status_v1 joan_lattice_validate_v1(
    const uint8_t *frame,
    uint64_t frame_length,
    const joan_program_binding_v1 *binding,
    joan_lattice_view_v1 *out_view,
    uint64_t out_view_size);

#ifdef __cplusplus
}
#endif

#endif
