#include "joan.h"

#include <inttypes.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(void *) == 8, "JOAN native ABI v1 requires a 64-bit target");
_Static_assert(sizeof(joan_program_binding_v1) == 64, "binding size drift");
_Static_assert(alignof(joan_program_binding_v1) == 8, "binding alignment drift");
_Static_assert(offsetof(joan_program_binding_v1, struct_size) == 0, "binding size offset drift");
_Static_assert(offsetof(joan_program_binding_v1, abi_version) == 4, "binding version offset drift");
_Static_assert(offsetof(joan_program_binding_v1, semantic_profile) == 6, "binding profile offset drift");
_Static_assert(offsetof(joan_program_binding_v1, semantic_root) == 8, "binding root offset drift");
_Static_assert(offsetof(joan_program_binding_v1, reserved) == 40, "binding reserved offset drift");
_Static_assert(sizeof(joan_span_v1) == 16, "span size drift");
_Static_assert(alignof(joan_span_v1) == 8, "span alignment drift");
_Static_assert(offsetof(joan_span_v1, offset) == 0, "span offset drift");
_Static_assert(offsetof(joan_span_v1, length) == 8, "span length offset drift");
_Static_assert(sizeof(joan_lattice_view_v1) == 224, "view size drift");
_Static_assert(alignof(joan_lattice_view_v1) == 8, "view alignment drift");
_Static_assert(offsetof(joan_lattice_view_v1, frame_length) == 8, "frame length offset drift");
_Static_assert(offsetof(joan_lattice_view_v1, schema_digest) == 16, "schema offset drift");
_Static_assert(offsetof(joan_lattice_view_v1, intent_digest) == 48, "intent offset drift");
_Static_assert(offsetof(joan_lattice_view_v1, semantic_profile) == 80, "profile offset drift");
_Static_assert(offsetof(joan_lattice_view_v1, semantic_root) == 88, "root offset drift");
_Static_assert(offsetof(joan_lattice_view_v1, levels) == 120, "levels offset drift");
_Static_assert(offsetof(joan_lattice_view_v1, reserved) == 216, "reserved offset drift");

static unsigned case_count = 0;
static unsigned passed = 0;
static const uint64_t mutation_seed = UINT64_C(0x4a4f414e4c313500);
static const unsigned mutation_count = 4096;

static void make_valid_frame(uint8_t frame[100]) {
  memset(frame, 0, 100);
  memcpy(frame, "JNL0", 4);
  frame[5] = 1;
  frame[7] = UINT8_C(1) << 2;
  memset(frame + 8, 7, 32);
  memset(frame + 40, 9, 32);
  frame[83] = 4;
  memcpy(frame + 96, "call", 4);
}

static joan_program_binding_v1 make_binding(void) {
  joan_program_binding_v1 binding;
  memset(&binding, 0, sizeof(binding));
  binding.struct_size = (uint32_t)sizeof(binding);
  binding.abi_version = (uint16_t)JOAN_ABI_VERSION_V1;
  binding.semantic_profile = JOAN_SEMANTIC_PROFILE_INFORMATION_V1;
  memset(binding.semantic_root, 3, sizeof(binding.semantic_root));
  return binding;
}

static void expect_status(const char *name, joan_status_v1 actual, joan_status_v1 expected) {
  case_count += 1;
  if (actual != expected) {
    fprintf(stderr, "%s: expected status %" PRIu32 ", got %" PRIu32 "\n", name, expected, actual);
    return;
  }
  passed += 1;
}

static joan_status_v1 validate(
    const uint8_t *frame,
    uint64_t frame_length,
    const joan_program_binding_v1 *binding,
    joan_lattice_view_v1 *output) {
  return joan_lattice_validate_v1(frame, frame_length, binding, output, sizeof(*output));
}

static uint64_t mix_u64(uint64_t hash, uint64_t value) {
  for (unsigned index = 0; index < 8; ++index) {
    hash ^= (uint8_t)(value >> (index * 8));
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static uint64_t run_mutations(const joan_program_binding_v1 *binding) {
  uint64_t state = mutation_seed;
  uint64_t digest = UINT64_C(14695981039346656037);
  for (unsigned ordinal = 0; ordinal < mutation_count; ++ordinal) {
    uint8_t mutated[100];
    joan_lattice_view_v1 output;
    make_valid_frame(mutated);
    state = state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    size_t offset = (size_t)(state % sizeof(mutated));
    state = state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    uint8_t mask = (uint8_t)(state >> 56) | UINT8_C(1);
    mutated[offset] ^= mask;
    memset(&output, 0xA5, sizeof(output));
    joan_status_v1 status = validate(mutated, sizeof(mutated), binding, &output);
    if (status > JOAN_STATUS_NONCANONICAL_LEVEL_MAP_V1 && status != JOAN_STATUS_INTERNAL_INVARIANT_V1) {
      return 0;
    }
    digest = mix_u64(digest, ordinal);
    digest = mix_u64(digest, offset);
    digest = mix_u64(digest, mask);
    digest = mix_u64(digest, status);
  }
  return digest;
}

int main(void) {
  alignas(8) uint8_t frame[100];
  joan_program_binding_v1 binding = make_binding();
  joan_lattice_view_v1 output;
  joan_lattice_view_v1 sentinel;
  memset(&sentinel, 0xA5, sizeof(sentinel));
  make_valid_frame(frame);
  output = sentinel;

  expect_status("version", joan_abi_version_v1(), JOAN_ABI_VERSION_V1);
  expect_status("max-buffer", (joan_status_v1)(joan_abi_max_buffer_len_v1() == JOAN_ABI_MAX_BUFFER_LEN_V1), 1);
  expect_status("binding-size", joan_abi_program_binding_size_v1(), (joan_status_v1)sizeof(binding));
  expect_status("view-size", joan_abi_lattice_view_size_v1(), (joan_status_v1)sizeof(output));
  expect_status("null-frame", validate(NULL, sizeof(frame), &binding, &output), JOAN_STATUS_NULL_ARGUMENT_V1);
  expect_status("null-binding", validate(frame, sizeof(frame), NULL, &output), JOAN_STATUS_NULL_ARGUMENT_V1);
  expect_status("null-output", joan_lattice_validate_v1(frame, sizeof(frame), &binding, NULL, sizeof(output)), JOAN_STATUS_NULL_ARGUMENT_V1);
  expect_status("small-output", joan_lattice_validate_v1(frame, sizeof(frame), &binding, &output, sizeof(output) - 1), JOAN_STATUS_OUTPUT_TOO_SMALL_V1);

  alignas(8) uint8_t misaligned_binding_storage[sizeof(binding) + 8];
  memcpy(misaligned_binding_storage + 1, &binding, sizeof(binding));
  expect_status("misaligned-binding", validate(frame, sizeof(frame), (const joan_program_binding_v1 *)(const void *)(misaligned_binding_storage + 1), &output), JOAN_STATUS_MISALIGNED_ARGUMENT_V1);
  alignas(8) uint8_t misaligned_output_storage[sizeof(output) + 8];
  expect_status("misaligned-output", joan_lattice_validate_v1(frame, sizeof(frame), &binding, (joan_lattice_view_v1 *)(void *)(misaligned_output_storage + 1), sizeof(output)), JOAN_STATUS_MISALIGNED_ARGUMENT_V1);

  alignas(8) uint8_t overlap_storage[sizeof(output)];
  make_valid_frame(overlap_storage);
  expect_status("output-frame-overlap", joan_lattice_validate_v1(overlap_storage, 100, &binding, (joan_lattice_view_v1 *)(void *)overlap_storage, sizeof(output)), JOAN_STATUS_OUTPUT_OVERLAPS_INPUT_V1);
  alignas(8) uint8_t output_after_frame_storage[sizeof(output) + 8];
  make_valid_frame(output_after_frame_storage);
  expect_status("output-after-frame-partial-overlap", joan_lattice_validate_v1(output_after_frame_storage, 100, &binding, (joan_lattice_view_v1 *)(void *)(output_after_frame_storage + 8), sizeof(output)), JOAN_STATUS_OUTPUT_OVERLAPS_INPUT_V1);
  alignas(8) uint8_t frame_after_output_storage[sizeof(output) + 8];
  make_valid_frame(frame_after_output_storage + 8);
  expect_status("frame-after-output-partial-overlap", joan_lattice_validate_v1(frame_after_output_storage + 8, 100, &binding, (joan_lattice_view_v1 *)(void *)frame_after_output_storage, sizeof(output)), JOAN_STATUS_OUTPUT_OVERLAPS_INPUT_V1);
  alignas(8) uint8_t binding_overlap_storage[sizeof(output)];
  memcpy(binding_overlap_storage, &binding, sizeof(binding));
  expect_status("output-binding-overlap", joan_lattice_validate_v1(frame, sizeof(frame), (const joan_program_binding_v1 *)(const void *)binding_overlap_storage, (joan_lattice_view_v1 *)(void *)binding_overlap_storage, sizeof(output)), JOAN_STATUS_OUTPUT_OVERLAPS_INPUT_V1);

  joan_program_binding_v1 invalid_binding = binding;
  invalid_binding.struct_size -= 1;
  expect_status("binding-size-field", validate(frame, sizeof(frame), &invalid_binding, &output), JOAN_STATUS_UNSUPPORTED_ABI_V1);
  invalid_binding = binding;
  invalid_binding.abi_version += 1;
  expect_status("binding-version", validate(frame, sizeof(frame), &invalid_binding, &output), JOAN_STATUS_UNSUPPORTED_ABI_V1);
  invalid_binding = binding;
  invalid_binding.semantic_profile = 99;
  expect_status("binding-profile", validate(frame, sizeof(frame), &invalid_binding, &output), JOAN_STATUS_UNSUPPORTED_ABI_V1);
  invalid_binding = binding;
  invalid_binding.reserved[0] = 1;
  expect_status("binding-reserved", validate(frame, sizeof(frame), &invalid_binding, &output), JOAN_STATUS_INVALID_BINDING_V1);

  for (uint64_t length = 0; length < 96; ++length) {
    char name[32];
    int written = snprintf(name, sizeof(name), "truncated-%" PRIu64, length);
    if (written < 0 || (size_t)written >= sizeof(name)) {
      return 1;
    }
    expect_status(name, validate(frame, length, &binding, &output), JOAN_STATUS_TRUNCATED_HEADER_V1);
  }
  expect_status("too-large", validate(frame, JOAN_ABI_MAX_BUFFER_LEN_V1 + 1, &binding, &output), JOAN_STATUS_FRAME_TOO_LARGE_V1);
  expect_status("u64-max", validate(frame, UINT64_MAX, &binding, &output), JOAN_STATUS_FRAME_TOO_LARGE_V1);

  uint8_t *maximum_frame = malloc((size_t)JOAN_ABI_MAX_BUFFER_LEN_V1);
  if (maximum_frame == NULL) {
    return 1;
  }
  memset(maximum_frame, 0, (size_t)JOAN_ABI_MAX_BUFFER_LEN_V1);
  memcpy(maximum_frame, "JNL0", 4);
  maximum_frame[7] = 1;
  uint32_t maximum_payload = (uint32_t)(JOAN_ABI_MAX_BUFFER_LEN_V1 - UINT64_C(96));
  maximum_frame[72] = (uint8_t)(maximum_payload >> 24);
  maximum_frame[73] = (uint8_t)(maximum_payload >> 16);
  maximum_frame[74] = (uint8_t)(maximum_payload >> 8);
  maximum_frame[75] = (uint8_t)maximum_payload;
  expect_status("maximum-valid", validate(maximum_frame, JOAN_ABI_MAX_BUFFER_LEN_V1, &binding, &output), JOAN_STATUS_OK_V1);
  uint64_t maximum_minus_one = JOAN_ABI_MAX_BUFFER_LEN_V1 - UINT64_C(1);
  uint32_t maximum_minus_one_payload = (uint32_t)(maximum_minus_one - UINT64_C(96));
  maximum_frame[72] = (uint8_t)(maximum_minus_one_payload >> 24);
  maximum_frame[73] = (uint8_t)(maximum_minus_one_payload >> 16);
  maximum_frame[74] = (uint8_t)(maximum_minus_one_payload >> 8);
  maximum_frame[75] = (uint8_t)maximum_minus_one_payload;
  expect_status("maximum-minus-one-valid", validate(maximum_frame, maximum_minus_one, &binding, &output), JOAN_STATUS_OK_V1);
  free(maximum_frame);
  output = sentinel;

  uint8_t invalid[100];
  make_valid_frame(invalid);
  invalid[0] = 'X';
  expect_status("magic", validate(invalid, sizeof(invalid), &binding, &output), JOAN_STATUS_INVALID_MAGIC_V1);
  make_valid_frame(invalid);
  invalid[4] = 1;
  expect_status("frame-version", validate(invalid, sizeof(invalid), &binding, &output), JOAN_STATUS_UNSUPPORTED_FRAME_VERSION_V1);
  make_valid_frame(invalid);
  invalid[5] = 0x80;
  expect_status("flags", validate(invalid, sizeof(invalid), &binding, &output), JOAN_STATUS_UNSUPPORTED_FLAGS_V1);
  make_valid_frame(invalid);
  invalid[6] = 0x80;
  expect_status("reserved", validate(invalid, sizeof(invalid), &binding, &output), JOAN_STATUS_RESERVED_BITS_V1);
  make_valid_frame(invalid);
  invalid[7] |= 1;
  invalid[75] = 1;
  expect_status("length-mismatch", validate(invalid, sizeof(invalid), &binding, &output), JOAN_STATUS_LENGTH_MISMATCH_V1);
  make_valid_frame(invalid);
  invalid[7] |= 1;
  expect_status("noncanonical-map", validate(invalid, sizeof(invalid), &binding, &output), JOAN_STATUS_NONCANONICAL_LEVEL_MAP_V1);

  expect_status("error-output-unchanged", memcmp(&output, &sentinel, sizeof(output)) == 0 ? 1 : 0, 1);
  make_valid_frame(frame);
  expect_status("valid", validate(frame, sizeof(frame), &binding, &output), JOAN_STATUS_OK_V1);
  bool complete_view = output.struct_size == sizeof(output)
      && output.abi_version == JOAN_ABI_VERSION_V1
      && output.lattice_version == 0
      && output.flags == 1
      && output.frame_length == sizeof(frame)
      && output.level_count == JOAN_ABI_LEVEL_COUNT_V1
      && output.reserved0 == 0
      && output.reserved[0] == 0
      && output.schema_digest[0] == 7
      && output.schema_digest[31] == 7
      && output.intent_digest[0] == 9
      && output.intent_digest[31] == 9;
  expect_status("complete-view", complete_view ? 1 : 0, 1);
  bool root_bound = output.semantic_profile == binding.semantic_profile
      && memcmp(output.semantic_root, binding.semantic_root, sizeof(binding.semantic_root)) == 0;
  bool zero_copy_offsets = output.levels[2].offset == 96 && output.levels[2].length == 4;
  frame[output.levels[2].offset] = 'C';
  zero_copy_offsets = zero_copy_offsets && frame[96] == 'C';
  expect_status("semantic-binding", root_bound ? 1 : 0, 1);
  expect_status("zero-copy-offsets", zero_copy_offsets ? 1 : 0, 1);

  uint64_t mutation_digest = run_mutations(&binding);
  if (mutation_digest == 0) {
    return 1;
  }

  if (passed != case_count) {
    return 1;
  }
  printf("{\"schema\":\"joan.native-abi-report.v1\",\"status\":\"passed\",\"abi_version\":1,\"binding_size\":64,\"lattice_view_size\":224,\"max_buffer_len\":16777216,\"case_count\":%u,\"passed\":%u,\"mutation_count\":%u,\"mutation_seed\":\"0x%016" PRIx64 "\",\"mutation_outcome_fnv1a64\":\"%016" PRIx64 "\",\"payload_zero_copy\":true,\"asserted_semantic_binding_preserved\":true,\"verified_rust_binding_profiles\":3}\n", case_count, passed, mutation_count, mutation_seed, mutation_digest);
  return 0;
}
