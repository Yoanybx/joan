#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/evp.h>
#endif

static const unsigned char PREFIX[] = {'J', 'O', 'A', 'N', 0, 'H', 'A', 'S', 'H', 0, 'V', '1'};
static const unsigned char PROFILE[] = "joan-hash-v1";
static const unsigned char DOMAIN[] = "joan.source.v1";

static void u64be(uint64_t value, unsigned char output[8]) {
    for (size_t index = 0; index < 8; index++) {
        output[7 - index] = (unsigned char)(value & 0xffU);
        value >>= 8U;
    }
}

static uint64_t elapsed_ns(const struct timespec *start, const struct timespec *end) {
    uint64_t seconds = (uint64_t)(end->tv_sec - start->tv_sec);
    int64_t nanoseconds = end->tv_nsec - start->tv_nsec;
    if (nanoseconds < 0) {
        seconds -= 1U;
        nanoseconds += 1000000000L;
    }
    return seconds * 1000000000U + (uint64_t)nanoseconds;
}

#ifdef __APPLE__
static int digest_once(const unsigned char *payload, size_t payload_size, unsigned char output[32]) {
    unsigned char profile_length[8];
    unsigned char domain_length[8];
    unsigned char payload_length[8];
    u64be(sizeof(PROFILE) - 1U, profile_length);
    u64be(sizeof(DOMAIN) - 1U, domain_length);
    u64be(payload_size, payload_length);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_SHA256_CTX context;
    if (CC_SHA256_Init(&context) != 1 ||
        CC_SHA256_Update(&context, PREFIX, sizeof(PREFIX)) != 1 ||
        CC_SHA256_Update(&context, profile_length, sizeof(profile_length)) != 1 ||
        CC_SHA256_Update(&context, PROFILE, sizeof(PROFILE) - 1U) != 1 ||
        CC_SHA256_Update(&context, domain_length, sizeof(domain_length)) != 1 ||
        CC_SHA256_Update(&context, DOMAIN, sizeof(DOMAIN) - 1U) != 1 ||
        CC_SHA256_Update(&context, payload_length, sizeof(payload_length)) != 1 ||
        CC_SHA256_Update(&context, payload, (CC_LONG)payload_size) != 1 ||
        CC_SHA256_Final(output, &context) != 1) {
        return 0;
    }
#pragma clang diagnostic pop
    return 1;
}
#else
static int digest_once(const unsigned char *payload, size_t payload_size, unsigned char output[32]) {
    unsigned char profile_length[8];
    unsigned char domain_length[8];
    unsigned char payload_length[8];
    unsigned int output_size = 0;
    u64be(sizeof(PROFILE) - 1U, profile_length);
    u64be(sizeof(DOMAIN) - 1U, domain_length);
    u64be(payload_size, payload_length);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL) return 0;
    int success = EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(context, PREFIX, sizeof(PREFIX)) == 1 &&
        EVP_DigestUpdate(context, profile_length, sizeof(profile_length)) == 1 &&
        EVP_DigestUpdate(context, PROFILE, sizeof(PROFILE) - 1U) == 1 &&
        EVP_DigestUpdate(context, domain_length, sizeof(domain_length)) == 1 &&
        EVP_DigestUpdate(context, DOMAIN, sizeof(DOMAIN) - 1U) == 1 &&
        EVP_DigestUpdate(context, payload_length, sizeof(payload_length)) == 1 &&
        EVP_DigestUpdate(context, payload, payload_size) == 1 &&
        EVP_DigestFinal_ex(context, output, &output_size) == 1 && output_size == 32U;
    EVP_MD_CTX_free(context);
    return success;
}
#endif

int main(int argc, char **argv) {
    if (argc != 3) {
        fputs("usage: jce1-digest-c <payload-bytes> <iterations>\n", stderr);
        return 2;
    }
    char *end = NULL;
    uint64_t payload_size = strtoull(argv[1], &end, 10);
    if (*argv[1] == '\0' || *end != '\0' || payload_size == 0U || payload_size > 1048576U) return 2;
    uint64_t iterations = strtoull(argv[2], &end, 10);
    if (*argv[2] == '\0' || *end != '\0' || iterations == 0U || iterations > 100000000U) return 2;

    unsigned char *payload = malloc((size_t)payload_size);
    if (payload == NULL) return 3;
    for (uint64_t index = 0; index < payload_size; index++) {
        payload[index] = (unsigned char)((index * 31U + 17U) % 251U);
    }

    unsigned char digest[32];
    for (uint64_t index = 0; index < (iterations < 100U ? iterations : 100U); index++) {
        if (!digest_once(payload, (size_t)payload_size, digest)) return 4;
    }
    struct timespec start;
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (uint64_t index = 0; index < iterations; index++) {
        if (!digest_once(payload, (size_t)payload_size, digest)) return 4;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    uint64_t nanoseconds = elapsed_ns(&start, &end_time);
    if (nanoseconds == 0U) nanoseconds = 1U;
    uint64_t operations = iterations * 1000000000U / nanoseconds;
    uint64_t bytes_per_second = operations * payload_size;

    char hexadecimal[65];
    for (size_t index = 0; index < 32; index++) {
        snprintf(&hexadecimal[index * 2U], 3U, "%02x", digest[index]);
    }
    hexadecimal[64] = '\0';
    printf("{\"schema\":\"joan.digest-benchmark.v1\",\"implementation\":\"c-system-crypto\","
           "\"payload_bytes\":%" PRIu64 ",\"iterations\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ","
           "\"operations_per_second\":%" PRIu64 ",\"bytes_per_second\":%" PRIu64 ","
           "\"digest\":{\"algorithm\":\"sha256\",\"profile\":\"joan-hash-v1\","
           "\"domain\":\"joan.source.v1\",\"value\":\"%s\"},"
           "\"claim_scope\":\"implementation-microbenchmark-not-language-superiority\"}\n",
           payload_size, iterations, nanoseconds, operations, bytes_per_second, hexadecimal);
    free(payload);
    return 0;
}
