#pragma once

#include <dnscore/dnscore_config_features.h>
#include <stdint.h>

#define TEST_DSA   0 // disabled
#define TEST_RSA   1
#define TEST_ECDSA 1
#define TEST_EDDSA 1

#if DNSCORE_HAS_LIBRESSL_MODE
#undef TEST_EDDSA
#define TEST_EDDSA 0
#endif

struct dnskey_inputs_s
{
    const char *const record_text;
    uint8_t           algorithm;
    uint16_t          bit_size;
    uint16_t          tag;
    const char *const domain_name;
    const char *const file_name;
};

struct dnskey_private_inputs_s
{
    uint16_t          tag;
    const char *const file_name;
    const char *const file_text;
};

struct expected_signature_s
{
    uint8_t     alg;
    uint16_t    tag;
    const char *domain;
    const char *base64;
};
