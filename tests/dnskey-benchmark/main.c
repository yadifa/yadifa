/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
 * The YADIFA TM software product is provided under the BSD 3-clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in the
 *          documentation and/or other materials provided with the distribution.
 *        * Neither the name of EURid nor the names of its contributors may be
 *          used to endorse or promote products derived from this software
 *          without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *----------------------------------------------------------------------------*/

#include <sys/time.h>

#include <dnscore/dnscore_config.h>

#include <dnscore/dnscore.h>
#include <dnscore/threaded_dll_cw.h>
#include <dnscore/threaded_qsl_cw.h>
#include <dnscore/thread_pool.h>

#include <dnscore/dns_message_verify_rrsig.h>
#include <dnscore/dns_udp.h>
#include <dnscore/dnsname.h>
#include <dnscore/dns_message.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/dns_packet_reader.h>
#include <dnscore/base64.h>
#include <dnscore/parsing.h>
#include "dnscore/config_settings.h"
#include "dnscore/dnskey_postquantumsafe.h"
#include "dnscore/timems.h"

#if DNSCORE_HAS_OQS_SUPPORT
#include <oqs/oqsconfig.h>
#endif

#define DUMP_DNSKEY_RDATA 0
#define DUMP_DNSKEY_PRIVATE_TEXT 0
#define DUMP_DNSKEY_PUBLIC_TEXT 0

static const uint32_t signature_batch_count = 300; // kept low because some algorithms are very slow

static const uint8_t ns1_yadifa_eu[] = {
    6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0,                //  0 .. 11
    0, 2, // NS                                                     // 12 .. 13
    0, 1, // IN                                                     // 14 .. 15
    0, 1, 81, 128, // 86400                                         // 16 .. 19
    0, 4 + 6 + 3 + 1, // rdata size                                 // 20 .. 21
    3, 'n', 's', '1', 5, 'e', 'u', 'r', 'i', 'd', 2, 'e', 'u', 0,   // 22 .. 35
};


static ya_result dnskey_signature_benchmark(dnskey_t *key, const char *tag)
{
    uint8_t         *signature;
    bytes_signer_t   bytes_signer;
    bytes_verifier_t bytes_verifier;

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR; // no key
    }

    if(!dnskey_is_private(key))
    {
        return DNSSEC_ERROR_KEYRING_KEY_IS_NOT_PRIVATE; // not private
    }

    int      buffer_size = 65535;
    uint8_t *buffer = malloc(buffer_size);
    if(buffer == NULL)
    {
        return MAKE_ERRNO_ERROR(ENOMEM);
    }
    uint32_t signature_size = 0x1000000;
    signature = malloc(signature_size);
    if(signature == NULL)
    {
        free(buffer);
        return MAKE_ERRNO_ERROR(ENOMEM);
    }

    for(uint_fast8_t record_count = 1; record_count < 5; ++record_count)
    {
        formatln("algorithm: %s record_count: %u wire_size: %u", tag, (uint32_t)record_count, (uint32_t)(sizeof(ns1_yadifa_eu) * record_count));

        for(uint_fast8_t i = 0; i < record_count; ++i)
        {
            memcpy(&buffer[sizeof(ns1_yadifa_eu) * i], ns1_yadifa_eu, sizeof(ns1_yadifa_eu));
        }

        uint32_t rrset_size = sizeof(ns1_yadifa_eu) * record_count;

        int32_t signature_generated = ERROR;

        int64_t signature_start = timeus();

        for(uint32_t signature_index = 0; signature_index < signature_batch_count; ++signature_index)
        {
            key->vtbl->signer_init(key, &bytes_signer);
            // adds bytes to sign
            bytes_signer.vtbl->update(&bytes_signer, buffer, rrset_size);

            if(FAIL(signature_generated = bytes_signer.vtbl->sign(&bytes_signer, signature, &signature_size)))
            {
                break;
            }
            bytes_signer.vtbl->finalise(&bytes_signer);
        }
        int64_t signature_stop = timeus();

        if(ISOK(signature_generated))
        {
            const double signatures_time = (signature_stop - signature_start) / ONE_SECOND_US_F;
            const double signature_time_s = signatures_time / signature_batch_count;
            formatln("algorithm: %s signature_size: %u", tag, signature_size);
            formatln("algorithm: %s signature_count: %u signatures_time_s: %12.9f signature_time: %12.9f",
                tag,
                signature_batch_count,
                signatures_time,
                signature_time_s);

            int32_t signature_verified = ERROR;

            int64_t verify_start = timeus();

            for(uint32_t signature_index = 0; signature_index < signature_batch_count; ++signature_index)
            {
                key->vtbl->verifier_init(key, &bytes_verifier);
                bytes_verifier.vtbl->update(&bytes_verifier, buffer, rrset_size);

                if(FAIL(signature_verified = bytes_verifier.vtbl->verify(&bytes_verifier, signature, signature_size)))
                {
                    break;
                }
            }

            int64_t verify_stop = timeus();

            if(ISOK(signature_verified))
            {
                const double verifications_time = (verify_stop - verify_start) / ONE_SECOND_US_F;
                const double verification_time_s = verifications_time / signature_batch_count;
                formatln("algorithm: %s verification_count: %u verifications_time: %12.9f verification_time: %12.9f",
                    tag,
                    signature_batch_count,
                    verifications_time,
                    verification_time_s);

                buffer[rrset_size - 1] ^= 1;

                int64_t fail_verify_start = timeus();
                for(uint32_t signature_index = 0; signature_index < signature_batch_count; ++signature_index)
                {
                    key->vtbl->verifier_init(key, &bytes_verifier);
                    bytes_verifier.vtbl->update(&bytes_verifier, buffer, rrset_size);

                    if(ISOK(signature_verified = bytes_verifier.vtbl->verify(&bytes_verifier, signature, signature_size)))
                    {
                        break;
                    }
                }
                int64_t fail_verify_stop = timeus();

                if(ISOK(signature_verified))
                {
                    const double fail_verifications_time = (fail_verify_stop - fail_verify_start) / ONE_SECOND_US_F;
                    const double fail_verification_time_s = fail_verifications_time / signature_batch_count;
                    formatln("algorithm: %s fail_verification_count: %u fail_verifications_time: %12.9f fail_verification_time: %12.9f",
                        tag,
                        signature_batch_count,
                        fail_verifications_time,
                        fail_verification_time_s);
                }
                else
                {
                    osformatln(termerr, "ERROR: %s: dnskey_signature_benchmark: fail_verify: %r (should have failed)", tag, signature_verified);
                }
            }
            else
            {
                osformatln(termerr, "ERROR: %s: dnskey_signature_benchmark: verify: %r", tag, signature_verified);
            }
        }
        else
        {
            osformatln(termerr, "ERROR: %s: dnskey_signature_benchmark: sign: %r", tag, signature_generated);
        }
    }

    free(signature);
    free(buffer);
    return SUCCESS;
}

static ya_result dnskey_algorithm_benchmark(uint8_t algorithm, uint32_t size)
{
    const dnskey_features_t *features = dnskey_supported_algorithm(algorithm);
    assert(features != NULL);
    const char *algorithm_category_name = (features->names != NULL)?features->names[0]:NULL;
    const char *algorithm_name = algorithm_category_name;
    assert(algorithm_name != NULL);
    char name_tag[256];
    if(size != 0)
    {
        snformat(name_tag, sizeof(name_tag), "%s[%i]", algorithm_name, size);
        algorithm_name = name_tag;
    }
    ya_result ret;
    dnskey_t *key;
    int64_t newinstance_start = timeus();
    ret = dnskey_newinstance(size, algorithm, DNSKEY_FLAGS_ZSK, "yadifa.eu", &key);
    if(ret < 0)
    {
        if(ret == DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM)
        {
            osformatln(termerr, "ERROR: %s: algorithm not supported", algorithm_name);
            return FEATURE_NOT_IMPLEMENTED_ERROR;
        }
        osformatln(termerr, "ERROR: %s: dnskey_newinstance failed: %08x = %s", algorithm_name, ret, error_gettext(ret));
        return INVALID_STATE_ERROR;
    }
    int64_t newinstance_stop = timeus();

    uint32_t rdata_expected_size = key->vtbl->dnskey_rdatasize(key);

    format("algorithm: %s name: %s", algorithm_name, algorithm_category_name);
    if(size > 0)
    {
        format("/%u", size);
    }
    println("");

    formatln("algorithm: %s rdata_expected_size: %u", algorithm_name, rdata_expected_size);

    uint8_t *rdata = malloc(rdata_expected_size);
    assert(rdata != NULL);

    uint32_t rdata_size = key->vtbl->dnskey_writerdata(key, rdata, rdata_expected_size);

    formatln("algorithm: %s rdata_size: %u", algorithm_name, rdata_expected_size);

#if DUMP_DNSKEY_RDATA
    osprint_dump(termout, rdata, rdata_size, 32, OSPRINT_DUMP_HEXTEXT);
    println("");
#else
    (void)rdata_size;
#endif

    output_stream_t private_key_baos;
    output_stream_t public_key_baos;
    bytearray_output_stream_init_ex(&private_key_baos, NULL, 0, 0);
    bytearray_output_stream_init_ex(&public_key_baos, NULL, 0, 0);

    if(FAIL(ret = dnskey_store_private_key_to_stream(key, &private_key_baos)))
    {
        osformatln(termerr, "ERROR: %s: dnskey_store_private_key_to_stream failed: %08x = %s", algorithm_name, ret, error_gettext(ret));
        ret = INVALID_STATE_ERROR;
        goto dnskey_algorithm_benchmark_end;
    }
    uint32_t private_key_size_bytes = bytearray_output_stream_size(&private_key_baos);
    formatln("algorithm: %s private_key_size_bytes: %u (text)", algorithm_name, private_key_size_bytes);
#if DUMP_DNSKEY_PRIVATE_TEXT
    output_stream_write(termout, bytearray_output_stream_buffer(&private_key_baos), bytearray_output_stream_size(&private_key_baos));
    println("");
#endif
    if(FAIL(ret = dnskey_store_public_key_to_stream(key, &public_key_baos)))
    {
        osformatln(termerr, "ERROR: %s: dnskey_store_public_key_to_stream failed: %08x = %s", algorithm_name, ret, error_gettext(ret));
        ret = INVALID_STATE_ERROR;
        goto dnskey_algorithm_benchmark_end;
    }
    uint32_t public_key_size_bytes = bytearray_output_stream_size(&public_key_baos);
    formatln("algorithm: %s public_key_size_bytes: %u  (text)", algorithm_name, public_key_size_bytes);
#if DUMP_DNSKEY_PUBLIC_TEXT
    output_stream_write(termout, bytearray_output_stream_buffer(&public_key_baos), bytearray_output_stream_size(&public_key_baos));
    println("");
#endif
    formatln("algorithm: %s generation_time: %9.6f", algorithm_name, timeus_diff_seconds_double(newinstance_start, newinstance_stop));

    ret = dnskey_signature_benchmark(key, algorithm_name);

dnskey_algorithm_benchmark_end:
    free(rdata);
    output_stream_close(&public_key_baos);
    output_stream_close(&private_key_baos);
    dnskey_release(key);

    return ret;
}

int main(int argc, char *argv[])
{
    dnscore_init();

    uint32_t alg_first = 1;
    uint32_t alg_last = 255;

    if(argc > 1)
    {
        if(FAIL(parse_u32_check_range(argv[1], &alg_first, 1, 255, 10)))
        {
            formatln("failed to parse '%s' as an integer in the [1; 255] range", argv[1]);
            return EXIT_FAILURE;
        }

        if(argc > 2)
        {
            if(FAIL(parse_u32_check_range(argv[2], &alg_last, alg_first, 255, 10)))
            {
                formatln("failed to parse '%s' as an integer in the [%i; 255] range", argv[1], alg_first);
                return EXIT_FAILURE;
            }
        }
        else
        {
            alg_last = alg_first;
        }
    }

#if DNSCORE_HAS_OQS_SUPPORT
    formatln("oqs_library_version: %s", OQS_VERSION_TEXT);
    formatln("oqs_compile_build_target: %s", OQS_COMPILE_BUILD_TARGET);
#endif
    formatln("algorithm_range: [%u ;%u]", alg_first, alg_last);

#if DNSCORE_HAS_OQS_SUPPORT
    dnskey_postquantumsafe_info_t pqs_info = {0};
#endif

    for(uint32_t algorithm = alg_first; algorithm <= alg_last; ++algorithm)
    {
        const dnskey_features_t *features = dnskey_supported_algorithm(algorithm);
        if(features == NULL)
        {
            formatln("begin: algorithm_id: %02x", algorithm);
            formatln("end: algorithm_id: %02x", algorithm);
            continue;
        }
        format("begin: algorithm_id: %02x", algorithm);
        flushout();
        flusherr();
        if(features->names == NULL)
        {
            println(" name: NULL");
            osformatln(termerr, "ERROR: algoritmh %02x has no name", algorithm);
            continue;
        }

        formatln(" name: %s size_min: %i size_max: %i size_step: %i usage_mask: %x", features->names[0], features->size_bits_min, features->size_bits_max, features->size_multiple, features->usage);

#if DNSCORE_HAS_OQS_SUPPORT
        if(ISOK(dnskey_postquantumsafe_info(algorithm, &pqs_info)))
        {
            formatln("oqs: method: %s version: %s public_size: %lu private_size: %lu signature_size: %lu nist_level_claim: %hhu",
                pqs_info.method_name,
                pqs_info.alg_version,
                pqs_info.length_public_key,
                pqs_info.length_secret_key,
                pqs_info.length_signature,
                pqs_info.claimed_nist_level);
            bool bad = false;
            if(pqs_info.length_public_key > UINT16_MAX - 4)
            {
                bad = true;
                formatln("bad: algorithm: %i method: %s public key is too big to be stored in an RDATA record", algorithm, pqs_info.method_name);
            }
            if(pqs_info.length_signature > UINT16_MAX - (18 + 256))
            {
                bad = true;
                formatln("bad: algorithm: %i method: %s signature may be too big to be stored in an RDATA record", algorithm, pqs_info.method_name);
            }
            if(bad)
            {
                formatln("end: algorithm_id: %02x", algorithm);
                continue;
            }
        }
#endif

        if(features->size_bits_max == features->size_bits_min)
        {
            dnskey_algorithm_benchmark(algorithm, 0);
        }
        else
        {
            uint32_t sizes_count = 0;
            uint32_t sizes[4];
            sizes[sizes_count++] = features->size_bits_min;
            if(features->size_bits_zsk_default > features->size_bits_min)
            {
                sizes[sizes_count++] = features->size_bits_zsk_default;
            }
            if(features->size_bits_ksk_default > features->size_bits_zsk_default)
            {
                sizes[sizes_count++] = features->size_bits_ksk_default;
            }
            if(features->size_bits_max > features->size_bits_ksk_default)
            {
                sizes[sizes_count++] = features->size_bits_max;
            }

            for(uint32_t i = 0; i < sizes_count; ++i)
            {
                if(FAIL(dnskey_algorithm_benchmark(algorithm, sizes[i])))
                {
                    break;
                }
            }
        }

        formatln("end: algorithm_id: %02x", algorithm);
    }

    flushout();
    flusherr();

    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
