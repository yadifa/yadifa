/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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
 *------------------------------------------------------------------------------
 *
 */

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <openssl/ossl_typ.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <string.h>

#ifdef NID_X9_62_prime256v1

#define DNSKEY_ALGORITHM_ECDSAP256SHA256_NID NID_X9_62_prime256v1
//#define DNSKEY_ALGORITHM_ECDSAP384SHA384_NID NID_secp384r1

static unsigned char digest[32] =
{
    0x45,0x14,0x4e,0x0e,0x51,0xf1,0x41,0xea,
    0x42,0xec,0x42,0xea,0x40,0x2c,0xe2,0x8d,
    0xd8,0x05,0x89,0x66,0x25,0x7e,0x90,0xba,
    0xc0,0x54,0x31,0xff,0xd7,0xe9,0x0a,0x7b
};

static int nids[1] =
{
    DNSKEY_ALGORITHM_ECDSAP256SHA256_NID
    //,DNSKEY_ALGORITHM_ECDSAP384SHA384_NID
};

static EC_KEY*
ecdsa_genkey_by_nid(int nid)
{
    //yassert(size == 256 || size == 384);

    int err;
    EC_KEY *ecdsa;
    EC_GROUP *group;

    if((group = EC_GROUP_new_by_curve_name(nid)) == NULL)
    {
        return NULL;
    }

    if((ecdsa = EC_KEY_new()) == NULL)
    {
        return NULL;
    }

    EC_KEY_set_group(ecdsa, group);

    err = EC_KEY_generate_key(ecdsa); /* no callback */

    EC_GROUP_clear_free(group);

    if(err == 0)
    {
        // error

        EC_KEY_free(ecdsa);
        ecdsa = NULL;
    }

    return ecdsa;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L

static size_t ecdsa_sign(EC_KEY *key, void* digest, size_t digest_len, unsigned char *output_buffer, size_t output_buffer_size)
{
    (void)output_buffer_size;

    unsigned char *output = output_buffer;

    ECDSA_SIG *sig = ECDSA_do_sign(digest, digest_len, key);

    if(sig != NULL)
    {
        //int bn_size = dnskey_ecdsa_nid_to_signature_bn_size(key->nid);

        const BIGNUM *sig_r;
        const BIGNUM *sig_s;
        ECDSA_SIG_get0(sig, &sig_r, &sig_s);

        int r_size = BN_num_bytes(sig_r);
        memset(output, 0, 32 - r_size);
        BN_bn2bin(sig_r, &output[32 - r_size]);
        output += 32;

        int s_size = BN_num_bytes(sig_s);
        memset(output, 0, 32 - s_size);
        BN_bn2bin(sig_s, &output[32 - s_size]);
        output += 32;

        ECDSA_SIG_free(sig);

        size_t output_size = r_size + s_size;

        return output_size;
    }
    else
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
            printf("digest signature returned an ssl error %08x %s", (unsigned int)ssl_err, buffer);
        }

        ERR_clear_error();

        return 0;
    }
}

static int ecdsa_verify(EC_KEY *key, const unsigned char *digest, size_t digest_len, const unsigned char *signature, size_t signature_len)
{
    (void)signature_len;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    int sig_r_size = 32;
    /*
    while(signature[sig_r_size - 1] == 0)
    {
        --sig_r_size;
    }
    */
    BIGNUM *sig_r = BN_bin2bn(signature, sig_r_size, NULL);
    signature += 32;
    int sig_s_size = 32;
    /*
    while(signature[sig_s_size - 1] == 0)
    {
        --sig_r_size;
    }
    */
    BIGNUM *sig_s = BN_bin2bn(signature, sig_s_size, NULL);
    ECDSA_SIG_set0(sig, sig_r, sig_s);

    int err = ECDSA_do_verify(digest, digest_len, sig, key);

    if(err == 1)
    {
        ECDSA_SIG_free(sig);
        return 1;
    }
    else
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
            printf("digest verification returned an ssl error %08lx %s", ssl_err, buffer);
        }

        ECDSA_SIG_free(sig);
        ERR_clear_error();

        return 0;
    }
}

#endif

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    unsigned char buffer[4096];

    ENGINE_load_openssl();
    ENGINE_load_builtin_engines();
    SSL_library_init();
    SSL_load_error_strings();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L

    for(size_t i = 0; i < sizeof(nids)/sizeof(int); ++i)
    {
        for(int tries = 0; tries < 10000; ++tries)
        {
            EC_KEY *key = ecdsa_genkey_by_nid(nids[i]);
            size_t signature_size;
            if((signature_size = ecdsa_sign(key, digest, sizeof(digest), buffer, sizeof(buffer))) > 0)
            {
                if(ecdsa_verify(key, digest, sizeof(digest), buffer, signature_size) != 1)
                {
                    printf("failure #%i\n", tries);
                }
            }
            else
            {
                break;
            }
            EC_KEY_free(key);
        }
    }
#endif

    return EXIT_SUCCESS;
}
#else
main() {puts("ooops");}
#endif
