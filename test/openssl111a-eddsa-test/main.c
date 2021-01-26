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

#ifdef NID_ED25519

#define DNSKEY_ALGORITHM_ED25519_NID NID_ED25519
//#define DNSKEY_ALGORITHM_ED448_NID NID_ED448

static unsigned char data[] =
{
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Intege"
    "r nec odio. Praesent libero. Sed cursus ante dapibus diam. Sed "
    "nisi. Nulla quis sem at nibh elementum imperdiet. Duis sagittis"
    "ipsum. Praesent mauris. Fusce nec tellus sed augue semper porta"
    ". Mauris massa. Vestibulum lacinia arcu eget nulla. Class apten"
    "t taciti sociosqu ad litora torquent per conubia nostra, per in"
    "ceptos himenaeos. Curabitur sodales ligula in libero. Sed digni"
    "ssim lacinia nunc. Curabitur tortor. Pellentesque nibh. Aenean "
    "quam. In scelerisque sem at dolor. Maecenas mattis. Sed convall"
    "is tristique sem. Proin ut ligula vel nunc egestas porttitor. M"
    "orbi lectus risus, iaculis vel, suscipit quis, luctus non, mass"
    "a. Fusce ac turpis quis ligula lacinia aliquet. Mauris ipsum. N"
    "ulla metus metus, ullamcorper vel, tincidunt sed, euismod in, n"
    "ibh. Quisque volutpat condimentum velit. Class aptent taciti so"
    "ciosqu ad litora torquent per conubia nostra, per inceptos hime"
    "naeos. Nam nec ante. Sed lacinia, urna non tincidunt mattis, to"
    "rtor neque adipiscing diam, a cursus ipsum ante quis turpis. Nu"
    "lla facilisi. Ut fringilla. Suspendisse potenti. Nunc feugiat m"
    "i a tellus consequat imperdiet. Vestibulum sapien. Proin quam. "
};

static int nids[1] =
{
    DNSKEY_ALGORITHM_ED25519_NID
    //,DNSKEY_ALGORITHM_ED448_NID
};

static EVP_PKEY*
eddsa_genkey_by_nid(int nid)
{
    EVP_PKEY *evp_key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(nid, NULL);

    if(ctx != NULL)
    {
        if(EVP_PKEY_keygen_init(ctx) == 1)
        {
            if(EVP_PKEY_keygen(ctx, &evp_key) == 1)
            {
            }
        }

        EVP_PKEY_CTX_free(ctx);
    }

    return evp_key;
}

static size_t eddsa_sign(EVP_PKEY *key, void* digest, size_t digest_len, unsigned char *output_buffer, size_t output_buffer_size)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, NULL, NULL, key);
    size_t signature_size = output_buffer_size;
    if(EVP_DigestSign(ctx, output_buffer, &signature_size, digest, digest_len) != 1)
    {
        signature_size = 0;
    }
    EVP_MD_CTX_destroy(ctx);
    return signature_size;
}

static int eddsa_verify(EVP_PKEY *key, const unsigned char *digest, size_t digest_len, const unsigned char *signature, size_t signature_len)
{
    int ret = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key);
    if(EVP_DigestVerify(ctx, signature, signature_len, digest, digest_len) == 1)
    {
        ret = 1;
    }
    EVP_MD_CTX_destroy(ctx);
    return ret;
}

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

    for(size_t i = 0; i < sizeof(nids)/sizeof(int); ++i)
    {
        for(int tries = 0; tries < 10000; ++tries)
        {
            EVP_PKEY *key = eddsa_genkey_by_nid(nids[i]);
            int signature_size;
            if((signature_size = eddsa_sign(key, data, sizeof(data), buffer, sizeof(buffer))) > 0)
            {
                if(eddsa_verify(key, data, sizeof(data), buffer, signature_size) == 1)
                {
                    //printf("success\n");
                }
                else
                {
                    printf("failure\n");
                }
            }

            EVP_PKEY_free(key);
        }
    }

    return EXIT_SUCCESS;
}
#else
main() {puts("oops");}
#endif
