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
 *  @brief test
 *
 *  Computes the NSEC3 hash of a domain
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/base16.h>
#include <dnscore/dnsname.h>
#include <dnscore/nsec3-hash.h>
#include <dnscore/format.h>
#include <dnscore/dnsformat.h>
#include <openssl/sha.h>

static void nsec3_hash_print(const u8 *fqdn, const u8 *salt, size_t salt_len, u16 iterations)
{
    u8 digest[64];

    nsec3_hash_function* const digestname = nsec3_hash_get_function(1);
    digestname(fqdn, dnsname_len(fqdn), salt, salt_len, iterations, &digest[1], FALSE);
    digest[0] = SHA_DIGEST_LENGTH;

    formatln("%{dnsname}:   %{digest32h}", fqdn, digest);

    digestname(fqdn, dnsname_len(fqdn), salt, salt_len, iterations, &digest[1], TRUE);

    formatln("*.%{dnsname}: %{digest32h}", fqdn, digest);
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();
    dnsformat_class_init();

    u8* salt = NULL;
    size_t salt_len = 0;
    int iterations = 0;
    ya_result ret;
    u8 fqdn[256];

    if(argc == 1)
    {
        printf("%s [-h BASE16HASH] [-i iterationcount] domain1 [domain2] ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    for(int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "-h") == 0)
        {
            if(i + 1 < argc)
            {
                // read the hash

                ++i;

                size_t len = strlen(argv[i]);

                if((len & 1) != 0)
                {
                    formatln("%s hash size isn't odd (%i)", argv[i], len);
                    exit(1);
                }

                free(salt);
                salt = (u8*)malloc(len / 2);
                if(ISOK(ret = base16_decode(argv[i], len, salt)))
                {
                    salt_len = ret;
                    continue;
                }
                else
                {
                    exit(2);
                }
            }
            else
            {
                exit(3);
            }
        }

        if(strcmp(argv[i], "-i") == 0)
        {
            ++i;
            if(i < argc)
            {
                // read the iterations

                if(sscanf(argv[i], "%i", &iterations) == 1)
                {
                    continue;
                }
            }

            exit(4);
        }

        // parse the domain

        ret = cstr_to_dnsrname_with_check(fqdn, argv[i]);

        if(FAIL(ret))
        {
            exit(4);
        }

        nsec3_hash_print(fqdn, salt, salt_len, iterations);
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
