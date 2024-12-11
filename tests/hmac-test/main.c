/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

/**-----------------------------------------------------------------------------
 * @defgroup test
 * @ingroup test
 * @brief skeleton file
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * skeleton test program, will not be installed with a "make install"
 *
 * To create a new test based on the skeleton:
 *
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 *----------------------------------------------------------------------------*/

#include <dnscore/dnscore.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/zone_reader_text.h>
#include <dnscore/base64.h>
#include <dnscore/hmac.h>
#include <dnscore/format.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/dnskey_signature.h>
#include <dnsdb/zdb_packed_ttlrdata.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/logger_channel_stream.h>

static int  test_success_count = 0;
static int  test_error_count = 0;

static void test_result(ya_result ret, const char *text, ...)
{
    va_list args;
    format("RESULT: %r : ", ret);
    va_start(args, text);

    vosformat(termout, text, args);
    output_stream_write(termout, "\n", 1);
    va_end(args);
    if(ISOK(ret))
    {
        ++test_success_count;
    }
    else
    {
        ++test_error_count;
    }
}

static uint8_t *base64_to_bin(const char *b64, size_t *lenp)
{
    *lenp = 0;
    size_t   b64_len = strlen(b64);
    size_t   len = BASE64_DECODED_SIZE(b64_len);
    uint8_t *buffer = (uint8_t *)malloc(len);
    if(buffer != NULL)
    {
        ya_result ret;
        if(ISOK(ret = base64_decode(b64, b64_len, buffer)))
        {
            *lenp = ret;
            return buffer;
        }
        free(buffer);
    }
    return NULL;
}

static const char lorem_ipsum_text[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam in sodales tellus. "
    "Donec orci augue, congue vitae mollis in, egestas eu lectus. Duis libero ligula, "
    "finibus quis elit dapibus, ullamcorper bibendum sem. Cras varius tortor vel quam "
    "interdum, placerat lacinia dolor feugiat. Aliquam erat volutpat. Cras a felis nisi. "
    "Vestibulum varius tellus vel bibendum finibus.";

struct hmac_alg_res_s
{
    int         algorithm;
    const char *value;
};

typedef struct hmac_alg_res_s hmac_alg_res_t;

static hmac_alg_res_t         samples[] = {{0, "YhOc9ENgibc9l+13lfJ6USFK7jkcbTr8Zp+XvB9cLMg="},
                                           {HMAC_MD5, "NetCX3K2N0uCsgvKlIYcXA=="},
                                           {HMAC_SHA1, "/O3ab59YrAOzymTAt2b1QGNZUrg="},
                                           {HMAC_SHA224, "+gAhvLKc9v8UfjddqyTN1XEh3c3+NWiSowcIRg=="},
                                           {HMAC_SHA256, "We08zCIpp16iowf0zesfzhoPI/UU4zGCVmGQL2TXaLs="},
                                           {HMAC_SHA384, "geXamCltBXjNmxxz17sO9X7cdtFXA6y5SCCr68hDIDOZYfbulRKm7jCMuJUUAkEE"},
                                           {HMAC_SHA512, "b9gKDEbk32pBmAwquaWkc+rpSnTtLq3uiW3N+UDTUv65nA1ndt/rWOHxqGdHrjbsrmjeAwZAVxFNtKk6gk6/fA=="},
                                           {0, NULL}};

static void                   hmac_test_inner(tsig_hmac_t mac, hmac_alg_res_t *sample)
{
    uint8_t  out[HMAC_BUFFER_SIZE];
    char     out64[BASE64_ENCODED_SIZE(sizeof(out))];
    uint32_t out_len = sizeof(out);
    memset(out, 0xac, sizeof(out));
    memset(out64, 0xca, sizeof(out64));
    if(ISOK(hmac_update(mac, lorem_ipsum_text, sizeof(lorem_ipsum_text))))
    {
        if(ISOK(hmac_final(mac, out, &out_len)))
        {
            uint32_t out64_len = base64_encode(out, out_len, out64);
            out64[out64_len] = '\0';
            formatln("HMAC %i : %s", sample->algorithm, out64);

            output_stream_flush(termout);
            if(strcmp(sample->value, out64) == 0)
            {
                // success
                test_result(SUCCESS, "result matched");
            }
            else
            {
                // failure
                test_result(ERROR, "result didn't match");
            }
        }
        else
        {
            test_result(ERROR, "didn't get result");
        }
    }
    else
    {
        test_result(ERROR, "couldn't update");
    }
}

static void hmac_test()
{
    size_t   key_len = 0;
    uint8_t *key = NULL;

    for(int_fast32_t i = 0;; ++i)
    {
        hmac_alg_res_t *sample = &samples[i];
        if(sample->algorithm == 0)
        {
            if(sample->value == NULL)
            {
                break;
            }

            free(key);

            key_len = 0;
            key = base64_to_bin(sample->value, &key_len);
            continue;
        }

        tsig_hmac_t mac = tsig_hmac_allocate();

        if(ISOK(hmac_init(mac, key, key_len, sample->algorithm)))
        {
            hmac_test_inner(mac, sample);
            hmac_reset(mac);
            if(ISOK(hmac_init(mac, key, key_len, sample->algorithm)))
            {
                hmac_test_inner(mac, sample);
            }
            else
            {
                test_result(ERROR, "couldn't re-initialise the HMAC");
            }
            hmac_free(mac);
        }
        else
        {
            test_result(ERROR, "couldn't initialise the HMAC");
        }
    }

    free(key);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    hmac_test();

    formatln("summary: success_count=%i errors_count=%i", test_success_count, test_error_count);

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
