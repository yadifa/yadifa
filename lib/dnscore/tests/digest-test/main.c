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

#include "yatest.h"
#include "dnscore/base16.h"
#include <dnscore/dnscore.h>
#include <dnscore/digest.h>

struct contexts_s
{
    void (*digest_init)(digest_t *ctx);
    const char *message;
    const char *b16_result;
};

struct contexts_s md5_contexts[] = {{digest_md5_init, "", "d41d8cd98f00b204e9800998ecf8427e"}, {digest_md5_init, "The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"}, {NULL, NULL, NULL}};

struct contexts_s contexts[] = {{digest_rawdata_init, "", ""},
                                {digest_rawdata_init, "The quick brown fox jumps over the lazy dog", "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"},
                                {digest_md5_init, "", "d41d8cd98f00b204e9800998ecf8427e"},
                                {digest_md5_init, "The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"},
                                {digest_sha1_init, "The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
                                {digest_sha1_init, "The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"},
                                {digest_sha1_init, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
                                {digest_sha256_init, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                                {digest_sha256_init, "The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
                                {digest_sha384_init, "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
                                {digest_sha384_init, "The quick brown fox jumps over the lazy dog", "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"},
                                {digest_sha512_init,
                                 "",
                                 "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a"
                                 "538327af927da3e"},
                                {digest_sha512_init,
                                 "The quick brown fox jumps over the lazy dog",
                                 "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa"
                                 "0538f3db854fee6"},
                                {NULL, NULL, NULL}};

static int        digest_context_test(struct contexts_s *context)
{
    uint8_t  expected[128];
    uint8_t  result[128];

    digest_t digest;

    context->digest_init(&digest);

    yatest_log("testing '%s' digest with '%s' input", digest_class_name(&digest), context->message);

    digest_update(&digest, context->message, strlen(context->message));
    int digest_size = digest_get_size(&digest);

    if(context->digest_init != digest_rawdata_init)
    {
        int buffer_would_overflow = digest_final_copy_bytes(&digest, result, 1);
        if(buffer_would_overflow != BUFFER_WOULD_OVERFLOW)
        {
            yatest_err("digest_final_copy_bytes expected to return BUFFER_WOULD_OVERFLOW, got %08x = %s instead", buffer_would_overflow, error_gettext(buffer_would_overflow));
            return 1;
        }
    }

    int result_size = digest_final_copy_bytes(&digest, result, sizeof(result));
    if(context->digest_init == digest_rawdata_init)
    {
        yatest_log("digest-from-ctx:");
        yatest_hexdump(&digest.digest[0], &digest.digest[digest_size]);
    }
    yatest_log("result:");
    yatest_hexdump(result, result + result_size);
    int expected_size = strlen(context->b16_result);
    if(context->digest_init == digest_rawdata_init)
    {
        uint8_t *ptr = NULL;
        int32_t  ptr_size = digest_get_digest(&digest, (void **)&ptr);
        yatest_log("ptr:");
        yatest_hexdump(ptr, ptr + ptr_size);
        if(ptr_size != result_size)
        {
            yatest_err("digest sizes differ: ptr=%i != result=%i", ptr_size, result_size);
            return 1;
        }
        if(memcmp(ptr, result, result_size) != 0)
        {
            yatest_err("digest content differ ptr/result");
            yatest_hexdump(ptr, ptr + ptr_size);
            yatest_hexdump(result, result + result_size);
            return 1;
        }
    }
    digest_finalise(&digest);
    if((digest_size << 1) != expected_size)
    {
        yatest_err("digest size doesn't match the expected digest size: digest_size*2=%i != expected_size=%i ", (digest_size << 1), expected_size);
        return 1;
    }
    if(digest_size != result_size)
    {
        yatest_err("digest size doesn't match the result digest size: digest_size=%i != result_size=%i");
        return 1;
    }
    base16_decode(context->b16_result, expected_size, expected);
    if(memcmp(expected, result, result_size) == 0)
    {
        yatest_log("%s: success", digest_class_name(&digest));
        return 0;
    }
    else
    {
        yatest_err("%s: failure", digest_class_name(&digest));
        yatest_log("expected:");
        yatest_hexdump(expected, expected + result_size);
        yatest_log("result:");
        yatest_hexdump(result, result + result_size);
        return 1;
    }
}

static int digest_context_final_get_test(struct contexts_s *context)
{
    uint8_t  expected[128];
    uint8_t  result[128];
    void    *resultp;

    digest_t digest;

    context->digest_init(&digest);

    yatest_log("testing '%s' digest with '%s' input", digest_class_name(&digest), context->message);

    digest_update(&digest, context->message, strlen(context->message));
    int digest_size = digest_get_size(&digest);
    digest_final(&digest);

    int result_size = digest_get_digest(&digest, &resultp);
    if(result_size > (int)sizeof(result))
    {
        yatest_err("digest_get_digest returned a digest at %p with size %i > %i (test bug?)", resultp, result_size, sizeof(result));
        return 1;
    }
    memcpy(result, resultp, result_size);

    yatest_log("result:");
    yatest_hexdump(result, result + result_size);
    int expected_size = strlen(context->b16_result);
    if(context->digest_init == digest_rawdata_init)
    {
        uint8_t *ptr = NULL;
        int32_t  ptr_size = digest_get_digest(&digest, (void **)&ptr);
        yatest_log("ptr:");
        yatest_hexdump(ptr, ptr + ptr_size);
        if(ptr_size != result_size)
        {
            yatest_err("digest sizes differ: ptr=%i != result=%i", ptr_size, result_size);
            return 1;
        }
        if(memcmp(ptr, result, result_size) != 0)
        {
            yatest_err("digest content differ ptr/result");
            yatest_hexdump(ptr, ptr + ptr_size);
            yatest_hexdump(result, result + result_size);
            return 1;
        }
    }
    digest_finalise(&digest);
    if((digest_size << 1) != expected_size)
    {
        yatest_err("digest size doesn't match the expected digest size: digest_size*2=%i != expected_size=%i ", (digest_size << 1), expected_size);
        return 1;
    }
    if(digest_size != result_size)
    {
        yatest_err("digest size doesn't match the result digest size: digest_size=%i != result_size=%i");
        return 1;
    }
    base16_decode(context->b16_result, expected_size, expected);
    if(memcmp(expected, result, result_size) == 0)
    {
        yatest_log("%s: success", digest_class_name(&digest));
        return 0;
    }
    else
    {
        yatest_err("%S: failure: expected/result", digest_class_name(&digest));
        yatest_hexdump(expected, expected + result_size);
        yatest_hexdump(result, result + result_size);
        return 1;
    }
}

static int md5_test()
{
    dnscore_init();
    for(int_fast32_t i = 0; md5_contexts[i].message != NULL; ++i)
    {
        if(digest_context_test(&md5_contexts[i]) != 0)
        {
            return 1;
        }
    }
    dnscore_finalize();
    return 0;
}

static int simple_test()
{
    dnscore_init();
    for(int_fast32_t i = 0; contexts[i].message != NULL; ++i)
    {
        if(digest_context_test(&contexts[i]) != 0)
        {
            return 1;
        }
    }
    dnscore_finalize();
    return 0;
}

static int final_get_test()
{
    dnscore_init();
    for(int_fast32_t i = 0; contexts[i].message != NULL; ++i)
    {
        if(digest_context_final_get_test(&contexts[i]) != 0)
        {
            return 1;
        }
    }
    dnscore_finalize();
    return 0;
}

static int overflow_test()
{
    dnscore_init();
    digest_t digest;
    digest_sha256_init(&digest);
    char *message = "Hello World!";
    digest_update(&digest, message, strlen(message));
    int result_size = digest_final_copy_bytes(&digest, NULL, 0);
    if(ISOK(result_size))
    {
        yatest_err("digest_final_copy_bytes: %s", error_gettext(result_size));
        return 1;
    }
    digest_finalise(&digest);
    dnscore_finalize();
    return 0;
}

static int digest_get_digest_test()
{
    dnscore_init();
    digest_t digest;
    digest_sha256_init(&digest);
    char *message = "Hello World!";
    digest_update(&digest, message, strlen(message));
    uint8_t *ptr = NULL;
    digest_final(&digest);
    /*int result_size = */ digest_get_digest(&digest, (void **)&ptr);
    digest_finalise(&digest);
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(simple_test)
YATEST(final_get_test)
YATEST(overflow_test)
YATEST(digest_get_digest_test)
YATEST(md5_test)
YATEST_TABLE_END
