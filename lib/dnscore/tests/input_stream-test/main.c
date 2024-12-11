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

#include "yatest.h"
#include "yatest_stream.h"

#include <dnscore/dnscore.h>
#include <dnscore/zalloc.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/input_stream.h>
#include <dnscore/dnsname.h>

static const uint8_t pattern[] = {0x11,
                                  0x22,
                                  0x33,
                                  0x44, // 11223344 big endian
                                  0x55,
                                  0x66, // 5566 big endian
                                  0x44,
                                  0x33,
                                  0x22,
                                  0x11, // 11223344 little endian
                                  0x84,
                                  0x33,
                                  0x22,
                                  0x81, // 81223384 little endian
                                  0x66,
                                  0x55, // 5566 little endian
                                  0x80,
                                  0x7f,
                                  0xfe,
                                  0xff,
                                  0xff,
                                  0x17, // 7 * 3 + 3 bits = 24 bits = 0x2ffffff but pack-encoded
                                  0xfe,
                                  0xff,
                                  0xff,
                                  0xff,
                                  0xff,
                                  0xff,
                                  0xff,
                                  0xff,
                                  0x2f, // 7 * 8 + 4 bits = 60 bits = 0x2ffffffffffffffe but
                                        // pack-encoded
                                  6,
                                  'y',
                                  'a',
                                  'd',
                                  'i',
                                  'f',
                                  'a',
                                  2,
                                  'e',
                                  'u',
                                  0, // yadifa.eu, fqdn
                                  5,
                                  'e',
                                  'u',
                                  'r',
                                  'i',
                                  'd',
                                  2,
                                  'e',
                                  'u',
                                  0, // eurid.eu, fqdn
                                  'H',
                                  'e',
                                  'l',
                                  'l',
                                  'o',
                                  ' ',
                                  'W',
                                  'o',
                                  'r',
                                  'l',
                                  'd',
                                  '!',
                                  '\n',
                                  'N',
                                  'o',
                                  'l',
                                  'i',
                                  'n',
                                  'e',
                                  'f',
                                  'e',
                                  'e',
                                  'd'};

static const uint8_t yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}; // yadifa.eu, fqdn
static const uint8_t eurid_eu[] = {5, 'e', 'u', 'r', 'i', 'd', 2, 'e', 'u', 0};       // eurid.eu, fqdn
static const char    hello_world[] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\n'};
static const char    nolinefeed[] = {'N', 'o', 'l', 'i', 'n', 'e', 'f', 'e', 'e', 'd'};

static const char    domain_too_long[] =
    "\020abcdefghijklmnop\020abcdefghijklmnop\020abcdefghijklmnop\020abcdefghijklmnop"  // 64
    "\020abcdefghijklmnop\020abcdefghijklmnop\020abcdefghijklmnop\020abcdefghijklmnop"  // 128
    "\020abcdefghijklmnop\020abcdefghijklmnop\020abcdefghijklmnop\020abcdefghijklmnop"  // 192
    "\020abcdefghijklmnop\020abcdefghijklmnop\020abcdefghijklmnop\020abcdefghijklmnop"; // 256
static const char invalid_charset[] = "\014\300notadomain%";
static const char label_too_long[] = "\100ijmeritamzthjcmoazehtcmazihtmerijtgmkejgcmzelrkjgmlezrkjgmzelrk1";

static int        features_test()
{
    int      ret;
    uint32_t tmpu32;
    int32_t  tmps32;
    uint64_t tmpu64;
    uint16_t tmpu16;
    uint8_t  tmpu8;
    int8_t   tmps8;

    dnscore_init();

    input_stream_t is;
    bytearray_input_stream_init_const(&is, pattern, sizeof(pattern));

    yatest_bytearray_hexdump_next(&is, 4);

    {
        input_stream_read_nu32(&is, &tmpu32);
        uint32_t word = 0x11223344;
        if(tmpu32 != word)
        {
            yatest_err("features_test: input_stream_read_nu32 expected %08x got %08x", word, tmpu32);
            return 1;
        }
    }

    yatest_bytearray_hexdump_next(&is, 2);

    {
        input_stream_read_nu16(&is, &tmpu16);
        uint16_t word = 0x5566;
        if(tmpu16 != word)
        {
            yatest_err("features_test: input_stream_read_nu32 expected %04x got %04x", word, tmpu16);
            return 1;
        }
    }

    yatest_bytearray_hexdump_next(&is, 4);

    {
        input_stream_read_u32(&is, &tmpu32);
#if DNSCORE_HAS_BIG_ENDIAN
        uint32_t word = 0x44332211;
#else
        uint32_t word = 0x11223344;
#endif
        if(tmpu32 != word)
        {
            yatest_err("features_test: input_stream_read_u32 expected %08x got %08x", word, tmpu32);
            return 1;
        }
    }

    yatest_bytearray_hexdump_next(&is, 4);

    {
        input_stream_read_s32(&is, &tmps32);
#if DNSCORE_HAS_BIG_ENDIAN
        int32_t word = 0x84332281;
#else
        int32_t word = 0x81223384;
#endif
        if(tmps32 != word)
        {
            yatest_err("features_test: input_stream_read_s32 expected %08x got %08x", word, tmps32);
            return 1;
        }
    }

    yatest_bytearray_hexdump_next(&is, 2);

    {
        input_stream_read_u16(&is, &tmpu16);
#if DNSCORE_HAS_BIG_ENDIAN
        uint16_t word = 0x6655;
#else
        uint16_t word = 0x5566;
#endif
        if(tmpu16 != word)
        {
            yatest_err("features_test: input_stream_read_u16 expected %04x got %04x", word, tmpu16);
            return 1;
        }
    }

    yatest_bytearray_hexdump_next(&is, 1);

    {
        input_stream_read_u8(&is, &tmpu8);
        uint8_t word = 0x80;
        if(tmpu8 != word)
        {
            yatest_err("features_test: input_stream_read_u8 expected %02x got %02x", word, tmpu8);
            return 1;
        }
    }

    yatest_bytearray_hexdump_next(&is, 1);

    {
        input_stream_read_s8(&is, &tmps8);
        int8_t word = 0x7f;
        if(tmps8 != word)
        {
            yatest_err("features_test: input_stream_read_s8 expected %02x got %02x", word, tmps8);
            return 1;
        }
    }

    yatest_bytearray_hexdump_next(&is, 4);

    {
        input_stream_read_pu32(&is, &tmpu32);
        uint32_t word = 0x2fffffe;
        if(tmpu32 != word)
        {
            yatest_err("features_test: input_stream_read_pu32 expected %08x got %08x", word, tmpu32);
            return 1;
        }
    }

    yatest_bytearray_hexdump_next(&is, 9);

    {
        input_stream_read_pu64(&is, &tmpu64);
        uint64_t word = 0x2ffffffffffffffe;
        if(tmpu64 != word)
        {
            yatest_err("features_test: input_stream_read_pu64 expected %016llx got %016llx", word, tmpu64);
            return 1;
        }
    }

    uint8_t fqdn[256];

    yatest_bytearray_hexdump_next(&is, sizeof(yadifa_eu));

    ret = input_stream_read_dnsname(&is, fqdn);
    if(ret != sizeof(yadifa_eu))
    {
        yatest_err("features_test: input_stream_read_dnsname returned an unexpected value: %i/%08x", ret, ret);
        return 1;
    }
    if(!dnsname_equals(fqdn, yadifa_eu))
    {
        yatest_hexdump(fqdn, fqdn + dnsname_len_checked_with_size(fqdn, sizeof(fqdn)));
        yatest_hexdump(yadifa_eu, yadifa_eu + dnsname_len_checked_with_size(yadifa_eu, sizeof(yadifa_eu)));
        yatest_err("features_test: input_stream_read_dnsname didn't read a proper name: %{dnsname} instead of %{dnsname}", fqdn, yadifa_eu);
        return 1;
    }

    yatest_bytearray_hexdump_next(&is, sizeof(eurid_eu));

    ret = input_stream_read_rname(&is, fqdn);
    if(ret != sizeof(eurid_eu))
    {
        yatest_err("features_test: input_stream_read_rname returned an unexpected value: %i/%08x", ret, ret);
        return 1;
    }
    if(!dnsname_equals(fqdn, eurid_eu))
    {
        yatest_hexdump(fqdn, fqdn + dnsname_len_checked_with_size(fqdn, sizeof(fqdn)));
        yatest_hexdump(eurid_eu, eurid_eu + dnsname_len_checked_with_size(eurid_eu, sizeof(eurid_eu)));
        yatest_err("features_test: input_stream_read_rname didn't read a proper name", fqdn, eurid_eu);
        return 1;
    }

    char text[256];

    yatest_bytearray_hexdump_next(&is, sizeof(hello_world));

    ret = input_stream_read_line(&is, text, sizeof(text));
    if(ret != sizeof(hello_world))
    {
        yatest_err("features_test: input_stream_read_line returned an unexpected value: %i/%08x", ret, ret);
        return 1;
    }

    if(memcmp(text, hello_world, sizeof(hello_world)))
    {
        yatest_err("features_test: input_stream_read_line didn't read the line properly");
        return 1;
    }

    yatest_bytearray_hexdump_next(&is, sizeof(nolinefeed));

    ret = input_stream_read_line(&is, text, sizeof(text));
    if(ret != sizeof(nolinefeed))
    {
        yatest_err("features_test: input_stream_read_line returned an unexpected value: %i/%08x", ret, ret);
        return 1;
    }

    if(memcmp(text, nolinefeed, sizeof(nolinefeed)))
    {
        yatest_err("features_test: input_stream_read_line didn't read the line properly");
        return 1;
    }

    ret = input_stream_read_line(&is, text, sizeof(text));
    if(ret != 0)
    {
        yatest_err("features_test: input_stream_read_line returned an unexpected value: %i/%08x (instead of 0)", ret, ret);
        return 1;
    }

    input_stream_close(&is);

    bytearray_input_stream_init_const(&is, pattern, sizeof(pattern));
    ret = input_stream_skip_fully(&is, sizeof(pattern));
    if(ret != sizeof(pattern))
    {
        yatest_err("features_test: input_stream_skip_fully returned an unexpected value: %i/%08x instead of %i", ret, ret, sizeof(pattern));
        return 1;
    }

    input_stream_close(&is);

    return 0;
}

static int dnsname_error_test()
{
    int            ret;
    input_stream_t is;
    uint8_t        fqdn[256];

    dnscore_init();

    //

    bytearray_input_stream_init_const(&is, domain_too_long, sizeof(domain_too_long));
    ret = input_stream_read_dnsname(&is, fqdn);
    if(ret != DOMAIN_TOO_LONG)
    {
        yatest_err(
            "dnsname_error_test: input_stream_read_dnsname returned an unexpected value: %i/%08x instead of "
            "DOMAIN_TOO_LONG=%08x",
            ret,
            ret,
            DOMAIN_TOO_LONG);
        return 1;
    }

    input_stream_close(&is);

    //

    bytearray_input_stream_init_const(&is, invalid_charset, sizeof(invalid_charset));
    ret = input_stream_read_dnsname(&is, fqdn);
    if(ret != INVALID_CHARSET)
    {
        yatest_err(
            "dnsname_error_test: input_stream_read_dnsname returned an unexpected value: %i/%08x instead of "
            "INVALID_CHARSET=%08x",
            ret,
            ret,
            INVALID_CHARSET);
        return 1;
    }

    //

    bytearray_input_stream_init_const(&is, label_too_long, sizeof(label_too_long));
    ret = input_stream_read_dnsname(&is, fqdn);
    if(ret != LABEL_TOO_LONG)
    {
        yatest_err(
            "dnsname_error_test: input_stream_read_dnsname returned an unexpected value: %i/%08x instead of "
            "LABEL_TOO_LONG=%08x",
            ret,
            ret,
            LABEL_TOO_LONG);
        return 1;
    }

    input_stream_close(&is);

    return 0;
}

static int rname_error_test()
{
    int            ret;
    input_stream_t is;
    uint8_t        fqdn[256];

    dnscore_init();

    //

    bytearray_input_stream_init_const(&is, domain_too_long, sizeof(domain_too_long));
    ret = input_stream_read_rname(&is, fqdn);
    if(ret != DOMAIN_TOO_LONG)
    {
        yatest_err(
            "rname_error_test: input_stream_read_rname returned an unexpected value: %i/%08x instead of "
            "DOMAIN_TOO_LONG=%08x",
            ret,
            ret,
            DOMAIN_TOO_LONG);
        return 1;
    }

    input_stream_close(&is);

    //

    bytearray_input_stream_init_const(&is, label_too_long, sizeof(label_too_long));
    ret = input_stream_read_rname(&is, fqdn);
    if(ret != LABEL_TOO_LONG)
    {
        yatest_err(
            "rname_error_test: input_stream_read_rname returned an unexpected value: %i/%08x instead of "
            "LABEL_TOO_LONG=%08x",
            ret,
            ret,
            LABEL_TOO_LONG);
        return 1;
    }

    input_stream_close(&is);

    return 0;
}

static int sink_test()
{
    int  ret;
    char dummy[1];
    dnscore_init();
    input_stream_t is;
    input_stream_set_sink(&is);
    ret = input_stream_read(&is, dummy, sizeof(dummy));
    if(ret != -1)
    {
        yatest_err("sink_test: input_stream_read should have returned -1, got %i/%08x instead", ret, ret);
        return 1;
    }
    ret = input_stream_skip(&is, sizeof(dummy));
    if(ret != -1)
    {
        yatest_err("sink_test: input_stream_skip should have returned -1, got %i/%08x instead", ret, ret);
        return 1;
    }
    input_stream_close(&is);
    return 0;
}

static int void_test()
{
    int  ret;
    char dummy[1];
    dnscore_init();
    input_stream_t is;
    input_stream_set_void(&is);
    ret = input_stream_read(&is, dummy, sizeof(dummy));
    if(ret != INVALID_STATE_ERROR)
    {
        yatest_err("void_test: input_stream_read should have returned INVALID_STATE_ERROR, got %i/%08x instead", ret, ret);
        return 1;
    }
    ret = input_stream_skip(&is, sizeof(dummy));
    if(ret != INVALID_STATE_ERROR)
    {
        yatest_err("void_test: input_stream_skip should have returned INVALID_STATE_ERROR, got %i/%08x instead", ret, ret);
        return 1;
    }
    input_stream_close(&is); // will abort in DEBUG builds, don't do DEBUG builds for coverage
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(features_test)
YATEST(dnsname_error_test)
YATEST(rname_error_test)
YATEST(sink_test)
YATEST(void_test)
YATEST_TABLE_END
