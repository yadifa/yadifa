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
#include "dnscore/host_address.h"
#include <dnscore/dnscore.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/parser.h>
#include <dnscore/tsig.h>

// static const char pascal_string[] = {12, 'H','e','l','l','o',' ','W','o','r','l','d','!'};

static const char    hello_world[] = "Hello World!";
static const char    hello_world_quoted[] = "\"Hello World!\"";
static const char    hello_world_quoted_with_quotes[] = "\"\\\"Hello World!\\\"\"";
static const char    hello_world_no_spc[] = "HelloWorld!";
static const char    hello_world_with_tab[] = "Hello\tWorld!";

static const char    totrim[] = "   Hello   World!     ";

static const char    delim_text[] = " Hello, World!";

static const char    starts_with_digits[] = "0123456789 Hello World!";
static const char    ends_with_digits[] = "Hello World! 0123456789";

static const char   *keywords[4] = {"port", "key"};

static const char    matched_chars[] = {',', '.', ';'};

static const uint8_t key_name[] = {5, 'm', 'y', 'k', 'e', 'y', 0};
static const uint8_t key_mac[] = {0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09};

static int           parse_u32_check_range_test()
{
    int ret;
    dnscore_init();
    uint32_t v;
    ret = parse_u32_check_range("87ABCDEF", &v, 0, UINT32_MAX, 16);
    if(ret < 0)
    {
        yatest_err("parse_u32_check_range(\"87ABCDEF\", &v, 0, UINT32_MAX, 16) failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(v != 0x87ABCDEF)
    {
        yatest_err("parse_u32_check_range didn't set the value to the expected 0x87ABCDEF, got %08x instead", v);
        return 1;
    }
    ret = parse_u32_check_range("87ABCDEF", &v, 0, INT32_MAX, 16);
    if(ret >= 0)
    {
        yatest_err("parse_u32_check_range(\"87ABCDEF\", &v, 0, INT32_MAX, 16) didn't fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u32_check_range("87ABCDEF", &v, 0x90000000, UINT32_MAX, 16);
    if(ret >= 0)
    {
        yatest_err("parse_u32_check_range(\"87ABCDEF\", &v, 0x90000000, UINT32_MAX, 16) didn't fail with PARSEINT_ERROR");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_u32_check_range_len_base10_test()
{
    int ret;
    dnscore_init();
    uint32_t v;
    ret = parse_u32_check_range_len_base10("10000000000", 10, &v, 0, UINT32_MAX);
    if(ret < 0)
    {
        yatest_err("parse_u32_check_range_len_base10(\"10000000000\", 10, &v, 0, UINT32_MAX) failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(v != 1000000000)
    {
        yatest_err("parse_u32_check_range_len_base10 didn't set the value to the expected 1000000000, got %08x instead", v);
        return 1;
    }
    ret = parse_u32_check_range_len_base10("10000000000", 10, &v, 0, 999999999);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err("parse_u32_check_range_len_base10(\"10000000000\", 10, &v, 0, 999999999) didn't fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u32_check_range_len_base10("10000000000", 10, &v, 1000000001, UINT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u32_check_range_len_base10(\"10000000000\", 10, &v, 1000000001, UINT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u32_check_range_len_base10("10000000000", 11, &v, 1000000001, UINT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u32_check_range_len_base10(\"10000000000\", 11, &v, 1000000001, UINT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u32_check_range_len_base10("10000A00000", 10, &v, 1000000001, UINT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u32_check_range_len_base10(\"10000A00000\", 10, &v, 1000000001, UINT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u32_check_range_len_base10("10000A000A", 10, &v, 1000000001, UINT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u32_check_range_len_base10(\"10000A000A\", 10, &v, 1000000001, UINT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_s32_check_range_len_base10_test()
{
    int ret;
    dnscore_init();
    int32_t v;
    ret = parse_s32_check_range_len_base10("10000000000", 10, &v, 0, INT32_MAX);
    if(ret < 0)
    {
        yatest_err("parse_s32_check_range_len_base10(\"10000000000\", 10, &v, 0, INT32_MAX) failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(v != 1000000000)
    {
        yatest_err("parse_s32_check_range_len_base10 didn't set the value to the expected 1000000000, got %08x instead", v);
        return 1;
    }
    ret = parse_s32_check_range_len_base10("-10000000000", 11, &v, INT32_MIN, INT32_MAX);
    if(ret < 0)
    {
        yatest_err("parse_s32_check_range_len_base10(\"-10000000000\", 10, &v, 0, INT32_MAX) failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(v != -1000000000)
    {
        yatest_err("parse_s32_check_range_len_base10 didn't set the value to the expected 1000000000, got %08x instead", v);
        return 1;
    }
    ret = parse_s32_check_range_len_base10("10000000000", 10, &v, 0, 999999999);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err("parse_s32_check_range_len_base10(\"10000000000\", 10, &v, 0, 999999999) didn't fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_s32_check_range_len_base10("10000000000", 10, &v, 1000000001, INT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_s32_check_range_len_base10(\"10000000000\", 10, &v, 1000000001, INT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    ret = parse_s32_check_range_len_base10("10000000000", 12, &v, 1000000001, INT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_s32_check_range_len_base10(\"10000000000\", 12, &v, 1000000001, INT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    ret = parse_s32_check_range_len_base10("10000A00000", 10, &v, 1000000001, INT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_s32_check_range_len_base10(\"10000A00000\", 10, &v, 1000000001, INT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    ret = parse_s32_check_range_len_base10("A0000000000", 10, &v, 1000000001, INT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_s32_check_range_len_base10(\"A0000000000\", 10, &v, 1000000001, INT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    ret = parse_s32_check_range_len_base10("A00000000A", 10, &v, 1000000001, INT32_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_s32_check_range_len_base10(\"A00000000A\", 10, &v, 1000000001, INT32_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_u64_check_range_len_base10_test()
{
    int ret;
    dnscore_init();
    uint64_t v;
    ret = parse_u64_check_range_len_base10("100000000000000000000", 20, &v, 0, UINT64_MAX);
    if(ret < 0)
    {
        yatest_err("parse_u64_check_range_len_base10(\"100000000000000000000\", 20, &v, 0, UINT64_MAX) failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(v != 10000000000000000000ULL)
    {
        yatest_err(
            "parse_u64_check_range_len_base10 didn't set the value to the expected 10000000000000000000, got %016llx "
            "instead",
            v);
        return 1;
    }
    ret = parse_u64_check_range_len_base10("1000", 4, &v, 0, UINT64_MAX);
    if(ret < 0)
    {
        yatest_err("parse_u64_check_range_len_base10(\"1000\", 4, &v, 0, UINT64_MAX) failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(v != 1000)
    {
        yatest_err(
            "parse_u64_check_range_len_base10 didn't set the value to the expected 10000000000000000000, got %016llx "
            "instead",
            v);
        return 1;
    }
    ret = parse_u64_check_range_len_base10("100000000000000000000", 20, &v, 0, 9999999999999999999ULL);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u64_check_range_len_base10(\"100000000000000000000\", 20, &v, 0, 9999999999999999999ULL) didn't "
            "fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u64_check_range_len_base10("100000000000000000000", 20, &v, 10000000000000000001ULL, UINT64_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u64_check_range_len_base10(\"100000000000000000000\", 20, &v, 10000000000000000001ULL, UINT64_MAX) "
            "didn't fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u64_check_range_len_base10("100000000000000000000", 21, &v, 10000000000000000001ULL, UINT64_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u64_check_range_len_base10(\"100000000000000000000\", 21, &v, 10000000000000000001ULL, UINT64_MAX) "
            "didn't fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u64_check_range_len_base10("10000A000000000000000", 20, &v, 10000000000000000001ULL, UINT64_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u64_check_range_len_base10(\"10000A000000000000000\", 20, &v, 10000000000000000001ULL, UINT64_MAX) "
            "didn't fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u64_check_range_len_base10("10000A000000000000000", 19, &v, 10000000000000000001ULL, UINT64_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u64_check_range_len_base10(\"10000A000000000000000\", 19, &v, 10000000000000000001ULL, UINT64_MAX) "
            "didn't fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u64_check_range_len_base10("0000000000000000000A", 20, &v, 10000000000000000001ULL, UINT64_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u64_check_range_len_base10(\"0000000000000000000A\", 20, &v, 10000000000000000001ULL, UINT64_MAX) "
            "didn't fail with PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u64_check_range_len_base10("28446744073709551616", 20, &v, 0, UINT64_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u64_check_range_len_base10(\"28446744073709551616\", 20, &v, 0, UINT64_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    ret = parse_u64_check_range_len_base10("18446744073709551617", 20, &v, 0, UINT64_MAX);
    if(ret != PARSEINT_ERROR)
    {
        yatest_err(
            "parse_u64_check_range_len_base10(\"18446744073709551617\", 20, &v, 0, UINT64_MAX) didn't fail with "
            "PARSEINT_ERROR");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_pstring_test()
{
    int ret;
    dnscore_init();
    char   *p;
    uint8_t dst[512];

    memset(dst, 0xff, sizeof(dst));
    p = (char *)hello_world_quoted;
    ret = parse_pstring(&p, sizeof(hello_world_quoted) - 1, dst, sizeof(dst));
    if((ret != 13) || (memcmp(&dst[1], hello_world, ret - 1) != 0))
    {
        yatest_err("error parsing hello_world_quoted");
        return 1;
    }
    memset(dst, 0xff, sizeof(dst));
    p = (char *)hello_world_quoted_with_quotes;
    ret = parse_pstring(&p, sizeof(hello_world_quoted_with_quotes) - 1, dst, sizeof(dst));
    if((ret != 15) || (memcmp(&dst[1], hello_world_quoted, ret - 1) != 0))
    {
        yatest_err("error parsing hello_world_quoted_with_quotes");
        return 1;
    }
    memset(dst, 0xff, sizeof(dst));
    p = (char *)hello_world_with_tab;
    ret = parse_pstring(&p, sizeof(hello_world_with_tab) - 1, dst, sizeof(dst));
    if(ret != PARSE_INVALID_CHARACTER)
    {
        yatest_err("expected PARSE_INVALID_CHARACTER parsing hello_world_with_tab");
        return 1;
    }
    memset(dst, 0xff, sizeof(dst));
    p = (char *)hello_world_with_tab;
    ret = parse_pstring(&p, 0, dst, sizeof(dst));
    if(ret != PARSESTRING_ERROR)
    {
        yatest_err("expected PARSESTRING_ERROR parsing an empty string");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_yyyymmddhhmmss_check_range_test()
{
    int ret;
    dnscore_init();

    time_t epoch0;
    ret = parse_yyyymmddhhmmss_check_range("19700101000000", &epoch0);
    if(ret < 0)
    {
        yatest_err("failed to parse 19700101000000: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(epoch0 != 0)
    {
        yatest_err("expected epoch 0");
        return 1;
    }

    time_t epochD;
    ret = parse_yyyymmddhhmmss_check_range("20380119031407", &epochD);
    if(ret < 0)
    {
        yatest_err("failed to parse 19700101000000: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(epochD != 0x7fffffff)
    {
        yatest_err("expected epoch INT32_MAX");
        return 1;
    }

    ret = parse_yyyymmddhhmmss_check_range("203801190314070", &epochD);
    if(ret != PARSEDATE_ERROR)
    {
        yatest_err("expected to fail with PARSEDATE_ERROR, got %08x = %s instead (length)", ret, error_gettext(ret));
        return 1;
    }

    ret = parse_yyyymmddhhmmss_check_range("203X0119031407", &epochD);
    if(ret != PARSEDATE_ERROR)
    {
        yatest_err("expected to fail with PARSEDATE_ERROR, got %08x = %s instead (year)", ret, error_gettext(ret));
        return 1;
    }

    ret = parse_yyyymmddhhmmss_check_range("20340X19031407", &epochD);
    if(ret != PARSEDATE_ERROR)
    {
        yatest_err("expected to fail with PARSEDATE_ERROR, got %08x = %s instead (month)", ret, error_gettext(ret));
        return 1;
    }

    ret = parse_yyyymmddhhmmss_check_range("2034011X031407", &epochD);
    if(ret != PARSEDATE_ERROR)
    {
        yatest_err("expected to fail with PARSEDATE_ERROR, got %08x = %s instead (day)", ret, error_gettext(ret));
        return 1;
    }

    ret = parse_yyyymmddhhmmss_check_range("203401190X1407", &epochD);
    if(ret != PARSEDATE_ERROR)
    {
        yatest_err("expected to fail with PARSEDATE_ERROR, got %08x = %s instead (hour)", ret, error_gettext(ret));
        return 1;
    }

    ret = parse_yyyymmddhhmmss_check_range("20340119031X07", &epochD);
    if(ret != PARSEDATE_ERROR)
    {
        yatest_err("expected to fail with PARSEDATE_ERROR, got %08x = %s instead (minute)", ret, error_gettext(ret));
        return 1;
    }

    ret = parse_yyyymmddhhmmss_check_range("2034011903140X", &epochD);
    if(ret != PARSEDATE_ERROR)
    {
        yatest_err("expected to fail with PARSEDATE_ERROR, got %08x = %s instead (second)", ret, error_gettext(ret));
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int parse_copy_trim_spaces_test()
{
    int ret;
    dnscore_init();
    char dst[512];
    ret = parse_copy_trim_spaces(totrim, sizeof(totrim), dst, sizeof(dst));
    if(ret < 0)
    {
        yatest_err("parse_copy_trim_spaces failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(ret != sizeof(hello_world) - 1)
    {
        yatest_err("parse_copy_trim_spaces expected to return %i, not %i", sizeof(hello_world) - 1, ret);
        return 1;
    }
    ret = parse_copy_trim_spaces(hello_world, sizeof(hello_world), dst, sizeof(dst));
    if(ret < 0)
    {
        yatest_err("parse_copy_trim_spaces failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(ret != sizeof(hello_world) - 1)
    {
        yatest_err("parse_copy_trim_spaces expected to return %i, not %i", sizeof(hello_world) - 1, ret);
        return 1;
    }
    ret = parse_copy_trim_spaces("", sizeof(totrim), dst, sizeof(dst));
    if(ret < 0)
    {
        yatest_err("parse_copy_trim_spaces failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(ret != 0)
    {
        yatest_err("parse_copy_trim_spaces expected to return %i, not %i", 0, ret);
        return 1;
    }
    ret = parse_copy_trim_spaces(" ", sizeof(totrim), dst, sizeof(dst));
    if(ret < 0)
    {
        yatest_err("parse_copy_trim_spaces failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(ret != 0)
    {
        yatest_err("parse_copy_trim_spaces expected to return %i, not %i", 0, ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_remove_spaces_test()
{
    int  ret;
    char tmp[512];
    strcpy(tmp, totrim);
    dnscore_init();
    ret = parse_remove_spaces(tmp);
    if(ret < 0)
    {
        yatest_err("parse_remove_spaces failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(ret != sizeof(hello_world_no_spc) - 1)
    {
        yatest_err("parse_copy_trim_spaces expected to return %i, not %i", sizeof(hello_world_no_spc) - 1, ret);
        return 1;
    }
    if(strcmp(tmp, hello_world_no_spc) != 0)
    {
        yatest_err("parse_copy_trim_spaces expected '%s', got '%s'", hello_world_no_spc, tmp);
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int parse_trim_end_test()
{
    int  ret;
    char tmp[512];
    dnscore_init();
    strcpy(tmp, "Hello World!\r\n\r\n");
    ret = parse_trim_end(tmp, strlen(tmp));
    if(ret < 0)
    {
        yatest_err("parse_trim_end returned %08x", ret);
        return 1;
    }
    if(strcmp(tmp, hello_world) != 0)
    {
        yatest_err("parse_trim_end expected '%s', got '%s'", hello_world_no_spc, tmp);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_skip_word_specific_test()
{
    int     ret;
    int32_t matched = -1;
    dnscore_init();
    ret = parse_skip_word_specific("key brol", 7, keywords, 2, &matched);
    if((ret < 0) || (matched != 1))
    {
        yatest_err("parse_skip_word_specific key: %08x = %s (%i) (1)", ret, error_gettext(ret), matched);
        return 1;
    }
    ret = parse_skip_word_specific("port brol", 7, keywords, 2, &matched);
    if((ret < 0) || (matched != 0))
    {
        yatest_err("parse_skip_word_specific key: %08x = %s (%i) (0)", ret, error_gettext(ret), matched);
        return 1;
    }
    ret = parse_skip_word_specific("truc brol", 7, keywords, 2, &matched);
    if((ret != PARSEWORD_NOMATCH_ERROR) || (matched != -1))
    {
        yatest_err("parse_skip_word_specific key: %08x = %s (PARSEWORD_NOMATCH_ERROR) (%i) (-1)", ret, error_gettext(ret), matched);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_skip_until_chars_test()
{
    dnscore_init();
    const char  src[] = "Hello, World!";
    const char  src2[] = "Hello+ World!";
    const char *next = parse_skip_until_chars(src, matched_chars, sizeof(matched_chars));
    if(*next != ',')
    {
        yatest_err("parse_skip_until_chars failed to stop on the first matching character");
        return 1;
    }
    next = parse_skip_until_chars(src2, matched_chars, sizeof(matched_chars));
    if(*next != '\0')
    {
        yatest_err("parse_skip_until_chars failed to stop on the first matching character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_ip_address_test()
{
    int ret;
    dnscore_init();
    uint8_t        dst[512];
    static char   *ipv6_txt = "2002::1";
    static uint8_t ipv6_bin[] = {32, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static char   *ipv4_txt = "127.0.0.1";
    static uint8_t ipv4_bin[] = {127, 0, 0, 1};

    ret = parse_ip_address(ipv6_txt, strlen(ipv6_txt), dst, sizeof(dst));
    if(ret < 0)
    {
        yatest_err("parse_ip_address ipv6 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(ret != sizeof(ipv6_bin))
    {
        yatest_err("parse_ip_address ipv6 size doesn't match");
        return 1;
    }
    if(memcmp(dst, ipv6_bin, sizeof(ipv6_bin)) != 0)
    {
        yatest_err("parse_ip_address ipv6 value doesn't match");
        return 1;
    }

    ret = parse_ip_address(ipv4_txt, strlen(ipv4_txt), dst, sizeof(dst));
    if(ret < 0)
    {
        yatest_err("parse_ip_address ipv4 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(ret != sizeof(ipv4_bin))
    {
        yatest_err("parse_ip_address ipv4 size doesn't match");
        return 1;
    }
    if(memcmp(dst, ipv4_bin, sizeof(ipv4_bin)) != 0)
    {
        yatest_err("parse_ip_address ipv4 value doesn't match");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_skip_spaces_test()
{
    dnscore_init();
    const char *p = parse_skip_spaces(totrim);
    if(*p != 'H')
    {
        yatest_err("parse_skip_spaces didn't point to the expected character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_skip_spaces_ex_test()
{
    dnscore_init();
    const char *p = parse_skip_spaces_ex(totrim, totrim + strlen(totrim));
    if(*p != 'H')
    {
        yatest_err("parse_skip_spaces didn't point to the expected character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_skip_digits_test()
{
    dnscore_init();
    const char *p = parse_skip_digits(starts_with_digits);
    if(*p != ' ')
    {
        yatest_err("parse_skip_digits didn't point to the expected character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_skip_nondigits_test()
{
    dnscore_init();
    const char *p = parse_skip_nondigits(ends_with_digits);
    if(*p != '0')
    {
        yatest_err("parse_skip_nondigits didn't point to the expected character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_next_blank_test()
{
    dnscore_init();
    const char *p = parse_next_blank(hello_world);
    if(*p != ' ')
    {
        yatest_err("parse_next_blank didn't point to the expected character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_next_blank_ex_test()
{
    dnscore_init();
    const char *p = parse_next_blank_ex(hello_world, hello_world + strlen(hello_world));
    if(*p != ' ')
    {
        yatest_err("parse_next_blank didn't point to the expected character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_next_space_test()
{
    dnscore_init();
    const char *p = parse_next_space(hello_world);
    if(*p != ' ')
    {
        yatest_err("parse_next_space didn't point to the expected character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_next_char_equals_test()
{
    dnscore_init();
    const char *p = parse_next_char_equals(hello_world, 'W');
    if(*p != 'W')
    {
        yatest_err("parse_next_char_equals didn't point to the expected character");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int parse_copy_word_test()
{
    int ret;
    dnscore_init();
    char dst[256];

    ret = parse_copy_word(dst, sizeof(dst), hello_world);
    if((ret != 5) || (strcmp(dst, "Hello") != 0))
    {
        yatest_err("unexpected result");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int parse_copy_next_word_test()
{
    int ret;
    dnscore_init();
    char dst[256];

    ret = parse_copy_next_word(dst, sizeof(dst), totrim);
    if((ret != 8) || (strcmp(dst, "Hello") != 0))
    {
        yatest_err("unexpected result");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int parse_next_token_test()
{
    int ret;
    dnscore_init();
    char dst[256];

    ret = parse_next_token(dst, sizeof(dst), delim_text, ",");
    if((ret != 6) || (strcmp(dst, " Hello") != 0))
    {
        yatest_err("unexpected result");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int parse_timeus_from_smarttime_test()
{
    int64_t ret;
    dnscore_init();

    ret = parse_timeus_from_smarttime("19700101000000000000");
    if(ret != 0)
    {
        yatest_err("unexpected result");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int parse_hostaddr_test()
{
    int64_t ret;
    dnscore_init();
    ret = tsig_register(key_name, key_mac, sizeof(key_mac), HMAC_SHA1);

    if(FAIL(ret))
    {
        yatest_err("tsig_register failed with %x", ret);
        exit(1);
    }

    host_address_t *ha;
    ret = parse_hostaddr("127.0.0.1 port 53 key mykey. tls", &ha);
    if(ret != 0)
    {
        yatest_err("unexpected result");
        return 1;
    }
    if(ha->tsig == NULL)
    {
        yatest_err("tsig field is NULL");
        return 1;
    }
    if(ha->port != NU16(53))
    {
        yatest_err("unexpected port value");
        return 1;
    }
    if(ha->tls != HOST_ADDRESS_TLS_ENFORCE)
    {
        yatest_err("unexpected tls value");
        return 1;
    }
    if(ha->version != 4)
    {
        yatest_err("unexpected version value");
        return 1;
    }
    if(ha->ip.v4.value != NU32(0x7f000001))
    {
        yatest_err("unexpected ip value");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(parse_u32_check_range_test)
YATEST(parse_u32_check_range_len_base10_test)
YATEST(parse_s32_check_range_len_base10_test)
YATEST(parse_u64_check_range_len_base10_test)
YATEST(parse_pstring_test)
YATEST(parse_yyyymmddhhmmss_check_range_test)
YATEST(parse_copy_trim_spaces_test)
YATEST(parse_remove_spaces_test)
YATEST(parse_trim_end_test)
YATEST(parse_skip_word_specific_test)
YATEST(parse_skip_until_chars_test)
YATEST(parse_ip_address_test)
YATEST(parse_skip_spaces_test)
YATEST(parse_skip_spaces_ex_test)
YATEST(parse_skip_digits_test)
YATEST(parse_skip_nondigits_test)
YATEST(parse_next_blank_test)
YATEST(parse_next_blank_ex_test)
YATEST(parse_next_space_test)
YATEST(parse_next_char_equals_test)
YATEST(parse_copy_word_test)
YATEST(parse_copy_next_word_test)
YATEST(parse_next_token_test)
YATEST(parse_timeus_from_smarttime_test)
YATEST(parse_hostaddr_test)
YATEST_TABLE_END
