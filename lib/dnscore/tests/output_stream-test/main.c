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
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/base16.h>
#include <dnscore/base32.h>
#include <dnscore/base32hex.h>
#include <dnscore/base64.h>

static char *yatest_source_message_base16 = "Many hands make light work.";
static char *yatest_source_encoded_base16 = "4 D616E792068616E6473206D616B65206C6967687420776F726B2E";

static char *yatest_source_message_base16lc = "Many hands make light work.";
static char *yatest_source_encoded_base16lc = "4 d616e792068616e6473206d616b65206c6967687420776f726b2e";

static char *yatest_source_message_base32 = "Many hands make light work.";
static char *yatest_source_encoded_base32 = "J VQW46JANBQW4ZDTEBWWC23FEBWGSZ3IOQQHO33SNMXA====";

static char *yatest_source_message_base32hex = "Many hands make light work.";
static char *yatest_source_encoded_base32hex = "9 LGMSU90D1GMSP3J41MM2QR541M6IPR8EGG7ERRIDCN0====";

static char *yatest_source_message_base32hexlc = "Many hands make light work.";
static char *yatest_source_encoded_base32hexlc = "9 lgmsu90d1gmsp3j41mm2qr541m6ipr8egg7erridcn0====";

static char *yatest_source_message_base64 = "Many hands make light work.";
static char *yatest_source_encoded_base64 = "T WFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";

#define WRITE_VALUE_TEST(function_, value_)                                                                                                                                                                                                    \
    ret = function_(&baos, value_);                                                                                                                                                                                                            \
    if(FAIL(ret))                                                                                                                                                                                                                              \
    {                                                                                                                                                                                                                                          \
        yatest_err("%s failed with %s", #function_, error_gettext(ret));                                                                                                                                                                       \
        exit(1);                                                                                                                                                                                                                               \
    }

static char    value_text[] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', 0};
static uint8_t value_dnsname[] = {5, 'H', 'e', 'l', 'l', 'o', 5, 'W', 'o', 'r', 'l', 'd', 0};
static char    value_dnsname_text[] = "Hello.World.";
static uint8_t value_dnsname_escape[] = {5, 'H', 'e', 'l', 'l', '@', 5, 'W', '@', 'r', 'l', 'd', 0};
;
static char    value_dnsname_escape_text[] = "Hell\\@.W\\@rld.";
static uint8_t value_dnslabel[] = {5, 'H', 'e', 'l', 'l', 'o'};
static char    value_dnslabel_text[] = "Hello";
static uint8_t value_dnslabel_escape[] = {5, 'H', 'e', 'l', 'l', '@'};
;
static char    value_dnslabel_escape_text[] = "Hell\\@";
static uint8_t value_root[] = {0};
static char    value_root_text[] = ".";
static char    value_root_label_text[] = "";

static void    expect_text(input_stream_t *is, const char *text, size_t text_size, const char *name)
{
    char buffer[256];
    int  ret = input_stream_read_fully(is, buffer, text_size);
    if(FAIL(ret))
    {
        yatest_err("expect_text: '%s' input_stream_read_fully failed with %s", name, error_gettext(ret));
        exit(1);
    }
    if(ret != (int)text_size)
    {
        yatest_err("expect_text: '%s' input_stream_read_fully didn't read %i bytes, got %i instead", name, ret, text_size);
        exit(1);
    }
    if(memcmp(buffer, text, text_size) != 0)
    {
        yatest_err("expect_text: '%s' input_stream_read_fully got mismatched content: got/expected:", name);
        yatest_hexdump(buffer, buffer + ret);
        yatest_hexdump(text, text + text_size);
        exit(1);
    }
}

static void expect_value(const void *a, const void *b, size_t ab_size, const char *name)
{
    if(memcmp(a, b, ab_size) != 0)
    {
        yatest_err("%s read a value that didn't match the expectations", name);
        yatest_hexdump(a, a + ab_size);
        yatest_hexdump(b, b + ab_size);
        exit(1);
    }
}

#define READ_VALUE_TEST(function_, type_, value_)                                                                                                                                                                                              \
    {                                                                                                                                                                                                                                          \
        type_ a;                                                                                                                                                                                                                               \
        type_ b = value_;                                                                                                                                                                                                                      \
        ret = function_(&bais, &a);                                                                                                                                                                                                            \
        if(FAIL(ret))                                                                                                                                                                                                                          \
        {                                                                                                                                                                                                                                      \
            yatest_err("%s failed with %s", #function_, error_gettext(ret));                                                                                                                                                                   \
            exit(1);                                                                                                                                                                                                                           \
        }                                                                                                                                                                                                                                      \
        expect_value(&a, &b, sizeof(type_), #function_);                                                                                                                                                                                       \
    }

static int write_test()
{
    int             ret;
    output_stream_t baos;
    input_stream_t  bais;
    dnscore_init();
    bytearray_output_stream_init(&baos, NULL, 0);

    WRITE_VALUE_TEST(output_stream_write_u8, 0x01);
    WRITE_VALUE_TEST(output_stream_write_u16, 0x0203);
    WRITE_VALUE_TEST(output_stream_write_u32, 0x04050607);
    WRITE_VALUE_TEST(output_stream_write_nu16, 0x0809);
    WRITE_VALUE_TEST(output_stream_write_nu32, 0x0a0b0c0d);
    WRITE_VALUE_TEST(output_stream_write_pu16, 0x0e0f);
    WRITE_VALUE_TEST(output_stream_write_pu32, 0x10111213);
    WRITE_VALUE_TEST(output_stream_write_pu64, 0x1415161718191a1bULL);
    WRITE_VALUE_TEST(output_stream_write_text, value_text);
    WRITE_VALUE_TEST(output_stream_write_dnsname, value_dnsname);
    WRITE_VALUE_TEST(output_stream_write_dnsname_text, value_dnsname);
    WRITE_VALUE_TEST(output_stream_write_dnsname_text, value_root);
    WRITE_VALUE_TEST(output_stream_write_dnsname_text_escaped, value_dnsname);
    WRITE_VALUE_TEST(output_stream_write_dnsname_text_escaped, value_dnsname_escape);
    WRITE_VALUE_TEST(output_stream_write_dnsname_text_escaped, value_root);
    WRITE_VALUE_TEST(output_stream_write_dnslabel_text_escaped, value_dnslabel);
    WRITE_VALUE_TEST(output_stream_write_dnslabel_text_escaped, value_dnslabel_escape);
    WRITE_VALUE_TEST(output_stream_write_dnslabel_text_escaped, value_root); // 0 bytes

    dnslabel_vector_t dnslabel_vector;
    ret = dnsname_to_dnslabel_vector(value_dnsname, dnslabel_vector);
    if(FAIL(ret))
    {
        yatest_err("dnsname_to_dnslabel_vector failed: %s", error_gettext(ret));
        return 1;
    }
    ret = output_stream_write_dnslabel_vector(&baos, dnslabel_vector, ret);
    if(FAIL(ret))
    {
        yatest_err("output_stream_write_dnslabel_vector failed: %s", error_gettext(ret));
        return 1;
    }

    dnslabel_stack_t dnslabel_stack;
    ret = dnsname_to_dnslabel_stack(value_dnsname, dnslabel_stack);
    if(FAIL(ret))
    {
        yatest_err("dnsname_to_dnslabel_stack failed: %s", error_gettext(ret));
        return 1;
    }
    ret = output_stream_write_dnslabel_stack(&baos, dnslabel_stack, ret);
    if(FAIL(ret))
    {
        yatest_err("output_stream_write_dnslabel_stack failed: %s", error_gettext(ret));
        return 1;
    }

    yatest_log("write_test: %i bytes written", bytearray_output_stream_size(&baos));
    yatest_hexdump(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));

    bytearray_input_stream_init(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), false);

    READ_VALUE_TEST(input_stream_read_u8, uint8_t, 0x01);
    READ_VALUE_TEST(input_stream_read_u16, uint16_t, 0x0203);
    READ_VALUE_TEST(input_stream_read_u32, uint32_t, 0x04050607);
    READ_VALUE_TEST(input_stream_read_nu16, uint16_t, 0x0809);
    READ_VALUE_TEST(input_stream_read_nu32, uint32_t, 0x0a0b0c0d);
    READ_VALUE_TEST(input_stream_read_pu16, uint16_t, 0x0e0f);
    READ_VALUE_TEST(input_stream_read_pu32, uint32_t, 0x10111213);
    READ_VALUE_TEST(input_stream_read_pu64, uint64_t, 0x1415161718191a1bULL);
    // READ_VALUEP_TEST(input_stream_read_text, _chars, "Hello World!");

    expect_text(&bais, value_text, sizeof(value_text) - 1, "output_stream_write_text");
    expect_text(&bais, (char *)value_dnsname, sizeof(value_dnsname), "output_stream_write_dnsname");
    expect_text(&bais, value_dnsname_text, sizeof(value_dnsname_text) - 1, "output_stream_write_dnsname_text");
    expect_text(&bais, value_root_text, sizeof(value_root_text) - 1, "output_stream_write_dnsname_text");
    expect_text(&bais, value_dnsname_text, sizeof(value_dnsname_text) - 1, "output_stream_write_dnsname_text_escaped");
    expect_text(&bais, value_dnsname_escape_text, sizeof(value_dnsname_escape_text) - 1, "output_stream_write_dnsname_text_escaped");
    expect_text(&bais, value_root_text, sizeof(value_root_text) - 1, "output_stream_write_dnsname_text_escaped");
    expect_text(&bais, value_dnslabel_text, sizeof(value_dnslabel_text) - 1, "output_stream_write_dnslabel_text_escaped");
    expect_text(&bais, value_dnslabel_escape_text, sizeof(value_dnslabel_escape_text) - 1, "output_stream_write_dnslabel_text_escaped");
    expect_text(&bais, value_root_label_text, sizeof(value_root_label_text) - 1,
                "output_stream_write_dnslabel_text_escaped"); // 0 bytes
    expect_text(&bais, (char *)value_dnsname, sizeof(value_dnsname), "output_stream_write_dnslabel_vector");
    expect_text(&bais, (char *)value_dnsname, sizeof(value_dnsname), "output_stream_write_dnslabel_stack");

    return 0;
}

static int void_output_stream()
{
    int ret;
    dnscore_init();
    output_stream_t os;
    output_stream_set_void(&os);
    ret = output_stream_write(&os, &os, sizeof(os));
    if(ret != INVALID_STATE_ERROR)
    {
        yatest_err("output_stream_write returned %i instead of INVALID_STATE_ERROR", ret);
        exit(1);
    }
    ret = output_stream_flush(&os);
    if(ret != INVALID_STATE_ERROR)
    {
        yatest_err("output_stream_flush returned %i instead of INVALID_STATE_ERROR", ret);
        exit(1);
    }
    output_stream_close(&os);
    return 0;
}

static int sink_output_stream()
{
    int ret;
    dnscore_init();
    output_stream_t os;
    output_stream_set_sink(&os);
    ret = output_stream_write(&os, &os, sizeof(os));
    if(ret != sizeof(os))
    {
        yatest_err("output_stream_write returned %i instead of %i", ret, sizeof(os));
        exit(1);
    }
    ret = output_stream_flush(&os);
    if(ret != 0)
    {
        yatest_err("output_stream_flush returned %i instead of %i", ret, 0);
        exit(1);
    }
    output_stream_close(&os);
    return 0;
}

typedef ya_result output_stream_decode_base_t(output_stream_t *os, const char *string, uint32_t length);
typedef uint32_t  base_encode_t(const void *buffer_in, uint32_t size_in, char *buffer_out);

static int        decode_base(output_stream_decode_base_t *osdecode_base, const char *encoded, const char *decoded, base_encode_t *encode)
{
    int ret;
    dnscore_init();
    output_stream_t os;
    bytearray_output_stream_init(&os, NULL, 0);
    size_t encoded_len = strlen(encoded);
    ret = osdecode_base(&os, encoded, encoded_len);
    if(FAIL(ret))
    {
        yatest_err("failed to decode: %s", error_gettext(ret));
        return 1;
    }
    if(ret != (int)encoded_len)
    {
        yatest_err("failed to write the whole input: %i written instead of %i", ret, encoded_len);
        return 1;
    }
    size_t output_size = bytearray_output_stream_size(&os);
    size_t decoded_len = strlen(decoded);
    if(output_size != decoded_len)
    {
        yatest_err("decoded length mismatch: got %i, expected %i", ret, output_size);
        return 1;
    }
    if(memcmp(bytearray_output_stream_buffer(&os), decoded, decoded_len) != 0)
    {
        yatest_err("decoded value doesn't match the expected one");
        yatest_hexdump(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + output_size);
        yatest_hexdump(decoded, decoded + decoded_len);
        return 1;
    }

    // decent coverage requires to test longer inputs (more than 64 bytes long) as well as broken ones (before and after
    // 64)

    size_t         buffer_size = 4096;
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, INT32_MAX);
    char *buffer = (char *)malloc(buffer_size);
    char *encoded_buffer = (char *)malloc(buffer_size * 8);
    input_stream_read(&ris, buffer, buffer_size);

    // decode a bigger input

    bytearray_output_stream_reset(&os);
    size_t encoded_buffer_size = encode(buffer, buffer_size, encoded_buffer);
    ret = osdecode_base(&os, encoded_buffer, encoded_buffer_size);
    if(FAIL(ret))
    {
        yatest_err("failed to decode: %s (long)", error_gettext(ret));
        return 1;
    }
    if(ret != (int)encoded_buffer_size)
    {
        yatest_err("failed to write the whole input: %i written instead of %i (long)", ret, encoded_buffer_size);
        return 1;
    }
    output_size = bytearray_output_stream_size(&os);
    decoded_len = strlen(decoded);

    if(output_size != buffer_size)
    {
        yatest_err("decoded length mismatch: got %i, expected %i (long)", ret, buffer_size);
        return 1;
    }
    if(memcmp(bytearray_output_stream_buffer(&os), buffer, buffer_size) != 0)
    {
        yatest_err("decoded value doesn't match the expected one (long)");
        yatest_hexdump(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + output_size);
        yatest_hexdump(decoded, decoded + decoded_len);
        return 1;
    }

    // make an error with the length
    bytearray_output_stream_reset(&os);
    ret = osdecode_base(&os, encoded_buffer, encoded_buffer_size - 1);
    if(ISOK(ret))
    {
        yatest_err("didn't fail to decode (error at the end), returned %i", ret);
        return 1;
    }

    // make an error at the end
    encoded_buffer[encoded_buffer_size - 19] = '!';
    bytearray_output_stream_reset(&os);
    ret = osdecode_base(&os, encoded_buffer, encoded_buffer_size);
    if(ISOK(ret))
    {
        yatest_err("didn't fail to decode (error at the end), returned %i", ret);
        return 1;
    }

    // make an error at the middle
    encoded_buffer[encoded_buffer_size / 2] = '!';
    bytearray_output_stream_reset(&os);
    ret = osdecode_base(&os, encoded_buffer, encoded_buffer_size);
    if(ISOK(ret))
    {
        yatest_err("didn't fail to decode (error at the end), returned %i", ret);
        return 1;
    }

    // make an error at the beginning
    encoded_buffer[7] = '!';
    bytearray_output_stream_reset(&os);
    ret = osdecode_base(&os, encoded_buffer, encoded_buffer_size);
    if(ISOK(ret))
    {
        yatest_err("didn't fail to decode (error at the end), returned %i", ret);
        return 1;
    }

    return 0;
}

static int decode_base64() { return decode_base(output_stream_decode_base64, yatest_source_encoded_base64, yatest_source_message_base64, base64_encode); }

static int decode_base32hex() { return decode_base(output_stream_decode_base32hex, yatest_source_encoded_base32hex, yatest_source_message_base32hex, base32hex_encode); }

static int decode_base32hexlc() { return decode_base(output_stream_decode_base32hex, yatest_source_encoded_base32hexlc, yatest_source_message_base32hexlc, base32hex_encode_lc); }

static int decode_base32() { return decode_base(output_stream_decode_base32, yatest_source_encoded_base32, yatest_source_message_base32, base32_encode); }

static int decode_base16() { return decode_base(output_stream_decode_base16, yatest_source_encoded_base16, yatest_source_message_base16, base16_encode); }

static int decode_base16lc() { return decode_base(output_stream_decode_base16, yatest_source_encoded_base16lc, yatest_source_message_base16lc, base16_encode_lc); }

YATEST_TABLE_BEGIN
YATEST(write_test)
YATEST(void_output_stream)
YATEST(sink_output_stream)
YATEST(decode_base64)
YATEST(decode_base32hex)
YATEST(decode_base32hexlc)
YATEST(decode_base32)
YATEST(decode_base16)
YATEST(decode_base16lc)
YATEST_TABLE_END
