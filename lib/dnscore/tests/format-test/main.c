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
#include "dnscore/ctrl_rfc.h"
#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/bytearray_output_stream.h>
#include <time.h>

static void init() { dnscore_init(); }

static void finalise() { dnscore_finalize(); }

#if !__FreeBSD__
extern char *tzname[2];
extern long  timezone;
extern int   daylight;
#endif

static int osformat_test()
{
#if !__FreeBSD__
    setenv("TZ", "Europe/Brussels", 1);
    tzset();
    yatest_log("TZ: %s,%s %i %i", tzname[0], tzname[1], timezone, daylight);
#endif

    static const char expected_output[] = {
        "%;\n"
        "-11i: < -2147483648>< 2147483647>;11i: <-2147483648 ><2147483647 >;lli: -9223372036854775808 "
        "9223372036854775807;li: -2147483648 2147483647;i: -2147483648 2147483647;hi: -32768 32767;hhi: -128 127;\n"
        "-11d: <          0>< 4294967295>;11d: <0          ><4294967295 >;lld: 0 18446744073709551615;ld: 0 "
        "4294967295;d: 0 4294967295;hd: 0 65535;hhd: 0 255;\n"
        "-11o: <          0><37777777777>;11o: <0          ><37777777777>;llo: 0 1777777777777777777777;lo: 0 "
        "37777777777;o: 0 37777777777;ho: 0 177777;hho: 0 377;\n"
        "-11x: <          0><   ffffffff>;11x: <0          ><ffffffff   >;llx: 0 ffffffffffffffff;lx: 0 ffffffff;x: 0 "
        "ffffffff;hx: 0 ffff;hhx: 0 ff;\n"
        "-11X: <          0><   FFFFFFFF>;11X: <0          ><FFFFFFFF   >;llX: 0 FFFFFFFFFFFFFFFF;lX: 0 FFFFFFFF;X: 0 "
        "FFFFFFFF;hX: 0 FFFF;hhX: 0 FF;\n"
        "P: 0000000000000000;\n"
        "p: 0000000000000000;\n"
        "f: 3.141500; Lf: 3.141500;11.8f:  3.14150000; L11.8f:  3.14150000;\n"
        "s: <Hello World >< Hello World> Hello World;\n"
        "c: .;\n"
        "{dnstype}: ANY;\n"
        "{undefined}: 123456789abcdef;\n"
        "t: <\t\t>;\n"
        "S: <  >;\n"
        "T: 2038-01-19 04:14:07;lT: 2038-01-19 04:14:07;llT: 2038-01-19 04:14:07.000000;\n"
        "U: 2038-01-19 03:14:07Z;lU: 2038-01-19 03:14:07;llU: 2038-01-19 03:14:07.000000Z;\n"
        "r: SUCCESS;"};

    init();
    output_stream_t baos;
    yatest_log("char: %i, short: %i, int: %i, long: %i, long long: %i, float: %i, double: %i, long double: %i", sizeof(char), sizeof(short), sizeof(int), sizeof(long), sizeof(long long), sizeof(float), sizeof(double), sizeof(long double));
    bytearray_output_stream_init(&baos, NULL, 65536);
    uint16_t dnstype = TYPE_ANY;
    osformat(&baos,
             "%%;"
             "\n"
             "-11i: <%-11i><%-11i>;"
             "11i: <%11i><%11i>;"
             "lli: %lli %lli;"
             "li: %li %li;"
             "i: %i %i;"
             "hi: %hi %hi;"
             "hhi: %hhi %hhi;"
             "\n"
             "-11d: <%-11d><%-11d>;"
             "11d: <%11d><%11d>;"
             "lld: %lld %lld;"
             "ld: %ld %ld;"
             "d: %d %d;"
             "hd: %hd %hd;"
             "hhd: %hhd %hhd;"
             "\n"
             "-11o: <%-11o><%-11o>;"
             "11o: <%11o><%11o>;"
             "llo: %llo %llo;"
             "lo: %lo %lo;"
             "o: %o %o;"
             "ho: %ho %ho;"
             "hho: %hho %hho;"
             "\n"
             "-11x: <%-11x><%-11x>;"
             "11x: <%11x><%11x>;"
             "llx: %llx %llx;"
             "lx: %lx %lx;"
             "x: %x %x;"
             "hx: %hx %hx;"
             "hhx: %hhx %hhx;"
             "\n"
             "-11X: <%-11X><%-11X>;"
             "11X: <%11X><%11X>;"
             "llX: %llX %llX;"
             "lX: %lX %lX;"
             "X: %X %X;"
             "hX: %hX %hX;"
             "hhX: %hhX %hhX;"
             "\n"
             "P: %P;"
             "\n"
             "p: %p;"
             "\n"
             "f: %f; Lf: %Lf;"
             "11.8f: %11.8f; L11.8f: %11.8Lf;"
             "\n"
             "s: <%12s><%-12s> %s;"
             "\n"
             "c: %c;"
             "\n"
             "{dnstype}: %{dnstype};"
             "\n"
             "{undefined}: %{undefined};"
             "\n"
             "t: <%t>;"
             "\n"
             "S: <%S>;"
             "\n"
             "T: %T;"
             "lT: %lT;"
             "llT: %llT;"
             "\n"
             "U: %U;"
             "lU: %lU;"
             "llU: %llU;"
             "\n"
             "r: %r;",
             INT32_MIN, // -11i
             INT32_MAX,
             INT32_MIN, // 11i
             INT32_MAX,
             INT64_MIN, // lli
             INT64_MAX,
             INT32_MIN, // li
             INT32_MAX,
             INT32_MIN, // i
             INT32_MAX,
             INT16_MIN, // hi
             INT16_MAX,
             INT8_MIN, // hhi
             INT8_MAX,

             0, // -11d
             UINT32_MAX,
             0, // 11d
             UINT32_MAX,
             0ULL, // lld
             UINT64_MAX,
             0, // ld
             UINT32_MAX,
             0, // d
             UINT32_MAX,
             0, // hd
             UINT16_MAX,
             0, // hhd
             UINT8_MAX,

             0, // -11o
             UINT32_MAX,
             0, // 11o
             UINT32_MAX,
             0ULL, // llo
             UINT64_MAX,
             0, // lo
             UINT32_MAX,
             0, // o
             UINT32_MAX,
             0, // ho
             UINT16_MAX,
             0, // hho
             UINT8_MAX,

             0, // -11x
             UINT32_MAX,
             0, // 11x
             UINT32_MAX,
             0ULL, // llx
             UINT64_MAX,
             0, // lx
             UINT32_MAX,
             0, // x
             UINT32_MAX,
             0, // hx
             UINT16_MAX,
             0, // hhx
             UINT8_MAX,

             0, // -11X
             UINT32_MAX,
             0, // 11X
             UINT32_MAX,
             0ULL, // llX
             UINT64_MAX,
             0, // lX
             UINT32_MAX,
             0, // X
             UINT32_MAX,
             0, // hX
             UINT16_MAX,
             0, // hhX
             UINT8_MAX,

             NULL, // P

             NULL, // p

             3.1415, // f

             (long double)3.1415, // Lf

             3.1415, // f

             (long double)3.1415, // Lf

             "Hello World", // s
             "Hello World",
             "Hello World",

             '.', // c

             &dnstype, // {dnstype}

             (intptr_t)0x123456789abcdef, // {undefined}

             2, // t

             2, // S

             INT32_MAX,             // T
             1000000LL * INT32_MAX, // lT
             1000000LL * INT32_MAX, // llT

             INT32_MAX,             // U
             1000000LL * INT32_MAX, // lU
             1000000LL * INT32_MAX, // llU

             SUCCESS // r
    );
    output_stream_write_u8(&baos, 0);
    output_stream_flush(&baos);
    yatest_log((const char *)bytearray_output_stream_buffer(&baos));
    if((bytearray_output_stream_size(&baos) != sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(&baos), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int osprint_wrapped_test()
{
    static const char expected_output[] = {
        "....Hello World\n"
        "  Press any \n"
        "  key. 0 1 2 3 \n"
        "  4 5 6 7 8 ab \n"
        "  cd ef gh ijk \n"
        "  lmn opq rst\n"
        "        last \n"
        "  line"};
    init();
    static const char text[] = "Hello World\tPress any key. 0 1 2 3 4 5 6 7 8 ab cd ef gh ijk lmn opq rst\n\t\t\t\t\r\nlast line";
    output_stream_t   baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    output_stream_write(&baos, "....", 4);  // to go to column 4
    osprint_wrapped(&baos, text, 4, 16, 2); // column 4 on a 16 columns screen, wrapping at column 2
    output_stream_write_u8(&baos, 0);
    output_stream_flush(&baos);
    yatest_log((const char *)bytearray_output_stream_buffer(&baos));
    if((bytearray_output_stream_size(&baos) != sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(&baos), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int debug_osformatln_test()
{
    static const char expected_output[] = {"Hello World 00000000\n"};
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    debug_osformatln(&baos, "Hello World %08x", 0);
    output_stream_write_u8(&baos, 0);
    output_stream_flush(&baos);
    yatest_log((const char *)bytearray_output_stream_buffer(&baos));
    char *p = (char *)bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos) - sizeof(expected_output);
    if((bytearray_output_stream_size(&baos) < sizeof(expected_output)) || (memcmp(expected_output, p, sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected: (minus the prefix)");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int debug_println_test()
{
    static const char expected_output[] = {"Hello World 00000000\n"};
    init();
    output_stream_close(termout);
    bytearray_output_stream_init(termout, NULL, 65536);
    debug_println("Hello World 00000000");
    output_stream_write_u8(termout, 0);
    output_stream_flush(termout);
    yatest_log((const char *)bytearray_output_stream_buffer(termout));
    char *p = (char *)bytearray_output_stream_buffer(termout) + bytearray_output_stream_size(termout) - sizeof(expected_output);
    if((bytearray_output_stream_size(termout) < sizeof(expected_output)) || (memcmp(expected_output, p, sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(termout), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(termout), bytearray_output_stream_buffer(termout) + bytearray_output_stream_size(termout));
        yatest_err("expected: (minus the prefix)");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    // output_stream_close(termout);
    finalise();
    return 0;
}

static int println_test()
{
    static const char expected_output[] = {"Hello World 00000000\n"};
    init();
    output_stream_close(termout);
    bytearray_output_stream_init(termout, NULL, 65536);
    println("Hello World 00000000");
    output_stream_write_u8(termout, 0);
    output_stream_flush(termout);
    yatest_log((char *)bytearray_output_stream_buffer(termout));
    if((bytearray_output_stream_size(termout) != sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(termout), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(termout), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(termout), bytearray_output_stream_buffer(termout) + bytearray_output_stream_size(termout));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    // output_stream_close(termout);
    finalise();
    return 0;
}

static int print_test()
{
    static const char expected_output[] = {"Hello World 00000000"};
    init();
    output_stream_close(termout);
    bytearray_output_stream_init(termout, NULL, 65536);
    print("Hello World 00000000");
    output_stream_write_u8(termout, 0);
    output_stream_flush(termout);
    yatest_log((char *)bytearray_output_stream_buffer(termout));
    if((bytearray_output_stream_size(termout) != sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(termout), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(termout), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(termout), bytearray_output_stream_buffer(termout) + bytearray_output_stream_size(termout));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    // output_stream_close(termout);
    finalise();
    return 0;
}

static int print_char_test()
{
    static const char expected_output[] = {"Hello World"};
    init();
    output_stream_close(termout);
    bytearray_output_stream_init(termout, NULL, 65536);

    for(int i = 0; expected_output[i] != '\0'; ++i)
    {
        print_char(expected_output[i]);
    }
    output_stream_write_u8(termout, 0);
    output_stream_flush(termout);
    yatest_log((char *)bytearray_output_stream_buffer(termout));
    if((bytearray_output_stream_size(termout) != sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(termout), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(termout), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(termout), bytearray_output_stream_buffer(termout) + bytearray_output_stream_size(termout));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    // output_stream_close(termout);
    finalise();
    return 0;
}

static int asnformat_test()
{
    static const char expected_output[] = {"Hello World 00000000"};
    init();
    char     *text = NULL;
    ya_result ret = asnformat(&text, 1024, "Hello World %08x", 0);
    if(ret < 0)
    {
        yatest_err("asnformat returned %08x", ret);
        return 1;
    }
    if(strcmp(text, expected_output) != 0)
    {
        yatest_err("output content doesn't match expectations:");
        yatest_err("got:");
        yatest_hexdump_err(text, text + strlen(text));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    // output_stream_close(termout);
    finalise();
    return 0;
}

static void format_handler_test(const void *p, output_stream_t *os, int32_t a, char b, bool c, void *reserved_for_method_parameters)
{
    (void)a;
    (void)b;
    (void)c;
    (void)reserved_for_method_parameters;
    uintptr_t val = (uintptr_t)p;
    do
    {
        output_stream_write_u8(os, '0' + (val % 10));
        val /= 10;
    } while(val != 0);
}

static int format_grow_hash_table_test()
{
    // format_grow_hash_table() is called when the format table grows
    ya_result ret;
    init();
    char      tmp[64];
    const int fmt_count = 1117;
    for(int i = 0; i < fmt_count; ++i)
    {
        format_handler_descriptor_t *fhd = (format_handler_descriptor_t *)yatest_malloc(sizeof(format_handler_descriptor_t));
        fhd->format_handler = format_handler_test;
        snprintf(tmp, sizeof(tmp), "fmt%i", i);
        fhd->name = yatest_strdup(tmp);
        fhd->name_len = strlen(fhd->name);
        ret = format_registerclass(fhd);
        if(ret < 0)
        {
            yatest_err("format_registerclass failed for '%s' with %08x = %s", tmp, ret, error_gettext(ret));
            return 1;
        }
        if(i == 0)
        {
            ret = format_registerclass(fhd);
            if(ret != FORMAT_ALREADY_REGISTERED)
            {
                yatest_err("format_registerclass expected to return FORMAT_ALREADY_REGISTERED, returned %08x = %s", tmp, ret, error_gettext(ret));
                return 1;
            }
        }
    }
    for(int i = 0; i < fmt_count; ++i)
    {
        char txt[64];
        memset(txt, 0, sizeof(txt));
        snprintf(tmp, sizeof(tmp), "%%{fmt%i}", i);
        snformat(txt, sizeof(txt), tmp, (void *)(uintptr_t)18446744073709551615ULL);
        const char *expected = "51615590737044764481";
        if(strcmp(txt, expected) != 0)
        {
            yatest_err("formatting failed with '%s' ('%s' != '%s')", tmp, txt, expected);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int osprint_base16_test()
{
    int               ret;
    static const char expected_output[] = {
        "123456789ABCDEF0"
        "123456789ABCDEF1"
        "123456789ABCDEF2"
        "123456789ABCDEF3"
        " " // one space after 32 bytes
        "123456789ABCDEF4"};
    static const uint8_t data[40] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf2, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf3, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf4,
    };
    init();
    output_stream_t os;
    bytearray_output_stream_init(&os, NULL, 65536);

    ret = osprint_base16(&os, data, sizeof(data));
    if(ret < 0)
    {
        yatest_err("osprint_base16 returned %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    output_stream_write_u8(&os, 0);
    output_stream_flush(&os);
    yatest_log((char *)bytearray_output_stream_buffer(&os));
    if((bytearray_output_stream_size(&os) != sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(&os), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&os), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + bytearray_output_stream_size(&os));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    // output_stream_close(termout);
    finalise();
    return 0;
}

static int osprint_u32_test()
{
    static const char expected_output[] = {"1234567890"};
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    osprint_u32(&baos, 1234567890);
    output_stream_write_u8(&baos, 0);
    output_stream_flush(&baos);
    yatest_log((const char *)bytearray_output_stream_buffer(&baos));
    if((bytearray_output_stream_size(&baos) < sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(&baos), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int osprint_u16_test()
{
    static const char expected_output[] = {"56789"};
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    osprint_u16(&baos, 56789);
    output_stream_write_u8(&baos, 0);
    output_stream_flush(&baos);
    yatest_log((const char *)bytearray_output_stream_buffer(&baos));
    if((bytearray_output_stream_size(&baos) < sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(&baos), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int osprint_u32_hex_test()
{
    static const char expected_output[] = {"12345678"};
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    osprint_u32_hex(&baos, 0x12345678);
    output_stream_write_u8(&baos, 0);
    output_stream_flush(&baos);
    yatest_log((const char *)bytearray_output_stream_buffer(&baos));
    if((bytearray_output_stream_size(&baos) < sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(&baos), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int osprint_quoted_text_escaped_test()
{
    static const char  expected_output[] = {"\"Hello World, CHR(1)=\\001, CR=\\013, LF=\\010, ESCAPE=\\\\\""};
    static const char *text = "Hello World, CHR(1)=\001, CR=\r, LF=\n, ESCAPE=\\";
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    osprint_quoted_text_escaped(&baos, (const uint8_t *)text, strlen(text));
    output_stream_write_u8(&baos, 0);
    output_stream_flush(&baos);
    yatest_log((const char *)bytearray_output_stream_buffer(&baos));
    if((bytearray_output_stream_size(&baos) < sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(&baos), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int osprint_char_times_test()
{
    static const char expected_output[] = {"AAAAA"};

    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    osprint_char_times(&baos, 'A', 5);
    output_stream_write_u8(&baos, 0);
    output_stream_flush(&baos);
    yatest_log((const char *)bytearray_output_stream_buffer(&baos));
    if((bytearray_output_stream_size(&baos) < sizeof(expected_output)) || (memcmp(expected_output, bytearray_output_stream_buffer(&baos), sizeof(expected_output)) != 0))
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), sizeof(expected_output));
        yatest_err("got:");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int snformat_test()
{
    int               ret;
    static const char expected_output[] = {"Hello World"};

    char              tmp[64];
    init();
    ret = snformat(tmp, sizeof(tmp), "%s %s", "Hello", "World");
    if(ret < 0)
    {
        yatest_err("snformat failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log(tmp);
    if(strcmp(tmp, expected_output) != 0)
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", strlen(tmp), sizeof(expected_output) - 1);
        yatest_err("got:");
        yatest_hexdump_err(tmp, tmp + strlen(tmp));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output) - 1);
        return 1;
    }
    finalise();
    return 0;
}

static int asformat_test()
{
    int               ret;
    static const char expected_output[] = {"Hello World"};
    char             *tmp = NULL;
    init();
    ret = asformat(&tmp, "%s %s", "Hello", "World");
    if(ret < 0)
    {
        yatest_err("asformat failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log(tmp);
    if(strcmp(tmp, expected_output) != 0)
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", strlen(tmp), sizeof(expected_output) - 1);
        yatest_err("got:");
        yatest_hexdump_err(tmp, tmp + strlen(tmp));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output) - 1);
        return 1;
    }
    free(tmp);
    finalise();
    return 0;
}

static int fformat_test()
{
    int               ret;
    static const char expected_output[] = {"Hello World"};
    init();
    char filename[64];
    char tmp[64];
    yatest_file_getname(11, filename, sizeof(filename));
    FILE *f = fopen(filename, "w+");
    if(f == NULL)
    {
        yatest_err("fopen(%s, \"w+\") failed with %s", strerror(errno));
        return 1;
    }
    ret = fformat(f, "%s %s", "Hello", "World");
    if(ret < 0)
    {
        yatest_err("asformat failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    char zero[1] = {0};
    fwrite(zero, 1, 1, f);
    fclose(f);
    f = fopen(filename, "r");
    int tmp_size = fread(tmp, 1, 64, f);
    if(tmp_size != sizeof(expected_output))
    {
        yatest_err("fread returned %i instead of %i", tmp_size, sizeof(expected_output));
        return 1;
    }
    fclose(f);
    yatest_log(tmp);
    if(strcmp(tmp, expected_output) != 0)
    {
        yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", strlen(tmp), sizeof(expected_output) - 1);
        yatest_err("got:");
        yatest_hexdump_err(tmp, tmp + strlen(tmp));
        yatest_err("expected:");
        yatest_hexdump_err(expected_output, expected_output + sizeof(expected_output) - 1);
        return 1;
    }
    finalise();
    return 0;
}

/**
 * That one will be complicated:
 * I need an rdata for all types, and the expected output.
 */

struct osprint_rdata_test_entry_s
{
    uint16_t      rtype;
    const uint8_t rdata[256];
    uint16_t      rdata_size;
    const char   *expected_text;
    int           error;
};

static struct osprint_rdata_test_entry_s osprint_rdata_test_entries[] = {
    {TYPE_A, {1, 2, 3, 4}, 4, "1.2.3.4", 0},
    {TYPE_A, {}, 5, "", INCORRECT_RDATA},
    {TYPE_AAAA, {0x26, 0x06, 0x47, 0x00, 0x30, 0x32, 0, 0, 0, 0, 0, 0, 0x68, 0x15, 0x29, 0xb8}, 16, "2606:4700:3032::6815:29b8", 0},
    {TYPE_AAAA, {}, 17, "", INCORRECT_RDATA},
    {TYPE_MX, {0x00, 0x0a, 4, 'm', 'a', 'i', 'l', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 18, "10 mail.yadifa.eu.", 0},
    {TYPE_MX, {0x00, 0x0a}, 2, "", INCORRECT_RDATA},
    {TYPE_NS, {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 15, "ns1.yadifa.eu.", 0},
    {TYPE_RP, {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 3, 'n', 's', '2', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 30, "ns1.yadifa.eu. ns2.yadifa.eu.", 0},
    {TYPE_RP, {}, 0, "", INCORRECT_RDATA},
    {TYPE_PX, {0, 10, 3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 3, 'n', 's', '2', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 32, "10 ns1.yadifa.eu. ns2.yadifa.eu.", 0},
    {TYPE_PX,
     {
         0,
         10,
     },
     2,
     "",
     INCORRECT_RDATA},
    {TYPE_TALINK, {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 3, 'n', 's', '2', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 30, "ns1.yadifa.eu. ns2.yadifa.eu.", 0},
    {TYPE_TALINK, {}, 0, "", INCORRECT_RDATA},
    {TYPE_WKS, {1, 2, 3, 4, 17, 128, 128, 128}, 8, "1.2.3.4 udp 0 8 16", 0},
    {TYPE_WKS, {1, 2, 3, 4, 6, 128, 128, 128}, 8, "1.2.3.4 tcp 0 8 16", 0},
    {TYPE_WKS, {}, 5, "", INCORRECT_RDATA},
    {TYPE_GPOS, {7, '5', '0', '.', '8', '4', '6', '7', 7, '4', '.', '3', '5', '2', '5', '0', 2, '1', '3'}, 19, "50.8467 4.35250 13", 0},
    {TYPE_GPOS, {7, '5', '0', '.', '8', '4', '6', '7', 7, '4', '.', '3', '5', '2', '5', '0', 2, '1', '3'}, 18, "", INCORRECT_RDATA},
    {TYPE_LOC, {0, 0, 0, 0, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, 16, "591 49 34.588 S 591 49 34.588 W 69090.60m 0m 0m 0m", 0}, // need to find example
    {TYPE_LOC, {1, 0, 0, 0, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, 1, "", INCORRECT_RDATA},                                      // need to find example
    {TYPE_CSYNC, {0x00, 0x00, 0x00, 0x42, 0x00, 0x03, 0x00, 0x04, 0x60, 0x00, 0x00, 0x08}, 12, "66 3 A NS AAAA", 0},
    {TYPE_CSYNC, {1, 2, 3, 4, 0, 1, 0, 1, 1}, 9, "16909060 1 MB", 0},
    {TYPE_OPENPGPKEY, {0x94, 0x6e, 0x68, 0x8e, 0xa7, 0xf4, 0x05, 0xaa, 0x87, 0x4f, 0xef}, 11, "lG5ojqf0BaqHT+8=", 0},
    {TYPE_OPENPGPKEY, {}, 0, "", INCORRECT_RDATA},
    {TYPE_HINFO, {5, 'H', 'e', 'l', 'l', 'o', 5, 'W', 'o', 'r', 'l', 'd'}, 12, "\"Hello\" \"World\"", 0},
    {TYPE_HINFO, {2}, 1, "", INCORRECT_RDATA},
    {TYPE_HINFO, {1, 'X', 2, 'Y'}, 4, "", INCORRECT_RDATA},
    {TYPE_SOA, {3, 'n', 's', '1', 0, 4, 'm', 'a', '.', 'l', 0, 0, 0, 0, 1, 0, 0, 14, 16, 0, 0, 7, 8, 0, 54, 238, 128, 0, 0, 2, 88}, 31, "ns1. ma\\.l. 1 3600 1800 3600000 600", 0},
    {TYPE_SOA, {3, 'n', 's', '1', 0}, 5, "", INCORRECT_RDATA},
    {TYPE_RRSIG,
     {0, 6, 8, 2, 0, 0, 14, 16, 0, 0, 0, 0, 127, 255, 255, 255, 12, 34, 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 'F', 'A', 'K', 'E', ' ', 'S', 'I', 'G', 'N', 'A', 'T', 'U', 'R', 'E'},
     43,
     "SOA 8 2 3600 19700101000000 20380119031407 3106 yadifa.eu. RkFLRSBTSUdOQVRVUkU=",
     0},
    {TYPE_DNSKEY, {1, 1, 3, 8, 'F', 'A', 'K', 'E', ' ', 'K', 'E', 'Y'}, 12, "257 3 8 RkFLRSBLRVk=", 0},
    {TYPE_DS, {0x12, 0x34, 8, 1, 1, 2, 3, 4, 5, 6, 7, 8}, 12, "4660 8 1 0102030405060708", 0},
    {TYPE_NSEC,
     {4, 'n', 'e', 'x', 't', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 0, 2, 127, 255, 1, 1, 255},
     23,
     "next.yadifa.eu. A NS MD MF CNAME SOA MB MG MR NULL WKS PTR HINFO MINFO MX URI CAA AVC TYPE259 TYPE260 TYPE261 "
     "TYPE262 TYPE263",
     0},
    {TYPE_NSEC3,
     {1, 1, 0, 10, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 2, 127, 255, 1, 1, 255},
     33,
     "1 1 10 - 041061050O3GG28A1C60Q3GF208H44OK A NS MD MF CNAME SOA MB MG MR NULL WKS PTR HINFO MINFO MX URI CAA AVC "
     "TYPE259 TYPE260 TYPE261 TYPE262 TYPE263",
     0},
    {TYPE_NSEC3,
     {1, 1, 0, 10, 2, 0xba, 0x11, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 2, 127, 255, 1, 1, 255},
     35,
     "1 1 10 ba11 041061050O3GG28A1C60Q3GF208H44OK A NS MD MF CNAME SOA MB MG MR NULL WKS PTR HINFO MINFO MX URI CAA "
     "AVC TYPE259 TYPE260 TYPE261 TYPE262 TYPE263",
     0},
    {TYPE_NSEC3PARAM, {1, 0, 0, 10, 0}, 5, "1 0 10 -", 0},
    {TYPE_NSEC3PARAM, {1, 0, 0, 10, 2, 0xba, 0x11}, 7, "1 0 10 ba11", 0},
    {TYPE_TLSA, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 10, "1 2 3 0405060708090A", 0},
    {TYPE_SSHFP, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 10, "1 2 030405060708090A", 0},
    {TYPE_NID, {0, 10, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}, 10, "10 1234:5678:9abc:def0", 0},
    {TYPE_NID, {}, 0, "", INCORRECT_RDATA},
    {TYPE_L64, {0, 10, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}, 10, "10 1234:5678:9abc:def0", 0},
    {TYPE_L32, {0, 10, 172, 20, 1, 1}, 6, "10 172.20.1.1", 0},
    {TYPE_L32, {}, 0, "", INCORRECT_RDATA},
    {TYPE_EUI48, {0, 0, 127, 128, 129, 130}, 6, "00-00-7f-80-81-82", 0},
    {TYPE_EUI48, {}, 0, "", INCORRECT_RDATA},
    {TYPE_EUI64, {0, 0, 127, 128, 129, 130, 131, 132}, 8, "00-00-7f-80-81-82-83-84", 0},
    {TYPE_EUI64, {}, 0, "", INCORRECT_RDATA},
    {TYPE_SRV, {12, 34, 56, 78, 1, 80, 3, 'w', 'w', 'w', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 21, "8716 20024 20481 www.yadifa.eu.", 0},
    {TYPE_TXT, {11, 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'}, 12, "\"Hello World\"", 0},
    {TYPE_TXT, {5, 'H', 'e', 'l', 'l', 'o', 5, 'W', 'o', 'r', 'l', 'd'}, 12, "\"Hello\" \"World\"", 0},
    {TYPE_TXT, {5, 'H', 'e', 'l', 'l', 'o', 5, 'W', 'o', 'r', 'l'}, 11, "", INCORRECT_RDATA},
    {TYPE_CAA, {0, 3, 't', 'a', 'g', 'h', 'e', 'l', 'l', 'o', ';', ' ', 'w', 'o', 'r', 'l', 'd'}, 17, "0 tag \"hello; world\"", 0},
    {TYPE_CAA, {}, 0, "", INCORRECT_RDATA},
    {TYPE_CERT,
     {0, 1, 0x12, 0x34, 8, 'h', 't', 't', 'p', ':', '/', '/', 'w', 'w', 'w', '.', 'y', 'a', 'd', 'i', 'f', 'a', '.', 'e', 'u', '/', 'c', 'e', 'r', 't', '.', 'p', 'e', 'm'},
     34,
     "PKIX 4660 RSASHA256 aHR0cDovL3d3dy55YWRpZmEuZXUvY2VydC5wZW0=",
     0},
    {TYPE_CERT,
     {255, 255, 0x12, 0x34, 240, 'h', 't', 't', 'p', ':', '/', '/', 'w', 'w', 'w', '.', 'y', 'a', 'd', 'i', 'f', 'a', '.', 'e', 'u', '/', 'c', 'e', 'r', 't', '.', 'p', 'e', 'm'},
     34,
     "65535 4660 240 aHR0cDovL3d3dy55YWRpZmEuZXUvY2VydC5wZW0=",
     0},
    {TYPE_CERT, {}, 0, "", INCORRECT_RDATA},
    {TYPE_DHCID, {1, 2, 3, 4, 5, 6, 7, 8}, 8, "AQIDBAUGBwg=", 0}, // 29
    {TYPE_TSIG,
     {4, 'f', 'a', 'k', 'e', 9, 'a', 'l', 'g', 'o', 'r', 'i', 't', 'h', 'm', 0, 0, 0, 0x66, 0x5d, 0x8e, 0x47, 0, 0x2c, 0, 4, 1, 2, 3, 4, 0x01, 0x23, 0, 0, 0, 2, 3, 4},
     38,
     "fake.algorithm. 1717407303 44 4 AQIDBA== 8961 NOERROR 2 03 04",
     0},
    {TYPE_ANY, {1, 2, 3, 4}, 4, "\\# 4 01020304", 0},
    // YADIFA CTRL types
    {TYPE_ZONE_TYPE, {0}, 1, ZT_HINT_STRING, 0},
    {TYPE_ZONE_TYPE, {1}, 1, ZT_PRIMARY_STRING, 0},
    {TYPE_ZONE_TYPE, {2}, 1, ZT_SECONDARY_STRING, 0},
    {TYPE_ZONE_TYPE, {3}, 1, ZT_STUB_STRING, 0},
    {TYPE_ZONE_TYPE, {4}, 1, "undefined", 0},
    {TYPE_ZONE_PRIMARY, {0x34, 172, 20, 1, 1, 0, 53, 5, 'm', 'y', 'k', 'e', 'y', 0}, 14, "172.20.1.1 53 mykey.", 0},
    {TYPE_ZONE_PRIMARY, {0x36, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0, 53, 5, 'm', 'y', 'k', 'e', 'y', 0}, 26, "1234:5678:9abc:def0:1234:5678:9abc:def0 53 mykey.", 0},
    {TYPE_CTRL_ZONEFREEZE, {}, 0, "", 0},
    {TYPE_CTRL_ZONEFREEZE, {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 11, "yadifa.eu.", 0},
    {TYPE_CTRL_SRVLOGLEVEL, {1}, 1, "01", 0},
    {TYPE_CTRL_SRVLOGLEVEL, {}, 0, "", INCORRECT_RDATA},
    {TYPE_CTRL_ZONESYNC, {1, 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 12, "01 yadifa.eu.", 0},
    {TYPE_CTRL_ZONESYNC, {}, 0, "", INCORRECT_RDATA},
    //{TYPE_, {}, 0, "", 0},
    {0, {}, 0, NULL, 0}};

static struct osprint_rdata_test_entry_s osprint_rdata_escaped_test_entries[] = {
    {TYPE_MX, {0x00, 0x0a, 4, 'm', 'a', 'i', 'l', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 18, "10 mail.yadifa.eu.", 0},
    {TYPE_TALINK, {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 3, 'n', 's', '2', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 30, "ns1.yadifa.eu. ns2.yadifa.eu.", 0},
    {TYPE_SOA, {3, 'n', 's', '1', 0, 4, 'm', 'a', '.', 'l', 0, 0, 0, 0, 1, 0, 0, 14, 16, 0, 0, 7, 8, 0, 54, 238, 128, 0, 0, 2, 88}, 31, "ns1. ma\\.l. 1 3600 1800 3600000 600", 0},
    {TYPE_RRSIG,
     {0, 6, 8, 2, 0, 0, 14, 16, 0, 0, 0, 0, 127, 255, 255, 255, 12, 34, 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 'F', 'A', 'K', 'E', ' ', 'S', 'I', 'G', 'N', 'A', 'T', 'U', 'R', 'E'},
     43,
     "SOA 8 2 3600 19700101000000 20380119031407 3106 yadifa.eu. RkFLRSBTSUdOQVRVUkU=",
     0},
    {TYPE_NSEC,
     {4, 'n', 'e', 'x', 't', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 0, 2, 127, 255, 1, 1, 255},
     23,
     "next.yadifa.eu. A NS MD MF CNAME SOA MB MG MR NULL WKS PTR HINFO MINFO MX URI CAA AVC TYPE259 TYPE260 TYPE261 "
     "TYPE262 TYPE263",
     0},
    {TYPE_SRV, {12, 34, 56, 78, 1, 80, 3, 'w', 'w', 'w', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0}, 21, "8716 20024 20481 www.yadifa.eu.", 0},
    {0, {}, 0, NULL, 0}};

static int rdata_printer_test(struct osprint_rdata_test_entry_s *entries, ya_result (*rdata_printer)(output_stream_t *, uint16_t, const uint8_t *, uint16_t))
{
    int ret;
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);

    for(int i = 0; entries[i].expected_text != NULL; ++i)
    {
        if(entries[i].error == 0)
        {
            yatest_log("[%3i] record type %i expects '%s'", i, ntohs(entries[i].rtype), entries[i].expected_text);
        }
        else
        {
            yatest_log("[%3i] record type %i expects %08x = %s", i, ntohs(entries[i].rtype), entries[i].error, error_gettext(entries[i].error));
        }
        bytearray_output_stream_reset(&baos);
        ret = rdata_printer(&baos, entries[i].rtype, entries[i].rdata, entries[i].rdata_size);
        if(ret < 0)
        {
            if(entries[i].error == 0)
            {
                yatest_err("osprint_rdata DNS type %i failed with %08x = %s", ntohs(entries[i].rtype), ret, error_gettext(ret));
                return 1;
            }
            else
            {
                if(ret != entries[i].error)
                {
                    yatest_err("osprint_rdata DNS type %i failed with %08x = %s, expected to fail with %08x = %s", ntohs(entries[i].rtype), ret, error_gettext(ret), entries[i].error, error_gettext(entries[i].error));
                    return 1;
                }
                else
                {
                    continue;
                }
            }
        }
        output_stream_write_u8(&baos, 0);
        output_stream_flush(&baos);
        yatest_log((const char *)bytearray_output_stream_buffer(&baos));
        const char *expected_output = entries[i].expected_text;
        size_t      expected_output_size = strlen(expected_output) + 1;
        if((bytearray_output_stream_size(&baos) != expected_output_size) || (memcmp(expected_output, bytearray_output_stream_buffer(&baos), expected_output_size) != 0))
        {
            yatest_err("output content doesn't match expectations: (sizes: %i vs %i)", bytearray_output_stream_size(&baos), expected_output_size);
            yatest_err("got:");
            yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
            yatest_err("expected:");
            yatest_hexdump_err(expected_output, expected_output + expected_output_size);
            return 1;
        }
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int osprint_rdata_test() { return rdata_printer_test(osprint_rdata_test_entries, osprint_rdata); }

static int osprint_rdata_escaped_test() { return rdata_printer_test(osprint_rdata_escaped_test_entries, osprint_rdata_escaped); }

static int print_rdata_test()
{
    init();
    output_stream_close(termout);
    bytearray_output_stream_init(termout, NULL, 65536);
    print_rdata(osprint_rdata_test_entries[0].rtype, osprint_rdata_test_entries[0].rdata, osprint_rdata_test_entries[0].rdata_size);
    output_stream_write_u8(termout, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(termout));
    if(strcmp((const char *)bytearray_output_stream_buffer(termout), osprint_rdata_test_entries[0].expected_text) != 0)
    {
        yatest_err("got '%s', expected '%s'", bytearray_output_stream_buffer(termout), osprint_rdata_test_entries[0].expected_text);
        return 1;
    }

    finalise();
    return 0;
}

static int osprint_dump_with_base_test()
{
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    osprint_dump_with_base(&baos, yatest_lorem_ipsum, 33, 16, OSPRINT_DUMP_LAYOUT_DENSE | OSPRINT_DUMP_BUFFER, yatest_lorem_ipsum);
    output_stream_write_u8(&baos, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&baos));
    static const char expect_dense_buffer[] =
        "0000 | 4c6f72656d20697073756d20646f6c6f |  Lorem ipsum dolo\n"
        "0010 | 722073697420616d65742c20636f6e73 |  r sit amet, cons\n"
        "0020 | 65                               |  e";
    if(strcmp((const char *)bytearray_output_stream_buffer(&baos), expect_dense_buffer) != 0)
    {
        yatest_err("OSPRINT_DUMP_LAYOUT_DENSE|OSPRINT_DUMP_BUFFER");
        yatest_err("got");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected");
        yatest_hexdump_err(expect_dense_buffer, expect_dense_buffer + sizeof(expect_dense_buffer));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int osprint_dump_with_base_squeezable_test()
{
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    static const uint8_t squeezable[] = {'Z', 'E', 'R', 'O', 'E', 'S', 0, 0, 0, 0, 0, 0, 0, 0, '<', '>', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    osprint_dump_with_base(&baos, squeezable, sizeof(squeezable), 16, OSPRINT_DUMP_LAYOUT_DENSE | OSPRINT_DUMP_BUFFER | OSPRINT_DUMP_SQUEEZE_ZEROES, squeezable);
    output_stream_write_u8(&baos, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&baos));
    static const char expect_dense_buffer[] =
        "0000 | 5a45524f455300000000000000003c3e |  ZEROES........<>\n"
        "0040 | 00                               |  .";
    if(strcmp((const char *)bytearray_output_stream_buffer(&baos), expect_dense_buffer) != 0)
    {
        yatest_err("OSPRINT_DUMP_LAYOUT_DENSE|OSPRINT_DUMP_BUFFER");
        yatest_err("got");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected");
        yatest_hexdump_err(expect_dense_buffer, expect_dense_buffer + sizeof(expect_dense_buffer));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int osprint_question_test()
{
    init();
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    static const uint8_t yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
    osprint_question(&baos, yadifa_eu, CLASS_IN, TYPE_A);
    output_stream_write_u8(&baos, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&baos));
    static const char expected[] = ";; QUESTION SECTION:\nyadifa.eu. IN A\n\n";
    if(strcmp((const char *)bytearray_output_stream_buffer(&baos), expected) != 0)
    {
        yatest_err("got");
        yatest_hexdump_err(bytearray_output_stream_buffer(&baos), bytearray_output_stream_buffer(&baos) + bytearray_output_stream_size(&baos));
        yatest_err("expected");
        yatest_hexdump_err(expected, expected + sizeof(expected));
        return 1;
    }
    output_stream_close(&baos);
    finalise();
    return 0;
}

static int print_question_test()
{
    init();
    output_stream_close(termout);
    bytearray_output_stream_init(termout, NULL, 65536);
    static const uint8_t yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
    print_question(yadifa_eu, CLASS_IN, TYPE_A);
    output_stream_write_u8(termout, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(termout));
    static const char expected[] = ";; QUESTION SECTION:\nyadifa.eu. IN A\n\n";
    if(strcmp((const char *)bytearray_output_stream_buffer(termout), expected) != 0)
    {
        yatest_err("got");
        yatest_hexdump_err(bytearray_output_stream_buffer(termout), bytearray_output_stream_buffer(termout) + bytearray_output_stream_size(termout));
        yatest_err("expected");
        yatest_hexdump_err(expected, expected + sizeof(expected));
        return 1;
    }
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(osformat_test)
YATEST(osprint_wrapped_test)
YATEST(debug_osformatln_test)
YATEST(debug_println_test)
YATEST(println_test)
YATEST(print_test)
YATEST(print_char_test)
YATEST(asnformat_test)
YATEST(format_grow_hash_table_test)
YATEST(osprint_base16_test)
YATEST(osprint_u32_test)
YATEST(osprint_u16_test)
YATEST(osprint_u32_hex_test)
YATEST(osprint_quoted_text_escaped_test)
YATEST(osprint_char_times_test)
YATEST(snformat_test)
YATEST(asformat_test)
YATEST(fformat_test)
YATEST(osprint_rdata_test)
YATEST(osprint_rdata_escaped_test)
YATEST(print_rdata_test)
YATEST(osprint_dump_with_base_test)
YATEST(osprint_dump_with_base_squeezable_test)
YATEST(osprint_question_test)
YATEST(print_question_test)
YATEST_TABLE_END
