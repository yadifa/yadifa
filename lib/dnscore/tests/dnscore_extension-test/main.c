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
#include <dnscore/dnscore.h>
#include <dnscore/dnscore_extension.h>
#include <dnscore/format.h>
#include <dnscore/base16.h>
#include <dnscore/bytearray_output_stream.h>

#define TYPE_ZERO NU16(0xed01)

static const uint8_t yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};

static const char   *type_zero = "ZERO";
static const char   *class_in = "IN";

static bool          zero_type_extension_dnsclass_format_handler(uint16_t rclass, const char **txtp, int32_t *lenp)
{
    if(rclass == CLASS_IN)
    {
        *txtp = class_in;
        *lenp = 2;
        return true;
    }
    return false;
}

static bool zero_type_extension_dnstype_format_handler(uint16_t rtype, const char **txtp, int32_t *lenp)
{
    if(rtype == TYPE_ZERO)
    {
        *txtp = type_zero;
        *lenp = 4;
        return true;
    }
    return false;
}

static bool zero_type_extension_osprint_data(output_stream_t *os, uint16_t rtype, const uint8_t *rdata_pointer, uint16_t rdata_size)
{
    if(rtype == TYPE_ZERO)
    {
        for(int i = 0; i < rdata_size; ++i)
        {
            osformat(os, "%02x", rdata_pointer[i]);
        }
        return true;
    }
    return false;
}

static ya_result zero_type_extension_zone_reader_text_copy_rdata(parser_t *p, uint16_t rtype, uint8_t *rdata, uint32_t rdata_size, const uint8_t *origin, const char **textp, uint32_t *text_lenp)
{
    (void)p; // the example doesn't need to use the parser
    (void)origin;
    if(rtype == TYPE_ZERO)
    {
        if(((*text_lenp) & 1) != 0)
        {
            return PARSE_ERROR;
        }
        if(rdata_size < (*text_lenp / 2))
        {
            return BUFFER_WOULD_OVERFLOW;
        }
        int ret = base16_decode(*textp, *text_lenp, rdata);
        return ret;
    }
    return UNSUPPORTED_RECORD; // the value that MUST be returned if the record is unknown
}

static uint16_t zero_type_extension_additional_class_count() { return 1; }

static uint16_t zero_type_extension_additional_type_count() { return 1; }

static bool     zero_type_extension_additional_class_get(int index, uint16_t *rclassp, const char **rclassnamep)
{
    if(index == 0)
    {
        *rclassp = CLASS_IN;
        *rclassnamep = class_in;
        return true;
    }
    return false;
}

static bool zero_type_extension_additional_type_get(int index, uint16_t *rtypep, const char **rtypenamep)
{
    if(index == 0)
    {
        *rtypep = TYPE_ZERO;
        *rtypenamep = type_zero;
        return true;
    }
    return false;
}

static dnscore_dns_extension_t zero_type_extension = {zero_type_extension_dnsclass_format_handler,
                                                      zero_type_extension_dnstype_format_handler,
                                                      zero_type_extension_osprint_data,
                                                      zero_type_extension_zone_reader_text_copy_rdata,
                                                      zero_type_extension_additional_class_count,
                                                      zero_type_extension_additional_type_count,
                                                      zero_type_extension_additional_class_get,
                                                      zero_type_extension_additional_type_get};

static int                     zero_test()
{
    int ret;

    dnscore_init();

    ret = dnscore_dns_extension_register(&zero_type_extension);
    if(FAIL(ret))
    {
        yatest_err("dnscore_dns_extension_register failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = dnscore_dns_extension_register(&zero_type_extension);
    if(ret != INVALID_STATE_ERROR)
    {
        yatest_err("dnscore_dns_extension_register expected to fail with INVALID_STATE_ERROR = %08x, got %08x = %s", INVALID_STATE_ERROR, ret, error_gettext(ret));
        return 1;
    }

    const char *txt;
    int32_t     txt_len;

    if(!dnscore_dns_extension_dnsclass_format_handler(CLASS_IN, &txt, &txt_len))
    {
        yatest_err("dnscore_dns_extension_dnsclass_format_handler returned false");
        return 1;
    }

    if(txt_len != (int32_t)strlen(class_in))
    {
        yatest_err("dnscore_dns_extension_dnsclass_format_handler txt_len = %i != %i", txt_len, strlen(class_in));
        return 1;
    }

    if(strcmp(txt, class_in) != 0)
    {
        yatest_err("dnscore_dns_extension_dnsclass_format_handler txt = '%s' != '%s'", txt, class_in);
        return 1;
    }

    if(!dnscore_dns_extension_dnstype_format_handler(TYPE_ZERO, &txt, &txt_len))
    {
        yatest_err("dnscore_dns_extension_dnstype_format_handler returned false");
        return 1;
    }

    if(txt_len != (int32_t)strlen(type_zero))
    {
        yatest_err("dnscore_dns_extension_dnstype_format_handler txt_len = %i != %i", txt_len, strlen(type_zero));
        return 1;
    }

    if(strcmp(txt, type_zero) != 0)
    {
        yatest_err("dnscore_dns_extension_dnstype_format_handler txt = '%s' != '%s'", txt, type_zero);
        return 1;
    }

    if(dnscore_dns_extension_dnstype_format_handler(0xffff, &txt, &txt_len))
    {
        yatest_err("dnscore_dns_extension_dnstype_format_handler returned true (unknown type)");
        return 1;
    }

    static uint8_t  zero_rdata[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const char     *text = "00010203040506070809";
    uint32_t        text_len = strlen(text);

    output_stream_t os;
    bytearray_output_stream_init(&os, NULL, 0);
    if(!dnscore_dns_extension_osprint_data(&os, TYPE_ZERO, zero_rdata, sizeof(zero_rdata)))
    {
        yatest_err("dnscore_dns_extension_osprint_data returned false");
        return 1;
    }
    if(bytearray_output_stream_size(&os) != text_len)
    {
        yatest_err("dnscore_dns_extension_osprint_data printed wrong number of chars: %i != %i", bytearray_output_stream_size(&os), text_len);
        return 1;
    }
    if(memcmp(bytearray_output_stream_buffer(&os), text, text_len) != 0)
    {
        yatest_err("dnscore_dns_extension_osprint_data printed value mismatch");
        return 1;
    }

    uint8_t rdata[64];

    ret = dnscore_dns_extension_zone_reader_text_copy_rdata(NULL, TYPE_ZERO, rdata, sizeof(rdata), yadifa_eu, &text, &text_len);
    if(ret < 0)
    {
        yatest_err("dnscore_dns_extension_zone_reader_text_copy_rdata failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(ret != sizeof(zero_rdata))
    {
        yatest_err("dnscore_dns_extension_zone_reader_text_copy_rdata len = %i != %i", ret, sizeof(zero_rdata));
        return 1;
    }
    if(memcmp(rdata, zero_rdata, sizeof(zero_rdata)) != 0)
    {
        yatest_err("dnscore_dns_extension_zone_reader_text_copy_rdata data mismatch");
        return 1;
    }

    ret = dnscore_dns_extension_zone_reader_text_copy_rdata(NULL, 0xffff, rdata, sizeof(rdata), yadifa_eu, &text, &text_len);
    if(ret != UNSUPPORTED_RECORD)
    {
        yatest_err(
            "dnscore_dns_extension_zone_reader_text_copy_rdata expected to failed with UNSUPPORTED_RECORD = %08x, got "
            "%08x = %s",
            UNSUPPORTED_RECORD,
            ret,
            error_gettext(ret));
        return 1;
    }

    uint16_t    v16;
    const char *name;
    if(!dnscore_dns_extension_get_class(0, &v16, &name))
    {
        yatest_err("dnscore_dns_extension_get_class returned false");
        return 1;
    }
    if(v16 != CLASS_IN)
    {
        yatest_err("dnscore_dns_extension_get_class class = %04x != %04x", v16, CLASS_IN);
        return 1;
    }

    if(dnscore_dns_extension_get_class(INT32_MAX, &v16, &name))
    {
        yatest_err("dnscore_dns_extension_get_class returned true (out of range)");
        return 1;
    }

    if(!dnscore_dns_extension_get_type(0, &v16, &name))
    {
        yatest_err("dnscore_dns_extension_get_type returned false");
        return 1;
    }
    if(v16 != TYPE_ZERO)
    {
        yatest_err("dnscore_dns_extension_get_type class = %04x != %04x", v16, TYPE_ZERO);
        return 1;
    }
    if(dnscore_dns_extension_get_type(INT32_MAX, &v16, &name))
    {
        yatest_err("dnscore_dns_extension_get_type returned true (out of range)");
        return 1;
    }

    dnscore_finalize();

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(zero_test)
YATEST_TABLE_END
