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
#include "dnscore/host_address.h"
#include "dnscore/format.h"
#include <dnscore/dnscore.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/parser.h>
#include <dnscore/tsig.h>

static const char input_0[] =
    "################################################################################\n"
    "#\n"
    "# Copyright (c) 2011-2025, EURid vzw. All rights reserved.\n"
    "# The YADIFA TM software product is provided under the BSD 3-clause license:\n"
    "#\n"
    "# Redistribution and use in source and binary forms, with or without\n"
    "# modification, are permitted provided that the following conditions\n"
    "# are met:\n"
    "#\n"
    "#        * Redistributions of source code must retain the above copyright\n"
    "#          notice, this list of conditions and the following disclaimer.\n"
    "#        * Redistributions in binary form must reproduce the above copyright\n"
    "#          notice, this list of conditions and the following disclaimer in the\n"
    "#          documentation and/or other materials provided with the distribution.\n"
    "#        * Neither the name of EURid nor the names of its contributors may be\n"
    "#          used to endorse or promote products derived from this software\n"
    "#          without specific prior written permission.\n"
    "#\n"
    "# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n"
    "# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
    "# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
    "# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE\n"
    "# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n"
    "# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n"
    "# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n"
    "# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n"
    "# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
    "# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n"
    "# POSSIBILITY OF SUCH DAMAGE.\n"
    "#\n"
    "################################################################################\n"
    "\n"
    "\"one\\\"two\"\n"
    "\"\"\n"
    "\"\\\\\"\n"
    "\"\\\\\\\\\"\n"
    "word00,word01 word02\tword03\n"
    "word10 \\word11 'word12' \"word13\"\n"
    "\"word20\"\n"
    "'word30'\n"
    "\"esc'40\"\n"
    "'esc\"50'\n"
    "esc\\\\60 \"esc\\\\61\" 'esc\\\\62' \"esc\\\"63\" \"esc\\\\'64\" 'esc\\\\\"65' 'esc\\'66'\n"
    "escend90\\\\\\\n"
    "escend91\n"
    "\"escendA0\\\\\"\n"
    "\"escendB0\\\\\\\\\"\n"
    "multi-(\n"
    "line)\n";

static const char        input_1[] = "wrong70\\\\\"\n";
static const char        input_2[] = "wrong80\\\\'\n";
static const char        input_escape[] = "word-\\065\n";
static const char        input_escape2[] = "\\065\n";
static const char        input_two_lines[] = "word00 (word01 word02\nword10 ) word11 word12\n";
static const char        input_ttls[] = "1 1s 1m 1h 1d 1w";
static const char        input_types[] = "A NS SOA MX AAAA TYPE65535";
static const char        input_tcp[] = "tcp";
static const char        input_ssh[] = "ssh";

static const char *const zrf_string_delimiters = "\"\"''";
static const char *const zrf_multiline_delimiters = "()";
static const char *const zrf_comment_markers = ";";
static const char *const zrf_blank_makers = "\040\t\r";
static const char *const zrf_escape_characters = "\\";

static parser_t          parser;
static input_stream_t    is;

static void              init(const char *text)
{
    int ret;
    dnscore_init();
    ret = parser_init(&parser,
                      zrf_string_delimiters,    // by 2
                      zrf_multiline_delimiters, // by 2
                      zrf_comment_markers,      // by 1
                      zrf_blank_makers,         // by 1
                      zrf_escape_characters);   // by 1
    if(ret < 0)
    {
        yatest_err("failed to initialise parser");
        exit(1);
    }

    if(text != NULL)
    {
        bytearray_input_stream_init(&is, text, strlen(text), false);
        parser_push_stream(&parser, &is);
    }
}

static void finalise() { dnscore_finalize(); }

static int  parser_input0_test()
{
    ya_result ret;
    char      buffer[1024];
    init(input_0);
    for(;;)
    {
        while(ISOK(ret = parser_copy_next_word(&parser, buffer, sizeof(buffer) - 1)))
        {
            buffer[ret] = '\0';
            yatest_log("word=<%s>", buffer);
        }

        if(ret == PARSER_REACHED_END_OF_LINE)
        {
            yatest_log("<EOL>");
            continue;
        }

        if(ret == PARSER_REACHED_END_OF_FILE)
        {
            yatest_log("<EOF>");
            break;
        }
        yatest_err("error parsing <%s>: %08x = %s", parser_text(&parser), ret, error_gettext(ret));
        return 1;
    }

    parser_set_eol(&parser);

    finalise();

    return 0;
}

static int parser_input1_test()
{
    ya_result ret;
    char      buffer[1024];
    init(input_1);
    for(;;)
    {
        while(ISOK(ret = parser_copy_next_word(&parser, buffer, sizeof(buffer) - 1)))
        {
            buffer[ret] = '\0';
            yatest_log("word=<%s>", buffer);
        }

        if(ret == PARSER_UNEXPECTED_STRING_DELIMITER)
        {
            break;
        }

        yatest_err("expected PARSER_UNEXPECTED_STRING_DELIMITER, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    finalise();

    return 0;
}

static int parser_input2_test()
{
    ya_result ret;
    char      buffer[1024];
    init(input_2);
    for(;;)
    {
        while(ISOK(ret = parser_copy_next_word(&parser, buffer, sizeof(buffer) - 1)))
        {
            buffer[ret] = '\0';
            yatest_log("word=<%s>", buffer);
        }

        if(ret == PARSER_UNEXPECTED_STRING_DELIMITER)
        {
            break;
        }

        yatest_err("expected PARSER_UNEXPECTED_STRING_DELIMITER, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    finalise();

    return 0;
}

static int parser_input_escape_test()
{
    ya_result ret;
    char      buffer[1024];
    init(input_escape);
    for(;;)
    {
        while(ISOK(ret = parser_copy_next_word(&parser, buffer, sizeof(buffer) - 1)))
        {
            buffer[ret] = '\0';
            yatest_log("word=<%s>", buffer);
        }

        if(ret == PARSER_REACHED_END_OF_LINE)
        {
            break;
        }

        yatest_err("expected PARSER_REACHED_END_OF_LINE, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    finalise();

    return 0;
}

static int parser_input_escape2_test()
{
    ya_result ret;
    init(input_escape2);

    ret = parser_next_token(&parser);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }
    parser_text_asciiz(&parser);
    yatest_log("word=<%s>", parser_text(&parser));
    if(strcmp(parser_text(&parser), "A") != 0)
    {
        yatest_err("unexpected result");
        return 1;
    }
    parser_text_unasciiz(&parser);

    finalise();

    return 0;
}

static int parser_concat_current_and_next_tokens_nospace_test()
{
    ya_result ret;
    init(input_two_lines);
    parser_next_word(&parser);
    ret = parser_concat_current_and_next_tokens_nospace(&parser);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }

    parser_text_asciiz(&parser);
    yatest_log("word=<%s>", parser_text(&parser));
    if(strcmp(parser_text(&parser), "word00word01word02word10word11word12") != 0)
    {
        yatest_err("unexpected result");
        return 1;
    }
    parser_text_unasciiz(&parser);

    finalise();
    return 0;
}

static int parser_copy_next_ttl_test()
{
    ya_result ret;
    init(input_ttls);
    int32_t ttl;

    // 1

    ret = parser_copy_next_ttl(&parser, &ttl);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log("ttl=%i", ttl);
    if(ttl != 1)
    {
        yatest_err("expected %i, got %i", 1, ttl);
        return 1;
    }

    // 1s

    ret = parser_copy_next_ttl(&parser, &ttl);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log("ttl=%i", ttl);
    if(ttl != 1)
    {
        yatest_err("expected %i, got %i", 1, ttl);
        return 1;
    }

    // 1m

    ret = parser_copy_next_ttl(&parser, &ttl);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log("ttl=%i", ttl);
    if(ttl != 60)
    {
        yatest_err("expected %i, got %i", 60, ttl);
        return 1;
    }

    // 1h

    ret = parser_copy_next_ttl(&parser, &ttl);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log("ttl=%i", ttl);
    if(ttl != 3600)
    {
        yatest_err("expected %i, got %i", 3600, ttl);
        return 1;
    }

    // 1d

    ret = parser_copy_next_ttl(&parser, &ttl);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log("ttl=%i", ttl);
    if(ttl != 86400)
    {
        yatest_err("expected %i, got %i", 86400, ttl);
        return 1;
    }

    // 1w

    ret = parser_copy_next_ttl(&parser, &ttl);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log("ttl=%i", ttl);
    if(ttl != 604800)
    {
        yatest_err("expected %i, got %i", 604800, ttl);
        return 1;
    }

    finalise();
    return 0;
}

static int parser_type_bit_maps_initialise_test()
{
    ya_result ret;
    init(input_types);
    type_bit_maps_context_t tbmctx;
    ret = parser_type_bit_maps_initialise(&parser, &tbmctx);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }

    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    type_bit_maps_output_stream_write(&tbmctx, &baos);
    output_stream_t baos2;
    bytearray_output_stream_init(&baos2, NULL, 65536);
    osprint_type_bitmap(&baos2, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos));
    output_stream_write_u8(&baos2, 0);
    if(strcmp((const char *)bytearray_output_stream_buffer(&baos2), " A NS SOA MX AAAA TYPE65535") != 0)
    {
        yatest_err("unexpected result");
        return 1;
    }

    finalise();
    return 0;
}

static int parser_get_network_protocol_from_next_word_test()
{
    ya_result ret;
    init(input_tcp);
    int protocol;
    ret = parser_get_network_protocol_from_next_word(&parser, &protocol);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }

    if(protocol != 6)
    {
        yatest_err("unexpected result");
        return 1;
    }

    finalise();
    return 0;
}

static int parser_get_network_service_port_from_next_word_test()
{
    ya_result ret;
    init(input_ssh);
    int service;
    ret = parser_get_network_service_port_from_next_word(&parser, &service);
    if(ret < 0)
    {
        yatest_err("%08x = %s", ret, error_gettext(ret));
        return 1;
    }

    if(service != 22)
    {
        yatest_err("unexpected result");
        return 1;
    }

    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(parser_input0_test)
YATEST(parser_input1_test)
YATEST(parser_input2_test)
YATEST(parser_input_escape_test)
YATEST(parser_input_escape2_test)
YATEST(parser_concat_current_and_next_tokens_nospace_test)
YATEST(parser_copy_next_ttl_test)
YATEST(parser_type_bit_maps_initialise_test)
YATEST(parser_get_network_protocol_from_next_word_test)
YATEST(parser_get_network_service_port_from_next_word_test)
YATEST_TABLE_END
