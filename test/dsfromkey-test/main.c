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

#include <dnscore/dnscore.h>
#include <dnscore/cmdline.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/config_settings.h>
#include <dnscore/format.h>
#include <dnscore/dnskey.h>
#include <dnscore/parser.h>
#include <dnscore/base64.h>
#include <dnscore/file_input_stream.h>

#define MAIN_SETTINGS_NAME "main"

#define VERSION "1.0.0"

struct main_settings_s
{
    u32     digest_algorithm;
    char*   file;
};

typedef struct main_settings_s main_settings_s;

static main_settings_s g_main_settings;

#define CONFIG_TYPE main_settings_s
CONFIG_BEGIN(main_settings_desc)
CONFIG_U32(digest_algorithm, "1")
CONFIG_FILE(file, "")
CONFIG_END(main_settings_desc)
#undef CONFIG_TYPE

CMDLINE_BEGIN(main_settings_cmdline)
// main
CMDLINE_SECTION(MAIN_SETTINGS_NAME)
CMDLINE_OPT("digest-algorithm", 'a', "digest_algorithm")
CMDLINE_HELP("1 or 2", "the digest algorithm to use")
CMDLINE_OPT("file", 'f', "file")
CMDLINE_HELP("[file]", "the public key file")
CMDLINE_MSG("","")
CMDLINE_VERSION_HELP(main_settings_cmdline)
CMDLINE_END(main_settings_cmdline)

ya_result
print_ds_from_public_key_from_file(const char *filename)
{
    parser_s parser;
    input_stream is;
    ya_result ret;
    u16 rclass;
    u16 rtype;
    u16 flags;
    u16 rdata_size;
    char origin[MAX_DOMAIN_LENGTH + 1];
    u8 fqdn[MAX_DOMAIN_LENGTH];
    u8 rdata[1024 + 4];

    if(ISOK(ret = file_input_stream_open(&is, filename)))
    {
        parser_init(&parser, "\"\"''", "()", ";#", "\040\t\r", "\\");
        parser_push_stream(&parser, &is);

        for(;;)
        {
            if(ISOK(ret = parser_next_token(&parser)))
            {
                if(!(ret & PARSER_WORD))
                {
                    if(ret & (PARSER_COMMENT|PARSER_EOL))
                    {
                        continue;
                    }

                    if(ret & PARSER_EOF)
                    {
                        input_stream *completed_stream = parser_pop_stream(&parser);
                        input_stream_close(completed_stream);
                        ret = UNEXPECTED_EOF;
                        break;
                    }
                    continue;
                }
            }

            const char *text = parser_text(&parser);
            u32 text_len = parser_text_length(&parser);
            memcpy(origin, text, text_len);
            origin[text_len] = '\0';

            if(FAIL(ret = cstr_to_dnsname_with_check_len(fqdn, text, text_len)))
            {
                break;
            }

            if(FAIL(ret = parser_copy_next_class(&parser, &rclass)))
            {
                break;
            }

            if(rclass != CLASS_IN)
            {
                // not IN
                ret = DNSSEC_ERROR_EXPECTED_CLASS_IN;
                break;
            }

            if(FAIL(ret = parser_copy_next_type(&parser, &rtype)))
            {
                break;
            }

            if(rtype != TYPE_DNSKEY)
            {
                // not DNSKEY
                ret = DNSSEC_ERROR_EXPECTED_TYPE_DNSKEY;
                break;
            }

            if(FAIL(ret = parser_copy_next_u16(&parser, &flags)))
            {
                break;
            }

            flags = htons(flags); // need to fix the endianness
            SET_U16_AT_P(rdata, flags);

            // protocol (8 bits integer)

            if(FAIL(ret = parser_copy_next_u8(&parser, &rdata[2])))
            {
                break;
            }

            // algorithm (8 bits integer)

            if(FAIL(ret = parser_copy_next_u8(&parser, &rdata[3])))
            {
                break;
            }

            // key (base64)

            if(FAIL(ret = parser_concat_next_tokens_nospace(&parser)))
            {
                break;
            }

            if(BASE64_DECODED_SIZE(ret) > (int)sizeof(rdata) - 4)
            {
                // overflow
                ret = DNSSEC_ERROR_UNEXPECTEDKEYSIZE;
                break;
            }

            if(FAIL(ret = base64_decode(parser_text(&parser), parser_text_length(&parser), &rdata[4])))
            {
                break;
            }

            if(ret > 1024)
            {
                ret = DNSSEC_ERROR_KEYISTOOBIG;
                break;
            }

            rdata_size = 4 + ret;

            u8 ds_rdata[256];

            if(ISOK(ret = dnskey_generate_ds_rdata(g_main_settings.digest_algorithm, fqdn,
                                                   rdata, rdata_size, ds_rdata)))
            {
                u32 ds_rdata_size = ret;
                rdata_desc rdatadesc = {TYPE_DS, ds_rdata_size, ds_rdata};
                formatln("%{dnsname} IN %{typerdatadesc}\n", fqdn, &rdatadesc);
            }
            else
            {
                formatln("error generating the DS record: %r", ret);
            }


            break;
        }

        parser_finalize(&parser);
    }

    return ret;
}


static ya_result
main_config(int argc, char *argv[])
{
    config_error_s cfg_error;
    ya_result ret;

    config_init();

    int priority = 0;

    config_register_struct(MAIN_SETTINGS_NAME, main_settings_desc, &g_main_settings, priority++);

    config_register_cmdline(priority++); // without this line, the help will not work

    struct config_source_s sources[1];

    if(FAIL(ret = config_source_set_commandline(&sources[0], main_settings_cmdline, argc, argv)))
    {
        formatln("command line definition: %r", ret);
        return ret;
    }

    if(FAIL(ret = config_read_from_sources(sources, 1, &cfg_error)))
    {
        formatln("settings: (%s:%i) %s: %r", cfg_error.file, cfg_error.line_number, cfg_error.line, ret);
        flushout();
        return ret;
    }

    if(cmdline_version_get())
    {
        println("\nversion: " VERSION "\n");
        return SUCCESS;
    }

    if(cmdline_help_get())
    {
        formatln("\nUsage:\n\n    %s [options]\n\nOptions:\n", argv[0]);
        cmdline_print_help(main_settings_cmdline, 4, 48, " :  ", 48, termout);
        formatln("");
        return SUCCESS;
    }

    return 1;
}

int
main(int argc, char *argv[])
{
    /* initializes the core library */
    dnscore_init();

    ya_result ret = main_config(argc, argv);

    if(ISOK(ret))
    {
        if(ret == 1)
        {
            if((g_main_settings.digest_algorithm < DS_DIGEST_SHA1) || (g_main_settings.digest_algorithm > DS_DIGEST_SHA256))
            {
                formatln("algorithm must be either 1 or 2, not %i", g_main_settings.digest_algorithm);
                return EXIT_FAILURE;
            }

            config_print(termout);

            // open the file
            // read the key
            // compute the DS
            // print the DS
#if EASY
            dnssec_key *key = NULL;
            if(ISOK(ret = dnskey_new_public_key_from_file(g_main_settings.file, &key)))
            {
                u8 dnskey_rdata[4096];
                u32 dnskey_rdata_size = key->vtbl->dnssec_key_writerdata(key, dnskey_rdata);

                u8 ds_rdata[256];

                if(ISOK(ret = dnskey_generate_ds_rdata(g_main_settings.digest_algorithm, dnskey_get_domain(key),
                        dnskey_rdata, dnskey_rdata_size, ds_rdata)))
                {
                    u32 ds_rdata_size = ret;
                    rdata_desc rdatadesc = {TYPE_DS, ds_rdata_size, ds_rdata};
                    formatln("%{dnsname} IN %{typerdatadesc}\n", dnskey_get_domain(key), &rdatadesc);
                }
                else
                {
                    formatln("error generating the DS record: %r", ret);
                }
            }
            else
            {
                formatln("error loading the key: %r", ret);
            }
#else   // NOT easy

            ret = print_ds_from_public_key_from_file(g_main_settings.file);
#endif
        }
        else
        {
            // help was printed.
        }
    }
    else
    {
        formatln("main_config returned: %r", ret);
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
