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

/** @defgroup yadifa
 *  @ingroup ###
 *  @brief
 */

#include "client-config.h"

#define KEYGEN_C_

#include "module/keygen.h"
#include "common.h"

#include <sys/time.h>

#include <dnscore/config_settings.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/cmdline.h>



#include <dnscore/dnskey.h>
#include <dnscore/rfc.h>

#include <dnslg/config-resolver.h>
#include <dnscore/timems.h>
#include <dnscore/format.h>
#include <dnscore/parsing.h>

#include "common-config.h"
#include "module.h"

//#include "query-result.h"

/*----------------------------------------------------------------------------*/
#pragma mark DEFINES

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

/*----------------------------------------------------------------------------*/
#pragma mark CONFIG

// ********************************************************************************
// ***** module settings
// ********************************************************************************

#define KEYGEN_SECTION_NAME "keygen"

#define KEYS_PATH_DEFAULT LOCALSTATEDIR "/zones/keys/"

static yadifa_keygen_settings_s g_keygen_settings;

#define CONFIG_TYPE yadifa_keygen_settings_s
CONFIG_BEGIN(keygen_settings_desc)

//CONFIG_STRING(       config_file,             ""                                                       )
CONFIG_STRING(       keys_path,           KEYS_PATH_DEFAULT                                                       )
CONFIG_STRING(       random_device_file,      ""                                                       )
CONFIG_FQDN(         origin,                  NULL                                                       )

CONFIG_STRING(       key_flag,                ""                                                       )
CONFIG_STRING(       algorithm,               "0"                                                      )

CONFIG_STRING(       publication_date_text,   ""                                                       )
CONFIG_STRING(       activation_date_text,    ""                                                       )
CONFIG_STRING(       revocation_date_text,    ""                                                       )
CONFIG_STRING(       inactivation_date_text,  ""                                                       )
CONFIG_STRING(       deletion_date_text,      ""                                                       )

CONFIG_U32(          ttl,                     "86400"                                                    )
CONFIG_U32(          key_size,                "0"                                                        )
CONFIG_U32(          digest,                  "0"                                                        )
//CONFIG_U32(          interval,                0                                                        )
CONFIG_U32(          verbosity_level,         "0"                                                        )

CONFIG_BOOL(         generate_key_only,       "off"                                                    )
CONFIG_BOOL(         backward_compatible_key, "off"                                                    )
CONFIG_BOOL(         successor_key,           "off"                                                    )
CONFIG_BOOL(         nsec3_capable,           "off"                                                    )



CONFIG_END(keygen_settings_desc)
#undef CONFIG_TYPE

/// use global resolver and general command line settings
//extern config_resolver_settings_s g_resolver_settings;

static ya_result
keygen_print_algorithm_help(const struct cmdline_desc_s *desc, output_stream *os)
{
    (void)desc;

    u8  count = dnskey_supported_algorithm_count();

    if(count == 0)
    {
        return FEATURE_NOT_SUPPORTED;
    }

    const int width_max = 80-32;

    int width = 0;
    u8 i = 0;
    const dnskey_features *f = dnskey_supported_algorithm_by_index(i);

    const char **np = f->names;

    osprint_char_times(os, ' ', 32);

    width += osprint(os, *np);
    bool separate = TRUE;
    ++np;

    for(;;)
    {
        if(width >= width_max)
        {
            width = 0;

            if(separate)
            {
                width += osprint(os, " | ");
                separate = FALSE;
            }

            osprintln(os, "");
            osprint_char_times(os, ' ', 32);
        }

        if(*np != NULL)
        {
            if(separate)
            {
                width += osprint(os, " | ");
                separate = FALSE;
            }

            width += osprint(os, *np);
            separate = TRUE;
            ++np;
        }
        else
        {
            if(++i >= count)
            {
                break;
            }

            f = dnskey_supported_algorithm_by_index(i);
            np = f->names;
        }
    }

    osprintln(os, "");

    return SUCCESS;
}

static ya_result
keygen_print_keysize_help(const struct cmdline_desc_s *desc, output_stream *os)
{
    (void)desc;

    u8  count = dnskey_supported_algorithm_count();

    for(u8 i = 0; i < count; ++i)
    {
        const dnskey_features *f = dnskey_supported_algorithm_by_index(i);
        const char **np = f->names;

        if(*np != NULL)
        {
            osprint_char_times(os, ' ', 32);
            osformat(os, "%20s: ", *np);
            if(f->size_bits_min < f->size_bits_max)
            {
                osformat(os, "[%u..%u]", f->size_bits_min, f->size_bits_max);

                if(f->size_multiple != 1)
                {
                    osformatln(os, " and divisible by %u", f->size_multiple);
                }
                else
                {
                    osprintln(os, "");
                }
            }
            else
            {
                osprintln(os, "ignored");
            }
        }
    }

    return SUCCESS;
}

// ********************************************************************************
// ***** module command line struct
// ********************************************************************************

static ya_result
keygen_cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    void *arg = CMDLINE_CALLBACK_ARG_GET(desc);
    (void)arg;
    (void)callback_owned;

    ya_result ret = cmdline_get_opt_long(desc, "origin", arg_name);

    return CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS;
}

CMDLINE_BEGIN(keygen_cmdline)
CMDLINE_FILTER(keygen_cmdline_filter_callback, NULL) // NULL is passed to the callback as a parameter (callback_owned)
// main hooks
CMDLINE_INDENT(4)
CMDLINE_IMSG("options:", "")
CMDLINE_INDENT(4)
// main
// CMDLINE_OPT(      "config",                  'c', "config_file"                )
CMDLINE_SECTION(  KEYGEN_SECTION_NAME)
CMDLINE_OPT(      "keys-path",           'K', "keys_path"              )
CMDLINE_HELP("<directory>", "write keys into directory")
/*
CMDLINE_OPT(      "random_device_file",      'r', "random_device_file"         )
CMDLINE_HELP("","")
*/

CMDLINE_OPT("origin",                   'o', "origin"                      )
CMDLINE_HELP("<domain>","the domain name") // why qname ?,

CMDLINE_OPT(      "algorithm",               'a', "algorithm"                  )
CMDLINE_HELP("<algorithm>","one of the supported key algorithms")
CMDLINE_CALLBACK(keygen_print_algorithm_help, NULL)
CMDLINE_OPT(      "key-flag",                'f', "key_flag"                   )
CMDLINE_HELP("KSK", "flag(s) to apply to the key")
CMDLINE_OPT(      "publication-date",        'P', "publication_date"           )
CMDLINE_HELP("date/[+-]offset/none","set key publication date (default: now)")
CMDLINE_OPT(      "activation-date",         'A', "activation_date"            )
CMDLINE_HELP("date/[+-]offset/none","set key activation date (default: now)")
CMDLINE_OPT(      "revocation-date",         'R', "revocation_date"            )
CMDLINE_HELP("date/[+-]offset/none","set key revocation date")
CMDLINE_OPT(      "inactivation-date",       'I', "inactivation_date"          )
CMDLINE_HELP("date/[+-]offset/none","set key inactivation date")
CMDLINE_OPT(      "deletion-date",           'D', "deletion_date"              )
CMDLINE_HELP("date/[+-]offset/none","set key inactivation date")
CMDLINE_OPT(      "key-size",                'b', "key_size"                   )
CMDLINE_HELP("<key size in bits>","key size in bits, when applicable")
CMDLINE_CALLBACK(keygen_print_keysize_help, NULL)
/*
CMDLINE_OPT(      "digest",                  'd', "digest"                     )
CMDLINE_HELP("","")

CMDLINE_OPT(      "interval",                'i', "interval"                   )
CMDLINE_HELP("","")
*/
CMDLINE_OPT(      "ttl",                     'L', "ttl"                        )
CMDLINE_HELP("<TTL>","key TTL")
/*
CMDLINE_OPT(      "verbosity_level",         'v', "verbosity_level"            )
CMDLINE_HELP("","")

CMDLINE_BOOL(     "generate_key_only",       'G', "generate_key_only"          )
CMDLINE_HELP("","")

CMDLINE_BOOL(     "backward_compatible_key", 'C', "backward_compatible_key"    )
CMDLINE_HELP("","")

CMDLINE_BOOL(     "successor_key",           'S', "successor_key"              )
CMDLINE_HELP("","")
*/
CMDLINE_BOOL(     "nsec3-capable",           '3', "nsec3_capable"              )
CMDLINE_HELP("","use NSEC3-capable algorithm")


// command line
CMDLINE_VERSION_HELP(keygen_cmdline)

CMDLINE_END(keygen_cmdline)

void
keygen_config_print()
{
    config_print(termout);

    printf("key directory          : %s\n", g_keygen_settings.keys_path);
    printf("random_device_file     : %s\n", g_keygen_settings.random_device_file);
    printf("\n");
    printf("key flag               : %s\n", g_keygen_settings.key_flag);
    printf("algorithm              : %s\n", g_keygen_settings.algorithm);
    printf("\n");
    printf("publication date       : %s\n", g_keygen_settings.publication_date_text);
    printf("activation date        : %s\n", g_keygen_settings.activation_date_text);
    printf("revocation date        : %s\n", g_keygen_settings.revocation_date_text);
    printf("deletion date          : %s\n", g_keygen_settings.deletion_date_text);
    printf("\n");
    printf("ttl                    : %i\n", g_keygen_settings.ttl);
    printf("key size               : %i\n", g_keygen_settings.key_size);
    printf("digest                 : %i\n", g_keygen_settings.digest);
    printf("interval               : %i\n", g_keygen_settings.interval);
    printf("verbosity_level        : %i\n", g_keygen_settings.verbosity_level);
    printf("\n");
    printf("generation key only    : %s\n", g_keygen_settings.generate_key_only ? "on" : "off");
    printf("backward compatible key: %s\n", g_keygen_settings.backward_compatible_key ? "on" : "off");
    printf("successor key          : %s\n", g_keygen_settings.successor_key ? "on" : "off");
    printf("nsec3 enabled          : %s\n", g_keygen_settings.nsec3_capable ? "on" : "off");
}

// ********************************************************************************
// ***** command help usage
// ********************************************************************************

// ********************************************************************************
// ***** module initializer
// ********************************************************************************

static ya_result
keygen_init(const module_s *m)
{
    (void)m;

    return SUCCESS;
}

// ********************************************************************************
// ***** module finaliser
// ********************************************************************************

static ya_result
keygen_finalize(const module_s *m)
{
    (void)m;
    return SUCCESS;
}

// ********************************************************************************
// ***** module register
// ********************************************************************************

static int
keygen_config_register(int priority)
{
    ya_result                                                    return_code;

    /*    ------------------------------------------------------------    */

    // 2. register main options: qname, qclass, qtype, ...
    //
    // init and register main settings container
    ZEROMEMORY(&g_keygen_settings, sizeof(g_keygen_settings));

    return_code = config_register_struct(KEYGEN_SECTION_NAME, keygen_settings_desc, &g_keygen_settings, ++priority);

    return return_code;
}

// ********************************************************************************
// ***** module setup
// ********************************************************************************

static int
keygen_setup(const module_s *m)
{
    (void)m;
    ya_result  ret = SUCCESS;

    /*
     * I expect parameters are meant to be checked here
     */

    if(g_keygen_settings.origin == NULL)
    {
        ret = DOMAINNAME_INVALID;
    }

    return ret;
}

// ********************************************************************************
// ***** module run
// ********************************************************************************

static ya_result
keygen_run(const module_s *m)
{
    (void)m;

    ya_result                                                    return_code;
#if 0
    keygen_config_print();
#endif

    /*    ------------------------------------------------------------    */

    char *keys_path;
    // 1. set 'keys_path'
    char keys_path_buffer[1024];

    if((g_keygen_settings.keys_path == NULL) || (strcmp(g_keygen_settings.keys_path, "") == 0))
    {
        // change directory to 'current working directory'
        if (getcwd(keys_path_buffer, sizeof(keys_path_buffer)) == NULL)
        {
            perror("getcwd() error");

            return 0;
        }

        keys_path = keys_path_buffer;
    }
    else
    {
        keys_path = g_keygen_settings.keys_path;
    }

    // 2. set 'algorithm'
    u8 algorithm;
    if(strlen(g_keygen_settings.algorithm) != 0)
    {
        if(FAIL(return_code = dns_encryption_algorithm_from_case_name(g_keygen_settings.algorithm, &algorithm)))
        {
            // if the algorithm hasn't been set and the origin is "help", then print the help

            u8 algorithm_value_source = config_value_get_source(KEYGEN_SECTION_NAME, "algorithm");

            if(algorithm_value_source <= CONFIG_SOURCE_DEFAULT) // if the value of the algorithm hasn't been set
            {
                if(dnsname_equals(g_keygen_settings.origin, (const u8 *)"\004help")) // if the origin is "help"
                {
                    return_code = YADIFA_MODULE_HELP_REQUESTED; // help expected?
                }
                else
                {
                    return_code = COMMAND_ARGUMENT_EXPECTED;
                }
            }
            else // the algorithm parameter is needed
            {
                // return the error code
            }

            return return_code;
        }

        if(g_keygen_settings.nsec3_capable)
        {
            // if an algorithm that doesn't support NSEC3 is used, convert it (or complain and stop?) or give up if it's not possible

            if(algorithm < DNSKEY_ALGORITHM_RSASHA256_NSEC3)
            {
                switch(algorithm)
                {
                    case DNSKEY_ALGORITHM_DSASHA1:
                        algorithm = DNSKEY_ALGORITHM_DSASHA1_NSEC3;
                        break;
                    case DNSKEY_ALGORITHM_RSASHA1:
                        algorithm = DNSKEY_ALGORITHM_RSASHA1_NSEC3;
                        break;
                    default:
                        return INVALID_STATE_ERROR;
                }
            }
        }
    }
    else
    {
        if(g_keygen_settings.nsec3_capable)
        {
            algorithm = DNSKEY_ALGORITHM_RSASHA1_NSEC3;
        }
        else
        {
            algorithm = DNSKEY_ALGORITHM_RSASHA1;
        }
    }

    const dnskey_features *algorithm_features = dnskey_supported_algorithm(algorithm);

    if((algorithm_features == NULL) || (algorithm_features->names == NULL))
    {
        return INVALID_STATE_ERROR; // the algorithm isn't defined
    }

    // 3. set 'key_flags'
    u16 key_flag;
    if((strcmp(g_keygen_settings.key_flag, "KSK") == 0))
    {
        key_flag = DNSKEY_FLAGS_KSK;
    }
    else if((strcmp(g_keygen_settings.key_flag, "ZSK") == 0))
    {
        key_flag = DNSKEY_FLAGS_ZSK;
    }
    else if((strcmp(g_keygen_settings.key_flag, "") == 0))
    {
        key_flag = DNSKEY_FLAGS_ZSK;
    }
    else
    {
        /// @todo 20160512 gve -- must add correct 'error'
        osformatln(termerr, "unsupported flags '%s': expected values are 'KSK' or 'ZSK' (default)", g_keygen_settings.key_flag);
        return INVALID_ARGUMENT_ERROR;
    }

    // 4. set 'key_size'
    u16 key_size;
    if(g_keygen_settings.key_size == 0)
    {
        if(key_flag == DNSKEY_FLAGS_KSK)
        {
            key_size = algorithm_features->size_bits_ksk_default;
        }
        else
        {
            key_size = algorithm_features->size_bits_zsk_default;
        }
    }
    else
    {
        key_size = (u16)g_keygen_settings.key_size;
    }

    if((key_size < algorithm_features->size_bits_min) || (key_size > algorithm_features->size_bits_max))
    {
        if(algorithm_features->size_bits_min == algorithm_features->size_bits_max)
        {
            key_size = algorithm_features->size_bits_min; // if min == max then there is only one choice : silently ignore

            if(config_value_get_source(KEYGEN_SECTION_NAME, "key_size") > CONFIG_SOURCE_DEFAULT)
            {
                osformatln(termerr, "unsupported key size %hhu: ignoring parameter for algorithm %s.", g_keygen_settings.key_size, g_keygen_settings.algorithm);
            }
        }
        else
        {
            osformatln(termerr, "unsupported size %hhu: expected a value in the [%hhu, %hhu] range", g_keygen_settings.key_size, algorithm_features->size_bits_min, algorithm_features->size_bits_max);
            return INVALID_ARGUMENT_ERROR;
        }
    }

    assert(algorithm_features->size_multiple > 0);

    if((key_size % algorithm_features->size_multiple) != 0)
    {
        osformatln(termerr, "unsupported size %hhu: value must be a multiple of %hhu", g_keygen_settings.key_size, algorithm_features->size_multiple);
        return INVALID_ARGUMENT_ERROR;
    }

    // 5. check 'qname'

    if(!dnsname_locase_verify_charspace(g_keygen_settings.origin))
    {
        return DOMAINNAME_INVALID;
    }

    // 6. generate the key
    dnssec_key *generated_key = NULL;

    char domain_text[256];
    dnsname_to_cstr(domain_text, g_keygen_settings.origin);

    return_code = dnskey_newinstance(key_size, algorithm, key_flag, domain_text, &generated_key);

    if(FAIL(return_code))
    {
        osformatln(termerr, "failed to generate the key: %r", return_code);
        return return_code;
    }

    // 7. adjust the dates if needed

    dnskey_set_created_epoch(generated_key, time(NULL));

    if(g_keygen_settings.publication_date_text != NULL)
    {
        s64 epochus = timeus_from_smarttime(g_keygen_settings.publication_date_text);
        if(epochus >= 0)
        {
            dnskey_set_publish_epoch(generated_key, epochus / ONE_SECOND_US);
        }
    }

    if(g_keygen_settings.activation_date_text != NULL)
    {
        s64 epochus = timeus_from_smarttime(g_keygen_settings.activation_date_text);
        if(epochus >= 0)
        {
            dnskey_set_activate_epoch(generated_key, epochus / ONE_SECOND_US);
        }
    }

    if(g_keygen_settings.inactivation_date_text != NULL)
    {
        s64 epochus = timeus_from_smarttime(g_keygen_settings.inactivation_date_text);
        if(epochus >= 0)
        {
            dnskey_set_inactive_epoch(generated_key, epochus / ONE_SECOND_US);
        }
    }

    if(g_keygen_settings.deletion_date_text != NULL)
    {
        s64 epochus = timeus_from_smarttime(g_keygen_settings.deletion_date_text);
        if(epochus >= 0)
        {
            dnskey_set_delete_epoch(generated_key, epochus / ONE_SECOND_US);
        }
    }

    // 8. write the files *.key and *.private
    if(ISOK(return_code))
    {
        if(FAIL(return_code = dnskey_store_keypair_to_dir(generated_key, keys_path)))
        {

            formatln("could not write the files to '%s': %r", keys_path, return_code);

            return return_code;
        }
    }

    if(generated_key != NULL)
    {
        // 9. print both key file names on stdout
        char filename[PATH_MAX];
        snformat(filename, sizeof(filename), "K%{dnsname}+%03d+%05d",
                  generated_key->owner_name,
                  generated_key->algorithm,
                  dnskey_get_tag(generated_key));
        formatln("%s", filename);
    }

    return SUCCESS;
}

// ********************************************************************************
// ***** module virtual table
// ********************************************************************************

const module_s keygen_program =
{
    keygen_init,                       // module initializer
    keygen_finalize,                   // module finalizer
    keygen_config_register,            // module register
    keygen_setup,                      // module setup
    keygen_run,                        // module run
    module_default_cmdline_help_print,

    keygen_cmdline,                    // module command line struct
    NULL,                           // module command line callback
    NULL,                           // module filter arguments

    "key generator",                // module public name
    "ykeygen",                      // module command (name as executable match)
    "keygen",                       // module parameter (name as first parameter aka command name)
    /*keygen_cmdline_help*/ NULL,               // module text to be printed upon help request
    ".yadifa.rc"                    // module rc file (ie: ".module.rc"
};
