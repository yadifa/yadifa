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
#include <dnscore/format.h>
#include <dnscore/config_settings.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/cmdline.h>

#include <dnscore/timems.h>
#include <dnscore/mutex.h>
#include <dnscore/thread_pool.h>

#include <dnscore/dnskey_rsa.h>
#include <dnscore/dnskey_dsa.h>
#include <dnscore/dnskey_ecdsa.h>

static smp_int workers_active;
static smp_int smp_tries;

struct main_args
{
    u8* domain;
    u32 size;
    u32 force_tag;
    bool ksk;
    u8 algorithm;
    u8 workers;
};

typedef struct main_args main_args;

#define CONFIG_TYPE main_args

CONFIG_BEGIN(main_args_desc)
CONFIG_FQDN(domain, ".")
CONFIG_U32_RANGE(size, "1024", 512, 4096)
CONFIG_U32_RANGE(force_tag, "65536", 0, 65536)
CONFIG_BOOL(ksk, "0")
CONFIG_DNSKEY_ALGORITHM(algorithm, "8")
CONFIG_U8(workers, "1")
CONFIG_END(main_args_desc)
#undef CONFIG_TYPE

CMDLINE_BEGIN(keygen_test_cmdline)
CMDLINE_SECTION("main")
CMDLINE_OPT("domain",'d',"domain")
CMDLINE_HELP("fqdn", "the domain name")
CMDLINE_OPT("size",'b',"size")
CMDLINE_HELP("bits", "the size of the key in bits, where appliable")
CMDLINE_OPT("force-tag",'T',"force_tag")
CMDLINE_HELP("tag", "(INSANE) the program will try to generate a key with the specific tag.")
CMDLINE_BOOL("ksk", 0, "ksk")
CMDLINE_HELP("", "generate a key-signing key")
CMDLINE_OPT("algorithm",'a',"algorithm")
CMDLINE_HELP("id", "the algorithm of the key")
CMDLINE_OPT("workers", 'w' ,"workers")
CMDLINE_HELP("thread-count", "when insanely looking for a tag, spawn that amount of workers")
CMDLINE_VERSION_HELP(keygen_test_cmdline)
CMDLINE_END(keygen_test_cmdline)

static main_args g_config = {NULL, 0, 0, FALSE, 0, 0};

static void
help(const char *name)
{
    formatln("%s domain [-a algorithm] [-b size] [--KSK] [-T forcedtag] [-w workers]\n\n", name);

    cmdline_print_help(keygen_test_cmdline, 4, 0, " :  ", 0, termout);
}

static ya_result
main_config(int argc, char *argv[])
{
    config_error_s cfg_error;
    ya_result ret;

    config_init();

    int priority = 0;

    config_register_struct("main", main_args_desc, &g_config, priority++);

    config_register_cmdline(priority++); // without this line, the help will not work

    struct config_source_s sources[1];

    if(FAIL(ret = config_source_set_commandline(&sources[0], keygen_test_cmdline, argc, argv)))
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

    if(cmdline_help_get())
    {
        help(argv[0]);
        return SUCCESS;
    }

    switch(g_config.algorithm)
    {
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
            g_config.size = 256;
            break;
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            g_config.size = 384;
            break;
        case DNSKEY_ALGORITHM_ED25519:
            g_config.size = 256;
            break;
        case DNSKEY_ALGORITHM_ED448:
            g_config.size = 456;
            break;
        default:
            break;
    }

    formatln("generating %skey for domain %{dnsname}, algorithm %s, size %i",
             g_config.ksk?"key-signing-":"",
             g_config.domain,
             dns_encryption_algorithm_get_name(g_config.algorithm),
             g_config.size);

    return ret;
}

static ya_result
dnskey_generate()
{
    ya_result ret = SUCCESS;
    s64 start = timeus();
    s64 lastreport = start;
    u64 tries = 1;
    char origin[256];
    dnsname_to_cstr(origin, g_config.domain);

    while(smp_int_get(&workers_active) == 1)
    {
        dnssec_key *key = NULL;
        if(ISOK(ret = dnskey_newinstance(
            g_config.size,
            g_config.algorithm,
            g_config.ksk?(DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY):DNSKEY_FLAG_ZONEKEY,
            origin, &key)))
        {
            if(g_config.force_tag < 65536)
            {
                u16 tag = dnskey_get_tag(key);
                if(tag != (u16)g_config.force_tag)
                {
                    dnskey_release(key);

                    ++tries;

                    s64 now = timeus();
                    if(now - lastreport > ONE_SECOND_US)
                    {
                        formatln("%llu tries, %lli seconds elapsed", tries, (now - start) / ONE_SECOND_US);
                        flushout();
                        lastreport = now;
                    }

                    continue;
                }
            }

            //s64 now = timeus();

            if(smp_int_setifequal(&workers_active, 1, 0))
            {
                //formatln("key generated after %llu trie(s) and %lli seconds", tries, (now - start) / ONE_SECOND_US);

                if(FAIL(ret = dnskey_store_keypair_to_dir(key, "./")))
                {
                    formatln("FAILED TO SAVE KEYPAIR TO LOCAL DIRECTORY: %r", ret);
#if 0
                    // this would be a very bad idea for anything but a test

                    if(FAIL(ret = dnskey_store_keypair_to_dir(key, "/tmp")))
                    {
                        formatln("FAILED TO SAVE KEYPAIR TO LOCAL DIRECTORY: %r", ret);

                    }
#endif
                }
            }
            else
            {
                //formatln("key generated after %llu trie(s) and %lli seconds (duplicate)", tries, (now - start) / ONE_SECOND_US);
            }

            dnskey_release(key);

            break;
        }
        else
        {
            formatln("failed to generate the key: %r", ret);
            break;
        }
    }

    smp_int_add(&smp_tries, tries);

    return ret;
}

static void*
dnskey_generate_thread(void* arg)
{
    (void)arg;
    dnskey_generate();
    return NULL;
}

int
main(int argc, char *argv[])
{
    /* initializes the core library */
    dnscore_init();

    ya_result ret = main_config(argc, argv);

    if(FAIL(ret))
    {
        return EXIT_FAILURE;
    }

    smp_int_init_set(&workers_active, 1);

    s64 start = timeus();

    if(g_config.workers == 1)
    {
        dnskey_generate();
    }
    else
    {
        struct thread_pool_s *tp = thread_pool_init_ex(g_config.workers, g_config.workers, "dnskey geneartors");
        if(tp != NULL)
        {
            for(int i = 0; i < g_config.workers; ++i)
            {
                thread_pool_enqueue_call(tp, dnskey_generate_thread, NULL, NULL, "dnskey_generate");
            }
            thread_pool_stop_all(); // including tp
            thread_pool_destroy(tp);
            tp = NULL;
        }
    }

    s64 now = timeus();

    formatln("key generated after a total of %llu trie(s) and %lli seconds", smp_int_get(&smp_tries), (now - start) / ONE_SECOND_US);

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
