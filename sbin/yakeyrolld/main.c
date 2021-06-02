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
 *
 * Query for all DNSKEYs
 *
 * Generate KSK (Publish: none, Active: now, Inactive: never, Delete: never) + ZSK (Publish none: Active +60s, Inactive +180s, Delete: never)
 * Remove all DNSKEYs and add KSK and ZSK
 *
 * loop:
 *   Generate ZSK (Publish none: Active +60s, Inactive +180s, Delete: never)
 *   Wait for update time + 60 seconds.
 *   Remove previous ZSK and add new ZSK
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/dnskey.h>
#include <dnscore/format.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/packet_writer.h>
#include <dnscore/signals.h>

#include <dnscore/timems.h>
#include <dnscore/thread_pool.h>

#include <dnscore/dnskey-signature.h>
#include <dnscore/packet_reader.h>
#include <dnscore/dnskey-keyring.h>
#include <dnscore/parsing.h>
#include <dnscore/zone_reader_text.h>
#include <dnscore/server-setup.h>
#include <dnscore/logger_channel_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/pid.h>
#include <dnscore/dnscore-release-date.h>

#include <sys/stat.h>

#include "keyroll.h"
#include "keyroll-config.h"

#include "config-dnssec-policy.h"
#include "dnssec-policy.h"
#include "buildinfo.h"

#define PURGE_QUESTION "YES"

extern logger_handle *g_dnssec_logger;
extern logger_handle *g_keyroll_logger;

#define MODULE_MSG_HANDLE g_keyroll_logger

#define FIRST_JANUARY_2019_00_00_00 1546300800
#define FIRST_JANUARY_2021_00_00_00 1609459200

#define SERVER_FAILURE_RETRY_DELAY 30
#define CONSECUTIVE_ERRORS_BEFORE_RESTART 60

#define WAIT_MARGIN (ONE_SECOND_US * 10)

#define PROGRAM_NAME "yakeyrolld"
#define KEYROLL_CONFIG_SECTION "yakeyrolld"
#define RELEASEDATE YADIFA_DNSCORE_RELEASE_DATE

// mount -t tmpfs -o size=16384 tmpfs /registry/yadifa/var/log/yakeyrolld

static random_ctx rnd;

enum PROGRAM_MODE
{
    NONE = 0,
    GENERATE,
    PLAY,
    PLAYLOOP,
    PRINT,
    PRINT_JSON,
    TEST
};

static value_name_table program_mode_enum_table[]=
{
    {NONE, "none"},
    {PLAY, "play"},
    {PLAYLOOP, "playloop"},
    {GENERATE, "generate"},
    {PRINT, "print"},
    {PRINT_JSON, "print-json"},
    {TEST, "test"},
    {0, NULL}
};

struct main_args
{
    ptr_vector domains;
    ptr_vector fqdns;
    char *configuration_file_path;
    char *log_path;
    char *keys_path;
    char *plan_path;
    char *pid_path;
    char *pid_file;
    char *generate_from;
    char *generate_until;
    char *policy_name;
    host_address *server;

    uid_t uid;
    gid_t gid;
    u32 timeout;
    u32 ttl;

    u32 update_apply_verify_retries;        // if an update wasn't applied successfully, retry CHECKING this amount of times
    u32 update_apply_verify_retries_delay;  // time between the above retries

    u32 match_verify_retries;        // if there is not match, retry checking this amount of times
    u32 match_verify_retries_delay;  // time between the above retries

    int program_mode;
    bool reset;
    bool purge;
    bool dryrun;
    bool wait_for_yadifad;
    bool daemonise;
    bool print_plan;
    bool user_confirmation;
#if DEBUG
    bool with_secret_keys;
#endif
};

typedef struct main_args main_args;

struct testing_args
{
    s64 timeus_offset;
};

typedef struct testing_args testing_args;

static ya_result
directory_writable(const char *path)
{
    if(path == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    struct stat ds;

    if(stat(path, &ds) < 0)
    {
        int err = errno;
        log_err("error: '%s': %s", path, strerror(err));
        formatln("error: '%s': %s", path, strerror(err));

        return MAKE_ERRNO_ERROR(err);
    }

    if((ds.st_mode & S_IFMT) != S_IFDIR)
    {
        log_err("error: '%s' is not a directory", path);
        formatln("error: '%s' is not a directory", path);

        return INVALID_PATH;
    }

    char tempfile[PATH_MAX];

    ya_result ret = snformat(tempfile, sizeof(tempfile), "%s/ydf.XXXXXX", path);

    if(FAIL(ret))
    {
        log_err("error: '%s' temp file name creation failed: %r", path, ret);
        formatln("error: '%s' temp file name creation failed: %r", path, ret);
        return ret;
    }

    if(ret >= PATH_MAX)
    {
        log_err("error: '%s' path is too big", path);
        formatln("error: '%s' path is too big", path);
        return INVALID_PATH;
    }

    int tempfd;
    if((tempfd = mkstemp_ex(tempfile)) < 0)
    {
        int ret = ERRNO_ERROR;
#ifndef WIN32
        formatln("error: '%s' is not writable as (%d:%d): %r", path, getuid(), getgid(), ret);
#else
        log_err("error: '%s' is not writable: %r", fullpath, ret);
        formatln("error: '%s' is not writable: %r", fullpath, ret);
#endif
        return ret;
    }

    unlink(tempfile);
    close_ex(tempfd);

    return SUCCESS;
}


#ifndef PREFIX
#define PREFIX "/usr/local"
#endif

#ifndef LOCALSTATEDIR
#define LOCALSTATEDIR PREFIX "/var"
#endif

#ifndef SYSCONFDIR
#define SYSCONFDIR PREFIX "/etc"
#endif

#define CONFIGURATION_FILE_PATH_DEFAULT SYSCONFDIR "/yakeyrolld.conf"

#define CONFIG_TYPE main_args

CONFIG_BEGIN(main_args_desc)
        CONFIG_STRING_ARRAY(domains,NULL, 200)      // I'm using a thread-pool for this, it cannot go beyond THREAD_POOL_SIZE_LIMIT_MAX threads.
        CONFIG_PATH(log_path, LOCALSTATEDIR "/log/yakeyrolld")
        CONFIG_FILE(configuration_file_path, CONFIGURATION_FILE_PATH_DEFAULT)
        CONFIG_PATH(keys_path, LOCALSTATEDIR "/zones/keys")
        CONFIG_PATH(plan_path, LOCALSTATEDIR "/plans")
        CONFIG_PATH(pid_path, LOCALSTATEDIR "/run")
        CONFIG_STRING(pid_file, "yakeyrolld.pid")
        CONFIG_HOST_LIST(server, "127.0.0.1")
        CONFIG_U32(timeout, "3")
        CONFIG_U32(ttl, "600")

        CONFIG_U32_RANGE(update_apply_verify_retries, "60", 0, 3600)        // if an update wasn't applied successfully, retry CHECKING this amount of times
        CONFIG_U32_RANGE(update_apply_verify_retries_delay, "1", 1, 60)     // time between the above retries

        CONFIG_U32_RANGE(match_verify_retries, "60", 0, 3600)        // if there is not match, retry checking this amount of times
        CONFIG_U32_RANGE(match_verify_retries_delay, "1", 1, 60)  // time between the above retries

        CONFIG_STRING(generate_from, "now")
        CONFIG_STRING(generate_until, "+1y")
        CONFIG_STRING(policy_name, "")
        CONFIG_UID(uid, "0")
        CONFIG_GID(gid, "0")
        CONFIG_BOOL(reset, "0")
        CONFIG_BOOL(dryrun, "0")
        CONFIG_BOOL(wait_for_yadifad, "1")
        CONFIG_BOOL(daemonise, "0")
        CONFIG_BOOL(print_plan, "0")
        CONFIG_BOOL(user_confirmation, "1")
#if DEBUG
        CONFIG_BOOL(with_secret_keys, "0")
#endif
        CONFIG_ENUM(program_mode, "none", program_mode_enum_table)
        CONFIG_ALIAS(policy, policy_name)
        CONFIG_ALIAS(domain, domains)
        CONFIG_ALIAS(daemon, daemonise)
        CONFIG_ALIAS(plans_path, plan_path)
CONFIG_END(main_args_desc)
#undef CONFIG_TYPE

#define CONFIG_TYPE testing_args

CONFIG_BEGIN(testing_args_desc)
        CONFIG_U64(timeus_offset, "0")
CONFIG_END(testing_args_desc)

CMDLINE_BEGIN(keyroll_cmdline)
        CMDLINE_VERSION_HELP(keyroll_cmdline)
        CMDLINE_SECTION(KEYROLL_CONFIG_SECTION)
        CMDLINE_OPT("config", 'c', "configuration_file_path")
        CMDLINE_HELP("", "sets the configuration file to use (default: " CONFIGURATION_FILE_PATH_DEFAULT ")")
        CMDLINE_OPT("mode", 'm', "program_mode")
        CMDLINE_HELP("", "sets the program mode (generate,play,playloop,print,json)")
        CMDLINE_OPT("domain",0,"domain")
        CMDLINE_HELP("fqdn", "the domain name, overrides the domains from the configuration file")
        CMDLINE_OPT("path",'p',"keys_path")
        CMDLINE_HELP("directory", "the directory where to store the keys")
        CMDLINE_OPT("server",'s',"server")
        CMDLINE_HELP("address", "the address of the server")
        CMDLINE_OPT("ttl",'t',"ttl")
        CMDLINE_HELP("seconds", "the TTL to use for both DNSKEY and RRSIG records")
        CMDLINE_BOOL("reset",0,"reset")
        CMDLINE_HELP("", "start by removing all the keys, create a new KSK and a new ZSK")
        CMDLINE_OPT("policy",0,"policy_name")
        CMDLINE_HELP("", "name of the policy to use")
        CMDLINE_OPT("from",0,"generate_from")
        CMDLINE_HELP("time", "at what time the plan starts (e.g. : now, -1y, YYYYMMDDHHSS in UTC).")
        CMDLINE_OPT("until",0,"generate_until")
        CMDLINE_HELP("time", "the upper time limit covered by the plan (+1y, YYYYMMDDHHSS in UTC).")
        CMDLINE_BLANK()
        CMDLINE_INDENT(4)
        CMDLINE_IMSG("", "time values can be:")
        CMDLINE_BLANK()
        CMDLINE_INDENT(4)
        CMDLINE_IMSG("", "now")
        CMDLINE_IMSG("", "tomorrow")
        CMDLINE_IMSG("", "yesterday")
        CMDLINE_IMSG("", "[+-]#{years|months|weeks|days|seconds} where # is an integer")
        CMDLINE_IMSG("", "YYYY-MM-DD")
        CMDLINE_IMSG("", "YYYYMMDD")
        CMDLINE_IMSG("", "YYYYMMDDHHMMSSUUUUUU")
        CMDLINE_BLANK()
        CMDLINE_INDENT(-8)
        CMDLINE_BOOL("dryrun",0,"dryrun")
        CMDLINE_HELP("", "do not send the update to the server")
        CMDLINE_BOOL("wait", 0, "wait_for_yadifad")
        CMDLINE_HELP("", "wait for yadifad to answer before starting to work (default)")
        CMDLINE_BOOL_NOT("nowait", 0, "wait_for_yadifad")
        CMDLINE_HELP("", "do not wait for yadifad to answer before starting to work")
        CMDLINE_BOOL("daemon", 0, "daemonise")
        CMDLINE_HELP("", "daemonise the program for supported modes (default)")
        CMDLINE_BOOL_NOT("nodaemon", 0, "daemonise")
        CMDLINE_HELP("", "do not daemonise the program (needed for systemd)")
        CMDLINE_BOOL_NOT("noconfirm",'Y', "user_confirmation")
        CMDLINE_HELP("", "do not ask for confirmation before destroying steps and .key and .private files")
        CMDLINE_BOOL("print-plan", 0, "print_plan")
        CMDLINE_HELP("", "prints the complete plan after generation or after loading")
#if DEBUG
        CMDLINE_BOOL("with-secret-keys", 0, "with_secret_keys")
#endif
#if DEBUG
        CMDLINE_SECTION("testing")
        CMDLINE_OPT("timeus-offset", 0, "timeus_offset")
        CMDLINE_HELP("", "fakes the current time changing the time by that many seconds (testing)")
#endif
        CMDLINE_BLANK()
CMDLINE_END(keyroll_cmdline)

static main_args g_config; // initilised in main_config(argc, argv)
static testing_args g_testing = {0};

static void
help_print(const char *name)
{
    formatln("%s [-c configurationfile] [...]\n\n", name);
    cmdline_print_help(keyroll_cmdline, 16, 28, " :  ", 48, termout);
}

/**
 * To abstract key generation or reading from storage
 */

static ya_result
main_config_main_postprocess(struct config_section_descriptor_s *csd)
{
    (void)csd;
    // no logger if help is requested

    if(cmdline_help_get() || cmdline_version_get())
    {
        return SUCCESS;
    }

    config_set_log_base_path(g_config.log_path);
    keyroll_set_dryrun_mode(g_config.dryrun);

    logger_start();

    logger_handle_create("keyroll", &g_keyroll_logger);
    logger_handle_create("dnssec", &g_dnssec_logger);

    timeus_set_offset(g_testing.timeus_offset);

    logger_flush();

    return SUCCESS;
}

static void
yakeyrolld_print_authors()
{
    print("\n"
          "\t\tYADIFAD authors:\n"
          "\t\t---------------\n"
          "\t\t\n"
          "\t\tGery Van Emelen\n"
          "\t\tEric Diaz Fernandez\n"
          "\n"
          "\t\tContact: " PACKAGE_BUGREPORT "\n"
    );
    flushout();
}

static void
yakeyrolld_show_version(u8 level)
{
    switch(level)
    {
        case 1:
            osformatln(termout, "%s %s (%s)\n", YKEYROLL_NAME, YKEYROLL_VERSION, RELEASEDATE);
            break;
        case 2:
#if HAS_BUILD_TIMESTAMP && defined(__DATE__)
            osformatln(termout, "%s %s (released %s, compiled %s)\n\nbuild settings: %s\n", YKEYROLL_NAME, YKEYROLL_VERSION, RELEASEDATE, __DATE__, BUILD_OPTIONS);
#else
            osformatln(termout, "%s %s (released %s)\n\nbuild settings: %s\n", YKEYROLL_NAME, YKEYROLL_VERSION, RELEASEDATE, BUILD_OPTIONS);
#endif
            break;
        case 3:
        default:
#if HAS_BUILD_TIMESTAMP && defined(__DATE__)
            osformatln(termout, "%s %s (released %s, compiled %s)\n", PROGRAM_NAME, YKEYROLL_VERSION, RELEASEDATE, __DATE__);
#else
            osformatln(termout, "%s %s (released %s)\n", YKEYROLL_NAME, YKEYROLL_VERSION, RELEASEDATE);
#endif
            yakeyrolld_print_authors();
            break;
    }

    flushout();
}

/**
 * Reads the configuration.
 * It's only a command line but extending to a file is relatively trivial.
 */

static ya_result
main_config(int argc, char *argv[])
{
    config_error_s cfg_error;
    ya_result ret;

    config_init();

    memset(&g_config, 0, sizeof(g_config));

    ptr_vector_init(&g_config.domains);
    ptr_vector_init(&g_config.fqdns);

    int priority = 0;

    if(FAIL(ret = config_register_cmdline(priority++))) // without this line, the help will not work
    {
        return ret;
    }

    if(FAIL(ret = config_register_struct(KEYROLL_CONFIG_SECTION, main_args_desc, &g_config, priority++)))
    {
        return ret;
    }

    if(FAIL(ret = config_register_struct("testing", testing_args_desc, &g_testing, priority++)))
    {
        return ret;
    }

    // hook the post-processing to know what to do with the logger
    // this is a bit dirty but the vtbl is a copy of an original and the const is a safeguard here
    // I'll need to add a registration function that allows to overwrite these.

    // also registers key-roll denial key-template and key-suite (hence the + 5)

    if(FAIL(ret = config_register_dnssec_policy(NULL, priority)))
    {
        return ret;
    }

    priority += 5;

    if(FAIL(ret = config_register_logger(NULL, NULL, priority)))
    {
        return ret;
    }

    // priority += 2;

    // shouldn't this be 2 sources instead of twice one ?

    struct config_source_s sources[1];

    if(FAIL(ret = config_source_set_commandline(&sources[0], keyroll_cmdline, argc, argv)))
    {
        formatln("command line definition: %r", ret);
        return ret;
    }

    if(FAIL(ret = config_read_from_sources(sources, 1, &cfg_error)))
    {
        if(cmdline_help_get())
        {
            help_print(argv[0]);
            ret = SUCCESS;
        }
        else if(cmdline_version_get())
        {
            yakeyrolld_show_version(cmdline_version_get());
            ret = SUCCESS;
        }
        else
        {
            formatln("settings: (%s:%i) %s: %s: %r", cfg_error.file, cfg_error.line_number, cfg_error.line, cfg_error.variable_name, ret);
        }
        flushout();
        return ret;
    }

    if(cmdline_help_get())
    {
        help_print(argv[0]);
        return SUCCESS;
    }

    if(cmdline_version_get())
    {
        yakeyrolld_show_version(cmdline_version_get());
        return SUCCESS;
    }

    config_source_set_file(&sources[0], g_config.configuration_file_path, CONFIG_SOURCE_FILE);

    config_section_descriptor_s *main_desc = config_section_get_descriptor(KEYROLL_CONFIG_SECTION);
    config_section_descriptor_vtbl_s *vtbl = (config_section_descriptor_vtbl_s*)main_desc->vtbl;
    vtbl->postprocess = main_config_main_postprocess;

    if(FAIL(ret = config_read_from_sources(sources, 1, &cfg_error)))
    {
        formatln("settings: (%s:%i) %s %s: %r", cfg_error.file, cfg_error.line_number, cfg_error.line, cfg_error.variable_name, ret);
        flushout();
        return ret;
    }

    if(g_config.server->port == 0)
    {
        g_config.server->port = NU16(DNS_DEFAULT_PORT);
    }

    for(int i = 0; i <= ptr_vector_last_index(&g_config.domains); ++i)
    {
        const char *name = (const char*)ptr_vector_get(&g_config.domains, i);
        u8 *fqdn = dnsname_zdup_from_name(name);
        if(fqdn == NULL)
        {
            formatln("cannot parse domain name: %s", name);
            ret = PARSESTRING_ERROR;
            return ret;
        }
        ptr_vector_append(&g_config.fqdns, fqdn);
    }

    // no stdout channel in daemon mode

    if(!((g_config.program_mode == PLAYLOOP) && g_config.daemonise))
    {
        if(!config_logger_isconfigured())
        {
            output_stream stdout_os;
            logger_channel *stdout_channel;

            fd_output_stream_attach(&stdout_os, dup_ex(1));
            buffer_output_stream_init(&stdout_os, &stdout_os, 65536);
            stdout_channel = logger_channel_alloc();
            if(stdout_channel == NULL)
            {
                return INVALID_STATE_ERROR;
            }
            logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);

            logger_channel_register("stdout", stdout_channel);

#if !DEBUG
            logger_handle_add_channel("keyroll", MSG_PROD_MASK, "stdout");
#else
            logger_handle_add_channel("keyroll", MSG_ALL_MASK, "stdout");
            logger_handle_add_channel("dnssec", MSG_ALL_MASK, "stdout");
#endif
        }
    }

    if(FAIL(ret = directory_writable(g_config.log_path)))
    {
        return ret;
    }

    return ret;
}

static ya_result
get_user_confirmation()
{
    ya_result ret = SUCCESS;

    log_notice("Asking user to confirm by typing '" PURGE_QUESTION "'");
    print("Please confirm by typing '" PURGE_QUESTION "' (without the '') followed by the ENTER key: ");
    flushout();

    char *line_buffer = NULL;
    size_t line_buffer_size = 0;
    ssize_t n = getline(&line_buffer, &line_buffer_size, stdin);

    if(n < 0)
    {
        ret = ERRNO_ERROR;
        formatln("getline failed: %r", ret);
        flushout();
        free(line_buffer);
        return ret;
    }

    while((n > 0) && isspace(line_buffer[--n]))
    {
        line_buffer[n] = '\0';
    }

    if(strcmp(line_buffer, PURGE_QUESTION) != 0)
    {
        log_err("expected: '" PURGE_QUESTION "', got '%s': stopping", line_buffer);
        formatln("expected: '" PURGE_QUESTION "', got '%s': stopping", line_buffer);
        flushout();
        free(line_buffer);
        return PARSEWORD_NOMATCH_ERROR;
    }
    else
    {
        log_notice("Got user confirmation");
    }

    return ret;
}

static ya_result
program_mode_generate(const u8 *domain)
{
    ya_result ret;

    rnd = random_init(0);

    if(dirent_get_file_type(g_config.plan_path, ".") == DT_UNKNOWN)
    {
        formatln("%{dnsname}: having trouble with directory '%s'", domain, g_config.plan_path);
        return INVALID_PATH;
    }

    keyroll_t keyroll;

    if(FAIL(ret = keyroll_init(&keyroll, domain, g_config.plan_path, g_config.keys_path, g_config.server, TRUE)))
    {
        return ret;
    }

    if(FAIL(ret = keyroll_update_apply_verify_retries_set(&keyroll, g_config.update_apply_verify_retries, g_config.update_apply_verify_retries_delay)))
    {
        log_err("%{dnsname}: update apply retry combination out of acceptable range", domain);
        formatln("%{dnsname}: update apply retry combination out of acceptable range", domain);
        keyroll_finalize(&keyroll);
        return ret;
    }

    if(FAIL(ret = keyroll_match_verify_retries_set(&keyroll, g_config.match_verify_retries, g_config.match_verify_retries_delay)))
    {
        log_err("%{dnsname}: match retry combination out of acceptable range", domain);
        formatln("%{dnsname}: match retry combination out of acceptable range", domain);
        keyroll_finalize(&keyroll);
        return ret;
    }

    // at this point:
    // _ we know the present state on the server
    // _ we know the plan folder for this domain exists

    if(g_config.reset)
    {
        // delete the content of the plan folder

        if(!g_config.dryrun)
        {
            log_info("%{dnsname}: deleting the plan and private keys for domain", keyroll.domain);
            formatln("%{dnsname}: deleting the plan and private keys for domain", keyroll.domain);
            keyroll_plan_purge(&keyroll);
        }
        else
        {
            log_info("%{dnsname}: dryrun: not really deleting the plan and private keys for domain", keyroll.domain);
            formatln("%{dnsname}: dryrun: not really deleting the plan and private keys for domain", keyroll.domain);
        }
    }
    else
    {
        if(FAIL(ret = keyroll_plan_load(&keyroll)))
        {
            if(ret != MAKE_ERRNO_ERROR(ENOENT))
            {
                log_err("%{dnsname}: plan loading failed: %r", keyroll.domain, ret);
                formatln("%{dnsname}: plan loading failed: %r", keyroll.domain, ret);

                keyroll_finalize(&keyroll);
                return ret;
            }

            log_info("%{dnsname}: there are no plans for the domain in the directory '%s'", keyroll.domain, g_config.plan_path);
            formatln("%{dnsname}: there are no plans for the domain in the directory '%s'", keyroll.domain, g_config.plan_path);
        }
    }

    s64 generate_from = timeus_from_smarttime(g_config.generate_from);

    if(generate_from < 0)
    {
        log_err("%{dnsname}: cannot parse '%s'", domain, g_config.generate_from);
        formatln("%{dnsname}: cannot parse '%s'", domain, g_config.generate_from);
        keyroll_finalize(&keyroll);
        return ret;
    }

    generate_from /= ONE_SECOND_US;
    generate_from *= ONE_SECOND_US;

    s64 generate_until = timeus_from_smarttime_ex(g_config.generate_until, generate_from);

    if(generate_until < 0)
    {
        log_err("%{dnsname}: cannot parse '%s'", domain, g_config.generate_until);
        formatln("%{dnsname}: cannot parse '%s'", domain, g_config.generate_until);
        return ret;
    }

    log_info("%{dnsname}: covering %llU to %llU", domain, generate_from, generate_until);
    formatln("%{dnsname}: covering %llU to %llU", domain, generate_from, generate_until);

    if(FAIL(ret = keyroll_plan_with_policy(&keyroll, generate_from, generate_until, g_config.policy_name)))
    {
        log_err("%{dnsname}: policy-based planning failed: %r", domain, ret);
        formatln("%{dnsname}: policy-based planning failed: %r", domain, ret);
        return ret;
    }

    if(g_config.print_plan)
    {
        if(FAIL(ret = keyroll_print(&keyroll, termout)))
        {
            log_err("%{dnsname}: the plan is not perfect", domain);
            formatln("%{dnsname}: the plan is not perfect", domain);
        }
    }

    if(g_config.dryrun)
    {
        log_info("%{dnsname}: dryrun: not storing the plan", domain);
        formatln("%{dnsname}: dryrun: not storing the plan", domain);
        ret = SUCCESS;
    }
    else
    {
        if(ISOK(ret = keyroll_store(&keyroll)))
        {
            log_info("%{dnsname}: plan stored", domain);
            formatln("%{dnsname}: plan stored", domain);
        }
        else
        {
            log_err("%{dnsname}: failed to store the plan: %r", domain, ret);
            formatln("%{dnsname}: failed to store the plan: %r", domain, ret);
        }
    }

    keyroll_finalize(&keyroll);

    return ret;
}

static ya_result
program_mode_generate_all()
{
    pid_t pid;
    ya_result ret;
    char pid_file_path_buffer[PATH_MAX];
    char *pid_file_path = &pid_file_path_buffer[0];

    snformat(pid_file_path_buffer, sizeof(pid_file_path_buffer), "%s/%s", g_config.pid_path, g_config.pid_file);

    if(FAIL(ret = pid_check_running_program(pid_file_path, &pid)))
    {
        log_err("already running with pid: %lu (%s)", pid, pid_file_path);
        return ret;
    }

    if(FAIL(ret = directory_writable(g_config.plan_path)))
    {
        return ret;
    }

    if(ISOK(ret = server_setup_env(&pid, &pid_file_path, g_config.uid, g_config.gid, SETUP_CREATE_PID_FILE|SETUP_ID_CHANGE|SETUP_CORE_LIMITS)))
    {
        if(g_config.reset && g_config.user_confirmation)
        {
            println("WARNING: A full data reset has been required for the following domains:");
            // delete the content of the plan folder
            for(int i = 0; i <= ptr_vector_last_index(&g_config.fqdns); ++i)
            {
                const u8 *domain = (const u8*)ptr_vector_get(&g_config.fqdns, i);
                formatln("    %{dnsname}", domain);
            }
            println("All currently stored steps and private keys for the above domains will be erased.\nThis operation cannot be undone.");
            if(FAIL(ret = get_user_confirmation()))
            {
                return ret;
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(&g_config.fqdns); ++i)
        {
            const u8 *domain = (const u8*)ptr_vector_get(&g_config.fqdns, i);
            log_info("zone generate: %{dnsname}", domain);
            if(FAIL(ret = program_mode_generate(domain)))
            {
                log_err("zone generate: %{dnsname} failed: %r", domain, ret);
                break;
            }
        }

        unlink(pid_file_path);
    }

    return ret;
}

static void
signal_int(u8 signum)
{
    (void)signum;

    if(!dnscore_shuttingdown())
    {
        dnscore_shutdown();
    }

    signal_handler_stop();
}

static void
signal_hup(u8 signum)
{
    (void)signum;

    logger_reopen();
}

static ya_result
program_mode_play(const u8 *domain, bool does_loop)
{
    ya_result ret;
    int consecutive_errors = 0;

    rnd = random_init(0);

    if(dirent_get_file_type(g_config.plan_path, ".") == DT_UNKNOWN)
    {
        log_info("play: %{dnsname}: having trouble with directory '%s'", domain, g_config.plan_path);
        return INVALID_PATH;
    }

    keyroll_t keyroll;

    // start from an empty state
    if(FAIL(ret = keyroll_init(&keyroll, domain, g_config.plan_path, g_config.keys_path, g_config.server, FALSE)))
    {
        return ret;
    }

    // at this point:
    // _ we know the present state on the server
    // _ we know the plan folder for this domain exists

    if(does_loop)
    {
        log_info("play: %{dnsname}: loading plan", domain);
        logger_flush();
    }

    if(FAIL(ret = keyroll_plan_load(&keyroll)))
    {
        if(ret != MAKE_ERRNO_ERROR(ENOENT))
        {
            log_info("play: %{dnsname}: plan loading failed: %r", domain, ret);
        }
        else
        {
            log_info("play: %{dnsname}: there are no plans on storage (%s)", domain, g_config.plan_path);
        }

        logger_flush();

        keyroll_finalize(&keyroll);

        return ret;
    }

    s64 step_time;

    do
    {
        step_time = timeus_with_offset();

        log_info("play: %{dnsname}: now is %llU (%lli)", domain, step_time, step_time);

        keyroll_step_t *current_step = keyroll_get_current_step_at(&keyroll, step_time);

        if(current_step == NULL)
        {
            log_info("play: %{dnsname}: there are no steps registered for this time", domain);

            keyroll_finalize(&keyroll);

            return INVALID_STATE_ERROR;
        }

        log_info("play: %{dnsname}: the current step happened at %llU (%lli)", domain, current_step->epochus, current_step->epochus);

        keyroll_step_t *next_step = keyroll_get_next_step_from(&keyroll, step_time + 1);

        s64 next_step_time;

        if(next_step != NULL)
        {
            next_step_time = next_step->epochus;
            log_info("play: %{dnsname}: the step that will follow will happen at %llU (%lli)", domain, next_step_time, next_step_time);
        }
        else
        {
            next_step_time = ONE_SECOND_US * MAX_U32;
        }

        /*
        // check the expected set with the server
        // do a query for all DNSKEY + RRSIG and compare with the step

        ptr_vector current_dnskey_rrsig_rr;
        ptr_vector_init_ex(&current_dnskey_rrsig_rr, 32);
        */
        const keyroll_step_t *matched_step = NULL;

        ret = keyroll_get_state_find_match_and_play(&keyroll, step_time, current_step, &matched_step);

        if(ISOK(ret))
        {
            log_info("play: %{dnsname}: first loop ended (%u)", domain, ret);
            break;
        }

        if(ret != STOPPED_BY_APPLICATION_SHUTDOWN)
        {
            log_info("play: %{dnsname}: keyroll_get_state_find_match returned %r (retrying in " TOSTRING(SERVER_FAILURE_RETRY_DELAY) " seconds)", domain, ret);

            s64 now = timeus();

            if(now + ONE_SECOND_US * SERVER_FAILURE_RETRY_DELAY < next_step_time)
            {
                for(int i = 0; (i < SERVER_FAILURE_RETRY_DELAY) && !dnscore_shuttingdown(); ++i)
                {
                    sleep(1);
                }
            }
            else
            {
                // we have gone through a step, current computations are invalid : restart the roll for this domain
                ret = KEYROLL_MUST_REINITIALIZE;

                keyroll_finalize(&keyroll);

                return ret;
            }
        }
    }
    while(g_config.wait_for_yadifad && !dnscore_shuttingdown());

    if(FAIL(ret))
    {
        log_notice("play: %{dnsname}: keyroll_get_state_find_match returned %r", domain, ret);

        keyroll_finalize(&keyroll);

        return ret;
    }

    keyroll_step_t *next_step = keyroll_get_next_step_from(&keyroll, step_time);

    if(next_step != NULL)
    {
        log_info("play: %{dnsname}: the next step happens at %llU (%lli)", domain, next_step->epochus, next_step->epochus);

        // find the interval for now

        s64 last_warning_us = 0;

        // wait until the next event

        while(!dnscore_shuttingdown())
        {
            log_info("play: %{dnsname}: waiting until %llU (%lli)", domain, next_step->epochus, next_step->epochus);

            do
            {
                s64 now = timeus_with_offset();

                if(now - WAIT_MARGIN >= next_step->epochus)
                {
                    break;
                }
                else
                {
                    usleep(MAX(MIN(next_step->epochus - (now - WAIT_MARGIN), WAIT_MARGIN), 1000));
                }
            }
            while(!dnscore_shuttingdown());

            if(dnscore_shuttingdown())
            {
                log_info("play: %{dnsname}: shutting down", domain);
                logger_flush();
                break;
            }

            step_time = timeus_with_offset();

            keyroll_step_t *current_step = keyroll_get_current_step_at(&keyroll, step_time);

            if(current_step == NULL)
            {
                log_err("play: %{dnsname}: there are no steps registered for this time: shutting down", domain);
                break;
            }

            ret = keyroll_get_state_find_match_and_play(&keyroll, step_time, current_step, NULL);

            log_warn("play: %{dnsname}: match and play returned: %r (%x)", domain, ret, ret);

            if(ISOK(ret))
            {
                consecutive_errors = 0;
            }
            else
            {
                // test for error conditions warranting a retry

                switch(ret)
                {
                    case MAKE_ERRNO_ERROR(ETIMEDOUT):
                    case MAKE_ERRNO_ERROR(EADDRNOTAVAIL):
                    case MAKE_ERRNO_ERROR(EAGAIN):
                    case DNS_ERROR_CODE(RCODE_SERVFAIL):
                    case DNS_ERROR_CODE(RCODE_REFUSED):
                    case UNABLE_TO_COMPLETE_FULL_READ:
                    {
                        ++consecutive_errors;

                        if(consecutive_errors < CONSECUTIVE_ERRORS_BEFORE_RESTART)
                        {
                            step_time = timeus_with_offset();
                            if(step_time - last_warning_us >= ONE_SECOND_US * 60)
                            {
                                log_warn("play: %{dnsname}: step play failure: %r: trying again (this message will only be printed every minute)", domain, ret);
                                last_warning_us = step_time;
                            }

                            sleep(1);
                            continue;
                        }
                        else
                        {
                            log_warn("play: %{dnsname}: step play failure: %r: restarting", domain, ret);
                            ret = KEYROLL_MUST_REINITIALIZE;
                            break;
                        }
                    }
                    default:
                    {
                        // unrecoverable error
                        log_err("play: %{dnsname}: step play failure: %r (%x): shutting down.  Please restart after fixing the issue.", domain, ret, ret);
                        break;
                    }
                }
                break;
            }

            if(!does_loop)
            {
                break;
            }

            next_step = keyroll_get_next_step_from(&keyroll, next_step->epochus + 1);
        }
    }
    else
    {
        log_info("play: %{dnsname}: there is no next step recorded after %llU", domain, step_time);
    }

    keyroll_finalize(&keyroll);

    return ret;
}

struct program_mode_play_thread_args
{
    const u8 *fqdn;
    bool does_loop;
};

typedef struct program_mode_play_thread_args program_mode_play_thread_args;

static void*
program_mode_play_thread(void *args_)
{
    program_mode_play_thread_args *args = (program_mode_play_thread_args*)args_;
    while(!dnscore_shuttingdown())
    {
        ya_result  ret = program_mode_play(args->fqdn, args->does_loop);

        if(ISOK(ret))
        {
            log_info("%{dnsname}: key roll stopped", args->fqdn);
            break;
        }
        else
        {
            if(ret == KEYROLL_MUST_REINITIALIZE)
            {
                log_warn("%{dnsname}: trying again from the start", args->fqdn);
            }
            else if(ret == STOPPED_BY_APPLICATION_SHUTDOWN)
            {
                log_warn("%{dnsname}: keyroll is shutting down", args->fqdn);
                break;
            }
            else
            {
                log_err("%{dnsname}: shutting down (%r)", args->fqdn, ret);
                logger_flush();
                dnscore_shutdown();
                break;
            }
        }
    }
    return NULL;
}

static ya_result
program_mode_play_all(bool does_loop, bool daemonise)
{
    ya_result ret;

    pid_t pid;
    char pid_file_path_buffer[PATH_MAX];
    char *pid_file_path = &pid_file_path_buffer[0];
    snformat(pid_file_path_buffer, sizeof(pid_file_path_buffer), "%s/%s", g_config.pid_path, g_config.pid_file);

    if(FAIL(ret = pid_check_running_program(pid_file_path, &pid)))
    {
        log_err("already running with pid: %lu (%s)", pid, pid_file_path);
        return ret;
    }

    if(FAIL(ret = directory_writable(g_config.keys_path)))
    {
        return ret;
    }

    if(ISOK(ret = server_setup_env(&pid, &pid_file_path, g_config.uid, g_config.gid, SETUP_CREATE_PID_FILE|SETUP_ID_CHANGE|SETUP_CORE_LIMITS)))
    {
        if(daemonise)
        {
            if(!does_loop)
            {
                log_warn("daemonise requires to enable loops");
                does_loop = true;
            }

            signal_handler_finalize();

            server_setup_daemon_go();

            u32 setup_flags = SETUP_CORE_LIMITS | SETUP_ID_CHANGE | SETUP_CREATE_PID_FILE;

            if(FAIL(ret = server_setup_env(NULL, &pid_file_path, g_config.uid, g_config.gid, setup_flags)))
            {
                log_err("server setup failed: %r", ret);
                return EXIT_FAILURE;
            }

            if(FAIL(ret = signal_handler_init()))
            {
                log_err("failed to setup the signal handler: %r", ret);

                osformatln(termerr, "error: failed to setup the signal handler: %r", ret);
                flusherr();

                logger_flush();

                return ret;
            }
        }
    }
    else
    {
        log_err("server setup failed: %r", ret);
        return ret;
    }

    struct thread_pool_s *tp = thread_pool_init(ptr_vector_size(&g_config.fqdns), ptr_vector_size(&g_config.fqdns) * 2);

    if(tp != NULL)
    {
        program_mode_play_thread_args *args;
        MALLOC_OBJECT_ARRAY_OR_DIE(args, program_mode_play_thread_args, ptr_vector_size(&g_config.fqdns), GENERIC_TAG);

        thread_pool_task_counter counter;
        thread_pool_counter_init(&counter, 0);

        for(int i = 0; i <= ptr_vector_last_index(&g_config.fqdns); ++i)
        {
            char *domain = (char*)ptr_vector_get(&g_config.domains, i);
            u8 *fqdn = (u8*)ptr_vector_get(&g_config.fqdns, i);
            log_info("zone play: %{dnsname}", fqdn);

            args[i].fqdn = fqdn; // VS false positive (nonsense)
            args[i].does_loop = does_loop;

            thread_pool_enqueue_call(tp, program_mode_play_thread, &args[i], &counter, domain);
        }

        // ensure the counter was incremented

        thread_pool_wait_queue_empty(tp);

        // wait for the shutdown or for workers to stop

        for(;;)
        {
            ret = thread_pool_counter_wait_equal_with_timeout(&counter, 0, ONE_SECOND_US * 30);

            log_debug("keyroll: waiting for the threads to stop");

            if(dnscore_shuttingdown())
            {
                break;
            }
        }

        s64 wait_stop_begin = timeus();
        bool wait_stop_error_message = FALSE;
        for(u32 wait_count = 0; thread_pool_counter_get_value(&counter) > 0; ++wait_count)
        {
            sleep(1);
            s64 wait_stop_now = timeus();
            s64 wait_stop_duration = wait_stop_now - wait_stop_begin;
            if(dnscore_shuttingdown() && (wait_stop_duration > (ONE_SECOND_US * 30)) )
            {
                if(!wait_stop_error_message)
                {
                    log_err("keyroll workers aren't stopping");
                    logger_flush();
                    wait_stop_error_message = TRUE;
                }
                if(wait_stop_duration > (ONE_SECOND_US * 60))
                {
                    log_err("not waiting anymore");
                    logger_flush();
                }
            }
        }

        thread_pool_destroy(tp);
        tp = NULL;

        free(args);
    }

    if(does_loop)
    {
        log_info("keyroll stopped");
    }

    unlink(pid_file_path);

    return SUCCESS;
}

static ya_result
program_mode_print(const u8 *domain)
{
    ya_result ret;
    if(dirent_get_file_type(g_config.plan_path, ".") == DT_UNKNOWN)
    {
        log_info("print: %{dnsname}: having trouble with directory '%s'", domain, g_config.plan_path);
        return INVALID_PATH;
    }

    keyroll_t keyroll;

    // start from an empty state
    if(FAIL(ret = keyroll_init(&keyroll, domain, g_config.plan_path, g_config.keys_path, g_config.server, FALSE)))
    {
        return ret;
    }

    // at this point:
    // _ we know the present state on the server
    // _ we know the plan folder for this domain exists

    if(FAIL(ret = keyroll_plan_load(&keyroll)))
    {
        if(ret != MAKE_ERRNO_ERROR(ENOENT))
        {
            log_info("print: %{dnsname}: plan loading failed: %r", domain, ret);
            formatln("print: %{dnsname}: plan loading failed: %r", domain, ret);
        }
        else
        {
            log_info("print: %{dnsname}: there are no plans on storage (%s)", domain, g_config.plan_path);
            formatln("print: %{dnsname}: there are no plans on storage (%s)", domain, g_config.plan_path);
        }

        return ret;
    }

    ret = keyroll_print(&keyroll, termout);

    return ret;
}

static ya_result
program_mode_print_json(const u8 *domain)
{
    ya_result ret;
    if(dirent_get_file_type(g_config.plan_path, ".") == DT_UNKNOWN)
    {
        log_info("print: %{dnsname}: having trouble with directory '%s'", domain, g_config.plan_path);
        return INVALID_PATH;
    }

    keyroll_t keyroll;

    // start from an empty state
    if(FAIL(ret = keyroll_init(&keyroll, domain, g_config.plan_path, g_config.keys_path, g_config.server, FALSE)))
    {
        return ret;
    }

    // at this point:
    // _ we know the present state on the server
    // _ we know the plan folder for this domain exists

    if(FAIL(ret = keyroll_plan_load(&keyroll)))
    {
        if(ret != MAKE_ERRNO_ERROR(ENOENT))
        {
            log_info("print: %{dnsname}: plan loading failed: %r", domain, ret);
            formatln("print: %{dnsname}: plan loading failed: %r", domain, ret);
        }
        else
        {
            log_info("print: %{dnsname}: there are no plans on storage (%s)", domain, g_config.plan_path);
            formatln("print: %{dnsname}: there are no plans on storage (%s)", domain, g_config.plan_path);
        }

        return ret;
    }

    ret = keyroll_print_json(&keyroll, termout);

    return ret;
}

static ya_result
program_mode_test()
{
    return SUCCESS;
}

int
main(int argc, char *argv[])
{
    /* initializes the core library */
    dnscore_init();
    keyroll_errors_register();

    ya_result ret = main_config(argc, argv);

    if(FAIL(ret) || cmdline_help_get() || cmdline_version_get())
    {
        return EXIT_FAILURE;
    }

    if(g_config.dryrun)
    {
        println("dryrun mode");
        log_notice("dryrun mode");
    }

    if(ptr_vector_size(&g_config.fqdns) == 0)
    {
        log_err("No domain has been configured.");
        println("No domain has been configured.");
        flushout();
        return EXIT_FAILURE;
    }

    signal_handler_init();
    signal_handler_set(SIGINT, signal_int);
    signal_handler_set(SIGTERM, signal_int);
    signal_handler_set(SIGHUP, signal_hup);

    flushout();
    flusherr();
    logger_flush();

    switch(g_config.program_mode)
    {
        case NONE:
        {
            println("\nno -m option given\n");
            help_print(argv[0]);
            break;
        }
        case GENERATE:
        {
            ret = program_mode_generate_all();
            break;
        }
        case PLAY:
        {
            ret = program_mode_play_all(FALSE, FALSE);
            break;
        }
        case PLAYLOOP:
        {
            ret = program_mode_play_all(TRUE, g_config.daemonise);
            break;
        }
        case PRINT:
        {
            for(int i = 0; i <= ptr_vector_last_index(&g_config.fqdns); ++i)
            {
                u8 *fqdn = (u8*)ptr_vector_get(&g_config.fqdns, i);
                program_mode_print(fqdn);
            }
            break;
        }
        case PRINT_JSON:
        {
            formatln("{\"version\": \"" YKEYROLL_VERSION "\", \"plans\": [");
            for(int i = 0; i <= ptr_vector_last_index(&g_config.fqdns); ++i)
            {
                if(i > 0)
                {
                    println(",");
                }
                u8 *fqdn = (u8*)ptr_vector_get(&g_config.fqdns, i);
                program_mode_print_json(fqdn);
            }
            println("]}");
            break;
        }

        case TEST:
        {
            ret = program_mode_test();
            break;
        }
        default:
        {
            ret = INVALID_STATE_ERROR;
            break;
        }
    }

    if(FAIL(ret))
    {
        log_err("failed with: %r", ret);
        osformatln(termerr, "failed with: %r", ret);
    }

    flushout();
    flusherr();
    fflush(NULL);

    signal_handler_finalize();
    dnscore_finalize();

    return ISOK(ret)?EXIT_SUCCESS:EXIT_FAILURE;
}
