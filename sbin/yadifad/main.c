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

/** @defgroup yadifad Yet Another DNS Implementation for all
 * 
 *  @brief Yet Another DNS Implementation for all
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#define _POSIX_SOURCES
#define __USE_POSIX

#include "server-config.h"

#include <sys/types.h>
#include <sys/time.h>
#ifndef WIN32
#include <sys/resource.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/fdtools.h>
#include <dnscore/parsing.h>
#include <dnscore/dnscore.h>
#include <dnscore/chroot.h>
#include <dnscore/async.h>
#include <dnscore/service.h>
#include <dnscore/logger-output-stream.h>
#include <dnscore/socket-server.h>

// #include <dnscore/dnskey_ecdsa.h>

#include <dnscore/pid.h>
#include <dnscore/server-setup.h>

#include <dnscore/sys_get_cpu_count.h>

#include <dnsdb/zdb.h>

#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnsdb/dnssec.h>
#include <dnsdb/dnssec-keystore.h>
#endif

#include "server_error.h"
#include "config_error.h"
#include "signals.h"
#include "server.h"
#include "notify.h"


#include "database-service.h"

#if HAS_DYNUPDATE_SUPPORT
#include "dynupdate_query_service.h"
#endif

#if HAS_DYNCONF_SUPPORT
#include "dynconf.h"
#endif

#include "process_class_ch.h"

#include "zone-signature-policy.h"

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic-module-handler.h"
#endif

#include "buildinfo.h"

#define MODULE_MSG_HANDLE g_server_logger

/*------------------------------------------------------------------------------
 * GO */

static bool server_do_clean_exit = FALSE;
int g_yadifa_exitcode = EXIT_SUCCESS;
static bool own_pid = FALSE;

static bool main_config_log_from_start = FALSE;     // start logging asap
static u32  main_config_features = DNSCORE_ALL;     // start all services (can be reduced on early config)
static bool main_config_help_requested = FALSE;     // no point in starting anything

void config_logger_setdefault();
void config_logger_cleardefault();
int process_command_line(int argc, char **argv, config_data *config);
int zalloc_init();
void config_unregister_main();

static void
server_register_errors()
{
    error_register(CFG_ERROR_BASE,"CFG_ERROR_BASE");

    /* Config error codes */

    error_register(CONFIG_ZONE_ERR,"Error in config file");

    /*
    error_register(YDF_ERROR_BASE,"YDF_ERROR_BASE");
    error_register(YDF_ALREADY_RUNNING,"YDF_ALREADY_RUNNING");
    error_register(YDF_PID_PATH_IS_WRONG,"YDF_PID_PATH_IS_WRONG");
    */

    /* Main error codes */
    
    error_register(ZONE_LOAD_MASTER_TYPE_EXPECTED,"ZONE_LOAD_MASTER_TYPE_EXPECTED");
    error_register(ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED,"ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED");
    error_register(ZONE_LOAD_SLAVE_TYPE_EXPECTED,"ZONE_LOAD_SLAVE_TYPE_EXPECTED");
    error_register(ZRE_NO_VALID_FILE_FOUND,"ZRE_NO_VALID_FILE_FOUND");
    
    error_register(ANSWER_NOT_ACCEPTABLE,"ANSWER_NOT_ACCEPTABLE");
    error_register(ANSWER_UNEXPECTED_EOF,"ANSWER_UNEXPECTED_EOF");

    /* ACL */
    error_register(ACL_ERROR_BASE,"ACL_ERROR_BASE");
    error_register(ACL_TOKEN_SIZE_ERROR,"ACL_TOKEN_SIZE_ERROR");
    error_register(ACL_UNEXPECTED_NEGATION,"ACL_UNEXPECTED_NEGATION");
    error_register(ACL_WRONG_V4_MASK,"ACL_WRONG_V4_MASK");
    error_register(ACL_WRONG_V6_MASK,"ACL_WRONG_V6_MASK");
    error_register(ACL_WRONG_MASK,"ACL_WRONG_MASK");
    error_register(ACL_DUPLICATE_ENTRY,"ACL_DUPLICATE_ENTRY");
    error_register(ACL_RESERVED_KEYWORD,"ACL_RESERVED_KEYWORD");
    error_register(ACL_TOO_MANY_TOKENS,"ACL_TOO_MANY_TOKENS");
    error_register(ACL_NAME_PARSE_ERROR,"ACL_NAME_PARSE_ERROR");
    error_register(ACL_UNKNOWN_TSIG_KEY,"ACL_UNKNOWN_TSIG_KEY");
    error_register(ACL_UPDATE_REJECTED,"ACL_UPDATE_REJECTED");
    error_register(ACL_NOTIFY_REJECTED,"ACL_NOTIFY_REJECTED");
    error_register(ACL_UNDEFINED_TOKEN,"ACL_UNDEFINED_TOKEN");
    
    error_register(CONFIG_WRONG_SIG_TYPE, "CONFIG_WRONG_SIG_TYPE");
    error_register(CONFIG_WRONG_SIG_VALIDITY, "CONFIG_WRONG_SIG_VALIDITY");
    error_register(CONFIG_WRONG_SIG_REGEN, "CONFIG_WRONG_SIG_REGEN");
    
    error_register(DATABASE_ZONE_MISSING_DOMAIN, "DATABASE_ZONE_MISSING_DOMAIN");
    error_register(DATABASE_ZONE_MISSING_MASTER, "DATABASE_ZONE_MISSING_MASTER");
    error_register(DATABASE_ZONE_MISSING_TYPE, "DATABASE_ZONE_MISSING_TYPE");
    error_register(DATABASE_ZONE_CONFIG_DUP, "DATABASE_ZONE_CONFIG_DUP");
    
    error_register(NOTIFY_QUERY_TO_MASTER, "NOTIFY_QUERY_TO_MASTER");
    error_register(NOTIFY_QUERY_TO_UNKNOWN, "NOTIFY_QUERY_TO_UNKNOWN");
    error_register(NOTIFY_QUERY_FROM_UNKNOWN, "NOTIFY_QUERY_FROM_UNKNOWN");
    
    error_register(POLICY_ILLEGAL_DATE, "POLICY_ILLEGAL_DATE");
    error_register(POLICY_ILLEGAL_DATE_TYPE, "POLICY_ILLEGAL_DATE_TYPE");
    error_register(POLICY_ILLEGAL_DATE_PARAMETERS, "POLICY_ILLEGAL_DATE_PARAMETERS");
    error_register(POLICY_ILLEGAL_DATE_COMPARE, "POLICY_ILLEGAL_DATE_COMPARE");
    error_register(POLICY_UNDEFINED, "POLICY_UNDEFINED");
    error_register(POLICY_KEY_SUITE_UNDEFINED, "POLICY_KEY_SUITE_UNDEFINED");
    error_register(POLICY_NULL_REQUESTED, "POLICY_NULL_REQUESTED");
    error_register(POLICY_ZONE_NOT_READY, "POLICY_ZONE_NOT_READY");

}

static void
main_dump_info()
{
    log_info("starting YADIFA " VERSION);
    log_info("built with " BUILD_OPTIONS);
#if !DEBUG
    log_info("release build");
#else
    log_info("debug build");
#endif
    log_info("------------------------------------------------");
    log_info("YADIFA is maintained by EURid");
    log_info("Source code is available at http://www.yadifa.eu");
    log_info("------------------------------------------------");
    log_info("got %u CPUs", sys_get_cpu_count());
    log_info("using %u UDP listeners per interface", g_config->thread_count_by_address);
    log_info("accepting up to %u TCP queries", g_config->max_tcp_queries);
#if DNSCORE_HAS_ZALLOC
    log_info("self-managed memory enabled"); // ZALLOC
#endif
}

static bool yadifad_config_on_section_loggers_read_done_once = FALSE;

static ya_result
yadifad_config_on_section_loggers_read(const char* name, int index)
{
    (void)name;
    (void)index;

    if(yadifad_config_on_section_loggers_read_done_once)
    {
        return SUCCESS;
    }

    //formatln("yadifad_config_on_section_main_read(%s,%i)", name, index);

    ya_result                                                   ret;
    pid_t                                                       pid;
    
    if(FAIL(ret = pid_check_running_program(g_config->pid_file, &pid)))
    {
        log_err("%s already running with pid: %lu (%s)", PROGRAM_NAME, pid, g_config->pid_file);
        return ret;
    }
    
    /*
     * From here we have the loggers ready (if any was set)
     */

    if(g_config->server_flags & SERVER_FL_DAEMON)
    {
        server_setup_daemon_go();
    }

    logger_start();
    
    if(!config_logger_isconfigured())
    {
        config_logger_setdefault();
    }
    else
    {
        config_logger_cleardefault();
    }
    
    main_dump_info();
    
    if(FAIL(ret = server_service_init()))
    {
        log_err("failed to initialise network service: %r", ret);
        return ret;
    }
    
    database_service_init();

    notify_service_init();

    /* Initialize signals used for inter process communication and
     * quitting the program
     */

    if(FAIL(ret = signal_handler_init()))
    {
        log_err("failed to setup the signal handler: %r", ret);

        if(!(g_config->server_flags & SERVER_FL_DAEMON))
        {
            osformatln(termerr, "error: failed to setup the signal handler: %r", ret);
            flusherr();
        }

        logger_flush();

        return ret;
    }

    notify_wait_servicing();
    
    signal_setup(); // hooks the signals

#if DEBUG
    println("yadifad_config_on_section_loggers_read done");
    flushout();
#endif

    yadifad_config_on_section_loggers_read_done_once = TRUE;

    return CONFIG_CALLBACK_RESULT_CONTINUE;
}


/**
 * Handles the configuration part of the server.
 * 
 * @param argc
 * @param argv
 * @return  0  if the configuration is successful and the server can start
 * @return  1 if no error occurred but the server must stop
 * @return -1 if an error occurred and the server must stop
 */

int
main_config(int argc, char *argv[])
{
    ya_result ret;
    
    if(main_config_log_from_start) // -L was used on the command line
    {
        config_logger_setdefault();
    }
    
    /*
     *  Initialise configuration file and set standard values
     */
    
    if(FAIL(ret = yadifad_config_init()))
    {
        osformatln(termerr, "error: setting up configuration: %r", ret);
        flusherr();

        return ret;
    }
    
    // channels then loggers
    config_add_on_section_read_callback("loggers", yadifad_config_on_section_loggers_read);
    
    if((ret = yadifad_config_cmdline(argc, argv)) != 0)
    {
        if(FAIL(ret))
        {
            return ret;
        }
        
        return 1;
    }

    if(FAIL(ret = yadifad_config_read(g_config->config_file)))
    {
        osformatln(termerr, "error: reading configuration: %r", ret);
        flusherr();

        return ret;
    }
    
    if(FAIL(ret = yadifad_config_finalize()))
    {
        osformatln(termerr, "error: processing configuration: %r", ret);
        flusherr();

        return ret;
    }
        
#if 0 && DEBUG
    config_print(termout);    
    osformatln(termout, "starting logging service");
#endif
    
    /*
     * flushes whatever is in the buffers
     */

    flushout();
    flusherr();
    
    return 0;
}

/**
 * Tries to create a temporary file in a directory.
 * Deletes the file afterward.
 * 
 * @param dir
 * @return true iff the file was created
 */

static bool
main_final_tests_is_directory_writable(const char* dir)
{
    char tempfile[PATH_MAX];
    
    snformat(tempfile, sizeof(tempfile), "%s/ydf.XXXXXX", dir);
    int tempfd;
    if((tempfd = mkstemp_ex(tempfile)) < 0)
    {
        int err = ERRNO_ERROR;
        ttylog_err("error: '%s' is not writable as (%d:%d): %r", dir, getuid(), getgid(), err);
        
        return FALSE;
    }
    unlink(tempfile);
    close_ex(tempfd);
    
    return TRUE;    
}

/**
 * last tests before the real startup (directory writable)
 */

static ya_result
main_final_tests()
{
    if(!main_final_tests_is_directory_writable(g_config->data_path))
    {
        return DIRECTORY_NOT_WRITABLE;
    }
    if(!main_final_tests_is_directory_writable(g_config->keys_path))
    {
        return DIRECTORY_NOT_WRITABLE;
    }

    if((g_config->server_flags & SERVER_FL_LOG_FILE_DISABLED) == 0)
    {
        if(!main_final_tests_is_directory_writable(g_config->log_path))
        {
            return DIRECTORY_NOT_WRITABLE;
        }
    }
    if(!main_final_tests_is_directory_writable(g_config->xfr_path))
    {
        return DIRECTORY_NOT_WRITABLE;
    }
    
    return SUCCESS;
}

/** \brief Function executed by atexit
 *
 * The atexit() function registers the given function to be called at normal
 * process termination, either via exit(?) or via return from the program
 * main(). Functions so registered are called in the reverse order of their
 * registration; no arguments are passed.
 */

static void
main_exit()
{
    if(own_pid)
    {
        log_info("shutting down");
    }
    
    server_service_stop();
    
    server_service_finalize();
    
#if HAS_DYNUPDATE_SUPPORT
    dynupdate_query_service_stop();
#endif
    
    notify_service_stop();
    
#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_handler_finalize();
#endif
    
    signal_handler_finalize();
    notify_service_finalize();
    database_service_finalize();

#if HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
    dnssec_policy_finalize();
#endif
    class_ch_set_hostname(NULL);    
    class_ch_set_id_server(NULL);
    class_ch_set_version(NULL);

#if DNSCORE_HAS_NSID_SUPPORT
    edns0_set_nsid(NULL, 0);
#endif
    
    logger_flush();
        
    flushout();
    flusherr();

    if(server_do_clean_exit)
    {
        database_shutdown(g_config->database);
        
        database_finalize();
        
        if(own_pid)
        {
            log_info("releasing pid file lock");

            pid_file_destroy(g_config->pid_file);
        }
        
        //config_unregister_main();

        logger_flush();

        flushout();
        flusherr();

#if HAS_ACL_SUPPORT
        acl_definitions_free();
#endif
        
        dnscore_finalize();
    }
    else
    {
        if(own_pid)
        {
            log_info("releasing pid file lock");

            pid_file_destroy(g_config->pid_file);
        }

        logger_flush();

        flushout();
        flusherr();
    }
}

/** \brief Main function of yadifa
 *
 *  @param[in] argc number of arguments on the command line
 *  @param[in] argv array of arguments on the command line
 *
 *  @return EXIT_SUCCESS
 *  @return EXIT_FAILURE
 *  @return exit codes
 *
 *
 */



/**
 * This will stop YADIFAD if the libraries have been build-configured differently or made differently.
 * 
 * The most typical trigger is "make debug" vs "make", is, because it has not been followed by,
 * respectively, a "make debug-install" or a "make install"
 * 
 * Or, in the case of a static build, a mix code versions that would have required a "make clean"
 * 
 */

static void
main_check_build_settings()
{
    if(dnscore_getfingerprint() != dnscore_getmyfingerprint())
    {
        printf("yadifad: the linked dnscore features are %08x but the lib has been compiled against one with %08x", dnscore_getfingerprint(), dnscore_getmyfingerprint());
        fflush(NULL);
        abort(); // binary incompatiblity : full stop
    }
    
    if(dnsdb_getfingerprint() != dnsdb_getmyfingerprint())
    {
        printf("yadifad: the linked dnsdb features are %08x but the lib has been compiled against one with %08x", dnsdb_getfingerprint(), dnsdb_getmyfingerprint());
        fflush(NULL);
        abort(); // binary incompatiblity : full stop
    }
}

/**
 * The flag must be checked this way as the internal command line/configuration parsing mechanism
 * would miss the start.
 * 
 * @param argc
 * @param argv
 */

static int
main_early_argv_check(int argc, char *argv[])
{
    int ret = 0;
    
    for(int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "-L") == 0)
        {
            main_config_log_from_start = TRUE;
        }
        if(strcmp(argv[i], "-h") == 0)
        {
            main_config_help_requested = TRUE;
            main_config_features = DNSCORE_TINYRUN;
            ++ret;
        }
        else if(strcmp(argv[i], "--help") == 0)
        {
            main_config_help_requested = TRUE;
            main_config_features = DNSCORE_TINYRUN;
            ++ret;
        }
        else if(strcmp(argv[i], "-V") == 0)
        {
            main_config_features = DNSCORE_TINYRUN;
        }
        else if(strcmp(argv[i], "--version") == 0)
        {
            main_config_features = DNSCORE_TINYRUN;
        }
    }
    
    return ret;
}

static void
main_ignore_signals_while_starting_up()
{
    static const int ignore_these[] = {SIGHUP, SIGUSR1, SIGINT, SIGTERM, SIGPIPE, 0};

    for(int i = 0; ignore_these[i] != 0; ++i)
    {
        signal(ignore_these[i], SIG_IGN);
    }
}

int
main(int argc, char *argv[])
{
    ya_result ret;
    


    /**
     *  Initialises the core library:
     * _ checks basic architecture settings (endianness, types sizes, random generator, ...)
     * _ initialises dns types and classes name<->id matching
     * _ initialises text formatting (format*, log*)
     * _ initialises standard output streams
     * _ initialises the logger
     * _ registers core error codes
     * _ registers TSIG algorithms
     * _ registers an exit function
     * _ resets and start the alarm/timer function
     */
    
#if DEBUG
    puts("YADIFA debug build");
#if HAS_RRL_SUPPORT
    puts("RRL support: yes");
#else
    puts("RRL support: no");
#endif
#endif
    
    main_check_build_settings();
    
    if(main_early_argv_check(argc, argv) != 0)
    {
        // print the help using printf & flush

        dnscore_init_ex(DNSCORE_TINYRUN, argc, argv);
        yadifad_print_usage(argv[0]);

        return 1;
    }

    main_ignore_signals_while_starting_up();

    dnscore_init_ex(main_config_features, argc, argv);

    //main_check_log_from_start(argc, (const char**)argv);
        
    async_message_pool_init();

    // registers yadifad error codes

    server_register_errors();
    
    // arms the exit handling function
    
#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_handler_init();
#endif

    atexit(main_exit);
    
    // ?
    // register all the services:
    // server, database, ...
    
#if HAS_DYNCONF_SUPPORT
    //dynconf_service_init();
    //dynconf_service_start();
#endif    
    // configures, exit if ordered to (version/help or error)
    //
    
    if((ret = main_config(argc, argv)) != SUCCESS)
    {
        return ISOK(ret)?EXIT_SUCCESS:EXIT_CONFIG_ERROR;
    }

    // This is always 'exit' on failure
    pid_t pid;
    if(FAIL(ret = pid_check_running_program(g_config->pid_file, &pid)))
    {
        log_err("%s already running with pid: %lu (%s)", PROGRAM_NAME, pid, g_config->pid_file);
        return EXIT_FAILURE; // don't use ret
    }

    /*
     * We are really starting up. After this we may want to do a clean exit.
     */

    server_do_clean_exit = TRUE;

    /*
     * Setup the necessary environmental changes: core limits, root change, id change, and creation of pid file
     */

    u32 setup_flags = SETUP_CORE_LIMITS | SETUP_ID_CHANGE | SETUP_CREATE_PID_FILE;

    if(g_config->server_flags & SERVER_FL_CHROOT)
    {
        setup_flags |= SETUP_ROOT_CHANGE;
    }

#ifndef WIN32
    {
        struct rlimit limits;
        getrlimit(RLIMIT_NOFILE, &limits);

        if(limits.rlim_cur < 1024)
        {
            ttylog_err("file open limits are too small (%i < 1024) to even try to go on.", limits.rlim_cur);
            return EXIT_FAILURE;
        }

        if(limits.rlim_cur < 65536)
        {
            ttylog_notice("file open limits could be higher (%i < 65536).  The highest the better.", limits.rlim_cur);
        }
    }
#endif

    if(FAIL(ret = server_setup_env(&g_config->pid, &g_config->pid_file, g_config->uid, g_config->gid, setup_flags)))
    {
        log_err("server setup failed: %r", ret);
        return EXIT_FAILURE;
    }
    
    own_pid = TRUE;
    
#if ZDB_HAS_DNSSEC_SUPPORT
    dnssec_keystore_setpath(g_config->keys_path);
#endif
    logger_reopen();

    /// last tests before the real startup (directory writable)
    
    if(FAIL(main_final_tests()))
    {
        return EXIT_FAILURE;
    }

    // database service
    //
    // needs about nobody

    log_info("loading zones");
    
    if(FAIL(ret = database_startup(&g_config->database)))
    {
        log_err("loading zones: %r", ret);

        return EXIT_FAILURE;
    }
    
    /*
     * Starts the services, ending with the server.
     * Waits for the shutdown signal.
     */
    
    int exit_code = EXIT_SUCCESS;

#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_startup();
#endif
    

        while(!dnscore_shuttingdown())
        {
            log_info("starting notify service");

            notify_service_start();

#if HAS_DYNUPDATE_SUPPORT

            log_info("starting dynupdate service");

            // dynupdate service
            //
            // called by the dns server
            // uses the database

            dynupdate_query_service_init();
            dynupdate_query_service_start();
#endif
/*
            if(ctrl_has_dedicated_listen())
            {
                // start ctrl server on its address(es) that does not match the DNS server addresses
            }
*/
            log_info("starting server");

            if(ISOK(ret = server_service_start_and_wait()))
            {
                exit_code = EXIT_SUCCESS;
            }
            else
            {
                exit_code = EXIT_FAILURE;
            }

#if HAS_DYNUPDATE_SUPPORT
            log_info("stopping dynupdate service");

            dynupdate_query_service_stop();
            dynupdate_query_service_finalise();

            log_info("dynupdate service stopped");
#endif

            log_info("stopping notify service");

            notify_service_stop();

            if(!dnscore_shuttingdown())
            {            
                // server stop
               // server context stop
               server_context_stop();
               // server context start
               if(ISOK(ret = server_context_create()))
               {
                   // server start
               }
               else
               {
                   log_try_err("failed to start server: %r", ret);
               }
            }
        }
    

    
#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_shutdown();
#endif
    
    /// @note DO NOT: logger_finalize() don't, it will be done automatically at exit

    return exit_code;
}

/** @} */
