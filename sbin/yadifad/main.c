/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2019, EURid vzw. All rights reserved.
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
#include "server-config.h"
#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
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

// #include <dnscore/dnskey_ecdsa.h>

#include <dnscore/pid.h>
#include <dnscore/server-setup.h>

#include <dnscore/sys_get_cpu_count.h>

#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnsdb/dnssec.h>
#include <dnsdb/dnssec-keystore.h>
#include <dnsdb/zdb.h>
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

#include "buildinfo.h"

#define MODULE_MSG_HANDLE g_server_logger

/*------------------------------------------------------------------------------
 * GO */

static bool server_do_clean_exit = FALSE;
int g_yadifa_exitcode = EXIT_SUCCESS;
static bool own_pid = FALSE;

static bool main_config_log_from_start = FALSE; // start logging asap

void config_logger_setdefault();
void config_logger_cleardefault();

int process_command_line(int argc, char **argv, config_data *config);

int zalloc_init();

static void
server_register_errors()
{
    error_register(CFG_ERROR_BASE,"CFG_ERROR_BASE");

    /* Config error codes */

    error_register(CONFIG_ZONE_ERR,"Error in config file");
    
    error_register(CONFIG_KEY_INCOMPLETE_KEY,"CONFIG_KEY_INCOMPLETE_KEY");
    error_register(CONFIG_KEY_UNSUPPORTED_ALGORITHM,"CONFIG_KEY_UNSUPPORTED_ALGORITHM");

    /*
    error_register(YDF_ERROR_BASE,"YDF_ERROR_BASE");
    error_register(YDF_ALREADY_RUNNING,"YDF_ALREADY_RUNNING");
    error_register(YDF_PID_PATH_IS_WRONG,"YDF_PID_PATH_IS_WRONG");
    */

    /* Main error codes */
    
    error_register(ZONE_LOAD_MASTER_TYPE_EXPECTED,"ZONE_LOAD_MASTER_TYPE_EXPECTED");
    error_register(ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED,"ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED");
    error_register(ZONE_LOAD_SLAVE_TYPE_EXPECTED,"ZONE_LOAD_SLAVE_TYPE_EXPECTED");
    
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
    error_register(ACL_TOO_MUCH_TOKENS,"ACL_TOO_MUCH_TOKENS");
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
    error_register(POLICY_NULL_REQUESTED, "POLICY_NULL_REQUESTED");
    error_register(POLICY_ZONE_NOT_READY, "POLICY_ZONE_NOT_READY");    
}

static void
main_dump_info()
{
    log_info("starting YADIFA " VERSION);
    log_info("built with " BUILD_OPTIONS);
#if !defined(DEBUG)
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

static ya_result
yadifad_config_on_section_loggers_read(const char* name, int index)
{
    //formatln("yadifad_config_on_section_main_read(%s,%i)", name, index);

    ya_result                                                   ret;
    
    if(FAIL(ret = pid_check_running_program(PROGRAM_NAME, g_config->pid_file))) /// @todo 20160127 edf -- needs to add pid_file stuff
    {
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
        return ret;
    }
    
    database_service_init();

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

    notify_service_init();

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
    
    
    if(main_config_log_from_start)
    {
        config_logger_setdefault();
    }
    
    /*
     *  Initialise configuration file and set standard values
     */
        
    if(FAIL(ret = yadifad_config_init()))
    {
        osformatln(termerr, "error: %r", ret);
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
        osformatln(termerr, "error: %r", ret);
        flusherr();

        return ret;
    }
    
    if(FAIL(ret = yadifad_config_finalise()))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();

        return ret;
    }
        
#if 0 && defined(DEBUG)
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
        ttylog_err("error: '%s' is not writable: %r", dir, ERRNO_ERROR);
        
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
    if(!main_final_tests_is_directory_writable(g_config->log_path))
    {
        return DIRECTORY_NOT_WRITABLE;
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
    
    server_service_finalise();
    
#if HAS_DYNUPDATE_SUPPORT
    dynupdate_query_service_stop();
#endif
    
    notify_service_stop();
    
    signal_handler_finalise();
    notify_service_finalise();
    database_service_finalise();
    
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

        logger_flush();

        flushout();
        flusherr();

#if HAS_ACL_SUPPORT
        acl_free_definitions();
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

static void
main_check_lock_from_start(int argc, const char **argv)
{
    for(int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "-L") == 0)
        {
            main_config_log_from_start = TRUE;
        }
    }
}

int
main(int argc, char *argv[])
{
    ya_result ret;
    


    /*    ------------------------------------------------------------    */
    
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
    
#ifdef DEBUG
    puts("YADIFA debug build");
#endif
    
    main_check_build_settings();
        
    dnscore_init();
    
    main_check_lock_from_start(argc, (const char**)argv);
        
    async_message_pool_init();

    // registers yadifad error codes

    server_register_errors();
    
    // arms the exit handling function

    atexit(main_exit);
    
#if HAS_DYNCONF_SUPPORT
    //dynconf_service_init();
    //dynconf_service_start();
#endif    
    // configures, exit if ordered to (version/help or error)
    
    if((ret = main_config(argc, argv)) != SUCCESS)
    {
        return ISOK(ret)?EXIT_SUCCESS:EXIT_CONFIG_ERROR;
    }



    // This is always 'exit' on failure
    if(FAIL(ret = pid_check_running_program(PROGRAM_NAME, g_config->pid_file)))
    {
        return ret;
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

    if(FAIL(ret = server_setup_env(&g_config->pid, &g_config->pid_file, g_config->uid, g_config->gid, setup_flags)))
    {
        log_err("server setup failed: %r", ret);
        return EXIT_FAILURE;
    }
    
    own_pid = TRUE;
    
#if ZDB_HAS_DNSSEC_SUPPORT
    dnssec_keystore_setpath(g_config->keys_path);
    dnssec_set_xfr_path(g_config->xfr_path);
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
    
    /**
     * @todo 20140415 edf -- only do this if we are master for at least one zone
     */
    
    log_info("starting notify service");

    notify_service_start();
    
#if HAS_DYNUPDATE_SUPPORT
    // dynupdate service
    //
    // called by the dns server
    // uses the database
    
    dynupdate_query_service_start();
#endif
    
    /*
     * Starts the services, ending with the server.
     * Waits for the shutdown signal.
     */
    
    int exit_code;


        
        if(ISOK(ret = server_service_start_and_wait()))
        {
            exit_code = EXIT_SUCCESS;
        }
        else
        {
            exit_code = EXIT_FAILURE;
        }


    
    /// @note DO NOT: logger_finalize() don't, it will be done automatically at exit

    return exit_code;
}

/** @} */
