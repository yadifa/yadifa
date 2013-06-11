/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
* DOCUMENTATION */
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/fdtools.h>
#include <dnscore/parsing.h>

#include "wrappers.h"
#include "server_error.h"
#include "config_error.h"
#include "signals.h"
#include "server.h"

#define MODULE_MSG_HANDLE g_server_logger

/*------------------------------------------------------------------------------
 * GO */

static bool server_do_clean_exit = FALSE;

void config_logger_setdefault();
void config_logger_cleardefault();

int process_command_line(int argc, char **argv, config_data *config);


/** \brief Function executed by atexit
 *
 * The atexit() function registers the given function to be called at normal
 * process termination, either via exit(?) or via return from the program
 * main(). Functions so registered are called in the reverse order of their
 * registration; no arguments are passed.
 */
static void
server_exit()
{
    logger_flush();
    
    flushout();
    flusherr();

    if(server_do_clean_exit)
    {
        database_finalize();
        dnscore_finalize();
    }
}

static void
server_register_errors()
{
    error_register(CFG_ERROR_BASE,"CFG_ERROR_BASE");

    /* Config error codes */
    error_register(NO_DATAPATH_FOUND,"No data path is empty");
    error_register(NO_VARIABLE_FOUND,"No variable param found in config file");
    error_register(NO_VALUE_FOUND,"No value param found in config file");
    error_register(NO_ARGUMENT_FOUND,"No argument param found in config file");
    error_register(INCORRECT_CONFIG_LINE,"Problems with some of the params");
    error_register(CONFIG_FILE_OPEN_FAILED,"CONFIG_FILE_OPEN_FAILED");
    error_register(CONFIG_FILE_INCL_FAILED,"CONFIG_FILE_INCL_FAILED");
    error_register(CONFIG_FILE_BROKEN_TAG,"CONFIG_FILE_BROKEN_TAG");
    error_register(CONFIG_FILE_BAD_CONT_END,"CONFIG_FILE_BAD_CONT_END");
    error_register(CONFIG_FILE_BAD_CONT_START,"CONFIG_FILE_BAD_CONT_START");
    error_register(CONFIG_FILE_BAD_KEYWORD,"CONFIG_FILE_BAD_KEYWORD");
    
    error_register(CONFIG_ZONE_ERR,"Error in config file");
    error_register(CONFIG_BAD_UID_ERR,"CONFIG_BAD_UID_ERR");
    error_register(CONFIG_BAD_GID_ERR,"CONFIG_BAD_GID_ERR");
    error_register(CONFIG_EMPTY_PATH_ERR,"CONFIG_EMPTY_PATH_ERR");

    error_register(CONFIG_UNKNOWN_SETTING_ERR,"CONFIG_UNKNOWN_SETTING_ERR");
    error_register(CONFIG_ZONE_CHAIN_ERR,"CONFIG_ZONE_CHAIN_ERR");
    error_register(CONFIG_KEY_WRONG_FIELD,"CONFIG_KEY_WRONG_FIELD");
    error_register(CONFIG_KEY_INCOMPLETE_KEY,"CONFIG_KEY_INCOMPLETE_KEY");
    error_register(CONFIG_KEY_UNSUPPORTED_ALGORITHM,"CONFIG_KEY_UNSUPPORTED_ALGORITHM");
    error_register(CONFIG_ZONE_DNSSEC_CONFLICT,"CONFIG_ZONE_DNSSEC_CONFLICT");

    error_register(NO_CLASS_FOUND,"No class found in resource record");
    error_register(DIFFERENT_CLASSES,"Different classes found in one zone file");
    error_register(WRONG_APEX,"The first type in a zone file must be SOA");
    error_register(DUPLICATED_SOA,"Only one soa type in a zone file");
    error_register(INCORRECT_TTL,"ttl is a incorrect number");
    error_register(INCORRECT_ORIGIN,"Origin is not a correct fqdn with a dot");
    //error_register(NO_ORIGIN_FOUND,"No origin found where we should");

    error_register(NO_TYPE_FOUND,"No type found in resource record");
    error_register(INCORRECT_RR,"Incorrect resource record");
    error_register(DUPLICATED_CLOSED_BRACKET,"More than 1 closed bracket found in rdata");
    error_register(DUPLICATED_OPEN_BRACKET,"More than 1 open bracket found in rdata");
    error_register(INCORRECT_LABEL_LEN,"Length of label bigger than 63");
    error_register(INCORRECT_DOMAIN_LEN,"Length of domain bigger than 255");
    error_register(INCORRECT_DOMAINNAME,"Not accepted character in domain name");
    //error_register(NO_LABEL_FOUND,"No labels found empty domain name");
    error_register(INCORRECT_PREFERENCE,"INCORRECT_PREFERENCE");

    /* Zone error codes */
    error_register(SOA_PARSING_ERR,"Error parsing SOA RR");
    error_register(NO_SOA_FOUND_ERR,"No SOA RR at the beginning");
    error_register(BRACKET_OPEN_ERR,"No closing bracket in for RR");
    error_register(PARSING_RR_ERR,"Error parsing RR");
    error_register(QNAME_LEN_ERR,"Qname is too long or does not exist");

    error_register(CONFIG_CHANNEL_DUPLICATE, "CONFIG_CHANNEL_DUPLICATE");
    error_register(CONFIG_CHANNEL_UNDEFINED, "CONFIG_CHANNEL_UNDEFINED");
    error_register(CONFIG_INVALID_DEBUGLEVEL, "CONFIG_INVALID_DEBUGLEVEL");
    error_register(CONFIG_LOGGER_UNDEFINED, "CONFIG_LOGGER_UNDEFINED");

    error_register(YDF_ERROR_BASE,"YDF_ERROR_BASE");

    /* Main error codes */
    error_register(YDF_ERROR_CONFIGURATION,"Error in configuration");

    error_register(YDF_ERROR_CHOWN,"Can change owner of file");

    error_register(VALUE_FOUND,"Pointer is not empty");

    error_register(FILE_NOT_FOUND_ERR,"No file found");
    error_register(FILE_OPEN_ERR,"Error opening file");
    error_register(FILE_CLOSE_ERR,"Error closing file");
    error_register(FILE_READ_ERR,"FILE_READ_ERR");
    error_register(FILE_WRITE_ERR,"FILE_WRITE_ERR");
    error_register(FILE_CHOWN_ERR,"FILE_CHOWN_ERR");
    
    error_register(ZONE_LOAD_MASTER_TYPE_EXPECTED,"ZONE_LOAD_MASTER_TYPE_EXPECTED");
    error_register(ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED,"ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED");
    error_register(ZONE_LOAD_SLAVE_TYPE_EXPECTED,"ZONE_LOAD_SLAVE_TYPE_EXPECTED");

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
    error_register(ACL_REJECTED_BY_IPV4,"ACL_REJECTED_BY_IPV4");
    error_register(ACL_REJECTED_BY_IPV6,"ACL_REJECTED_BY_IPV6");
    error_register(ACL_REJECTED_BY_TSIG,"ACL_REJECTED_BY_TSIG");
    error_register(ACL_UNDEFINED_TOKEN,"ACL_UNDEFINED_TOKEN");
    
    error_register(CONFIG_WRONG_SIG_TYPE, "CONFIG_WRONG_SIG_TYPE");
    error_register(CONFIG_WRONG_SIG_VALIDITY, "CONFIG_WRONG_SIG_VALIDITY");
    error_register(CONFIG_WRONG_SIG_REGEN, "CONFIG_WRONG_SIG_REGEN");
    
    error_register(DATABASE_ZONE_NOT_FOUND, "DATABASE_ZONE_NOT_FOUND");
    error_register(DATABASE_ZONE_MISSING_DOMAIN, "DATABASE_ZONE_MISSING_DOMAIN");
    error_register(DATABASE_ZONE_MISSING_MASTER, "DATABASE_ZONE_MISSING_MASTER");
    error_register(DATABASE_ZONE_CONFIG_DUP, "DATABASE_ZONE_CONFIG_DUP");
    error_register(DATABASE_EMPTY, "DATABASE_EMPTY");
    
    error_register(NOTIFY_ANSWER_NOT_AA, "NOTIFY_ANSWER_NOT_AA");
    error_register(NOTIFY_QUERY_TO_MASTER, "NOTIFY_QUERY_TO_MASTER");
    error_register(NOTIFY_QUERY_TO_UNKNOWN, "NOTIFY_QUERY_TO_UNKNOWN");
    error_register(NOTIFY_QUERY_FROM_UNKNOWN, "NOTIFY_QUERY_FROM_UNKNOWN");
}

/* @mainpage Info
 *  @b Yadifa @e Yet @e Another @e DNS @e Implementation @e For @e All
 *
 *  @section section
 *  @b Yadifa is an authorative name server. This means that no caching
 *  mechanism will be provided
 *
 *  @b Yadifa is written at @CONTACT EURid.
 *
 *  @b Yadifa is a program written by @CONTACT Gery Van Emelen <Gery@VanEmelen.net>
 */

/** \brief Damonize the program and set the correct system limitations
 *
 *  @param[in] config is a config_data structure needed for \b "pid file"
 *
 *  @return OK
 *  @return Otherwise log_quit will stop the program
 */
static void
daemonize()
{
    int                                                       fd0, fd1, fd2;
    mode_t                                                         mask = 0;
    pid_t                                                               pid;

    struct sigaction                                                     sa;

    /*    ------------------------------------------------------------    */

    log_info("daemonizing");

    dnscore_stop_timer();
    
    logger_flush();
    logger_stop();

    /* Clear file creation mask */
    umask(mask);

    /* Become a session leader to lose controlling TTYs */
    if((pid = fork()) < 0)
    {
        puts("can't fork");fflush(NULL);
        
        exit(EXIT_FAILURE);
    }

    if(pid != 0) /* parent */
    {
#ifndef NDEBUG
        puts("first level parent done");fflush(NULL);
#endif
        
        exit(EXIT_SUCCESS);
    }

    /* Set program in new session */
    setsid();

    /* Ensure future opens won't allocate controlling TTYs */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags   = 0;

    if(sigaction(SIGHUP, &sa, NULL) < 0)
    {
        puts("sigaction error");fflush(NULL);
        exit(EXIT_FAILURE);
    }

    /* Stevens way of detaching the program from the parent process,
     * forking twice
     */
    if((pid = fork()) < 0)
    {
        puts("can't fork");fflush(NULL);
        exit(EXIT_FAILURE);
    }

    if(pid != 0) /* parent */
    {
#ifndef NDEBUG
        puts("second level parent done");fflush(NULL);
#endif
        exit(EXIT_SUCCESS);
    }
    
#ifndef NDEBUG
    puts("detaching from console");fflush(NULL);
#endif
    
    logger_start();
    dnscore_reset_timer();

    /* Change the current working directory to the root so
     * we won't prevent file systems from being unmounted.
     */
    
#ifndef NDEBUG
    const char *output_file  = "/tmp/yadifa.std";
    printf("redirecting all to '%s'\n", output_file);fflush(NULL);
#else
    const char *output_file  = "/dev/null";
#endif

    /* Attach file descriptors 0, 1, and 2 to /dev/null */

    close_ex(0); /* about to be reopened */
    close_ex(1); /* about to be reopened */
    close_ex(2); /* about to be reopened */

    if((fd0 = open(output_file, O_RDWR|O_CREAT, 0666)) < 0)
    {
        log_err("stdin: %s '%s'", strerror(errno), output_file);
        exit(EXIT_FAILURE);
    }

    if((fd1 = dup(0)) < 0)
    {
        log_err("stdout: %s '%s'", strerror(errno), output_file);
        exit(EXIT_FAILURE);
    }

    if((fd2 = dup(0)) < 0)
    {
        log_err("stderr: %s '%s'", strerror(errno), output_file);
        exit(EXIT_FAILURE);
    }

    if((fd0 != 0) || (fd1 != 1) || (fd2 != 2))
    {
        log_err("unexpected file descriptors: %d %d %d instead of 0 1 2", fd0,  fd1, fd2);
        exit(EXIT_FAILURE);
    }

#ifndef NDEBUG
    puts("changing dir to /");fflush(NULL);
#endif
    
    Chdir("/"); /* chroot */
    
#ifndef NDEBUG
    puts("daemonized");fflush(NULL);
#endif

    log_info("daemonized");
    
    logger_flush();
}

/** \brief Create or overwrite the \b pid \b file with its new process id
 *
 *  @param[in] config is a config_data structure
 *
 *  @retval OK
 *  @retval YDF_ERROR_CHOWN if can not "chown"
 *  @return otherwise log_quit will stop the program with correct exit code
 */
static void
create_pid_file(config_data *config)
{
    int                                                                  fd;
    mode_t                                               permissions = 0644;
    char                                                         buffer[16];

    /*    ------------------------------------------------------------    */

    config->pid    = getpid();
    int buffer_len = snprintf(buffer, sizeof (buffer), "%d\n", config->pid);
    
    assert(buffer_len > 0);

    Chdir(config->pid_path); /* change to pid folder */

    fd = Open(config->pid_file, O_WRONLY | O_CREAT | O_TRUNC, permissions);

    if(writefully(fd, buffer, buffer_len) > 0)
    {
        if(chown(config->pid_file, config->uid, config->gid) >= 0)
        {
            close_ex(fd);
            
            return;
        }
        else
        {
            log_err("can't chown '%s' to %s.%s", config->pid_file, config->uid, config->gid);
            //return FILE_CHOWN_ERR;
        }
    }
    else
    {
        log_err("can't write pid to '%s'", config->pid_file);
        //return FILE_WRITE_ERR;
    }
    
    exit(EXIT_FAILURE);
}

/** \brief Read \b pid \b file, program quits on log_quit
 *
 *  @param[in] path
 *  @param[in] file_name
 *
 *  @retval pid
 *  @retval NOK (negative number),
 *  @return otherwise log_quit will stop the program with correct exit code
 */
static pid_t
read_pid_file()
{
    ssize_t                                                        received;
    int                                                                  fd;    
    char                                                                 *p;
    u32                                                                 pid;    
    char                                                      buffer[8 + 1];
    char                                                file_name[PATH_MAX];
    
    if((g_config->server_flags & SERVER_FL_CHROOT) && !g_config->chrooted)
    {
        fd = snformat(file_name, sizeof(file_name), "%s/%s/%s", g_config->chroot_path, g_config->pid_path, g_config->pid_file);
    }
    else
    {
        fd = snformat(file_name, sizeof(file_name), "%s/%s", g_config->pid_path, g_config->pid_file);
    }
    
    if(fd < 0)
    {
        log_err("path %s is too big", file_name);
        exit(EXIT_FAILURE);
    }

    /*    ------------------------------------------------------------    */

    if(-1 == (fd = open(file_name, O_RDONLY)))
    {
        if(errno != ENOENT)
        {
            log_err("can't open '%s': %r", file_name, ERRNO_ERROR);
            exit(EXIT_FAILURE);
        }

        return NOK; /* no file found : not running assumed */
    }

    if(-1 == (received = readfully(fd, buffer, sizeof(buffer) - 1)))
    {
        log_err("can't open '%s'", file_name);
        exit(EXIT_FAILURE);
    }

    close_ex(fd);      /* close the pid file */

    if(!received)   /* received == 0 => error */
    {
        return NOK;
    }

    buffer[received] = '\0';    /* Append a terminator for strlen */

    p = buffer;
    while(isdigit(*p)!=0) p++;  /* Cut after the first character that is not a digit (ie: CR LF ...) */
    *p = '\0';

    if(FAIL(parse_u32_check_range(buffer, &pid, 0, 99999, BASE_10)))
    {
        log_err("incorrect pid number");
        exit(EXIT_FAILURE);
    }

    return (pid_t)pid;
}

/** \brief Check if program is already running
 * 
 *  @param[in] config is a config_data structure
 *
 *  @return NONE
 *  @return otherwise log_quit will stop the program with correct exit code
 */
static void
check_running_program()
{
    pid_t                                                               pid;

    /*    ------------------------------------------------------------    */

    if(g_config->pid_path == NULL || g_config->pid_file == NULL)
    {
        log_err("pid file path is wrong");
        exit(EXIT_FAILURE);
    }

    if(ISOK(pid = read_pid_file()))
    {
        if(kill(pid, 0) == 0 || errno == EPERM)
        {
            log_err("%s already running with pid: %lu (%s%s)", PROGRAM_NAME, pid, g_config->pid_path, g_config->pid_file);
            exit(EXIT_FAILURE);
        }
    }
}

/** \brief Change uid and gid of the program
 *
 *  @param[in] config is a config_data structure
 *
 *  @return NONE
 *  @return otherwise log_quit will stop the program with correct exit code
 */
static void
change_identity(config_data *config)
{
    uid_t uid = getuid();
    gid_t gid = getgid();
    log_info("changing identity to %d:%d (current: %d:%d)", config->uid, config->gid, uid, gid);
    
    if(gid != config->gid)
    {    
        Setgid(config->gid);
    }
    if(uid != config->uid)
    {
        Setuid(config->uid);
    }
}

/**
 * dummy thread used to pre-load libgcc_s.so.1 (if the architecture needs this)
 * 
 * @param config
 */

static void *
change_chroot_dummy_thread(void *parm)
{    
    pthread_exit(parm);
    
    return parm;
}

/** \brief Change uid and gid of the program
 *
 *  @param[in] config is a config_data structure
 *
 *  @return NONE
 *  @return otherwise log_quit will stop the program with correct exit code
 */
static void
change_root(config_data *config)
{
    if(config->server_flags & SERVER_FL_CHROOT)
    {
        pthread_t t;
        
        log_debug("launching dummy thread");
            
        if(pthread_create(&t, NULL, change_chroot_dummy_thread, NULL) == 0)
        {
            log_debug("thread loaded before chroot");
            
            pthread_join(t, NULL);
        }
        else
        {
            log_err("unable to start dummy thread");
        }
                    
        log_info("going to jail");

        Chdir("."); // config->chroot_path will be prepend automatically
        Chroot(".");
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
int
main(int argc, char *argv[])
{
    ya_result                                                   return_code;

    /*    ------------------------------------------------------------    */
    
    /* Initializes the core library:
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
    
#if defined(HAS_TINY_FOOTPRINT)
    logger_set_queue_size(4096);
#endif
    
    dnscore_init();
    
    /*
     * Register yadifad error codes
     */

    server_register_errors();
    
    /*
     * what to call upon exit
     */

    atexit(server_exit);
    
    /*
     * setups a default (stdout) logger
     */
    
    config_logger_setdefault();
        
    /*
     *  Initialise configuration file and set standard values
     */
        
    if(FAIL(return_code = config_init()))
    {
        osformatln(termerr, "error: %r", return_code);
        flusherr();

        return EXIT_FAILURE;
    }

    /* 
     * If "command line" has "--config" option set: reads it and change the config param
     */
    
    if(FAIL(return_code = config_get_file(argc, argv)))
    {
        osformatln(termerr, "error: %r", return_code);
        flusherr();

        return EXIT_FAILURE;
    }
    
    logger_start();
    
    /* Read configuration file */

    if(FAIL(return_code = config_read_all()))
    {
        osformatln(termerr, "error: %r", return_code);
        flusherr();

        return EXIT_FAILURE;
    }

    /* 
     * After reading the config file, read everything else from the command
     * line options + prepare run mode
     */
    
    if(FAIL(return_code = process_command_line(argc, argv, g_config)))
    {
        /** @note Since the NULL logger handle does not outputs to stderr by default,
         *        calling any logging facility before the config update will not generate
         *        any output.
         */

        osformatln(termerr, "error: failure of run mode: %d: %r", g_config->run_mode, return_code);
        flusherr();

        return return_code;
    }

    /*
     * At this point the configuration information is ready
     */

    if(FAIL(return_code = config_update(g_config)))
    {
        osformatln(termerr, "error: setup: %r", return_code);
        flusherr();
        
        return return_code;
    }
    
    /*
     * flushes whatever is in the buffers
     */

    flushout();
    flusherr();
    
    /*
     * Starts handling signals
     */

    init_signals();
    
    /*
     * From here we have the loggers ready (if any was set)
     */

    /* Depending on the run mode ... */
    switch(g_config->run_mode & RUNMODE_FLAG) /* Remove switch flags */
    {
        case RUNMODE_EXIT_CLEAN:

            break;

        case RUNMODE_INTERACTIVE:
            /* Runs program in foreground */

#ifndef YADIFA_TCLCOMMANDS
            /* ERROR */
            log_err("interactive mode required but not built-in");
            exit(EXIT_FAILURE);
            break;
#endif /* YADIFA_TCLCOMMANDS */

        case RUNMODE_CONTINUE_CLEAN:
        case RUNMODE_DAEMON:
        {
            /* Check for running program
             * If another one runs exit
             */

            check_running_program();  /** @note: exits on failure */

            /*
             * We are really starting up. After this we may want to do a clean exit.
             */

            server_do_clean_exit = TRUE;

            /* Initialize signals used for inter process communication and
             * quitting the program
             */

            if(g_config->server_flags & SERVER_FL_DAEMON)
            {
                daemonize();
                init_signals();
            }
            
            struct rlimit core_limits = {RLIM_INFINITY, RLIM_INFINITY};
            
            if(setrlimit(RLIMIT_CORE, &core_limits) < 0)
            {
                log_err("unable to set core dump limit: %r", ERRNO_ERROR);
            }
#ifndef NDEBUG
            else
            {
                log_debug("core no-limit set");
            }
#endif

            if(g_config->server_flags & SERVER_FL_CHROOT)
            {
                change_root(g_config);      /* Chroot to new path */
            }

            change_identity(g_config);      /* Change uid and gid */

            /* Setup environment */
            create_pid_file(g_config);

            {
                /**
                 * Start main loop
                 *
                 * @note It never returns.
                 */

                server_run();

                /*
                 * This is NEVER reached.
                 */
            }
            
            break;
        }
        default:
            log_info("run mode: %d", g_config->run_mode);
    }

    config_free(g_config);

    return EXIT_SUCCESS;
}

/** @} */
