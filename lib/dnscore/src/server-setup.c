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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"
#include "dnscore/logger.h"
#include "dnscore/service.h"
#include "dnscore/config_settings.h"
#include "dnscore/fdtools.h"
#include "dnscore/thread_pool.h"
#include "dnscore/logger-output-stream.h"
#include "dnscore/chroot.h"

#include "dnscore/pid.h"
#include "dnscore/identity.h"

#include "dnscore/server-setup.h"
#include "dnscore/mt_output_stream.h"

#include "dnscore/process.h"
#include "dnscore/signals.h"

#include <fcntl.h>
#ifndef WIN32
#include <sys/resource.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#if DNSCORE_HAS_LOG_THREAD_TAG
void thread_tag_log_tags();
#endif

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

/*------------------------------------------------------------------------------
 * FUNCTIONS */
    
static inline void
ttylog_err(const char *format, ...)
{
    va_list args;
    
    
    if(logger_is_running())
    {
        va_start(args, format);
        logger_handle_vmsg(MODULE_MSG_HANDLE, MSG_ERR, format, args);
        va_end(args);
        logger_flush();
    }
    // else 
    {
        flushout();
        osprint(termerr, "error: ");
        va_start(args, format);
        vosformat(termerr, format, args);
        va_end(args);
        osprintln(termerr, "");
        flusherr();
    }
}

/** \brief Damonize the program and set the correct system limitations
 *
 *  @param[in] config is a config_data structure needed for \b "pid file"
 *
 *  @return OK
 *  @return Otherwise log_quit will stop the program
 */
int
server_setup_daemon_go_ex(bool parent_exit, bool child_logger_ownership)
{
#ifndef WIN32
    mode_t                                                         mask = 0;
    pid_t                                                               pid;
    struct sigaction                                                     sa;

    /*    ------------------------------------------------------------    */

    log_info("daemonizing");
    
    if(!config_logger_isconfigured())
    {
        osformatln(termerr, "warning: daemonize enabled with default logging on tty output, no output will be available.");
        flusherr();
    }

    log_debug("daemonize: stop timer");
    logger_flush();
    
    dnscore_stop_timer();

    log_debug("daemonize: stop services");
    logger_flush();
    
    service_stop_all();
    
    log_debug("daemonize: stop thread pools");
    logger_flush();
    
    ya_result error_code;
    
    if(FAIL(error_code = thread_pool_stop_all()))
    {
        osformatln(termerr, "daemonize: unable to stop all thread pools: %r", error_code);
        flusherr();

        exit(EXIT_FAILURE);
    }

#if DNSCORE_HAS_LOG_THREAD_TAG
    thread_tag_log_tags();
#endif
    
    logger_flush();
    logger_stop();

    /* Clear file creation mask */
    umask(mask);

#if DEBUG
    debug_println("releasing ownership of the logger");
    flushout();
#endif

    logger_release_ownership();
    
    /* Become a session leader to lose controlling TTYs */
    if((pid = fork()) < 0)
    {
        osformatln(termerr, "[%i] cannot fork: %r", getpid(), ERRNO_ERROR);
        flusherr();
        
        exit(EXIT_FAILURE);
    }

    // if the logger was running, disconnect ownership from the parent and give it to the child

    if(pid != 0) /* parent */
    {
#if DEBUG
        formatln("[%i] first level parent done", getpid());
        flushout();
#endif
        if(parent_exit)
        {
            exit(EXIT_SUCCESS);
        }

        // else re-enable everything and return

        logger_start();

#if DNSCORE_HAS_LOG_THREAD_TAG
        thread_tag_log_tags();
#endif
        dnscore_reset_timer();
        thread_pool_start_all();
        service_start_all();
        logger_flush();

        return pid;
    }

    /* Set program in new session */
    setsid();

#ifndef WIN32
    /* Ensure future opens won't allocate controlling TTYs */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags   = 0;

    if(sigaction(SIGHUP, &sa, NULL) < 0)
    {
        osformatln(termerr, "sigaction error: %r", ERRNO_ERROR);
        flusherr();
        
        exit(EXIT_FAILURE);
    }
#endif

    /* Stevens way of detaching the program from the parent process,
     * forking twice
     */
    if((pid = fork()) < 0)
    {
        osformatln(termerr, "cannot fork (2nd level): %r", ERRNO_ERROR);
        flusherr();
        
        exit(EXIT_FAILURE);
    }

    if(pid != 0) /* parent */
    {
#if DEBUG
        formatln("[%i] second level parent done", getpid());
        flushout();
#endif
        exit(EXIT_SUCCESS);
    }

#if DEBUG
    debug_osformatln(termout, "taking ownership of the logger (%i)", getpid());
    flushout();
#endif

    g_pid = getpid();

    if(child_logger_ownership)
    {
        logger_take_ownership(getpid());
    }

    logger_start();

#if DNSCORE_HAS_LOG_THREAD_TAG
    thread_tag_log_tags();
#endif

    log_debug("daemonize: start timer");
    
    dnscore_reset_timer();

#if DEBUG
    // It has been asked to fix the "tmpfile vulnerability" on DEBUG builds.
    // Although this mode is meant for us (Gery & I), we can imagine that
    // someone else could have some interest in it too.
    // So the output file name now includes high-precision time and PID and
    // will break if the file exists already.
    // Later, the "server" part will also be modifiable by the caller.

    char output_file[PATH_MAX];
    snformat(output_file, sizeof(output_file), "/tmp/server-%013x-%05x.std.txt", timeus(), getpid());
    debug_osformatln(termout,"redirecting all to '%s'\n", output_file);
    int file_flags = O_RDWR|O_CREAT|O_EXCL; // ensure no overwrite
#else
    const char *output_file  = "/dev/null";
    int file_flags = O_RDWR;
#endif

    /* Attach file descriptors 0, 1, and 2 to /dev/null */

    flushout();
    flusherr();

    int tmpfd;
    if((tmpfd = open_create_ex(output_file, file_flags, 0660)) < 0)
    {
        fprintf(stderr, "couldn't get file for redirection: %s '%s'\n", strerror(errno), output_file);
        fflush(NULL);
        exit(EXIT_FAILURE);
    }

    int tmpfdin;

#if DEBUG
    if((tmpfdin = open_create_ex("/dev/null", O_WRONLY, 0440)) < 0)
    {
        fprintf(stderr, "couldn't get file for redirection: %s '%s'\n", strerror(errno), output_file);
        fflush(NULL);
        exit(EXIT_FAILURE);
    }
#else
    tmpfdin = tmpfd;
#endif

    {
        int fd;
        if((fd = dup2_ex(tmpfdin, 0)) < 0)
        {
            log_err("dup2 failed from %i to %i: %s", tmpfdin, 0, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if(fd != 0)
        {
            log_err("expected fd %d instead of %d", 0, fd);
            exit(EXIT_FAILURE);
        }
    }

    for(int i = 1; i <= 2; i++)
    {
        int fd;
        if((fd = dup2_ex(tmpfd, i)) < 0)
        {
            log_err("dup2 failed from %i to %i: %s", tmpfd, i, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if(fd != i)
        {
            log_err("expected fd %d instead of %d", i, fd);
            exit(EXIT_FAILURE);
        }
    }

#if DEBUG
    debug_osformatln(termout, "detaching from console");
    flushout();
#endif



    log_debug("daemonize: start thread pools");
    
    thread_pool_start_all();
    
    log_debug("daemonize: start services");
    
    service_start_all();
    
    /* Change the current working directory to the root so
     * we won't prevent file systems from being unmounted.
     */

#if DEBUG
    debug_println("daemonized");
    flushout();
#endif

    log_info("daemonized");
    
    logger_flush();

    return pid;
#else
    return 0;
#endif
}

void
server_setup_daemon_go()
{
    server_setup_daemon_go_ex(TRUE, TRUE);
}

/// @NOTE 20201105 edf -- pid_file_pathp must be a char** because of managed paths, it cannot be a const char** either

ya_result
server_setup_env(pid_t *pid, char ** pid_file_pathp, uid_t uid, gid_t gid, u32 setup_flags)
{
    ya_result                                    return_code;

    if((pid == NULL) || (pid_file_pathp == NULL) || (*pid_file_pathp == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#ifndef WIN32
    if(setup_flags & SETUP_CORE_LIMITS)
    {
        struct rlimit core_limits = {RLIM_INFINITY, RLIM_INFINITY};

        if(setrlimit(RLIMIT_CORE, &core_limits) < 0)
        {
            ttylog_err("unable to set core dump limit: %r", ERRNO_ERROR);
        }
#if DEBUG
        else
        {
            log_debug("core no-limit set");
        }
#endif
    }

    if(setup_flags & SETUP_ROOT_CHANGE)
    {
        log_info("going to jail");

        if(FAIL(return_code = chroot_jail()))  /* Chroot to new path */
        {
            log_err("failed to jail: %r");
            return return_code;
        }
    }

    if(setup_flags & SETUP_ID_CHANGE)
    {
        /* Change uid and gid */

        if(FAIL(return_code = identity_change(uid, gid)))
        {
            ttylog_err("unable to change identity: %r", return_code);

            return return_code;
        }
    }


    if(setup_flags & SETUP_CREATE_PID_FILE)
    {
        /* Setup environment */

        if(FAIL(return_code = pid_file_create(pid, *pid_file_pathp, uid, gid)))
        {
            ttylog_err("unable to create pid file '%s': %r", *pid_file_pathp, return_code);

            return return_code;
        }
    }
#endif
    return SUCCESS;
}

/** @} */

