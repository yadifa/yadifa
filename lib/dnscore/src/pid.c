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

#include <sys/file.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

#include "dnscore/pid.h"

#include "dnscore/sys_types.h"
#include "dnscore/logger.h"
#include "dnscore/parser.h"
#include "dnscore/fdtools.h"
#include "dnscore/process.h"


/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** \brief Read \b pid \b file, program quits on log_quit
 *
 *  @param[in] path
 *  @param[in] file_name
 *
 *  @retval pid
 *  @retval NOK (negative number),
 *  @return otherwise log_quit will stop the program with correct exit code
 */
pid_t
pid_file_read(const char *pid_file_path)
{
    ssize_t                                                        received;
    int                                                                  fd;
    char                                                                 *p;
    u32                                                                 pid;
    ya_result                                                           ret;
    char                                                      buffer[8 + 1];

    /*    ------------------------------------------------------------    */
    
    yassert(pid_file_path != NULL);

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("pid file '%s': path is bigger than %i", pid_file_path, PATH_MAX);

        return INVALID_PATH;
    }

    if(FAIL(fd = open_ex(pid_file_path, O_RDONLY|O_CLOEXEC)))
    {
        ret = ERRNO_ERROR;

        log_debug("pid file '%s': cannot open: %r", pid_file_path, ret);

        return ret; /* no file found : not running assumed */
    }
    
    received = readfully(fd, buffer, sizeof(buffer) - 1);
    
    if(0 >= received)
    {
        if(received < 0)
        {
            ret = received;
            log_err("pid file '%s': cannot read pid: %r", pid_file_path, ret);
        }
        else
        {
            ret = UNEXPECTED_EOF;
        }

        return ret;
    }
    
    buffer[received] = '\0';    /* Append a terminator for strlen */

    p = buffer;
    while(isdigit(*p)!=0) p++;  /* Cut after the first character that is not a digit (ie: CR LF ...) */
    *p = '\0';

    if(FAIL(ret = parse_u32_check_range(buffer, &pid, 0, MAX_S32, BASE_10)))
    {
        log_err("pid file '%s': invalid pid number: %r", pid_file_path, ret);

        return ret;
    }
    
    close_ex(fd);      /* close the pid file */

    return (pid_t)pid;
}

/** \brief Create or overwrite the \b pid \b file with its new process id
 *
 *  @param[in] config is a config_data structure
 *
 *  @retval OK
 *  @retval YDF_ERROR_CHOWN if can not "chown"
 *  @return otherwise log_quit will stop the program with correct exit code
 */
ya_result
pid_file_create(pid_t *pid, const char *pid_file_path, uid_t new_uid, gid_t new_gid)
{
    ya_result ret;
    int                                                                  fd;
    mode_t                                               permissions = 0644;
#ifndef WIN32
    uid_t                                                    uid = getuid();
#endif
    char                                                         buffer[16];
    pid_t pid_tmp;

    if(pid == NULL)
    {
        pid = &pid_tmp;
    }

    /*    ------------------------------------------------------------    */
    
    yassert(pid_file_path != NULL);

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("pid file '%s': path is bigger than %i", pid_file_path, PATH_MAX);

        return INVALID_PATH;
    }

    *pid           = getpid_ex();
    int buffer_len = snprintf(buffer, sizeof(buffer), "%d\n", *pid); // VS complains for something that's Windows specific and wrong at the moment anyhow.

    yassert(buffer_len > 0);

    fd = open_create_ex(pid_file_path, O_WRONLY | O_CREAT | O_TRUNC, permissions);

    if(fd >= 0)
    {
        for(;;)
        {
#ifndef WIN32
            if(flock(fd, LOCK_EX|LOCK_NB) < 0)
            {
                ret = errno;
                if(ret == EINTR)
                {
                    continue;
                }

                if(ret == EWOULDBLOCK)
                {
                    // already locked
                    close_ex(fd);
                    return PID_LOCKED;
                }
                
                abort();
            }
#endif
            
            break;
        }
        
        if(ISOK(ret = pid_check_running_program(pid_file_path, NULL)))
        {
            // got the lock

            if(writefully(fd, buffer, buffer_len) > 0)
            {
                ret = SUCCESS;
#ifndef WIN32
                if(uid == 0)  // only applicable if you are root
                {
                    if(chown(pid_file_path, new_uid, new_gid) >= 0)
                    {
                        log_debug("pid file '%s': created", pid_file_path);
                    }
                    else
                    {
                        ret = ERRNO_ERROR;
                        log_err("pid file '%s': cannot change owner.group to %i.%i: %r", pid_file_path, new_uid, new_gid, ret);
                        pid_file_destroy(pid_file_path);
                    }
                }
#endif
            }
            else
            {
                ret = ERRNO_ERROR;
                log_err("pid file '%s': cannot write pid: %r", pid_file_path, ret);
                pid_file_destroy(pid_file_path);
            }
        }
    }
    else
    {
        ret = ERRNO_ERROR;
        log_err("pid file '%s': cannot create: %r", pid_file_path, ret);
    }

    close_ex(fd);

    return ret;
}

/** \brief Check if program is already running
 * 
 *  @param[in] config is a config_data structure
 *
 *  @return NONE
 *  @return otherwise log_quit will stop the program with correct exit code
 */
ya_result
pid_check_running_program(const char *pid_file_path, pid_t *out_pid)
{
#ifndef WIN32
    yassert(pid_file_path != NULL);
    pid_t                                                               pid;

    /*    ------------------------------------------------------------    */
    
    yassert(pid_file_path != NULL);

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("pid file '%s': path is bigger than %i", pid_file_path, PATH_MAX);

        return INVALID_PATH;
    }

    if(ISOK(pid = pid_file_read(pid_file_path)))
    {
        if((pid != getpid_ex()) && ((kill(pid, 0) == 0) || (errno == EPERM)))
        {
            if(out_pid != NULL)
            {
                *out_pid = pid;
            }
            return PID_LOCKED;
        }
    }
#endif
    return SUCCESS;
}

void
pid_file_destroy(const char *pid_file_path)
{
    yassert(pid_file_path != NULL);

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("pid file '%s': path is bigger than %i", pid_file_path, PATH_MAX);
        return;
    }
    
    if(FAIL(unlink(pid_file_path)))
    {
        int ret = ERRNO_ERROR;
        
        // don't complain if the file has already been destroyed
        if(ret != ENOENT)
        {
            log_err("pid file '%s': cannot delete: %r", pid_file_path, ret);
        }
    }
}

/** @} */
