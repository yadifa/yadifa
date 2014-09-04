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

#include "dnscore/sys_types.h"
#include "dnscore/logger.h"
#include "dnscore/parser.h"
#include "dnscore/fdtools.h"

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>


/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

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
    int                                                                  fd;
    mode_t                                               permissions = 0644;
    char                                                         buffer[16];

    uid_t                                                    uid = getuid();


    /*    ------------------------------------------------------------    */

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("path %s is too big", pid_file_path);

        exit(EXIT_FAILURE);
    }

    *pid           = getpid();
    int buffer_len = snprintf(buffer, sizeof (buffer), "%d\n", *pid);

    yassert(buffer_len > 0);

    if(FAIL(fd = open_create_ex(pid_file_path, O_WRONLY | O_CREAT | O_TRUNC, permissions)))
    {
        return ERRNO_ERROR;
    }

    if(writefully(fd, buffer, buffer_len) > 0)
    {
        if (uid == 0)  // only applicable if you are root
        {
            if(chown(pid_file_path, new_uid, new_gid) >= 0)
            {
                close_ex(fd);

                log_debug("created pid file: '%s'", pid_file_path);

                return SUCCESS;
            }
            else
            {
                log_err("can't chown '%s' to %s.%s", pid_file_path, new_uid, new_gid);
            }
        }
        else
        {
            return SUCCESS;
        }
    }
    else
    {
        log_err("can't write pid to '%s'", pid_file_path);
    }

    close_ex(fd);

    return ERRNO_ERROR;
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
pid_t
pid_file_read(const char *pid_file_path)
{
    ssize_t                                                        received;
    int                                                                  fd;
    char                                                                 *p;
    u32                                                                 pid;
    char                                                      buffer[8 + 1];

    /*    ------------------------------------------------------------    */

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("path %s is too big", pid_file_path);

        exit(EXIT_FAILURE);
    }

    if(0 > (fd = open_ex(pid_file_path, O_RDONLY)))
    {
        if(errno != ENOENT)
        {
            log_err("can't open '%s': %r", pid_file_path, ERRNO_ERROR);
            exit(EXIT_FAILURE);
        }

        return NOK; /* no file found : not running assumed */
    }

    if(0 > (received = readfully(fd, buffer, sizeof(buffer) - 1)))
    {
        log_err("can't open '%s'", pid_file_path);

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

    if(FAIL(parse_u32_check_range(buffer, &pid, 0, 99999, 10)))
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
ya_result
pid_check_running_program(const char *program_name, const char *pid_file_path)
{
    pid_t                                                               pid;

    /*    ------------------------------------------------------------    */

    if(pid_file_path == NULL)
    {
        log_err("pid file path is wrong");

        return INVALID_PATH;

    }

    if(ISOK(pid = pid_file_read(pid_file_path)))
    {
        if(kill(pid, 0) == 0 || errno == EPERM)
        {
            log_err("%s already running with pid: %lu (%s)", program_name, pid, pid_file_path);

            return PID_LOCKED;
        }
    }

    return SUCCESS;
}

void
pid_file_destroy(const char *pid_file)
{
    if(FAIL(unlink(pid_file)))
    {
        int err = errno;
        
        // don't complain if the file has already been destroyed
        if(err != ENOENT)
        {
            formatln("%s could not be removed (%s)", pid_file, strerror(err));
            flushout();
        }
    }
}


    /*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

