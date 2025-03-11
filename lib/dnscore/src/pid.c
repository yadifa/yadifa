/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup
 * @ingroup
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/// @note _FILE_OFFSET_BITS triggers an issue in a test on some old architectures and 64 bits offset aren't required here.

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif
#ifdef _TIME_BITS
#undef _TIME_BITS
#endif

#include "dnscore/dnscore_config.h"

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

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

/**
 * Seeks at 0, reads pid
 *
 * @param fd the file descriptor to use
 * @param pid_file_path the path of the pid file
 * @param pidp a pointer that will be set with the pid from inside the file
 *
 * @return SUCCESS or an error code
 */

ya_result pid_file_read_fd(int fd, const char *pid_file_path, pid_t *pidp)
{
    ssize_t   received;
    char     *p;
    uint32_t  pid;
    ya_result ret;
    char      buffer[8 + 1];

    off_t     offset = lseek(fd, 0, SEEK_SET);

    if(offset < 0)
    {
        ret = ERRNO_ERROR;
        log_err("pid file '%s': cannot seek: %r", pid_file_path, ret);
        return ret;
    }

    received = readfully(fd, buffer, sizeof(buffer) - 1);

    if(received <= 0)
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

    buffer[received] = '\0'; /* Append a terminator for strlen */

    p = buffer;
    while(isdigit(*p) != 0)
    {
        p++; /* Cut after the first character that is not a digit (ie: CR LF ...) */
    }
    *p = '\0';

    ret = parse_u32_check_range(buffer, &pid, 0, INT32_MAX, BASE_10);

    if(FAIL(ret))
    {
        log_err("pid file '%s': invalid pid number: %r", pid_file_path, ret);

        return ret;
    }

    if(pidp != NULL)
    {
        *pidp = pid;
    }

    return SUCCESS;
}

/**
 * Opens and read pid file
 *
 * Made available again for a project still using it.
 *
 * @param pid_file_path the path of the pid file
 * @param pidp a pointer that will be set with the pid from inside the file
 *
 * @return SUCCESS or an error code
 */

ya_result pid_file_read(const char *pid_file_path, pid_t *pidp)
{
    int       fd;
    ya_result ret;

    yassert(pid_file_path != NULL);

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("pid file '%s': path is bigger than %i", pid_file_path, PATH_MAX);
        return INVALID_PATH;
    }

    if(FAIL(fd = open_ex(pid_file_path, O_RDONLY | O_CLOEXEC)))
    {
        ret = ERRNO_ERROR;
        log_debug("pid file '%s': cannot open: %r", pid_file_path, ret);
        return ret; /* no file found : not running assumed */
    }

    for(;;)
    {
#if __unix__
        if(flock(fd, LOCK_EX | LOCK_NB) < 0)
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

            if(ret == EBADF)
            {
                // happened on an NFS mount with an opened file descriptor
                break;
            }

            abort();
        }
#endif

        break;
    }

    ret = pid_file_read_fd(fd, pid_file_path, pidp);

    close_ex(fd);

    return ret;
}

static bool pid_is_running_and_not_myself(pid_t pid)
{
    return ((pid != getpid_ex()) && ((kill(pid, 0) == 0) || (errno == EPERM))); // note: the errno is the one for 'kill'
}

/**
 * Creates or overwrites a pid file with its new process id
 * Doesn't work if another program has already created the pid file
 *
 * @param pid_file_path the path of the pid file
 * @param pidp a pointer that will be set with the pid of the running instance of the program
 * @param new_uid the user owner of the file (if the program runs as root), it's doing a fchown
 * @param new_gid the group owner of the file (if the program runs as root), it's doing a fchown
 *
 * @return SUCCESS or an error code
 */

ya_result pid_file_create(const char *pid_file_path, pid_t *pidp, uid_t new_uid, gid_t new_gid)
{
    ya_result ret;
    int       fd;
    mode_t    permissions = 0644;
#if __unix__
    uid_t uid = getuid();
#endif
    pid_t pid_tmp;
    char  buffer[16];

    if(pidp == NULL)
    {
        pidp = &pid_tmp;
    }

    yassert(pid_file_path != NULL);

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("pid file '%s': path is bigger than %i", pid_file_path, PATH_MAX);
        return INVALID_PATH;
    }

    fd = open_create_ex(pid_file_path, O_RDWR, permissions);

    if(fd >= 0)
    {
        for(;;)
        {
#if __unix__
            if(flock(fd, LOCK_EX | LOCK_NB) < 0)
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

        if(ISOK(ret = pid_file_read_fd(fd, pid_file_path, pidp)))
        {
            if(pid_is_running_and_not_myself(*pidp))
            {
                close_ex(fd);
                return PID_LOCKED;
            }
        }

        // can proceed

        for(;;)
        {
            ret = ftruncate(fd, 0);
            if(ret >= 0)
            {
                break;
            }

            ret = errno;
            if(ret != EINTR)
            {
                close_ex(fd);
                return MAKE_ERRNO_ERROR(ret);
            }
        }

        off_t offset = lseek(fd, 0, SEEK_SET);
        if(offset < 0)
        {
            ret = ERRNO_ERROR;
            log_err("pid file '%s': cannot seek: %r", pid_file_path, ret);
            close_ex(fd);
            return ret;
        }

        *pidp = getpid_ex();
        int buffer_len = snprintf(buffer, sizeof(buffer), "%d\n",
                                  *pidp); // VS complains for something that's Windows specific and wrong at the moment anyhow.

        yassert(buffer_len > 0);

        if(writefully(fd, buffer, buffer_len) > 0)
        {
            ret = SUCCESS;
#if __unix__
            if(uid == 0) // only applicable if you are root
            {
                if(fchown(fd, new_uid, new_gid) >= 0) // avoid race condition (Flawfinder)
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
    else
    {
        ret = ERRNO_ERROR;
        log_err("pid file '%s': cannot create: %r", pid_file_path, ret);
    }

    close_ex(fd);

    return ret;
}

/**
 * Check if program is already running checking the existence of a pid file.
 *
 * @param pid_file_path the path of the pid file
 * @param pidp a pointer that will be set with the pid from inside the file
 *
 * @return SUCCESS if the program doesn't appear to be running.
 * @return an error code (INVALID_PATH or PID_LOCKED)
 */

ya_result pid_check_running_program(const char *pid_file_path, pid_t *out_pid)
{
#if __unix__
    yassert(pid_file_path != NULL);
    ya_result ret;
    pid_t     pid = 0;

    yassert(pid_file_path != NULL);

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("pid file '%s': path is bigger than %i", pid_file_path, PATH_MAX);

        return INVALID_PATH;
    }

    if(ISOK(ret = pid_file_read(pid_file_path, &pid)))
    {
        if(pid_is_running_and_not_myself(pid))
        {
            if(out_pid != NULL)
            {
                *out_pid = pid;
            }
            return PID_LOCKED;
        }
    }
    else
    {
        if(ret == MAKE_ERRNO_ERROR(ENOENT))
        {
            ret = SUCCESS;
        }
    }
    return ret;
#endif
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

/**
 * Deletes a pid file.
 * File is being opened and locked while the deletion occurs. This is to avoid race conditions.
 *
 * @param pid_file_path the path of the pid file
 */

void pid_file_destroy(const char *pid_file_path)
{
    yassert(pid_file_path != NULL);

    ya_result ret;
    int       fd;

    if(strlen(pid_file_path) > PATH_MAX)
    {
        log_err("pid file '%s': path is bigger than %i", pid_file_path, PATH_MAX);
        return;
    }

    if(FAIL(fd = open_ex(pid_file_path, O_RDONLY | O_CLOEXEC)))
    {
        ret = ERRNO_ERROR;

        log_debug("pid file '%s': cannot open: %r", pid_file_path, ret);

        return;
    }

    for(int tries = 50; tries > 0; --tries)
    {
#if __unix__
        if(flock(fd, LOCK_EX | LOCK_NB) < 0)
        {
            ret = errno;
            if(ret == EINTR)
            {
                continue;
            }

            if(ret == EWOULDBLOCK)
            {
                usleep(1000);
                continue;
            }

            if(ret == EBADF)
            {
                // happened on an NFS mount with an opened file descriptor
                break;
            }

            ret = errno;
            log_debug("pid file '%s': error locking: %r", pid_file_path, MAKE_ERRNO_ERROR(ret));
        }
#endif

        break;
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
    close_ex(fd);
}

/** @} */
