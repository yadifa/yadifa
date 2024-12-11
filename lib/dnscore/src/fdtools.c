/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/sys_types.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/statvfs.h>

#define FDTOOLS_C_ 1

#include "dnscore/fdtools.h"
#include "dnscore/zalloc.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/timems.h"
#include "dnscore/logger.h"
#include "dnscore/mutex.h"
#include "dnscore/error_state.h"

/* GLOBAL VARIABLES */

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#if DEBUG
#define DEBUG_FD_OPEN_CLOSE_MONITOR 0
#else
#define DEBUG_FD_OPEN_CLOSE_MONITOR 0
#endif

#define FDTRACK_TAG 0x4b434152544446

#if DEBUG
// avoids logging these operations in the logger.
// this prevents a self-deadlock if the logger limit is reached (2^20 lines)
bool logger_is_self();
#endif

#if DEBUG
static void admin_warn(const char *pathname)
{
    uid_t uid = getuid();
    uid_t euid = getuid();
    gid_t gid = getgid();
    gid_t egid = getegid();

    bool  is_admin = (uid == 0) || (euid == 0) || (gid == 0) || (egid == 0);

    if(is_admin)
    {
        printf("It is unlikely file or directory creation should be made as an admin '%s' (DEBUG)\n", pathname);
        fflush(NULL);
    }
}
#endif

error_state_t nospace_error_state = ERROR_STATE_INITIALIZER;

#if DEBUG_FD_OPEN_CLOSE_MONITOR

// file descriptor track enabled

#include "dnscore/u32_treemap.h"
#include "dnscore/zalloc.h"
#include "dnscore/error_state.h"

static group_mutex_t fd_mtx = GROUP_MUTEX_INITIALIZER;

static u32_treemap_t fd_to_name = U32_TREEMAP_EMPTY;

struct fd_track
{
    stacktrace opener;
    stacktrace closer;
    char       name[256];
};

typedef struct fd_track fd_track;

static void             fd_set_name(int fd, const char *name)
{
    fd_track *track;

    group_mutex_lock(&fd_mtx, GROUP_MUTEX_WRITE);

    log_debug6("file descriptor: %i is '%s'", fd, name);

    u32_treemap_node_t *node = u32_treemap_insert(&fd_to_name, fd);

    if(node->value == NULL)
    {
        ZALLOC_OBJECT_OR_DIE(track, fd_track, FDTRACK_TAG);
        node->value = track;
        track->opener = 0;
        track->closer = 0;
        track->name[0] = '\0';
    }
    else
    {
        track = (fd_track *)node->value;
        if(track->name[0] != '\0')
        {
            log_err("file descriptor: %i was associated with '%s'", fd, track->name);
        }
    }

    strcpy_ex(track->name, name, sizeof(track->name));
    track->opener = debug_stacktrace_get();
    track->name[sizeof(track->name) - 1] = '\0';

    group_mutex_unlock(&fd_mtx, GROUP_MUTEX_WRITE);
}

static void fd_clear_name(int fd)
{
    group_mutex_lock(&fd_mtx, GROUP_MUTEX_WRITE);

    u32_treemap_node_t *node = u32_treemap_find(&fd_to_name, fd);
    if(node != NULL)
    {
        yassert(node->value != NULL);

        fd_track  *track = (fd_track *)node->value;
        stacktrace st = debug_stacktrace_get();

        if(track->name[0] != '\0')
        {
            log_debug6("file descriptor: %i is '%s' no more", fd, track->name);
        }
        else
        {
            log_debug6("file descriptor: %i is being closed by", fd);
            debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_DEBUG6, st);
            log_debug6("file descriptor: %i was closed already by", fd);
            debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_DEBUG6, track->closer);
            log_debug6("file descriptor: %i was last opened by", fd);
            debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_DEBUG6, track->opener);
        }

        track->closer = st;

        track->name[0] = '\0';
    }
    else
    {
        stacktrace st = debug_stacktrace_get();

        log_debug6("file descriptor: %i is untracked and is being closed by", fd);
        debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_DEBUG6, st);
    }

    group_mutex_unlock(&fd_mtx, GROUP_MUTEX_WRITE);
}
#endif

/**
 * Writes fully the buffer to the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t writefully(int fd, const void *buf, size_t count)
{
    const uint8_t *start = (const uint8_t *)buf;
    const uint8_t *current = start;
    ssize_t        n;
    bool           nospace = false;

    while(count > 0)
    {
        if((n = write(fd, current, count)) <= 0)
        {
            if(n == 0)
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN) /** @note It is nonsense to call writefully with a non-blocking fd */
            {
                if(current - start > 0)
                {
                    continue;
                }

                if(nospace)
                {
                    error_state_clear_locked(&nospace_error_state, NULL, 0, NULL);
                }

                return MAKE_ERRNO_ERROR(ETIMEDOUT);
            }

            if(err == ENOSPC)
            {
                // the disk is full : wait a bit, hope the admin catches it, try again later
                if(error_state_log_locked(&nospace_error_state, MAKE_ERRNO_ERROR(ENOSPC)))
                {
                    log_err("filesystem full for file descriptor %i", fd);
                }
                nospace = true;
                sleep((rand() & 7) + 1);
                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            if(nospace)
            {
                error_state_clear_locked(&nospace_error_state, NULL, 0, NULL);
            }

            return MAKE_ERRNO_ERROR(err);
        }

        current += n;
        count -= n;
    }

    if(nospace)
    {
        error_state_clear_locked(&nospace_error_state, NULL, 0, NULL);
    }

    return current - start;
}

/**
 * Reads fully the buffer from the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t readfully(int fd, void *buf, size_t length)
{
    uint8_t *start = (uint8_t *)buf;
    uint8_t *current = start;
    ssize_t  n;

    while(length > 0)
    {
        if((n = read(fd, current, length)) <= 0)
        {
            if(n == 0) // end of file
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN) /** @note It is nonsense to call readfully with a non-blocking fd */
            {
                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            return -1;
        }

        current += n;
        length -= n;
    }

    return current - start;
}

/**
 * Writes fully the buffer to the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t writefully_limited(int fd, const void *buf, size_t count, double minimum_rate_us)
{
    const uint8_t *start = (const uint8_t *)buf;
    const uint8_t *current = start;
    ssize_t        n;
    bool           nospace = false;

    uint64_t       tstart = timeus();

    // ASSUMED : timeout set on fd for read & write

    while(count > 0)
    {
        if((n = write(fd, current, count)) <= 0)
        {
            if(n == 0)
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN)
            {
                /*
                 * Measure the current elapsed time
                 * Measure the current bytes
                 * compare with the minimum rate
                 * act on it
                 */

                /* t is in us */

                uint64_t now = timeus();

                uint64_t time_elapsed_u64 = now - tstart;

                if(time_elapsed_u64 >= ONE_SECOND_US)
                {
                    double time_elapsed_us = time_elapsed_u64;

                    double bytes_written = (current - (uint8_t *)buf) * ONE_SECOND_US_F;

                    double expected_bytes_written = minimum_rate_us * time_elapsed_us;

                    if(bytes_written < expected_bytes_written) /* bytes/time < minimum_rate */
                    {
                        if(nospace)
                        {
                            error_state_clear_locked(&nospace_error_state, NULL, 0, NULL);
                        }
#if DEBUG
                        log_warn("writefully_limited: rate of %fBps < %fBps (%fµs)", bytes_written, expected_bytes_written, time_elapsed_us);
#else
                        log_debug("writefully_limited: rate of %fBps < %fBps (%fµs)", bytes_written, expected_bytes_written, time_elapsed_us);
#endif
                        return TCP_RATE_TOO_SLOW;
                    }
                }

                continue;
            }

            if(err == ENOSPC)
            {
                // the disk is full : wait a bit, hope the admin catches it, try again later
                if(error_state_log_locked(&nospace_error_state, MAKE_ERRNO_ERROR(ENOSPC)))
                {
                    log_err("filesystem full for file descriptor %i", fd);
                }
                nospace = true;
                sleep((rand() & 7) + 1);
                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            if(nospace)
            {
                error_state_clear_locked(&nospace_error_state, NULL, 0, NULL);
            }

            return ERROR;
        }

        current += n;
        count -= n;
    }

    if(nospace)
    {
        error_state_clear_locked(&nospace_error_state, NULL, 0, NULL);
    }

    return current - start;
}

int sendfully_limited(int fd, const void *buf, int count, int flags, double minimum_rate_us)
{
    const uint8_t *start = (const uint8_t *)buf;
    const uint8_t *current = start;
    ssize_t        n;

    uint64_t       tstart = timeus();

    // ASSUMED : timeout set on fd for read & write

    while(count > 0)
    {
        if((n = send(fd, current, count, flags)) <= 0)
        {
            if(n == 0)
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN)
            {
                /*
                 * Measure the current elapsed time
                 * Measure the current bytes
                 * compare with the minimum rate
                 * act on it
                 */

                /* t is in us */

                uint64_t now = timeus();

                uint64_t time_elapsed_u64 = now - tstart;

                if(time_elapsed_u64 >= ONE_SECOND_US)
                {
                    double time_elapsed_us = time_elapsed_u64;

                    double bytes_written = (current - (uint8_t *)buf) * ONE_SECOND_US_F;

                    double expected_bytes_written = minimum_rate_us * time_elapsed_us;

                    if(bytes_written < expected_bytes_written) /* bytes/time < minimum_rate */
                    {
#if DEBUG
                        log_warn("writefully_limited: rate of %fBps < %fBps (%fµs)", bytes_written, expected_bytes_written, time_elapsed_us);
#else
                        log_debug("writefully_limited: rate of %fBps < %fBps (%fµs)", bytes_written, expected_bytes_written, time_elapsed_us);
#endif
                        return TCP_RATE_TOO_SLOW;
                    }
                }

                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            return -1;
        }

        current += n;
        count -= n;
    }

    return current - start;
}

/**
 * Reads fully the buffer from the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t readfully_limited(int fd, void *buf, size_t count, double minimum_rate_us)
{
    uint8_t *start = (uint8_t *)buf;
    uint8_t *current = start;
    ssize_t  n;

    uint64_t tstart = timeus();

    // ASSUME : timeout set on fd for read & write

    while(count > 0)
    {
        if((n = read(fd, current, count)) <= 0)
        {
            if(n == 0)
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN) /** @note It is nonsense to call readfully with a non-blocking fd */
            {
                /*
                 * Measure the current elapsed time
                 * Measure the current bytes
                 * compare with the minimum rate
                 * act on it
                 */

                uint64_t now = timeus();

                /* t is in us */

                uint64_t time_elapsed_u64 = now - tstart;

                double   time_elapsed_us = time_elapsed_u64;

                if(time_elapsed_u64 >= ONE_SECOND_US)
                {
                    double bytes_read = (current - (uint8_t *)buf) * ONE_SECOND_US_F;

                    double expected_bytes_read = minimum_rate_us * time_elapsed_us;

                    if(bytes_read < expected_bytes_read) // bytes/time < minimum_rate
                    {
                        time_elapsed_us /= 1000000.0;
#if DEBUG
                        log_warn("readfully_limited: rate of %fBps < %fBps (%fµs) (DEBUG)", bytes_read, expected_bytes_read, time_elapsed_us);
#else
                        log_debug("readfully_limited: rate of %fBps < %fBps (%fµs)", bytes_read, expected_bytes_read, time_elapsed_us);
#endif
                        return TCP_RATE_TOO_SLOW;
                    }
                }

                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            return -1; /* EOF */
        }

        current += n;
        count -= n;
    }

    return current - start;
}

/**
 * Reads fully the buffer from the fd or up until timeout_seconds has elapsed
 * The socket need to have a read timeout applied.
 * It will only return a short count for system errors.
 *
 * ie: fs full, fd invalid/closed, ...
 */

ssize_t readfully_ex(int fd, void *buf, size_t length, int timeout_seconds)
{
    uint8_t *start = (uint8_t *)buf;
    uint8_t *current = start;
    ssize_t  n;

    int64_t  ts_start = timeus();

    while(length > 0)
    {
        if((n = read(fd, current, length)) <= 0)
        {
            if(n == 0) // end of file
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN) /** @note It is nonsense to call readfully with a non-blocking fd */
            {
                int64_t ts_stop = timeus();
                int64_t dt_s = (ts_stop - ts_start) / ONE_SECOND_US;
                if(dt_s >= timeout_seconds)
                {
                    return MAKE_ERRNO_ERROR(ETIMEDOUT);
                }
                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            return -1;
        }

        current += n;
        length -= n;
    }

    return current - start;
}

/**
 * Reads fully the buffer from the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t readfully_limited_ex(int fd, void *buf, size_t count, int64_t timeout_us, double minimum_rate_us)
{
    uint8_t *start = (uint8_t *)buf;
    uint8_t *current = start;
    ssize_t  n;

    if(timeout_us <= 0)
    {
        timeout_us = 1;
    }

    int64_t tstart = timeus();

    // ASSUME : timeout set on fd for read & write

    while(count > 0)
    {
        if((n = read(fd, current, count)) <= 0)
        {
            if(n == 0)
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN) /** @note It is nonsense to call readfully with a non-blocking fd */
            {
                /*
                 * Measure the current elapsed time
                 * Measure the current bytes
                 * compare with the minimum rate
                 * act on it
                 */

                int64_t now = timeus();

                /* t is in us */

                int64_t time_elapsed_u64 = now - tstart;

                double  time_elapsed_us = time_elapsed_u64;

                if(time_elapsed_u64 >= timeout_us)
                {
                    double bytes_read = (current - (uint8_t *)buf);
                    bytes_read *= ONE_SECOND_US_F;
                    bytes_read /= time_elapsed_u64;

                    double expected_bytes_read = minimum_rate_us * time_elapsed_us;

                    if(bytes_read < expected_bytes_read) // bytes/time < minimum_rate
                    {
                        time_elapsed_us /= 1000000.0;
#if DEBUG
                        log_warn("readfully_limited: rate of %fBps < %fBps (%fµs) (DEBUG)", bytes_read, expected_bytes_read, time_elapsed_us);
#else
                        log_debug("readfully_limited: rate of %fBps < %fBps (%fµs)", bytes_read, expected_bytes_read, time_elapsed_us);
#endif
                        return TCP_RATE_TOO_SLOW;
                    }
                }

                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            return -1; /* EOF */
        }

        current += n;
        count -= n;
    }

    return current - start;
}

int recvfully_limited_ex(int fd, void *buf, int count, int flags, int64_t timeout_us, double minimum_rate_us)
{
    uint8_t *start = (uint8_t *)buf;
    uint8_t *current = start;
    ssize_t  n;

    if(timeout_us <= 0)
    {
        timeout_us = 1;
    }

    int64_t tstart = timeus();

    // ASSUME : timeout set on fd for recv & write

    while(count > 0)
    {
        if((n = recv(fd, current, count, flags)) <= 0)
        {
            if(n == 0)
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN) /** @note It is nonsense to call recvfully with a non-blocking fd */
            {
                /*
                 * Measure the current elapsed time
                 * Measure the current bytes
                 * compare with the minimum rate
                 * act on it
                 */

                int64_t now = timeus();

                /* t is in us */

                int64_t time_elapsed_u64 = now - tstart;

                double  time_elapsed_us = time_elapsed_u64;

                if(time_elapsed_u64 >= timeout_us)
                {
                    double bytes_recv = (current - (uint8_t *)buf);
                    bytes_recv *= ONE_SECOND_US_F;
                    bytes_recv /= time_elapsed_u64;

                    double expected_bytes_recv = minimum_rate_us * time_elapsed_us;

                    if(bytes_recv < expected_bytes_recv) // bytes/time < minimum_rate
                    {
                        time_elapsed_us /= 1000000.0;
#if DEBUG
                        log_warn("recvfully_limited: rate of %fBps < %fBps (%fµs) (DEBUG)", bytes_recv, expected_bytes_recv, time_elapsed_us);
#else
                        log_debug("recvfully_limited: rate of %fBps < %fBps (%fµs)", bytes_recv, expected_bytes_recv, time_elapsed_us);
#endif
                        return TCP_RATE_TOO_SLOW;
                    }
                }

                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            return -1; /* EOF */
        }

        current += n;
        count -= n;
    }

    return current - start;
}

/**
 * Reads an ASCII text line from fd, stops at EOF or '\n'
 */

ssize_t readtextline(int fd, char *start, size_t count)
{
    char             *current = start;
    const char *const limit = &start[count];

    while(current < limit)
    {
        ssize_t n;

        if((n = read(fd, current, 1)) > 0)
        {
            uint8_t c = *current;

            current++;
            count--;

            if(c == '\n')
            {
                break;
            }
        }
        else
        {
            if(n == 0)
            {
                break;
            }

            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            if(err == EAGAIN)
            {
                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            return -1;
        }
    }

    return current - start;
}

/**
 * Deletes a file (see man 2 unlink).
 * Handles EINTR and other retry errors.
 * Safe to use in the logger thread as it only logs (debug) if the current
 * thread is not the logger's
 *
 * @param fd
 * @return
 */

#if __windows__
#define UNIX_TO_DOS_PATH(name__, name_tmp__)                                                                                                                                                                                                   \
    char *name_tmp__ = stack_alloc(strlen((name__)) + 1);                                                                                                                                                                                      \
    for(size_t i = 0;; ++i)                                                                                                                                                                                                                    \
    {                                                                                                                                                                                                                                          \
        name_tmp__[i] = (name__[i] != '/') ? name__[i] : '\\';                                                                                                                                                                                 \
        if(name__[i] == '\0')                                                                                                                                                                                                                  \
            break;                                                                                                                                                                                                                             \
    }                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                         \
    {                                                                                                                                                                                                                                          \
    } while(0)
#endif

int unlink_ex(const char *folder, const char *filename)
{
    char   fullpath[PATH_MAX];

    size_t l0 = strlen(folder);
    size_t l1 = strlen(filename);
    if(l0 + l1 < sizeof(fullpath))
    {
        memcpy(fullpath, folder, l0);
        fullpath[l0] = '/';
        memcpy(&fullpath[l0 + 1], filename, l1);
        fullpath[l0 + 1 + l1] = '\0';

        return unlink(fullpath);
    }
    else
    {
        errno = ENOMEM;
        return -1;
    }
}

/**
 * Copies the absolute path of a file into a buffer (canonises).
 *
 * Note: it's to canonise the filename.
 *
 * @param filename the file name
 * @param buffer the output buffer
 * @param buffer_size the size of the output buffer
 * @return the string length (without the terminator)
 */

ya_result file_get_absolute_path(const char *filename, char *buffer, size_t buffer_size)
{
    ya_result ret;

    if(filename[0] == '/')
    {
        strcpy_ex(buffer, filename, buffer_size);
        ret = strlen(buffer);
        return ret;
    }
    else
    {
        if(getcwd(buffer, buffer_size) == NULL)
        {
            return ERRNO_ERROR;
        }

        size_t n = strlen(buffer);

        if(n < buffer_size)
        {
            ret = n + 1;

            buffer += n;
            buffer_size -= n;

            *buffer++ = '/';
            --buffer_size;

            n = strlen(filename);
            if(n < buffer_size)
            {
                memcpy(buffer, filename, n);
                buffer[n] = '\0';

                return ret + n;
            }
        }

        return BUFFER_WOULD_OVERFLOW; // not enough room
    }
}

/**
 * Copies the absolute path of the file parent directory in the buffer.
 *
 * @param filename the filename, with or without an absolute or relative path
 * @param buffer the destination buffer
 * @param buffer_size the destination buffer size
 */

ya_result file_get_absolute_parent_directory(const char *filename, char *buffer, size_t buffer_size)
{
    char *last_separator = strrchr(filename, '/');
    if(last_separator != NULL)
    {
        if(filename[0] != '/')
        {
            if(getcwd(buffer, buffer_size) == NULL)
            {
                return ERRNO_ERROR;
            }
            size_t basedir_size = strlen(buffer);
            buffer_size -= basedir_size;
            buffer += basedir_size;
        }

        // note: no '/' yet at the end

        size_t basedir_size = last_separator - filename;
        if(basedir_size + 1 > buffer_size) // + 1 to take the '/' into account
        {
            return BUFFER_WOULD_OVERFLOW;
        }
        if(filename[0] != '/')
        {
            *buffer++ = '/';
        }
        memcpy(buffer, filename, basedir_size);
        buffer[basedir_size] = '\0';
        return SUCCESS;
    }
    else
    {
        if(getcwd(buffer, buffer_size) != NULL)
        {
            return SUCCESS;
        }
        else
        {
            return BUFFER_WOULD_OVERFLOW;
        }
    }
}

#if DEBUG_BENCH_FD
static debug_bench_t debug_open;
static debug_bench_t debug_open_create;
static debug_bench_t debug_close;
static bool          fdtools_debug_bench_register_done = false;

static inline void   fdtools_debug_bench_register()
{
    if(!fdtools_debug_bench_register_done)
    {
        fdtools_debug_bench_register_done = true;
        debug_bench_register(&debug_open, "open");
        debug_bench_register(&debug_open_create, "open_create");
        debug_bench_register(&debug_close, "close");
    }
}
#endif

/**
 * Opens a file. (see man 2 open)
 * Handles EINTR and other retry errors.
 * Safe to use in the logger thread as it only logs (debug) if the current
 * thread is not the logger's
 *
 * @param fd
 * @return
 */

ya_result open_ex(const char *pathname, int flags)
{
    int fd;

#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
        log_debug6("open_ex(%s,%o)", STRNULL(pathname), flags);
        errno = 0;
    }
#endif

    yassert(pathname != NULL);

#if DEBUG_BENCH_FD
    fdtools_debug_bench_register();
    uint64_t bench = debug_bench_start(&debug_open);
#endif

#if DNSCORE_FDTOOLS_CLOEXEC
    bool cloexec = (flags & O_CLOEXEC) != 0;
    flags &= ~O_CLOEXEC;
#endif

    while((fd = open(pathname, flags, 0644)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            // do NOT set this to an error code other than -1
            // fd = MAKE_ERRNO_ERROR(err);
            break;
        }
    }

#if DNSCORE_FDTOOLS_CLOEXEC
    if((fd >= 0) && cloexec)
    {
        ya_result ret;

        if(FAIL(ret = fd_setcloseonexec(fd)))
        {
            log_warn("open_ex(%s,%o): failed to set CLOEXEC: %r", STRNULL(pathname), flags | O_CLOEXEC, ret);
        }
    }
#endif

#if DEBUG_BENCH_FD
    debug_bench_stop(&debug_open, bench);
#endif

#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
        log_debug6("open_ex(%s,%o): %r (%i)", STRNULL(pathname), flags, ERRNO_ERROR, fd);
#if DEBUG_FD_OPEN_CLOSE_MONITOR
        if(fd > 0)
        {
            fd_set_name(fd, pathname);
        }
#endif
    }
#endif

    return fd;
}

/**
 * Opens a file, create if it does not exist. (see man 2 open with O_CREAT)
 * Handles EINTR and other retry errors.
 * Safe to use in the logger thread as it only logs (debug) if the current
 * thread is not the logger's
 *
 * @param fd
 * @return
 */

ya_result open_create_ex(const char *pathname, int flags, mode_t mode)
{
    int fd;

    /// @note do NOT : flags |= O_CREAT;

#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
        log_debug6("open_create_ex(%s,%o,%o)", STRNULL(pathname), flags, mode);
        errno = 0;
    }
#endif

#if DEBUG
    admin_warn(pathname);
#endif

    yassert(pathname != NULL);

#if DEBUG_BENCH_FD
    fdtools_debug_bench_register();
    uint64_t bench = debug_bench_start(&debug_open_create);
#endif

    while((fd = open(pathname, flags | O_CREAT, mode)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            // do NOT set this to an error code other than -1
            // fd = MAKE_ERRNO_ERROR(err);
            break;
        }
    }

#if DEBUG_BENCH_FD
    debug_bench_stop(&debug_open_create, bench);
#endif

#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
        log_debug6("open_create_ex(%s,%o,%o): %r (%i)", STRNULL(pathname), flags, mode, ERRNO_ERROR, fd);
#if DEBUG_FD_OPEN_CLOSE_MONITOR
        if(fd > 0)
        {
            fd_set_name(fd, pathname);
        }
#endif
    }
#endif

    return fd;
}

int mkstemp_ex(char *tmp_name_template)
{
#if __unix__
    int fd = mkstemp(tmp_name_template);
#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
#if DEBUG_FD_OPEN_CLOSE_MONITOR
        if(fd > 0)
        {
            fd_set_name(fd, tmp_name_template);
        }
#endif
    }
#endif
    return fd;
#else
    size_t len = strlen(tmp_name_template);
    if(len < 6)
    {
        return -1;
    }

    for(;;)
    {
        for(int_fast32_t i = len - 6; i < len; ++i)
        {
            tmp_name_template[i] = (rand() % 26) + 'A';
        }
        if(!file_exists(tmp_name_template))
        {
            int fd = open_create_ex(tmp_name_template, O_RDWR | _O_SHORT_LIVED | _O_TEMPORARY, 0600);
#if DEBUG
            if(!logger_is_self() && logger_is_running())
            {
#if DEBUG_FD_OPEN_CLOSE_MONITOR
                if(fd > 0)
                {
                    fd_set_name(fd, tmp_name_template);
                }
#endif
            }
#endif

            return fd;
        }
    }
#endif
}

/**
 * Opens a file, create if it does not exist. (see man 2 open with O_CREAT)
 * Handles EINTR and other retry errors.
 * This version of open_create_ex does NOT log anything, which is very important sometimes in the logger thread
 *
 * @param fd
 * @return
 */

ya_result open_create_ex_nolog(const char *pathname, int flags, mode_t mode)
{
    int fd;
#if DEBUG
    admin_warn(pathname);
#endif
    while((fd = open(pathname, flags, mode)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            // do NOT set this to an error code other than -1
            // fd = MAKE_ERRNO_ERROR(err);
            break;
        }
    }

    return fd;
}

/**
 * Closes a file descriptor (see man 2 close)
 * Handles EINTR and other retry errors.
 * At return the file will be closed or not closable.
 *
 * @param fd
 * @return
 */

ya_result
#if !DNSCORE_HAS_CLOSE_EX_REF
close_ex(int fd)
#else
close_ex_ref(int *fdp)
#endif
{
    ya_result return_value = SUCCESS;

#if DNSCORE_HAS_CLOSE_EX_REF
    int fd = *fdp;

    if(fd == -2)
    {
        abort();
    }

    *fdp = -2;
#endif

#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
#if DEBUG_FD_OPEN_CLOSE_MONITOR
        if(fd > 0)
        {
            fd_clear_name(fd);
        }
#endif

        log_debug6("close_ex(%i)", fd);
        errno = 0;
    }
#endif

#if DEBUG_BENCH_FD
    fdtools_debug_bench_register();
    uint64_t bench = debug_bench_start(&debug_close);
#endif

    while(close(fd) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            return_value = MAKE_ERRNO_ERROR(err);
            break;
        }
    }
#if DEBUG_BENCH_FD
    debug_bench_stop(&debug_close, bench);
#endif

#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
        log_debug6("close_ex(%i): %r", fd, return_value);
        if(FAIL(return_value))
        {
            logger_flush();
        }
    }
#endif

    return return_value;
}

ya_result
#if !DNSCORE_HAS_CLOSE_EX_REF
socketclose_ex(int fd)
#else
socketclose_ex_ref(int *fdp)
#endif
{
    ya_result return_value = SUCCESS;

#if DNSCORE_HAS_CLOSE_EX_REF
    int fd = *fdp;

    if(fd == -2)
    {
        abort();
    }

    *fdp = -2;
#endif

#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
#if DEBUG_FD_OPEN_CLOSE_MONITOR
        if(fd > 0)
        {
            fd_clear_name(fd);
        }
#endif

        log_debug6("socketclose_ex(%i)", fd);
        errno = 0;
    }
#endif

#if DEBUG_BENCH_FD
    fdtools_debug_bench_register();
    uint64_t bench = debug_bench_start(&debug_close);
#endif

#if __unix__
    while(close(fd) < 0)
#else
    while(closesocket(fd) < 0)
#endif
    {
        int err = errno;

        if(err != EINTR)
        {
            return_value = MAKE_ERRNO_ERROR(err);
            break;
        }
    }
#if DEBUG_BENCH_FD
    debug_bench_stop(&debug_close, bench);
#endif

#if DEBUG
    if(!logger_is_self() && logger_is_running())
    {
        log_debug6("socketclose_ex(%i): %r", fd, return_value);
        if(FAIL(return_value))
        {
            logger_flush();
        }
    }
#endif

    return return_value;
}

/**
 * Closes a file descriptor (see man 2 close)
 * Handles EINTR and other retry errors.
 * At return the file will be closed or not closable.
 *
 * @param fd
 * @return
 */

ya_result
#if !DNSCORE_HAS_CLOSE_EX_REF
close_ex_nolog(int fd)
#else
close_ex_nolog_ref(int *fdp)
#endif
{
    ya_result return_value = SUCCESS;

#if DNSCORE_HAS_CLOSE_EX_REF
    int fd = *fdp;

    if(fd == -2)
    {
        abort();
    }

    *fdp = -2;
#endif

    while(close(fd) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            return_value = MAKE_ERRNO_ERROR(err);
            break;
        }
    }

    return return_value;
}

int fsync_ex(int fd)
{
#if __unix__
    while(fsync(fd) < 0)
    {
        int err = errno;
        if(err != EINTR)
        {
            return ERRNO_ERROR;
        }
    }
#else
    FlushFileBuffers((HANDLE)_get_osfhandle(fd));
#endif
    return SUCCESS;
}

int fdatasync_ex(int fd)
{
#if __unix__
#if defined(__linux__)
    while(fdatasync(fd) < 0)
#else
    while(fsync(fd) < 0)
#endif
    {
        int err = errno;
        if(err != EINTR)
        {
            return ERRNO_ERROR;
        }
    }
#else
    FlushFileBuffers((HANDLE)_get_osfhandle(fd));
#endif
    return SUCCESS;
}

int dup_ex(int fd)
{
    int ret;
    while((ret = dup(fd)) < 0)
    {
        int err = errno;
        if(err != EINTR)
        {
            return ERRNO_ERROR;
        }
    }

    return ret;
}

int dup2_ex(int old_fd, int new_fd)
{
    int ret;
    while((ret = dup2(old_fd, new_fd)) < 0)
    {
        int err = errno;
        if(err != EINTR)
        {
            return ERRNO_ERROR;
        }
    }
#if __windows__
    ret = new_fd;
#endif
    return ret;
}

int truncate_ex(const char *path, off_t len)
{
    int ret;
    while((ret = truncate(path, len)) < 0)
    {
        int err = errno;
        if(err != EINTR)
        {
            return ERRNO_ERROR;
        }
    }

    return ret;
}

int ftruncate_ex(int fd, off_t len)
{
    int ret;
    while((ret = ftruncate(fd, len)) < 0)
    {
        int err = errno;
        if(err != EINTR)
        {
            return ERRNO_ERROR;
        }
    }

    return ret;
}

/**
 * Returns the type of socket.
 *
 * @param fd the file descriptor of the socket
 * @return SOCK_STREAM, SOCK_DGRAM, SOCK_RAW or an errno error code like MAKE_ERRON_ERROR(EBADF) or
 * MAKE_ERRON_ERROR(ENOTSOCK)
 */

ya_result fd_getsockettype(int fd)
{
    int       stype;
    socklen_t stype_len = sizeof(stype);
#if __unix__
    int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &stype, &stype_len);
#else
    int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, (char *)&stype, &stype_len);
#endif

    if(ret >= 0)
    {
        return stype; // SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, ...
    }
    else
    {
        return ERRNO_ERROR; // expecting EBADF or ENOTSOCK
    }
}

#if 0
int filestat(const char* name, struct stat* sp)
{
#if __unix__
    return stat(name, sp);
#else
    UNIX_TO_DOS_PATH(name, name_tmp);
    return stat(name_tmp, sp);
#endif
}
#endif
int64_t filesize(const char *name)
{
    struct stat s;
    if(filestat(name, &s) >= 0) // MUST be stat
    {
        if(S_ISREG(s.st_mode))
        {
            return s.st_size;
        }
        else
        {
            return INVALID_ARGUMENT_ERROR;
        }
    }

    return (int64_t)ERRNO_ERROR;
}

/**
 * Checks for existence of a file/dir/link
 *
 * @param name the file name
 *
 * @return 1 if the file exists, 0 if the file does not exists, an error otherwise
 */

ya_result file_exists(const char *name)
{
    struct stat s;
#if __unix__
    if(lstat(name, &s) >= 0) // MUST be lstat
    {
        return 1;
    }
#else
    if(filestat(name, &s) >= 0) // MUST be stat
    {
        return 1;
    }
#endif

    int err = errno;

    if(err == ENOENT)
    {
        return 0;
    }

    return MAKE_ERRNO_ERROR(err);
}

/**
 *
 * Checks if a file exists and is a link
 *
 * @param name the file name
 *
 * @return  0 : not a link
 *          1 : a link
 *        < 0 : error
 */

ya_result file_is_link(const char *name)
{
#if __unix__
    struct stat s;
    if(lstat(name, &s) >= 0) // MUST be lstat
    {
        return S_ISLNK(s.st_mode) ? 1 : 0;
    }

    return ERRNO_ERROR;
#else
    return 0;
#endif
}

/**
 *
 * Checks if a file exists and is a directory
 *
 * @param name the file name
 *
 * @return  0 : not a link
 *          1 : a link
 *        < 0 : error
 */

ya_result file_is_directory(const char *name)
{
#if __unix__
    struct stat s;
    if(lstat(name, &s) >= 0) // MUST be lstat
    {
        return S_ISDIR(s.st_mode) ? 1 : 0;
    }

    return ERRNO_ERROR;
#else
    return 0;
#endif
}

/**
 *
 * Creates all directories on pathname.
 *
 * Could be optimised a bit :
 *
 *      try the biggest path first,
 *      going down until it works,
 *      then create back up.
 *
 * @param pathname
 * @param mode
 * @param flags
 *
 * @return
 */

int mkdir_ex(const char *pathname, mode_t mode, uint32_t flags)
{
#if DEBUG
    log_debug("mkdir_ex(%s,%o,%x)", pathname, mode, flags);
#endif

#if DEBUG
    admin_warn(pathname);
#endif

    const char *s;
    char       *t;

    char        dir_path[PATH_MAX];

    s = pathname;
    t = dir_path;

    if(pathname[0] == '/')
    {
        t[0] = '/';
        t++;
        s++;
    }

    for(;;)
    {
        const char *p = (const char *)strchr(s, '/');

        bool        last = (p == NULL);

        if(last)
        {
            if(((flags & MKDIR_EX_PATH_TO_FILE) != 0) || (*s == '\0'))
            {
                return s - pathname;
            }

            p = s + strlen(s);
        }

        if(p - s == 0)
        {
            ++s;
            continue;
        }

        intptr_t n = (p - s);
        memcpy(t, s, n);
        t[n] = '\0';

        struct stat file_stat;
        if(filestat(dir_path, &file_stat) < 0)
        {
            int err = errno;

            if(err != ENOENT)
            {
#if DEBUG
                log_debug("mkdir_ex(%s,%o): stat returned %r", pathname, mode, MAKE_ERRNO_ERROR(err));
#endif

                return MAKE_ERRNO_ERROR(err);
            }

#if __unix__
            err = mkdir(dir_path, mode);
#else
            err = mkdir(dir_path);
#endif

            if(err < 0)
            {
#if DEBUG
                log_debug("mkdir_ex(%s,%o): mkdir(%s, %o) returned %r", pathname, mode, dir_path, mode, MAKE_ERRNO_ERROR(err));
#endif

                return ERRNO_ERROR;
            }
        }

        if(last)
        {
            s = &s[n];
            return s - pathname;
        }

        t[n++] = '/';

        t = &t[n];
        s = &s[n];
    }
}

/**
 * Returns the modification time of the file in microseconds
 * This does not mean the precision of the time is that high.
 * This is only to simplify reading the time on a file.
 *
 * @param name the file name
 * @param timestamp a pointer to the timestamp
 * @return an error code
 */

ya_result file_mtime(const char *name, int64_t *timestamp)
{
    struct stat st;
    yassert(name != NULL);
    yassert(timestamp != NULL);
    if(filestat(name, &st) >= 0)
    {
#if __windows__
        int64_t ts = ONE_SECOND_US * st.st_mtime;
#elif !__APPLE__
        int64_t ts = (ONE_SECOND_US * st.st_mtim.tv_sec) + (st.st_mtim.tv_nsec / 1000LL);
#else
        int64_t ts = (ONE_SECOND_US * st.st_mtimespec.tv_sec) + (st.st_mtimespec.tv_nsec / 1000LL);
#endif
        *timestamp = ts;
        return SUCCESS;
    }
    else
    {
        *timestamp = 0;
        return ERRNO_ERROR;
    }
}

/**
 * Returns the modification time of the file in microseconds
 * This does not mean the precision of the time is that high.
 * This is only to simplify reading the time on a file.
 *
 * @param name the file name
 * @param timestamp a pointer to the timestamp
 * @return an error code
 */

ya_result fd_mtime(int fd, int64_t *timestamp)
{
    struct stat st;
    yassert(timestamp != NULL);
    if(fstat(fd, &st) >= 0)
    {
#if __windows__
        int64_t ts = ONE_SECOND_US * st.st_mtime;
#elif !__APPLE__
        int64_t ts = (ONE_SECOND_US * st.st_mtim.tv_sec) + (st.st_mtim.tv_nsec / 1000LL);
#else
        int64_t ts = (ONE_SECOND_US * st.st_mtimespec.tv_sec) + (st.st_mtimespec.tv_nsec / 1000LL);
#endif
        *timestamp = ts;
        return SUCCESS;
    }
    else
    {
        *timestamp = 0;
        return ERRNO_ERROR;
    }
}

ya_result fd_setcloseonexec(int fd)
{
#if __unix__
    int ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
    if(FAIL(ret))
    {
        ret = ERRNO_ERROR;
    }
    return ret;
#else
    return SUCCESS;
#endif
}

ya_result fd_setnonblocking(int fd)
{
#if __unix__
    int ret;
    if(ISOK(ret = fcntl(fd, F_GETFL, 0)))
    {
        fcntl(fd, F_SETFL, ret | O_NONBLOCK);
    }
    else
    {
        ret = ERRNO_ERROR;
    }

    return ret;
#else
    return SUCCESS;
#endif
}

ya_result fd_setblocking(int fd)
{
#if __unix__
    int ret;
    if(ISOK(ret = fcntl(fd, F_GETFL, 0)))
    {
        fcntl(fd, F_SETFL, ret & ~O_NONBLOCK);
    }
    else
    {
        ret = ERRNO_ERROR;
    }

    return ret;
#else
    return SUCCESS;
#endif
}

/**
 * Fixes an issue with the dirent not always set as expected.
 *
 * The type can be set to DT_UNKNOWN instead of file or directory.
 * In that case the function will call stats to get the type.
 */

uint8_t dirent_get_type_from_fullpath(const char *fullpath)
{
    struct stat file_stat;
    uint8_t     d_type;

    d_type = DT_UNKNOWN;

    if(filestat(fullpath, &file_stat) < 0)
    {
        return 0;
    }

    if(S_ISREG(file_stat.st_mode))
    {
        d_type = DT_REG;
    }
    else if(S_ISDIR(file_stat.st_mode))
    {
        d_type = DT_DIR;
    }

    return d_type;
}

uint8_t dirent_get_file_type(const char *folder, const char *name)
{
    uint8_t d_type;
    char    fullpath[PATH_MAX];

    d_type = DT_UNKNOWN;

    /*
     * If the FS OR the OS does not support d_type :
     */

    if(ISOK(snprintf(fullpath, sizeof(fullpath), "%s/%s", folder, name)))
    {
        d_type = dirent_get_type_from_fullpath(fullpath);
    }

    return d_type;
}

// typedef ya_result readdir_callback(const char *basedir, const char* file, uint8_t filetype, void *args);

static group_mutex_t readdir_mutex = GROUP_MUTEX_INITIALIZER;

ya_result            readdir_forall(const char *basedir, readdir_callback *func, void *args)
{
    DIR      *dir;
    ya_result ret;
    size_t    basedir_len = strlen(basedir);
    if(basedir_len == 0)
    {
        basedir = ".";
        basedir_len = 1;
    }
    char *name;
    char  path[PATH_MAX];
    memcpy(path, basedir, basedir_len);
    path[basedir_len] = '/';
    name = &path[basedir_len + 1];

    dir = opendir(basedir);

    if(dir == NULL)
    {
        return ERRNO_ERROR;
    }

    for(;;)
    {
        group_mutex_lock(&readdir_mutex, GROUP_MUTEX_WRITE);
        struct dirent *tmp = readdir(dir);

        if(tmp == NULL)
        {
            group_mutex_unlock(&readdir_mutex, GROUP_MUTEX_WRITE);

            ret = SUCCESS;

            break;
        }

        // ignore names "." and ".."

#if __unix__
        const char *tmp_name = tmp->d_name;
#else
        const char *tmp_name = tmp->name;
#endif

        if(tmp_name[0] == '.')
        {
            if(((tmp_name[1] == '.') && (tmp_name[2] == '\0')) || (tmp_name[1] == '\0'))
            {
                group_mutex_unlock(&readdir_mutex, GROUP_MUTEX_WRITE);
                continue;
            }
        }

        size_t name_len = strlen(tmp_name);

        if(name_len + basedir_len + 1 + 1 > sizeof(path))
        {
            group_mutex_unlock(&readdir_mutex, GROUP_MUTEX_WRITE);
            log_err("readdir_forall: '%s/%s' is bigger than expected (%i): skipping", basedir, tmp_name, sizeof(path));
            continue;
        }

        memcpy(name, tmp_name, name_len + 1);

        group_mutex_unlock(&readdir_mutex, GROUP_MUTEX_WRITE);

        uint8_t d_type = dirent_get_type_from_fullpath(path);
        path[basedir_len] = '\0';
        ret = func(path, name, d_type, args);
        path[basedir_len] = '/';
        if(FAIL(ret))
        {
            closedir(dir);
            return ret;
        }

        switch(ret)
        {
            case READDIR_CALLBACK_CONTINUE:
            {
                break;
            }
            case READDIR_CALLBACK_ENTER:
            {
                if(d_type == DT_DIR)
                {
                    if(FAIL(ret = readdir_forall(path, func, args)))
                    {
                        closedir(dir);
                        return ret;
                    }

                    if(ret == READDIR_CALLBACK_EXIT)
                    {
                        closedir(dir);
                        return ret;
                    }
                }
                break;
            }
            case READDIR_CALLBACK_EXIT:
            {
                closedir(dir);
                return ret;
            }
            default:
            {
                // unhandled code
                break;
            }
        }
    }

    closedir(dir);

    return ret;
}

struct rmdir_ex_args_s
{
    char buffer[PATH_MAX];
};

static ya_result rmdir_ex_readdir(const char *basedir, const char *file, uint8_t filetype, void *args_)
{
    struct rmdir_ex_args_s *args = args_;
    snprintf(args->buffer, sizeof(args->buffer), "%s/%s", basedir, file);
    if(filetype == DT_DIR)
    {
        ya_result ret = readdir_forall(args->buffer, rmdir_ex_readdir, args);
        if(ISOK(ret))
        {
            snprintf(args->buffer, sizeof(args->buffer), "%s/%s", basedir, file);
            if(rmdir(args->buffer) >= 0)
            {
                return SUCCESS;
            }
            else
            {
                return ERRNO_ERROR;
            }
        }
        else
        {
            return ret;
        }
    }
    else // DT_REG
    {
        if(unlink(args->buffer) >= 0)
        {
            return SUCCESS;
        }
        else
        {
            return ERRNO_ERROR;
        }
    }
}

ya_result rmdir_ex(const char *directory, bool recursive)
{
    ya_result ret = SUCCESS;
    if(recursive)
    {
        struct rmdir_ex_args_s args;
        ret = readdir_forall(directory, rmdir_ex_readdir, &args);
    }
    if(ISOK(ret))
    {
        if(rmdir(directory) >= 0)
        {
            return SUCCESS;
        }
        else
        {
            return ERRNO_ERROR;
        }
    }
    return ret;
}

ya_result access_check(const char *path, int mode)
{
    int ret;
#if __unix__
    ret = access(path, mode);
#else
    ret = _access(path, mode);
#endif
    if(ret < 0)
    {
        ret = ERRNO_ERROR;
    }
    return ret;
}

/**
 * Returns the available space in bytes in the filesystem hosting the file.
 *
 * @param path the file in the filesystem
 * @param si a pointer to a storage_info_t structure
 *
 * @return the free size in bytes
 */

int64_t storage_info(const char *path, storage_info_t *si)
{
    struct statvfs s;
    if(statvfs(path, &s) >= 0)
    {
        si->size_total = (int64_t)s.f_frsize * (int64_t)s.f_blocks;
        si->size_free = (int64_t)s.f_bsize * (int64_t)s.f_bavail; // f_bfree is for admin
        si->inodes_total = (int64_t)s.f_files;
        si->inodes_free = (int64_t)s.f_favail; // f_ffree is for admin
        return SUCCESS;
    }
    else
    {
        return ERRNO_ERROR;
    }
}

/** @} */
