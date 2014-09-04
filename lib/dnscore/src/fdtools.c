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
/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "dnscore/fdtools.h"
#include "dnscore/timems.h"
#include "dnscore/logger.h"

 /* GLOBAL VARIABLES */

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger


/**
 * Writes fully the buffer to the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t
writefully(int fd, const void *buf, size_t count)
{
    const u8* start = (const u8*)buf;
    const u8* current = start;
    ssize_t n;

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
                break;
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

ssize_t
readfully(int fd, void *buf, size_t count)
{
    u8* start = (u8*)buf;
    u8* current = start;
    ssize_t n;

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
                break;
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
 * Writes fully the buffer to the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t
writefully_limited(int fd, const void *buf, size_t count, double minimum_rate)
{
    const u8* start = (const u8*)buf;
    const u8* current = start;
    ssize_t n;

    u64 tstart = timeus();

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
                
                u64 now = timeus();

                double t = (now - tstart);
                double b = (current - (u8*)buf)  * 1000000.;

                if(b < minimum_rate * t)  /* b/t < minimum_rate */
                {                           
                    return TCP_RATE_TOO_SLOW;
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

ssize_t
readfully_limited(int fd, void *buf, size_t count, double minimum_rate)
{
    u8* start = (u8*)buf;
    u8* current = start;
    ssize_t n;

    u64 tstart = timeus();

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

                u64 now = timeus();

                /* t is in us */
                
                double t = (now - tstart);
                double b = (current - (u8*)buf) * 1000000.;

                double expected_rate = minimum_rate * t;
                
                if(b < expected_rate)  /* b/t < minimum_rate */
                {
                    log_debug("readfully_limited: rate of %f < %f (%fµs)", b, expected_rate, t);

                    return TCP_RATE_TOO_SLOW;
                }

                continue;
            }

            if(current - start > 0)
            {
                break;
            }

            return -1;  /* EOF */
        }

        current += n;
        count -= n;
    }

    return current - start;
}

/**
 * Reads an ASCII text line from fd, stops at EOF or '\n'
 */

ssize_t
readtextline(int fd, char *start, size_t count)
{
    char *current = start;
    const char * const limit = &start[count];

    while(current < limit)
    {
        ssize_t n;
        
        if((n = read(fd, current, 1)) > 0)
        {
            u8 c = *current;
            
            current++;
            count --;
            
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
 * 
 * @param fd
 * @return 
 */

int
unlink_ex(const char *folder, const char *filename)
{
    char fullpath[PATH_MAX];
    
    int l0 = strlen(folder);
    int l1 = strlen(filename);
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
        return -1;
    }
}

#if DEBUG_BENCH_FD
static debug_bench_s debug_open;
static debug_bench_s debug_open_create;
static debug_bench_s debug_close;
static bool fdtools_debug_bench_register_done = FALSE;

static inline void fdtools_debug_bench_register()
{
    if(!fdtools_debug_bench_register_done)
    {
        fdtools_debug_bench_register_done = TRUE;
        debug_bench_register(&debug_open, "open");
        debug_bench_register(&debug_open_create, "open_create");
        debug_bench_register(&debug_close, "close");
    }
}
#endif

/**
 * Opens a file. (see man 2 open)
 * Handles EINTR and other retry errors.
 * 
 * @param fd
 * @return 
 */

ya_result
open_ex(const char *pathname, int flags)
{
    int fd;
    
#if DEBUG_BENCH_FD
    fdtools_debug_bench_register();
    u64 bench = debug_bench_start(&debug_open);
#endif
    
    while((fd = open(pathname, flags)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            //fd = MAKE_ERRNO_ERROR(err);
            break;
        }
    }
    
#if DEBUG_BENCH_FD
    debug_bench_stop(&debug_open, bench);
#endif
    
    return fd;
}

/**
 * Opens a file, create if it does not exist. (see man 2 open with O_CREAT)
 * Handles EINTR and other retry errors.
 * 
 * @param fd
 * @return 
 */

ya_result
open_create_ex(const char *pathname, int flags, mode_t mode)
{
    int fd;
    
#if DEBUG_BENCH_FD
    fdtools_debug_bench_register();
    u64 bench = debug_bench_start(&debug_open_create);
#endif
    
    while((fd = open(pathname, flags, mode)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            //fd = MAKE_ERRNO_ERROR(err);
            break;
        }
    }
    
#if DEBUG_BENCH_FD
    debug_bench_stop(&debug_open_create, bench);
#endif
    
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
close_ex(int fd)
{
    ya_result return_value = SUCCESS;
#if DEBUG_BENCH_FD
    fdtools_debug_bench_register();
    u64 bench = debug_bench_start(&debug_close);    
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
    
    return return_value;
}

s64
filesize(const char *name)
{
    struct stat s;
    if(stat(name, &s) >= 0)
    {
        if(S_ISREG(s.st_mode))
        {
            return s.st_size;
        }
    }
    
    return (s64)ERRNO_ERROR;
}

/** @} */
