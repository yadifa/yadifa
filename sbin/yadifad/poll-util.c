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

#include "server-config.h"

#include <dnscore/logger.h>
#include <dnscore/sys_error.h>
#include "server.h"

#if !DNSCORE_HAS_TCP_MANAGER
#include "poll-util.h"

#define MODULE_MSG_HANDLE g_server_logger

/*******************************************************************************************************************
 *
 * TCP USAGE LIMITS
 *
 ******************************************************************************************************************/

/**
 * This code maintains the limit on the tcp sockets
 */

static nfds_t         tcp_fds_count = 0;
static nfds_t         tcp_fds_idx = 0;
static struct pollfd *tcp_fds = NULL;

void
poll_free()
{
    tcp_fds_count = 0;
    tcp_fds_idx = 0;
    free(tcp_fds);
    tcp_fds = NULL;
}

void
poll_alloc(nfds_t count)
{
    if(tcp_fds != NULL)
    {
        if(count != tcp_fds_count)
        {
            poll_free();
        }
    }
    
    struct pollfd* ret;
    size_t bytes = sizeof(struct pollfd) * count;
    MALLOC_OR_DIE(struct pollfd*, ret, bytes, POLLFDBF_TAG);
    ZEROMEMORY(ret, bytes);

    for(nfds_t i = 0; i < count; i++)
    {
        ret[i].events = POLLIN|POLLHUP/*|POLLNVAL*/; // could be set to 0, POLLNVAL is implicit // VS false positive (nonsense)
    }

    tcp_fds = ret;
    tcp_fds_count = count;
}

bool
poll_add(int fd)
{
    if(tcp_fds_idx < tcp_fds_count)
    {
        tcp_fds[tcp_fds_idx].fd = fd;
        tcp_fds[tcp_fds_idx].revents = 0;

        tcp_fds_idx++;

        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

int
poll_update()
{
    int n = poll(tcp_fds, tcp_fds_idx, 0);
    
    if(n > 0)
    {
        // got hits
        
#if DEBUG
        int changes = 0;
#endif
        
        for(nfds_t i = 0; i < tcp_fds_idx; ++i)
        {
#if DEBUG
            log_notice("poll_update: [%3i] %i (%4x %4x) (debug)", i, tcp_fds[i].fd, tcp_fds[i].events, tcp_fds[i].revents);
#endif
            if(tcp_fds[i].revents != 0)
            {
                // lose it
#if DEBUG
                log_debug("poll_update: releasing %i (%4x %4x)", tcp_fds[i].fd, tcp_fds[i].events, tcp_fds[i].revents);
                ++changes;
#endif
                --tcp_fds_idx;
                if(tcp_fds_idx != i)
                {
#if DEBUG
                    log_debug("poll_update: replacing with %i (%4x %4x)", tcp_fds[tcp_fds_idx].fd, tcp_fds[tcp_fds_idx].events, tcp_fds[tcp_fds_idx].revents);
#endif
                    tcp_fds[i] = tcp_fds[tcp_fds_idx];
                    --i;
                }
            }
        }
        
#if DEBUG
        if(n != changes)
        {
            log_debug("poll_update: warning : did expect %i changes, got %i", n, changes);
        }
#endif        
        return tcp_fds_idx;
    }
    else if(n < 0)
    {
#if DEBUG
        log_debug("tcp: poll failed: %r", ERRNO_ERROR);
#endif
        
        return tcp_fds_idx;
    }
    else
    {
        // timeout
#if DEBUG
        log_debug("tcp: poll timed out");
#endif
        return tcp_fds_idx;
    }
}
#else

// not used

#endif