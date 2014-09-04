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

#include "config.h"

#include <dnscore/logger.h>
#include <dnscore/sys_error.h>

#include "poll-util.h"
#include "server.h"

#define MODULE_MSG_HANDLE g_server_logger

/*******************************************************************************************************************
 *
 * TCP USAGE LIMITS
 *
 ******************************************************************************************************************/

/**
 * This code maintains the limit on the tcp sockets
 * @todo Portability has to be tested.
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

    for(int i = 0; i < count; i++)
    {
        ret[i].events = POLLNVAL/*|POLLIN|POLLHUP*/;
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
        /* got hits */

        int f = -1;

        for(int i = 0; i < tcp_fds_idx; i++)
        {
            if(tcp_fds[i].revents != 0)
            {
                /* disable it
                 * look for a zero one from the end
                 */
                tcp_fds[i].fd = -1;

                if(f < 0)
                {
                    f = i;
                }
            }
            else    /* recompress */
            {
                if(f >= 0)
                {
                    tcp_fds[f].fd = tcp_fds[i].fd;
                    tcp_fds[f].revents = 0;
                    tcp_fds[i].fd = -1;

                    while(++f <= i) /* will at most stop at i */
                    {
                        if(tcp_fds[f].fd < 0)
                        {
                            break;
                        }
                    }
                }
            }
        }

        tcp_fds_idx -= n;
        
        return tcp_fds_idx;
    }
    else
    {
        if(n < 0)
        {
            log_info("tcp: poll failed: %r", ERRNO_ERROR);
            
            n = 0;
        }
        
        return tcp_fds_idx;
    }
}

