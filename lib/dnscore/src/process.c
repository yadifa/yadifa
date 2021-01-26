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
#include <unistd.h>
#include <sys/wait.h>
#include "dnscore/process.h"
#include "dnscore/thread_pool.h"

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

pid_t g_pid = -1;

pid_t
fork_ex()
{
#ifndef WIN32
    logger_flush();
    dnscore_stop_timer();
    service_stop_all();
    thread_pool_stop_all();

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_stop();
#endif
    pid_t pid = fork();
    
    if(pid == 0)
    {
        g_pid = getpid();
    }

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_start();
#endif

    thread_pool_start_all();
    service_start_all();
    dnscore_reset_timer();

    return pid;
#else
    return -1;
#endif
}

int
waitpid_ex(pid_t pid, int *wstatus, int options)
{
    int ret;

#ifndef WIN32
    
    while((ret = waitpid(pid, wstatus, options)) < 0)
    {
        int err = errno;
        
        if(err == EINTR)
        {
            continue;
        }
        else
        {
            return -1;
        }
    }
    
    return ret;
#else
    WaitForSingleObject(pid, INFINITE);
#endif
}

/** @} */
