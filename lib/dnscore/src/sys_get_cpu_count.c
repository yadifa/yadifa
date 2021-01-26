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

/** @defgroup cpu CPU
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include "dnscore/dnscore-config-features.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__linux__) && HAVE_CPUID_H
#include <cpuid.h>
#endif

#include "dnscore/sys_types.h"

/*
 *
 */

static u32 cpu_count_override = 0;

void
sys_set_cpu_count(int override)
{
    if(override < 0)
    {
        override = 0;
    }

    cpu_count_override = (u32)override;
}

u32
sys_get_cpu_count()
{
    if(cpu_count_override == 0)
    {
#ifndef WIN32
        int cc = sysconf(_SC_NPROCESSORS_ONLN);

        if( cc <= 0 )
        {
            /*
             * This fix has been made for FreeBSD that returns -1 for the above call
             */

            cc = 1;
        }

        return (u32)cc;
#else
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        DWORD cc = sysinfo.dwNumberOfProcessors;

        if(cc <= 0)
        {
            /*
             * This fix has been made for FreeBSD that returns -1 for the above call
             */

            cc = 1;
        }
        return (u32)cc;
#endif
    }


    return cpu_count_override;
}

bool
sys_has_hyperthreading()
{
#if defined(__linux__) && HAVE_CPUID_H
    unsigned int a,c,d,b;
    int ret = __get_cpuid(1,&a,&b,&c,&d);
    if(ret == 1)
    {
        return (d & (1<<28)) != 0;
    }
#endif    
    return FALSE;
}

/** @} */
