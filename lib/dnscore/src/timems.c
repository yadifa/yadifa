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
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "dnscore/timems.h"

/*
 * Return the time in ms
 */

u64
timeus()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    u64 r = tv.tv_sec;
    r *= 1000000LL;
    r += tv.tv_usec;

    return r;
}

u64
timems()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    u64 r = tv.tv_sec;
    r *= 1000;
    r += tv.tv_usec / 1000;

    return r;
}

/*
 * Wait until the ms is incremented, then return the time in ms
 */

u64
timems_new()
{
    u64 t;
    u64 tms;
    u64 ttr;
    
    t = timeus();
    tms = t/1000;
    
    do
    {
        usleep(MIN(1000 - (tms % 1000), 1));
        ttr = timeus() / 1000;
    }
    while(ttr == tms);

    return ttr;
}

/** @} */

/*----------------------------------------------------------------------------*/

