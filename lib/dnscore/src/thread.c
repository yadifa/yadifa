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

/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#define _GNU_SOURCE 1
#endif

#include <sys/types.h>
#include <unistd.h>

#include <dnscore/thread.h>

#include "dnscore/logger.h"

#define MODULE_MSG_HANDLE		g_system_logger

#if HAS_PTHREAD_SETNAME_NP

static int thread_count_get_nibbles(u32 count)
{
    int ret = 0;

    do
    {
        ++ret;
        count >>= 4;
    }
    while(count > 0);

    return ret;
}

void thread_set_name(const char *name, int index, int count)
{
    // 16 is the size limit for this, cfr man page
    char tmp[16 + 1];
    char fmt[11]; // :%010x/%010x

    if(--count <= 0)
    {
        strcpy_ex(tmp, name, sizeof(tmp));
    }
    else
    {
        int count_digits = thread_count_get_nibbles((u32) count);
        if(count_digits < 5)
        {
            // name:xx/xx
            int suffix_len = count_digits * 2 + 2;
            int avail = sizeof(tmp) - 1 - suffix_len;
            strcpy_ex(tmp, name, avail);
            int size = strlen(tmp);
            snformat(fmt, sizeof(fmt), ":%%0%ix/%%0%ix", count_digits, count_digits); // 11 bytes long as count_digits is at most 4 so 1 byte long
            snprintf(&tmp[size], sizeof(tmp) - size, fmt, index, count);
        }
        else
        {
            //name:xx

            assert(count_digits <= 8);

            int suffix_len = count_digits + 1;
            int avail = sizeof(tmp) - 1 - suffix_len;
            strcpy_ex(tmp, name, avail);
            int size = strlen(tmp);
            snformat(fmt, sizeof(fmt), ":%%0%ix", count_digits);  // 6 bytes as count_digits is at most 8 so 1 byte long
            snprintf(&tmp[size], sizeof(tmp) - size, fmt, index, count);
        }
    }

#if __APPLE__
    pthread_setname_np(tmp);
#elif __NetBSD__
    pthread_setname_np(thread_self(), tmp, strlen(tmp));
#else
    pthread_setname_np(thread_self(), tmp);
#endif // __APPLE__
}
#else
void thread_set_name(const char *name, int index, int count)
{
    (void)name;
    (void)index;
    (void)count;
}
#endif

/** @} */
