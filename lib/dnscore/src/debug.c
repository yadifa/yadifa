/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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

/** @defgroup debug Debug functions
 *  @ingroup dnscore
 *  @brief Debug functions.
 *
 *  Definitions of debug functions/hooks, mainly memory related.
 *
 * @{
 */
#include "dnscore/dnscore-config.h"
#include "dnscore/debug_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <malloc.h>
#endif

#include <unistd.h>
#include <sys/mman.h>

#include "dnscore/thread.h"
#include "dnscore/timems.h"

#if defined(__GLIBC__) || defined(__APPLE__)
#include <execinfo.h>
#include <dnscore/shared-heap.h>
#include <dnscore/debug_config.h>

#endif

#include "dnscore/sys_types.h"
#include "dnscore/format.h"
#include "dnscore/debug.h"
#include "dnscore/mutex.h"
#include "dnscore/logger.h"
#include "dnscore/ptr_set_debug.h"
#include "dnscore/u64_set_debug.h"
#include "dnscore/list-sl-debug.h"

#if defined(__GLIBC__) || defined(__APPLE__)
#define DNSCORE_DEBUG_STACKTRACE 1
#else /* __FreeBSD__ or unknown */
#define DNSCORE_DEBUG_STACKTRACE 0
#endif

#if defined(__linux__)
#define DNSCORE_DEBUG_MMAP 1
#endif

#ifdef    __cplusplus
extern "C" output_stream __termout__;
extern "C" output_stream __termerr__;
#else
extern output_stream __termout__;
extern output_stream __termerr__;
#endif

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

/****************************************************************************/

void
debug_dump(void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text)
{
    debug_dump_ex(data_pointer_, size_, line_size, hex, text, FALSE);
}

/****************************************************************************/

void
debug_dump_ex(void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text, bool address)
{
    if(__termout__.vtbl == NULL)
    {
        return;
    }
    
    osprint_dump(termout, data_pointer_, size_, line_size,
        ((address)?OSPRINT_DUMP_ADDRESS:0)  |
        ((hex)?OSPRINT_DUMP_HEX:0)          |
        ((text)?OSPRINT_DUMP_TEXT:0));
}

char*
debug_strdup(const char* str)
{
    size_t l = strlen(str) + 1;
    char* out;
    MALLOC_OR_DIE(char*, out, l, ZDB_STRDUP_TAG); /* ZALLOC IMPOSSIBLE, MUST KEEP MALLOC_OR_DIE */
    MEMCOPY(out, str, l);
    return out;
}

#if (DNSCORE_HAS_MALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_STATISTICS_SUPPORT || DNSCORE_HAS_MMAP_DEBUG_SUPPORT)

#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
void debug_memory_stat(int mask);
#endif

void
debug_stat(int mask)
{
    (void)mask;
    if(__termout__.vtbl == NULL)
    {
        return;
    }

    debug_memory_stat(mask);

    zalloc_print_stats(termout);
}
#endif

/**
 * Dumps the 4K-aligned page containing the pointer on stdout.
 */

void
debug_dump_page(void* ptr)
{
    if(__termout__.vtbl != NULL)
    {
        formatln("Page for %p:\n", ptr);

        if(ptr != NULL)
        {
            intptr p = (intptr)ptr;
            p = p & (~4095);
            debug_dump_ex((void*)p, 4096, 32, TRUE, TRUE, TRUE);
        }
    }
}

/** @} */
