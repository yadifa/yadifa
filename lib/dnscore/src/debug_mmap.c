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

#include <unistd.h>
#include <sys/mman.h>

#include "dnscore/sys_types.h"
#include "dnscore/format.h"
#include "dnscore/debug.h"
#include "dnscore/mutex.h"
#include "dnscore/logger.h"
#include "dnscore/ptr_set_debug.h"

#undef malloc
#undef free
#undef realloc
#undef calloc
#undef debug_mtest
#undef debug_stat
#undef debug_mallocated

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

struct debug_mmap_s
{
    void *addr;
    size_t len;
    int prot;
    int flags;
    int fildes;
    off_t off;
    s64 ts;
    stacktrace trace;
    void *mapped;
};

typedef struct debug_mmap_s debug_mmap_t;

#undef mmap
#undef munmap

#if DNSCORE_HAS_MMAP_DEBUG_SUPPORT

static ptr_set_debug debug_mmap_set = PTR_SET_DEBUG_EMPTY;
static pthread_mutex_t debug_mmap_mtx = PTHREAD_MUTEX_INITIALIZER;

void*
debug_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
    // DO NOT: formatln("debug_mmap(%p, %llx, %i, %i, %i, %lli)", addr, len, prot, flags, fildes, off);

    void *ret = mmap(addr, len, prot, flags, fildes, off);
    if(ret != MAP_FAILED)
    {
        debug_mmap_t *debug_mmap = (debug_mmap_t*)debug_malloc_unmonitored(sizeof(debug_mmap_t));
        debug_mmap->addr = addr;
        debug_mmap->len = len;
        debug_mmap->prot = prot;
        debug_mmap->flags = flags;
        debug_mmap->fildes = fildes;
        debug_mmap->off = off;
        debug_mmap->trace = debug_stacktrace_get();
        debug_mmap->ts = timeus();
        debug_mmap->mapped = ret;
        pthread_mutex_lock(&debug_mmap_mtx);
        ptr_node_debug *node = ptr_set_debug_insert(&debug_mmap_set, ret);
        node->value = debug_mmap;
        pthread_mutex_unlock(&debug_mmap_mtx);
    }
    return ret;
}

int debug_munmap(void *addr, size_t len)
{
    pthread_mutex_lock(&debug_mmap_mtx);
    ptr_node_debug *node = ptr_set_debug_find(&debug_mmap_set, addr);
    if(node != NULL)
    {
        debug_mmap_t *debug_mmap = (debug_mmap_t *)node->value;
        debug_free_unmonitored(debug_mmap);
        ptr_set_debug_delete(&debug_mmap_set, addr);
    }
    pthread_mutex_unlock(&debug_mmap_mtx);
    int ret = munmap(addr, len);
    return ret;
}

void
debug_mmap_stat()
{
    u32 count = 0;
    u64 total = 0;

    formatln("MMAP statistics:");

    pthread_mutex_lock(&debug_mmap_mtx);
    ptr_set_debug_iterator iter;
    ptr_set_debug_iterator_init(&debug_mmap_set, &iter);
    while(ptr_set_debug_iterator_hasnext(&iter))
    {
        const ptr_node_debug *node = ptr_set_debug_iterator_next_node(&iter);
        const debug_mmap_t *debug_mmap = (const debug_mmap_t *)node->value;
        formatln("MMAP %p %016llx %04x %04x %5i %08x (%lli)", debug_mmap->mapped, debug_mmap->len, debug_mmap->prot, debug_mmap->flags, debug_mmap->fildes, debug_mmap->off, debug_mmap->ts);
        debug_stacktrace_print(termout, debug_mmap->trace);
        output_stream_write_u8(termout, (u8)'\n');
        ++count;
        total += debug_mmap->len;
    }
    pthread_mutex_unlock(&debug_mmap_mtx);

    formatln("MMAP count: %u total: %llx (%llu)", count, total, total);
}

#else

void*
debug_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
    void *ret = mmap(addr, len, prot, flags, fildes, off);
    return ret;
}

int debug_munmap(void *addr, size_t len)
{
    int ret = munmap(addr, len);
    return ret;
}

void
debug_mmap_stat()
{
}

#endif

/** @} */
