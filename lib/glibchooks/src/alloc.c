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
 *------------------------------------------------------------------------------
 *
 */

#include "glibchooks/glibchooks_internal.h"

// memory allocation functions
static void *(*glibc_calloc)(size_t nmemb, size_t size);
static void *(*glibc_malloc)(size_t size);
static void (*glibc_free)(void *ptr);
static void *(*glibc_realloc)(void *ptr, size_t size);
static void *(*glibc_memalign)(size_t blocksize, size_t bytes);

static atomic_size_t malloc_count_total = 0;
static atomic_size_t malloc_count_peak = 0;
static atomic_size_t malloc_count_current = 0;
static atomic_size_t malloc_memory_total = 0;
static atomic_size_t malloc_memory_peak = 0;
static atomic_size_t malloc_memory_current = 0;

static void          alloc_hooks_init()
{
    glibc_malloc = function_hook("malloc");
    glibc_free = function_hook("free");
    glibc_calloc = function_hook("calloc");
    glibc_realloc = function_hook("realloc");
    glibc_memalign = function_hook("memalign");
}

static void alloc_hooks_print(FILE *f)
{
    fprintf(f, "malloc: count: total=%" PRIu64 " peak=%" PRIu64 " current=%" PRIu64 " memory: total=%" PRIu64 " peak=%" PRIu64 " current=%" PRIu64 "\n",
            (uint64_t)malloc_count_total,
            (uint64_t)malloc_count_peak,
            (uint64_t)malloc_count_current,
            (uint64_t)malloc_memory_total,
            (uint64_t)malloc_memory_peak,
            (uint64_t)malloc_memory_current);
}

INTERNAL hook_module_t alloc_module = {"alloc", NULL, alloc_hooks_init, alloc_hooks_print};

size_t                 malloc_usable_size(void *ptr);

static void            malloc_stat_add(size_t size)
{
    malloc_count_total++;
    malloc_count_current++;
    malloc_count_peak = MAX(malloc_count_current, malloc_count_peak);
    malloc_memory_total += size;
    malloc_memory_current += size;
    malloc_memory_peak = MAX(malloc_memory_current, malloc_memory_peak);
}

void *malloc(size_t size)
{
#if __FreeBSD__
    if(glibc_malloc == NULL)
    {
        alloc_hooks_init();
    }
#endif
    void *p = glibc_malloc(size);
    if(p != NULL)
    {
        size = malloc_usable_size(p);
        malloc_stat_add(size);
    }
    return p;
}

void free(void *ptr)
{
#if __FreeBSD__
    if(glibc_free == NULL)
    {
        alloc_hooks_init();
    }
#endif
    if(ptr != NULL)
    {
        size_t size = malloc_usable_size(ptr);
        malloc_count_current--;
        malloc_memory_current -= size;
    }
    glibc_free(ptr);
}

void *realloc(void *ptr, size_t size)
{
    size_t old_size;
    if(ptr != NULL)
    {
        old_size = malloc_usable_size(ptr);
    }
    void *p = glibc_realloc(ptr, size);
    if(ptr != NULL)
    {
        size_t new_size = malloc_usable_size(p);
        size = new_size - old_size;
        malloc_stat_add(size);
    }
    return p;
}

void *calloc(size_t nmemb, size_t size)
{
#if __FreeBSD__
    if(glibc_calloc == NULL)
    {
        alloc_hooks_init();
    }
#endif
    void *p = glibc_calloc(nmemb, size);
    if(p != NULL)
    {
        size = malloc_usable_size(p);
        malloc_stat_add(size);
    }
    return p;
}

void *memalign(size_t blocksize, size_t bytes)
{
#if __FreeBSD__
    if(glibc_memalign == NULL)
    {
        alloc_hooks_init();
    }
#endif
    void *p = glibc_memalign(blocksize, bytes);
    if(p != NULL)
    {
        size_t size = malloc_usable_size(p);
        malloc_stat_add(size);
    }
    return p;
}
