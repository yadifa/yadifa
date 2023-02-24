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

/** @defgroup stacktrace Stack trace debug functions
 *  @ingroup dnscore
 *  @brief Debug functions.
 *
 *  Definitions of stacktrace functions
 *
 * @{
 */

#include "dnscore/dnscore-config.h"
#include "dnscore/debug_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(__GLIBC__) || defined(__FreeBSD__) || defined(__APPLE__)

#define HAS_BACKTRACE 1
#else
#define HAS_BACKTRACE 0
#endif

#if HAS_BACKTRACE
#include <execinfo.h>

#if HAS_BFD_DEBUG_SUPPORT
#include <bfd.h>
#ifndef DMGL_PARAMS
    #define DMGL_PARAMS      (1 << 0)       /* Include function args */
    #define DMGL_ANSI        (1 << 1)       /* Include const, volatile, etc */
#endif
#endif
#endif

#include <dnscore/list-sl-debug.h>
#include <dnscore/logger_handle.h>

#include "dnscore/sys_types.h"
#include "dnscore/u64_set_debug.h"

#undef malloc
#undef free
#undef realloc
#undef calloc
#undef debug_mtest
#undef debug_stat
#undef debug_mallocated

//////////////////////////////////////////////////////////////////////////////
//
// STACKTRACE
//
//////////////////////////////////////////////////////////////////////////////

bool debug_bfd_resolve_address(void *address, const char *binary_file_path, const char **out_file, const char **out_function, u32 *out_line);
void debug_bfd_clear();

#if HAS_BACKTRACE
typedef u64_set_debug stacktrace_set;
static stacktrace_set stacktraces_list_set = U64_SET_EMPTY;
static pthread_mutex_t stacktraces_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

void malloc_busy_acquire();
void malloc_busy_release();

#if HAS_BACKTRACE
static ya_result 
debug_stacktraces_list_set_search(void* data, void* parm)
{
    stacktrace trace_a = (stacktrace)data;
    stacktrace trace_b = (stacktrace)parm;

    if(data == NULL || parm == NULL)
    {
        return COLLECTION_ITEM_STOP;
    }

    for(;;)
    {
        if(*trace_a != *trace_b)
        {
            break;
        }
        if((*trace_a|*trace_b) == 0)
        {
            return COLLECTION_ITEM_PROCESS_THEN_STOP;
        }
        trace_a++;
        trace_b++;
    }

    return COLLECTION_ITEM_STOP;            
}
#endif

stacktrace
debug_stacktrace_get_ex(int index)
{
#if HAS_BACKTRACE
    void* buffer_[1024];
#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
    malloc_busy_acquire();
#endif

    int n = backtrace(buffer_, sizeof(buffer_) / sizeof(void*));
    
    void** buffer = &buffer_[index];
    n -= index; // minus this function

    if(n < 0)
    {
#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
        malloc_busy_release();
#endif
        return NULL;
    }

    // backtrace to key
    
    stacktrace sp = (stacktrace)buffer;
    u64 key = 0;
    for(int i = 0; i < n; i++)
    {
        key += sp[i] << ( n & ((__SIZEOF_POINTER__ * 8) - 1) );
    }
    
    pthread_mutex_lock(&stacktraces_mutex);
    
    stacktrace trace;
    u64_node_debug *node = u64_set_debug_insert(&stacktraces_list_set, key);
    if(node->value == NULL)
    {
        list_sl_debug_s *sll;
        sll = (list_sl_debug_s*)debug_malloc_unmonitored(sizeof(list_sl_debug_s));
        list_sl_debug_init(sll);
        node->value = sll;
        trace = (stacktrace)debug_malloc_unmonitored((n + 2) * sizeof(intptr));
        memcpy(trace, buffer, n * sizeof(void*));
        trace[n] = 0;
        list_sl_debug_insert(sll, trace);
        trace[n+1] = (intptr)backtrace_symbols(buffer, n);
    }
    else
    {
        list_sl_debug_s *sll;
        sll = (list_sl_debug_s *)node->value;
        trace = (stacktrace)list_sl_debug_search(sll, debug_stacktraces_list_set_search, buffer);
        if(trace == NULL)
        {
            trace = (stacktrace)debug_malloc_unmonitored((n + 2) * sizeof(intptr));
            memcpy(trace, buffer, n * sizeof(void*));
            trace[n] = 0;
            list_sl_debug_insert(sll, trace);
            trace[n+1] = (intptr)backtrace_symbols(buffer, n);
        }
    }
    
    pthread_mutex_unlock(&stacktraces_mutex);
#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
    malloc_busy_release();
#endif
    
    return trace;
#else
    (void)index;
    return NULL;
#endif
}

stacktrace
debug_stacktrace_get()
{
    stacktrace st = debug_stacktrace_get_ex(1);
    return st;
}

/**
 * clears all stacktraces from memory
 * should only be called at shutdown
 */

#if HAS_BACKTRACE
static void
debug_stacktrace_clear_delete(u64_node_debug *node)
{
    list_sl_debug_s *sll = (list_sl_debug_s *)node->value;
    if(sll != NULL)
    {
        stacktrace trace;
        while((trace = (stacktrace)list_sl_debug_pop(sll)) != NULL)
        {
            int n = 0;
            while(trace[n] != 0)
            {
                ++n;
            }

            char **trace_strings = (char**)trace[n + 1];
            debug_free_unmonitored(trace_strings);
            debug_free_unmonitored(trace);
        }

        debug_free_unmonitored(sll);
        node->value = NULL;
    }
}
#endif

void
debug_stacktrace_clear()
{
#if HAS_BACKTRACE
    pthread_mutex_lock(&stacktraces_mutex);
    u64_set_debug_callback_and_destroy(&stacktraces_list_set, debug_stacktrace_clear_delete);
    pthread_mutex_unlock(&stacktraces_mutex);
#if !DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
#if HAS_BFD_DEBUG_SUPPORT
    debug_bfd_clear();
#endif
#endif
#endif
}

void
debug_stacktrace_log(logger_handle* handle, u32 level, stacktrace trace)
{
#if HAS_BACKTRACE
    int n = 0;

    if(trace != NULL)
    {
        while(trace[n] != 0)
        {
            ++n;
        }
    
        char **trace_strings = (char**)trace[n + 1];
        for(int i = 0; i < n; i++)
        {
            void *address = (void*)trace[i];
            const char *text = (trace_strings != NULL) ? trace_strings[i] : "???";
        
#if HAS_BFD_DEBUG_SUPPORT
            char *parenthesis = strchr(text, '(');
            if(parenthesis != NULL)
            {
                u32 n = parenthesis - text;

                assert(n < PATH_MAX);

                char binary[PATH_MAX];            
                memcpy(binary, text, n);
                binary[n] = '\0';

                const char *file = NULL;
                const char *function = NULL;
                u32 line;

                debug_bfd_resolve_address(address, binary, &file, &function, &line);

                if((file != NULL) && (*file != '\0'))
                {                    
                    logger_handle_msg(handle, level, "%p: %s (%s:%i)", address, function, file, line);
                }
                else
                {
                    logger_handle_msg(handle, level, "%p: %s", address, text);
                }
            }
            else
            {
#endif
                logger_handle_msg(handle, level, "%p %s", address, text);
#if HAS_BFD_DEBUG_SUPPORT     
           }
#endif
        }
    }
#else
    (void)trace;
    logger_handle_msg(handle, level, "backtrace not supported");
#endif
}

void
debug_stacktrace_log_with_prefix(logger_handle* handle, u32 level, stacktrace trace, const char *prefix)
{
#if HAS_BACKTRACE
    int n = 0;

    if(trace != NULL)
    {
        while(trace[n] != 0)
        {
            ++n;
        }
    
        char **trace_strings = (char**)trace[n + 1];
        for(int i = 0; i < n; i++)
        {
            void *address = (void*)trace[i];
            const char *text = (trace_strings != NULL) ? trace_strings[i] : "???";
        
#if HAS_BFD_DEBUG_SUPPORT
            char *parenthesis = strchr(text, '(');
            if(parenthesis != NULL)
            {
                u32 n = parenthesis - text;

                assert(n < PATH_MAX);

                char binary[PATH_MAX];            
                memcpy(binary, text, n);
                binary[n] = '\0';

                const char *file = NULL;
                const char *function = NULL;
                u32 line;

                debug_bfd_resolve_address(address, binary, &file, &function, &line);

                if((file != NULL) && (*file != '\0'))
                {                    
                    logger_handle_msg(handle, level, "%s%p: %s (%s:%i)", prefix, address, function, file, line);
                }
                else
                {
                    logger_handle_msg(handle, level, "%s%p: %s", prefix, address, text);
                }
            }
            else
            {
#endif
                logger_handle_msg(handle, level, "%s%p %s", prefix, address, text);
#if HAS_BFD_DEBUG_SUPPORT     
           }
#endif
        }
    }
#else
    (void)trace;
    (void)prefix;
    logger_handle_msg(handle, level, "backtrace not supported");
#endif
}

void
debug_stacktrace_try_log(logger_handle* handle, u32 level, stacktrace trace)
{
#if HAS_BACKTRACE
    int n = 0;

    if(trace != NULL)
    {
        while(trace[n] != 0)
        {
            ++n;
        }
    
        char **trace_strings = (char**)trace[n + 1];
        for(int i = 0; i < n; i++)
        {
            void *address = (void*)trace[i];
            const char *text = (trace_strings != NULL) ? trace_strings[i] : "???";
        
#if HAS_BFD_DEBUG_SUPPORT
            char *parenthesis = strchr(text, '(');
            if(parenthesis != NULL)
            {
                u32 n = parenthesis - text;

                assert(n < PATH_MAX);

                char binary[PATH_MAX];            
                memcpy(binary, text, n);
                binary[n] = '\0';

                const char *file = NULL;
                const char *function = NULL;
                u32 line;

                debug_bfd_resolve_address(address, binary, &file, &function, &line);

                if((file != NULL) && (*file != '\0'))
                {                    
                    logger_handle_msg(handle, level, "%p: %s (%s:%i)", address, function, file, line);
                }
                else
                {
                    logger_handle_msg(handle, level, "%p: %s", address, text);
                }
            }
            else
            {
#endif
                logger_handle_try_msg(handle, level, "%p %s", address, text);
#if HAS_BFD_DEBUG_SUPPORT     
           }
#endif
        }
    }
#else
    (void)trace;
    logger_handle_try_msg(handle, level, "backtrace not supported");
#endif
}

void
debug_stacktrace_print(output_stream *os, stacktrace trace)
{
    if(trace == NULL)
    {
        output_stream_write(os, "NULL-TRACE", 10);
        return;
    }

#if HAS_BACKTRACE
    int n = 0;

    while(trace[n] != 0)
    {
        ++n;
    }

    char **trace_strings = (char**)trace[n + 1];
    for(int i = 0; i < n; i++)
    {
        osformatln(os, "%p %s", (void*)trace[i], (trace_strings != NULL) ? trace_strings[i] : "???");
    }
#else
    osformatln(os, "backtrace not supported");
#endif
}

#if defined(__GLIBC__)

bool
debug_log_stacktrace(logger_handle *handle, u32 level, const char *prefix)
{
    void* addresses[1024];
#if HAS_BFD_DEBUG_SUPPORT
    char binary[PATH_MAX];
#endif

#if defined(__GLIBC__)
    
    int n = backtrace(addresses, sizeof(addresses) / sizeof(void*));
    
    if(n > 0)
    {
        char **symbols = backtrace_symbols(addresses, n);
    
        if(symbols != NULL)
        {
            for(int i = 1; i < n; i++)
            {
                char *parenthesis = strchr(symbols[i], '(');
                if(parenthesis != NULL)
                {
#if HAS_BFD_DEBUG_SUPPORT
                    u32 n = parenthesis - symbols[i];
                    memcpy(binary, symbols[i], n);
                    binary[n] = '\0';
                    
                    const char *func = "?";
                    const char *file = "?";
                    u32 line = ~0;
                    
                    debug_bfd_resolve_address(addresses[i], binary, &file, &func, &line);                                       
                    
                    if((file != NULL) && (*file != '\0'))
                    {                    
                        logger_handle_msg(handle, level, "%s: %p: %s (%s:%i)", prefix, addresses[i], func, file, line);
                    }
                    else
                    {
                        logger_handle_msg(handle, level, "%s: %p: %s", prefix, addresses[i], symbols[i]);
                    }
#else
                    logger_handle_msg(handle, level, "%s: %p: %s", prefix, addresses[i], symbols[i]);
#endif
                }
            }

            free(symbols);
        }
        else
        {
            for(int i = 1; i < n; i++)
            {
                logger_handle_msg(handle, level, "%s: %p: ?", prefix, addresses[i]);
            }
        }
    }
    else
#endif // linux only
    {
        logger_handle_msg(handle, level, "%s: ?: ?", prefix);
    }
    
    return TRUE;
}

#else

bool
debug_log_stacktrace(logger_handle *handle, u32 level, const char *prefix)
{
    (void)handle;
    (void)level;
    (void)prefix;
    return TRUE;
}

#endif

/** @} */
