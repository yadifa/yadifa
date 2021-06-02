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

/** @defgroup debug Debug functions
 *  @ingroup dnscore
 *  @brief Debug functions.
 *
 *  Definitions of debug functions/hooks, mainly memory related.
 *
 * @{
 */
#include "dnscore/dnscore-config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <malloc.h>
#endif

#include <unistd.h>
#include <sys/mman.h>

#include "dnscore/thread.h"
#include "dnscore/dnscore-config.h"
#include "dnscore/timems.h"

#if defined(__GLIBC__) || defined(__APPLE__)
    #include <execinfo.h>
    #if HAS_BFD_DEBUG_SUPPORT
        #include <bfd.h>
        #ifndef DMGL_PARAMS
            #define DMGL_PARAMS      (1 << 0)       /* Include function args */
            #define DMGL_ANSI        (1 << 1)       /* Include const, volatile, etc */
        #endif
    #endif
#endif

#include "dnscore/sys_types.h"
#include "dnscore/format.h"
#include "dnscore/debug.h"
#include "dnscore/mutex.h"
#include "dnscore/logger.h"
#include "dnscore/ptr_set_debug.h"
#include "dnscore/u64_set_debug.h"
#include "dnscore/list-sl-debug.h"

#undef malloc
#undef free
#undef realloc
#undef calloc
#undef debug_mtest
#undef debug_stat
#undef debug_mallocated

#if defined(__GLIBC__) || defined(__APPLE__)
#define DNSCORE_DEBUG_STACKTRACE 1
#else /* __FreeBSD__ or unknown */
#define DNSCORE_DEBUG_STACKTRACE 0
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

#if HAS_LIBC_MALLOC_DEBUG_SUPPORT

typedef void *malloc_hook_t(size_t, const void *);
typedef void *realloc_hook_t(void *, size_t, const void *);
typedef void free_hook_t(void *, const void *);
typedef void *memalign_hook_t(size_t, size_t, const void *);

static bool _real_malloc_initialised = FALSE;

malloc_hook_t *_real_malloc = malloc;
realloc_hook_t *_real_realloc = realloc;
free_hook_t *_real_free = free;
memalign_hook_t *_real_memalign = memalign;

static pthread_mutex_t malloc_hook_mtx = PTHREAD_MUTEX_INITIALIZER;
static ptr_set_debug malloc_hook_tracked_set = PTR_SET_DEBUG_PTR_EMPTY;
static ptr_set_debug malloc_hook_caller_set = PTR_SET_DEBUG_PTR_EMPTY;
static pthread_mutex_t libc_hook_mtx = PTHREAD_MUTEX_INITIALIZER;
volatile size_t malloc_hook_total = 0;
volatile size_t malloc_hook_malloc = 0;
volatile size_t malloc_hook_free = 0;
volatile size_t malloc_hook_realloc = 0;
volatile size_t malloc_hook_memalign = 0;

struct malloc_hook_header_t
{
    u64 begin;
    u32 magic;
    u32 size;
    const void* caller;
#if __SIZEOF_POINTER__ == 4
    u32 padding;
#endif
    u64 end;
};

typedef struct malloc_hook_header_t malloc_hook_header_t;

void debug_malloc_hook_tracked_dump();
void debug_malloc_hook_caller_dump();

#endif



/**
 * These are to ensure I get trashed memory at alloc and on a free.
 * =>
 * No "lucky" inits.
 * No "lucky" destroyed uses.
 *
 */

#define DB_MALLOC_MAGIC 0xd1a2e81c
#define DB_MFREED_MAGIC 0xe81cd1a2

#define MALLOC_PADDING  8
#define MALLOC_REALSIZE(mr_size_) ((mr_size_+(MALLOC_PADDING-1))&(-MALLOC_PADDING))

typedef struct db_header db_header;

struct db_header
{
    u32 magic;
    u32 size;

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
#define HEADER_TAG_SIZE 8
    u64 tag;
#else
#define HEADER_TAG_SIZE 0
#endif

#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
    u64 serial;
#endif

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
#define HEADER_SIZE_CHAIN (8+(2*__SIZEOF_POINTER__))
    db_header* next;
    db_header* previous;
#else
#define HEADER_SIZE_CHAIN 0
#endif

#if DNSCORE_DEBUG_STACKTRACE
    intptr* _trace;
#endif
};

#define HEADER_SIZE sizeof(db_header)

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
static db_header db_mem_first = {
    DB_MALLOC_MAGIC, 0,
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    0xffffffffffffffffLL,
#endif
#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
    0,
#endif
#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
    &db_mem_first, &db_mem_first,
#endif
#if DNSCORE_DEBUG_STACKTRACE
    NULL,
#endif
};
#endif

#if HAS_BFD_DEBUG_SUPPORT

//////////////////////////////////////////////////////////////////////////////
//
// Line numbers in stacktraces
//
//////////////////////////////////////////////////////////////////////////////

/// @note edf: from http://en.wikibooks.org/wiki/Linux_Applications_Debugging_Techniques/The_call_stack

struct bfd_node
{
    bfd* _bfd;
    asymbol **_symbols;
    asection *_text;
    u32 _symbols_count;
    bool _has_symbols;
};

typedef struct bfd_node bfd_node;

static pthread_mutex_t bfd_mtx = PTHREAD_MUTEX_INITIALIZER;
static bool bfd_initialised = FALSE;
static ptr_set_debug bfd_collection = PTR_SET_DEBUG_ASCIIZ_EMPTY;
static char *proc_self_exe = NULL;

static char *
debug_get_self_exe()
{
    char path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", path, sizeof(path));
    if(n > 0)
    {
        path[n] = '\0';
        char *ret = strdup(path);
        return ret;
    }
    
    return NULL;
}

/*
static char *
debug_get_real_file(const char *file)
{
    char path[PATH_MAX];
    ssize_t n = readlink(file, path, sizeof(path));
    if(n > 0)
    {
        path[n] = '\0';
        char *ret;
        
        if(strcmp(file, path) == 0)
        {
            ret = file;
        }
        else
        {
            ret = strdup(path);
        }
        
        return ret;
    }
    
    return NULL;
}
*/
struct bfd_data
{
    bfd_node *bfdn;
    bfd_vma pc;
    bfd_boolean found;
    const char *filename;
    const char *function;
    unsigned int line;
};



static void
debug_bfd_flags_format(const void *value, output_stream *os, s32 padding, char pad_char, bool left_justified, void* reserved_for_method_parameters)
{
    u64 flags = (u64)value;
    output_stream_write(os, "{ ", 2);
    if(flags & HAS_RELOC)
    {
        output_stream_write(os, "RELOC ", 6);
    }
    if(flags & EXEC_P)
    {
        output_stream_write(os, "EXEC ", 5);
    }
    if(flags & HAS_LINENO)
    {
        output_stream_write(os, "LINENO ", 7);
    }
    if(flags & HAS_DEBUG)
    {
        output_stream_write(os, "DEBUG ", 6);
    }
    if(flags & HAS_SYMS)
    {
        output_stream_write(os, "SYMS ", 5);
    }
    if(flags & HAS_LOCALS)
    {
        output_stream_write(os, "LOCALS ", 6);
    }
    if(flags & DYNAMIC)
    {
        output_stream_write(os, "DYNAMIC ", 8);
    }
    output_stream_write(os, "}", 1);
}

static const char debug_bfd_symbol_flags_format_letter[24] =
{
    'l','g','D','f',
    '?','k','K','w',
    's','o','!','C',
    'W','I','F','d',
    'O','R','T','e',
    'E','S','u','U'
};

static void
debug_bfd_symbol_flags_format(const void *value, output_stream *os, s32 padding, char pad_char, bool left_justified, void* reserved_for_method_parameters)
{
    char *p;
    char tmp[24];
    
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u32 flags = (u32)(intptr)value;
    if(flags != 0)
    {
        p = tmp;
        for(int i = 0; i < 24; i++)
        {
            if((flags & (1 << i)) != 0)
            {
                *p++ = debug_bfd_symbol_flags_format_letter[i];
            }
        }
        output_stream_write(os, tmp, p - tmp);
    }
    else
    {
        tmp[0] = '-';
        output_stream_write(os, tmp, 1);
    }
}

static void
debug_bfd_symbol_flag_help()
{
    log_debug(
"- : no flags\n"
"l : local     The symbol has local scope; <<static>> in <<C>>. The value is the offset into the section of the data.\n"
"g : global    The symbol has global scope; initialized data in <<C>>. The value is the offset into the section of the data.\n"
"D : debugging The symbol is a debugging record. The value has an arbitrary meaning, unless BSF_DEBUGGING_RELOC is also set.\n"
"f : function  The symbol denotes a function entry point.  Used in ELF, perhaps others someday.\n"
/*#if 0 // not common
"? : unknown\n"
"k : keep      Used by the linker.\n"
"L : keep g    Used by the linker. (global ?)\n"
"w : weak      A weak global symbol, overridable without warnings by a regular global symbol of the same name.\n"
#endif*/
"s : section   Points to a section.\n"
/*#if 0 // not common
"o : oldcommon The symbol used to be a common symbol, but now it is allocated.\n"
"! : notatend  In some files the type of a symbol sometimes alters its location in an output file - ie in coff a <<ISFCN>> symbol which is also <<C_EXT>> symbol appears where it was declared and not at the end of a section.  This bit is set by the target BFD part to convey this information.\n"
"C : construct Signal that the symbol is the label of constructor section.\n"
"W : warning   Signal that the symbol is a warning symbol.  The name is a warning.  The name of the next symbol is the one to warn about; if a reference is made to a symbol with the same name as the next symbol, a warning is issued by the linker.\n"
"I : indirect  Signal that the symbol is indirect.  This symbol is an indirect pointer to the symbol with the same name as the next symbol.\n"
"F : file      Marks symbols that contain a file name.  This is used for ELF STT_FILE symbols.\n"
#endif*/
"d : dynamic   Symbol is from dynamic linking information.\n"
"O : object    The symbol denotes a data object.  Used in ELF, and perhaps others someday.\n"
/*#if 0 // not common
"R : dbg reloc This symbol is a debugging symbol.  The value is the offset into the section of the data.  BSF_DEBUGGING should be set as well.\n"
"T : threadloc This symbol is thread local.\n"
"e : relc      This symbol represents a complex relocation expression, with the expression tree serialized in the symbol name.\n"
"E : srelc     This symbol represents a signed complex relocation expression, with the expression tree serialized in the symbol name.\n"
"S : synthetic This symbol was created by bfd_get_synthetic_symtab.\n"
"u : gnuidrctf This symbol is an indirect code object.  Unrelated to BSF_INDIRECT. The dynamic linker will compute the value of this symbol by calling the function that it points to.  BSF_FUNCTION must also be also set.\n"
"U : gnunique  This symbol is a globally unique data object.  The dynamic linker will make sure that in the entire process there is just one symbol with this name and type in use.  BSF_OBJECT must also be set.\n"
#endif*/
    );
}

static bool
debug_bfd_resolve_address(void *address, const char *binary_file_path, const char **out_file, const char **out_function, u32 *out_line)
{   
    if(binary_file_path == NULL)
    {
        if(proc_self_exe == NULL)
        {
            proc_self_exe = debug_get_self_exe();
            
            if(proc_self_exe == NULL)
            {
                return FALSE;
            }
        }
        
        binary_file_path = proc_self_exe;
    }
    
    pthread_mutex_lock(&bfd_mtx);
    
    if(!bfd_initialised)
    {
        bfd_init();
        bfd_initialised = TRUE;
        debug_bfd_symbol_flag_help();        
    }
    
    ptr_node_debug *node = ptr_set_debug_insert(&bfd_collection, (char*)binary_file_path);
    
    bfd_node *bfdn = (bfd_node*)node->value;
    
    if(bfdn == NULL)
    {
        bfd* b = bfd_openr(binary_file_path, 0);
        
        if(b != NULL)
        {
            if(bfd_check_format(b, bfd_archive))
            {
                bfd_close(b);
                return FALSE;
            }
            
            char **matching = NULL;
 
            if(!bfd_check_format_matches(b, bfd_object, &matching))
            {
                free(matching);
                bfd_close(b);
                return FALSE;
            }
            
            bfdn = (bfd_node*)malloc(sizeof(bfd_node));
            ZEROMEMORY(bfdn, sizeof(bfd_node));
            bfdn->_bfd = b;
            
            u32 flags = bfd_get_file_flags(b);
            
            format_writer bfd_flags_writer = {debug_bfd_flags_format, (void*)(intptr)flags};
            
            log_debug("bfd: %s: %w", binary_file_path, &bfd_flags_writer);
            
            format_writer bfd_symbol_flags_writer = {debug_bfd_symbol_flags_format, 0};
            
            if( (bfdn->_has_symbols = (flags & HAS_SYMS)) )
            {
                u32 tab_n = bfd_get_symtab_upper_bound(b);
                u32 dyntab_n = bfd_get_dynamic_symtab_upper_bound(b);

                bool dynamic = (flags & DYNAMIC);
                u32 n = (dynamic)?dyntab_n:tab_n;

                bfdn->_symbols = (asymbol**)malloc(n);
                if(!dynamic)
                {
                    bfdn->_symbols_count = bfd_canonicalize_symtab(b, bfdn->_symbols);
                }
                else
                {
                    bfdn->_symbols_count = bfd_canonicalize_dynamic_symtab(b, bfdn->_symbols);
                }
                bfdn->_text = bfd_get_section_by_name(b, ".text");
                
                asymbol** sympa = bfdn->_symbols;
                for(u32 i = 0; i < bfdn->_symbols_count; i++)
                {
                    asymbol *sym = sympa[i];
                    bfd_symbol_flags_writer.value = (void*)(intptr)sym->flags;
                    log_debug1("bfd: %s %w %p", sym->name, &bfd_symbol_flags_writer, sym->value);
                }
            }
            
            node->key = strdup(binary_file_path);
            node->value = bfdn;
        }
        else
        {
            ptr_set_debug_delete(&bfd_collection, binary_file_path);
        }
    }
    
    pthread_mutex_unlock(&bfd_mtx);
    
    bool ret = FALSE;
    
    if(bfdn != NULL)
    {

        intptr offset = (intptr)address;
        if(offset >= bfdn->_text->vma)
        {
            offset -= bfdn->_text->vma;
            pthread_mutex_lock(&bfd_mtx);
            ret = bfd_find_nearest_line(bfdn->_bfd, bfdn->_text, bfdn->_symbols, offset, out_file, out_function, out_line);
#if DEBUG
            if(!ret)
            {
                log_debug("bfd: line not found ...");
            }
#endif
            pthread_mutex_unlock(&bfd_mtx);
        }
        else
        {
            *out_line = 0;
        }
    }
    
    return ret;
}

static void
debug_bfd_clear_delete(ptr_node_debug *node)
{
    bfd_node *bfd = (bfd_node*)node->value;
    if(bfd != NULL)
    {
        free(bfd->_symbols);
        bfd_close(bfd->_bfd);
        free(bfd);
    }
    free(node->key);
}

static
void debug_bfd_clear()
{
    pthread_mutex_lock(&bfd_mtx);
    ptr_set_debug_callback_and_destroy(&bfd_collection, debug_bfd_clear_delete);
    pthread_mutex_unlock(&bfd_mtx);
}

#endif

typedef u64_set_debug stacktrace_set;

//////////////////////////////////////////////////////////////////////////////
//
// STACKTRACE
//
//////////////////////////////////////////////////////////////////////////////


static stacktrace_set stacktraces_list_set = U64_SET_EMPTY;
static pthread_mutex_t stacktraces_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef __GLIBC__
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
debug_stacktrace_get()
{
#ifdef __GLIBC__
    void* buffer_[1024];

    int n = backtrace(buffer_, sizeof(buffer_) / sizeof(void*));
    
    void** buffer = &buffer_[1];
    n -= 1; // minus this function

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
        sll = (list_sl_debug_s*)malloc(sizeof(list_sl_debug_s));
        list_sl_debug_init(sll);
        node->value = sll;
        trace = (stacktrace)malloc((n + 2) * sizeof(intptr));
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
            trace = (stacktrace)malloc((n + 2) * sizeof(intptr));
            memcpy(trace, buffer, n * sizeof(void*));
            trace[n] = 0;
            list_sl_debug_insert(sll, trace);
            trace[n+1] = (intptr)backtrace_symbols(buffer, n);
        }
    }
    
    pthread_mutex_unlock(&stacktraces_mutex);
    
    return trace;
#else
    return NULL;
#endif
}

/**
 * clears all stacktraces from memory
 * should only be called at shutdown
 */

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
            free(trace_strings);
            free(trace);
        }
        
        free(sll);
        node->value = NULL;
    }
}

void
debug_stacktrace_clear()
{
    pthread_mutex_lock(&stacktraces_mutex);
    u64_set_debug_callback_and_destroy(&stacktraces_list_set, debug_stacktrace_clear_delete);
    pthread_mutex_unlock(&stacktraces_mutex);
#if !DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
#if HAS_BFD_DEBUG_SUPPORT
    debug_bfd_clear();
#endif
#endif
}

void
debug_stacktrace_log(logger_handle* handle, u32 level, stacktrace trace)
{
#ifdef __GLIBC__
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
    logger_handle_msg(handle, level, "backtrace not supported");
#endif
}

void
debug_stacktrace_log_with_prefix(logger_handle* handle, u32 level, stacktrace trace, const char *prefix)
{
#ifdef __GLIBC__
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
    logger_handle_msg(handle, level, "backtrace not supported");
#endif
}

void
debug_stacktrace_try_log(logger_handle* handle, u32 level, stacktrace trace)
{
#ifdef __GLIBC__
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

#ifdef __GLIBC__
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

#define REAL_SIZE(rs_size_) MALLOC_REALSIZE((rs_size_)+HEADER_SIZE)

#if DNSCORE_DEBUG_ENHANCED_STATISTICS


/* [  0]   1..  8
 * [  1]   9.. 16
 * [  2]  17.. 24
 * ...
 * [ 15] 121..128
 * [ 31] 248..256
 * [ 32] 257..2^31
 */

static u64 db_alloc_count_by_size[(DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE / 8) + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0
};

static u64 db_alloc_peak_by_size[(DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE / 8) + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0
};

#endif

static u64 db_total_allocated = 0;
static u64 db_total_freed = 0;
static u64 db_current_allocated = 0;
static u64 db_current_blocks = 0;
static u64 db_peak_allocated = 0;

#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
static u64 db_next_block_serial = 0;
#endif

static bool db_showallocs = DNSCORE_DEBUG_SHOW_ALLOCS;

static pthread_mutex_t alloc_mutex = PTHREAD_MUTEX_INITIALIZER;

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

/****************************************************************************/

/****************************************************************************/

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



void*
debug_malloc(
             size_t size_,
             const char* file, int line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
        , u64 tag
#endif
        )
{
    size_t size = MALLOC_REALSIZE(size_);

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    assert((tag != 0) && (tag != ~0ULL));
#endif

    pthread_mutex_lock(&alloc_mutex);

    u64 current_allocated = db_current_allocated;

    pthread_mutex_unlock(&alloc_mutex);


    if(current_allocated + size > DNSCORE_DEBUG_ALLOC_MAX)
    {
        if(__termout__.vtbl != NULL)
        {
            format("DB_MAX_ALLOC reached !!! (%u)", DNSCORE_DEBUG_ALLOC_MAX);
        }

        abort();
    }

    db_header* ptr = (db_header*)malloc(size + HEADER_SIZE); /* Header */

    if(ptr == NULL)
    {
        perror("debug_malloc");

        fflush(NULL);

        abort();
    }

    pthread_mutex_lock(&alloc_mutex);

#if DNSCORE_DEBUG_STACKTRACE
    ptr->_trace = debug_stacktrace_get();
#endif

    ptr->magic = DB_MALLOC_MAGIC;
    ptr->size = size;

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    ptr->tag = tag;
#endif

#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
    ptr->serial = ++db_next_block_serial;

    if(ptr->serial == 0x01cb || ptr->serial == 0x01d0)
    {
        time(NULL);
    }

#endif

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS

    ptr->next = &db_mem_first;
    ptr->previous = db_mem_first.previous;

    db_mem_first.previous->next = ptr;
    db_mem_first.previous = ptr;

#endif

    db_total_allocated += size;
    db_current_allocated += size;
    db_peak_allocated = MAX(db_current_allocated, db_peak_allocated);
    db_current_blocks++;


#if DNSCORE_DEBUG_ENHANCED_STATISTICS

    if(size_ < DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE)
    {
        db_alloc_count_by_size[(size_ - 1) >> 3]++;
        db_alloc_peak_by_size[(size_ - 1) >> 3]++;
    }
    else
    {
        db_alloc_count_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]++;
        db_alloc_peak_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]++;
    }

#endif

    pthread_mutex_unlock(&alloc_mutex);

    if(db_showallocs)
    {
        if(__termout__.vtbl != NULL)
        {
            format("[%08x] malloc(%3x", thread_self(), (u32)size);
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            print(" | ");
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
#endif
#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
            format(" | #%08llx", ptr->serial);
#endif
            formatln(")=%p (%s:%i)", ptr + 1, file, line);
        }
    }

    ptr++;

    /* ensure the memory is not initialized "by chance" */

#if DNSCORE_DEBUG_MALLOC_TRASHMEMORY
    memset(ptr, 0xac, size_); /* AC : AlloCated */
    memset(((u8*)ptr) + size_, 0xca, size - size_); /* CA : AlloCated for padding */
#endif

    return ptr;
}

void*
debug_calloc(
             size_t size_,
             const char* file, int line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
        , u64 tag
#endif
        )
{
    void* p = debug_malloc(size_, file, line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            , tag
#endif
            );

    if(p != NULL)
    {
        ZEROMEMORY(p, size_);
    }

    return p;
}

void
debug_free(void* ptr_, const char* file, int line)
{
    if(ptr_ == NULL)
    {
        return;
    }

    db_header* ptr = (db_header*)ptr_;

    ptr--;

    if(ptr->magic != DB_MALLOC_MAGIC)
    {
        fflush(NULL);

        if(__termout__.vtbl != NULL)
        {
            if(ptr->magic == DB_MFREED_MAGIC)
            {
                formatln("DOUBLE FREE @ %p (%s:%i)", ptr, file, line);
            }
            else
            {
                formatln("MEMORY CORRUPTED @%p (%s:%i)", ptr, file, line);
            }
        }
        
        stacktrace trace = debug_stacktrace_get();
        debug_stacktrace_print(termout, trace);

        debug_dump(ptr, 64, 32, TRUE, TRUE);
        
        flushout();

        abort();
    }

    size_t size = ptr->size;

    if(db_showallocs)
    {
        if(__termout__.vtbl != NULL)
        {
            format("[%08x] free(%p [%3x]", thread_self(), ptr + 1, (u32)size);

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            print(" | ");
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
#endif
#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
            format(" | #%08llx", ptr->serial);
#endif
            formatln(") (%s:%i)", file, line);
        }
    }

    pthread_mutex_lock(&alloc_mutex);

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
    ptr->previous->next = ptr->next;
    ptr->next->previous = ptr->previous;
    ptr->next = (void*)~0;
    ptr->previous = (void*)~0;
#endif

    db_total_freed += size;
    db_current_allocated -= size;
    db_current_blocks--;

#if DNSCORE_DEBUG_ENHANCED_STATISTICS

    if(size < DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE)
    {
        db_alloc_count_by_size[(size - 1) >> 3]--;
    }
    else
    {
        db_alloc_count_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]--;
    }

#endif

    pthread_mutex_unlock(&alloc_mutex);

    ptr->magic = DB_MFREED_MAGIC; /* This is destroyed AFTER free */

    memset(ptr + 1, 0xfe, size); /* FE : FrEed */

    free(ptr);
}

void
*
debug_realloc(void* ptr, size_t size, const char* file, int line)

{
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    u64 tag = 0x4c554e4152;
#endif

    db_header* hdr;

    if(ptr != NULL)
    {
        hdr = (db_header*)ptr;
        hdr--;
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
        tag = hdr->tag;
#endif
    }

    void* newptr = debug_malloc(size, file, line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            , tag
#endif
            );

    if(ptr != NULL)
    {
        if(hdr->size < size)
        {
            size = hdr->size;
        }

        MEMCOPY(newptr, ptr, size);

        debug_free(ptr, file, line);
    }

    return newptr;
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

void
debug_mtest(void* ptr_)
{
    if(ptr_ == NULL)
    {
        return;
    }

    db_header* ptr = (db_header*)ptr_;

    ptr--;
    if(ptr->magic != DB_MALLOC_MAGIC)
    {
        if(__termout__.vtbl != NULL)
        {
            if(ptr->magic == DB_MFREED_MAGIC)
            {
                formatln("DOUBLE FREE @ %p", ptr);
            }
            else
            {
                formatln("MEMORY CORRUPTED @%p", ptr);
            }
        }

        stacktrace trace = debug_stacktrace_get();
        debug_stacktrace_print(termout, trace);
        
        debug_dump(ptr, 64, 32, TRUE, TRUE);

        abort();
    }
}

u32
debug_get_block_count()
{
    return db_current_blocks;
}
void
debug_stat(int mask)
{
    if(__termout__.vtbl == NULL)
    {
        return;
    }
    
    pthread_mutex_lock(&alloc_mutex);
    
    formatln("%16llx | DB: MEM: Total Allocated=%llu", timeus(), db_total_allocated);
    formatln("%16llx | DB: MEM: Total Freed=%llu", timeus(), db_total_freed);
    formatln("%16llx | DB: MEM: Peak Usage=%llu", timeus(), db_peak_allocated);
    formatln("%16llx | DB: MEM: Allocated=%llu", timeus(), db_current_allocated);
    formatln("%16llx | DB: MEM: Blocks=%llu", timeus(), db_current_blocks);
    formatln("%16llx | DB: MEM: Monitoring Overhead=%llu (%i)", timeus(), (u64)(db_current_blocks * HEADER_SIZE), (int)HEADER_SIZE);

#if HAS_LIBC_MALLOC_DEBUG_SUPPORT
    formatln("%16llx | C ALLOC: total: %llu malloc=%llu free=%llu realloc=%llu memalign=%llu",
        timeus(),
        malloc_hook_total,
        malloc_hook_malloc,
        malloc_hook_free,
        malloc_hook_realloc,
        malloc_hook_memalign);
#endif

#if DNSCORE_DEBUG_ENHANCED_STATISTICS
    if(mask & DEBUG_STAT_SIZES)
    {
        formatln("%16llx | DB: MEM: Block sizes: ([size/8]={current / peak}", timeus());

        format("%16llx | ", timeus());
        
        int i;

        for(i = 0; i < (DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3); i++)
        {
            format("[%4i]={%8llu / %8llu} ;", (i + 1) << 3, db_alloc_count_by_size[i], db_alloc_peak_by_size[i]);

            if((i & 3) == 3)
            {
                format("\n%16llx | ", timeus());
            }
        }
        
        println("");

        formatln("%16llx | [++++]={%8llu / %8llu}", timeus(),
                 db_alloc_count_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3],
                 db_alloc_peak_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]);
    }
#endif

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
    if(mask & DEBUG_STAT_TAGS)
    {
        db_header *ptr;
        
        u64 mintag = MAX_U64;
        u64 nexttag;
        
        // find the minimum
        
        for(ptr = db_mem_first.next; ptr != &db_mem_first; ptr = ptr->next)
        {   
            u64 tag = ptr->tag;
            if(tag < mintag)
            {
                mintag = tag;
            }
        }
        
        formatln("%16llx | ", timeus());
        
        //        0123456789ABCDEF   012345678   012345678   012345678   012345678   012345678
        formatln("%16llx | [-----TAG------] :   COUNT    :    MIN     :    MAX     :    MEAN    :   TOTAL", timeus());
        
        for(; mintag != MAX_U64; mintag = nexttag)
        {
            nexttag = MAX_U64;
            u32 count = 0;
            u32 minsize = MAX_U32;
            u32 maxsize = 0;
            u64 totalsize = 0;

            for(ptr = db_mem_first.next; ptr != &db_mem_first; ptr = ptr->next)
            {   
                u64 tag = ptr->tag;

                if((tag > mintag) && (tag < nexttag))
                {
                    nexttag = tag;
                    continue;
                }

                if(tag != mintag)
                {
                    continue;
                }

                count++;
                totalsize += ptr->size;

                if(ptr->size < minsize)
                {
                    minsize = ptr->size;
                }

                if(ptr->size > maxsize)
                {
                    maxsize = ptr->size;
                }
            }
            
            char tag_text[9];
            SET_U64_AT(tag_text[0], mintag);
            tag_text[8] = '\0';
            if(count > 0)
            {
                formatln("%16llx | %16s : %10u : %10u : %10u : %10u : %12llu", timeus(), tag_text, count, minsize, maxsize, totalsize / count, totalsize);
            }
            else
            {
                formatln("%16llx | %16s : %10u : %10u : %10u : ---------- : %12llu", timeus(), tag_text, count, minsize, maxsize, totalsize);
            }
        }
        
        formatln("%16llx | ", timeus());
    }
    
    flushout();
    
    if(mask & DEBUG_STAT_DUMP)
    {
        db_header* ptr = db_mem_first.next;
        int index = 0;
        
        while(ptr != &db_mem_first)
        {
            formatln("block #%04x %16p [%08x]", index, (void*)& ptr[1], ptr->size);

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
            formatln(" | ");
#endif

#if DNSCORE_DEBUG_STACKTRACE
            int n = 0;
            intptr *st = ptr->_trace;
            if(st != NULL)
            {
                while(st[n] != 0)
                {
                    ++n;
                }
            
                char **trace_strings = (char**)st[n + 1];
                for(int i = 0; i < n; i++)
                {
                    formatln("%p %s", (void*)st[i], (trace_strings != NULL) ? trace_strings[i] : "???");
                }
            }
#endif

#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
            formatln("#%08llx | ", ptr->serial);
#endif
            osprint_dump(termout, & ptr[1], MIN(ptr->size, 128), 32, OSPRINT_DUMP_ALL);

            formatln("\n");
            ptr = ptr->next;
            index++;
        }
        
        flushout();
        flusherr();
        //malloc_stats();
        //malloc_info(0, stdout);
    }
#endif
    
    pthread_mutex_unlock(&alloc_mutex);
}

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

bool
debug_mallocated(void* ptr)
{
    if(ptr == NULL)
    {
        /* NULL is ok */

        return TRUE;
    }

    db_header* hdr = (db_header*)ptr;
    hdr--;

    if(hdr->magic == DB_MALLOC_MAGIC)
    {
        return TRUE;
    }
    else if(hdr->magic == DB_MFREED_MAGIC)
    {
        if(__termout__.vtbl != NULL)
        {
            if(hdr->magic == DB_MFREED_MAGIC)
            {
                formatln("DOUBLE FREE @ %p", ptr);
                debug_dump_page(ptr);
            }
        }
        return FALSE;
    }
    else
    {
        if(__termout__.vtbl != NULL)
        {
            formatln("MEMORY CORRUPTED @%p", ptr);
            debug_dump_page(ptr);
        }
        assert(FALSE);

        return FALSE;
    }
}

#if HAS_LIBC_MALLOC_DEBUG_SUPPORT

#if 0 /* fix */
#else

#define __yadifa_malloc_hook __malloc_hook
#define __yadifa_realloc_hook __realloc_hook
#define __yadifa_free_hook __free_hook
#define __yadifa_memalign_hook __memalign_hook

#endif

#define DEBUG_MALLOC_HOOK_DUMP 0

static bool debug_malloc_istracked(void* ptr)
{
    bool ret; 
    pthread_mutex_lock(&malloc_hook_mtx);
    ptr_node_debug *node = ptr_set_debug_find(&malloc_hook_tracked_set, ptr);
    ret = (node != NULL);
    pthread_mutex_unlock(&malloc_hook_mtx);
    return ret;
}

static void debug_malloc_track_alloc_nolock(void* ptr)
{
    //formatln("track alloc %p", ptr);
    
    ptr_node_debug *node = ptr_set_debug_insert(&malloc_hook_tracked_set, ptr);
    
    intptr flags = (intptr)node->value;
    if(flags != 0)
    {
        // track bug
        pthread_mutex_unlock(&malloc_hook_mtx);
        abort();
    }
    flags |= 1;
    node->value = (void*)flags;
}

static void debug_malloc_track_free_nolock(void* ptr)
{
    //formatln("track free  %p", ptr);
    
    ptr_node_debug *node = ptr_set_debug_find(&malloc_hook_tracked_set, ptr);
    
    if(node == NULL)
    {
        // free of non-existing
        pthread_mutex_unlock(&malloc_hook_mtx);
        abort();
    }
    
    intptr flags = (intptr)node->value;
    if((flags & 1) != 1)
    {
        // double free
        pthread_mutex_unlock(&malloc_hook_mtx);
        abort();
    }
    
    flags &= ~1;
    node->value = (void*)flags;
}

void debug_malloc_hook_tracked_dump()
{
    pthread_mutex_lock(&malloc_hook_mtx);
    ptr_set_debug_iterator iter;
    ptr_set_debug_iterator_init(&malloc_hook_tracked_set, &iter);
    while(ptr_set_debug_iterator_hasnext(&iter))
    {
        const ptr_node_debug *node = ptr_set_debug_iterator_next_node(&iter);
        if(((intptr)node->value) == 1)
        {
            const malloc_hook_header_t *hdr =  (const malloc_hook_header_t*)node->key;
            --hdr;
            formatln("%p : size=%llu caller=%p", node->key, hdr->size, hdr->caller);
        }
    }
    pthread_mutex_unlock(&malloc_hook_mtx);
}

struct malloc_hook_caller_t
{
    ssize_t count;
    ssize_t size;
    ssize_t peak;
};

typedef struct malloc_hook_caller_t malloc_hook_caller_t;

void debug_malloc_caller_add(const void* caller_address, ssize_t size)
{
    ptr_node_debug *node = ptr_set_debug_insert(&malloc_hook_caller_set, (void*)caller_address);
    malloc_hook_caller_t *caller = (malloc_hook_caller_t*)node->value;
    if(caller == NULL)
    {
        caller = (malloc_hook_caller_t*)__libc_malloc(sizeof(malloc_hook_caller_t));
        memset(caller, 0, sizeof(malloc_hook_caller_t));
        node->value = caller;
    }
 
    if(size > 0)
    {
        ++caller->count;
    }
    else if(size < 0)
    {
        --caller->count;
    }
    caller->size += size;
    if(caller->size > caller->peak)
    {
        caller->peak = caller->size;
    }
}

void debug_malloc_hook_caller_dump()
{
    formatln("debug_malloc_hook_caller_dump(): begin");
    ssize_t count_total = 0;
    ssize_t size_total = 0;
    pthread_mutex_lock(&malloc_hook_mtx);
    ptr_set_debug_iterator iter;
    ptr_set_debug_iterator_init(&malloc_hook_caller_set, &iter);
    while(ptr_set_debug_iterator_hasnext(&iter))
    {
        const ptr_node_debug *node = ptr_set_debug_iterator_next_node(&iter);
        const malloc_hook_caller_t *caller = (malloc_hook_caller_t*)node->value;
        ssize_t mean = 0;
        ssize_t count = caller->count;
        ssize_t size = caller->size;
        if(count != 0)
        {
            mean = size / count;
        }
        formatln("%p : count=%lli size=%lli peak=%lli (mean bloc size=%lli)", node->key, caller->count, caller->size, caller->peak, mean);
        
        count_total += caller->count;
        size_total += caller->size;
    }
    pthread_mutex_unlock(&malloc_hook_mtx);
    formatln("COUNT TOTAL : %lli", count_total);
    formatln("SIZE TOTAL  : %lli", size_total);
    formatln("debug_malloc_hook_caller_dump(): end");
}

static void *debug_malloc_hook(size_t size, const void *caller)
{
    void *ret = _real_malloc(size + sizeof(malloc_hook_header_t), caller);
    if(ret != NULL)
    {        
        malloc_hook_header_t *hdr = (malloc_hook_header_t*)ret;
        hdr->begin = 0x4242424242424242;
        hdr->magic = 0xd1a27344;
        hdr->size = size;
        hdr->caller = caller;
        hdr->end = 0x4545454545454545;
        ++hdr;
        
        pthread_mutex_lock(&malloc_hook_mtx);
        malloc_hook_total += size;
        malloc_hook_malloc++;
        debug_malloc_caller_add(caller, size);
        debug_malloc_track_alloc_nolock(hdr);
        pthread_mutex_unlock(&malloc_hook_mtx);
#if DEBUG_MALLOC_HOOK_DUMP
        formatln("malloc(%llu) = %p", size, hdr);
#endif
        
        return hdr;
    }
    else
    {
        return ret;
    }
}

static void *debug_realloc_hook(void *ptr, size_t size, const void *caller)
{
    if(ptr != NULL)
    {
        if(!debug_malloc_istracked(ptr))
        {
#if DEBUG_MALLOC_HOOK_DUMP
            formatln("realloc(%p, %llu) untracked", ptr, size);
#endif
            return _real_realloc(ptr, size, caller);
        }
        
        malloc_hook_header_t *hdr = (malloc_hook_header_t*)ptr;
        --hdr;
        if(hdr->magic != 0xd1a27344)
        {
            abort();
        }
        
        hdr->begin = 0x6262626262626262;
        hdr->end = 0x6565656565656565;
        
        const void* old_caller = hdr->caller;
        ssize_t old_size = hdr->size;

        void *ret = _real_realloc(hdr, size + sizeof(malloc_hook_header_t), caller);
        
        if(ret != NULL)
        {
            hdr = (malloc_hook_header_t*)ret;
            hdr->begin = 0x4242424242424242;
            hdr->size = size;
            hdr->caller = caller;
            hdr->end = 0x4545454545454545;
            ++hdr;
            
            pthread_mutex_lock(&malloc_hook_mtx);
            
            debug_malloc_caller_add(old_caller, -old_size);
            debug_malloc_track_free_nolock(ptr);
            
            malloc_hook_total += size - old_size;
            malloc_hook_realloc++;
            
            debug_malloc_caller_add(caller, size);
            debug_malloc_track_alloc_nolock(hdr);
            
            pthread_mutex_unlock(&malloc_hook_mtx);
#if DEBUG_MALLOC_HOOK_DUMP
            formatln("realloc(%p, %llu) = %p", ptr, size, hdr);
#endif
            return hdr;
        }
        else
        {
            return ret;
        }
    }
    else
    {
        ptr = debug_malloc_hook(size, caller);
        return ptr;
    }
}

static void debug_free_hook(void *ptr, const void *caller)
{
    if(ptr != NULL)
    {
        if(!debug_malloc_istracked(ptr))
        {
#if DEBUG_MALLOC_HOOK_DUMP
            formatln("free(%p) untracked", ptr);
#endif
            _real_free(ptr, caller);
            return;
        }
        
        malloc_hook_header_t *hdr = (malloc_hook_header_t*)ptr;
        --hdr;
        if(hdr->magic != 0xd1a27344)
        {
            abort();
        }
        hdr->begin = 0x6262626262626262;
        hdr->end = 0x6565656565656565;
        
        ssize_t size = hdr->size;
        
        pthread_mutex_lock(&malloc_hook_mtx);
        malloc_hook_total -= size;
        malloc_hook_free++;
        
        debug_malloc_caller_add(hdr->caller, -size);
        debug_malloc_track_free_nolock(ptr);
        
        pthread_mutex_unlock(&malloc_hook_mtx);
        
        _real_free(hdr, caller);
#if DEBUG_MALLOC_HOOK_DUMP
        formatln("free(%p)", ptr);
#endif
    }
}

static void *debug_memalign_hook(size_t alignment, size_t size, const void *caller)
{
    void *ret = _real_memalign(alignment, size + sizeof(malloc_hook_header_t), caller);
    if(ret != NULL)
    {
        malloc_hook_header_t *hdr = (malloc_hook_header_t*)ret;
        hdr->begin = 0x4242424242424242;
        hdr->magic = 0xd1a27344;
        hdr->size = size;
        hdr->caller = caller;
        hdr->end = 0x4545454545454545;
        ++hdr;
        
        pthread_mutex_lock(&malloc_hook_mtx);
        malloc_hook_total += size;
        malloc_hook_memalign++;
        debug_malloc_caller_add(caller, size);
        debug_malloc_track_alloc_nolock(hdr);
        pthread_mutex_unlock(&malloc_hook_mtx);
#if DEBUG_MALLOC_HOOK_DUMP
        formatln("memalign(%llu, %llu) = %p", alignment, size, hdr);
#endif
        return hdr;
    }
    else
    {
        return ret;
    }
}

void debug_malloc_hooks_init()
{
    if(!_real_malloc_initialised)
    {
        _real_malloc_initialised = TRUE;
        
        _real_malloc = __yadifa_malloc_hook;
        _real_realloc = __yadifa_realloc_hook;
        _real_free = __yadifa_free_hook;
        _real_memalign = __yadifa_memalign_hook;
        
        __yadifa_malloc_hook = debug_malloc_hook;
        __yadifa_realloc_hook = debug_realloc_hook;
        __yadifa_free_hook = debug_free_hook;
        __yadifa_memalign_hook = debug_memalign_hook;
    }
}

void debug_malloc_hooks_finalize()
{
    if(_real_malloc_initialised)
    {
        _real_malloc_initialised = FALSE;
        
        __yadifa_malloc_hook = _real_malloc;
        __yadifa_realloc_hook = _real_realloc;
        __yadifa_free_hook = _real_free;
        __yadifa_memalign_hook = _real_memalign;
    }
}

void *debug_malloc_unmonitored(size_t size)
{
    return _real_malloc(size, NULL);
}

void debug_free_unmonitored(void* ptr)
{
    _real_free(ptr, NULL);
}

#else
void debug_malloc_hooks_init()
{
}

void debug_malloc_hooks_finalize()
{
}

void *debug_malloc_unmonitored(size_t size)
{
    void *ptr = malloc(size);
    if(ptr == NULL)
    {
        abort();
    }
    return ptr;
}

void debug_free_unmonitored(void* ptr)
{
    free(ptr);
}

void debug_malloc_hook_tracked_dump()
{
}

#endif

#if DEBUG

static pthread_mutex_t debug_bench_mtx = PTHREAD_MUTEX_INITIALIZER;
static debug_bench_s *debug_bench_first = NULL;
static bool debug_bench_init_done = FALSE;

void
debug_bench_init()
{
    if(debug_bench_init_done)
    {
        return;
    }
    
    pthread_mutexattr_t mta;
    int err;
    
    err = pthread_mutexattr_init(&mta);
    
    if(err == 0)
    {
        err = pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
    
        if(err == 0)
        {
            err = pthread_mutex_init(&debug_bench_mtx, &mta);

            if(err == 0)
            {
                debug_bench_init_done = TRUE;
            }
            else
            {
                formatln("debug_bench_init: pthread_mutex_init: %r", MAKE_ERRNO_ERROR(err));
            }
        }
        else
        {
            formatln("debug_bench_init: pthread_mutexattr_settype: %r", MAKE_ERRNO_ERROR(err));
        }
        
        pthread_mutexattr_destroy(&mta);
    }
    else
    {
        formatln("debug_bench_init: pthread_mutexattr_init: %r", MAKE_ERRNO_ERROR(err));
    }
}

void
debug_bench_register(debug_bench_s *bench, const char *name)
{
    pthread_mutex_lock(&debug_bench_mtx);
    
    debug_bench_s *b = debug_bench_first;
    while((b != bench) && (b != NULL))
    {
        b = b->next;
    }
    
    if(b == NULL)
    {
        bench->next = debug_bench_first;
        bench->name = strdup(name);
        bench->time_min = MAX_U64;
        bench->time_max = 0;
        bench->time_total = 0;
        bench->time_count = 0;
        debug_bench_first = bench;
    }
    else
    {
        log_debug("debug_bench_register(%p,%s): duplicate", bench, name);
    }
    pthread_mutex_unlock(&debug_bench_mtx);
}

void
debug_bench_commit(debug_bench_s *bench, u64 delta)
{
    pthread_mutex_lock(&debug_bench_mtx);
    bench->time_min = MIN(bench->time_min, delta);
    bench->time_max = MAX(bench->time_max, delta);
    bench->time_total += delta;
    bench->time_count++;
    pthread_mutex_unlock(&debug_bench_mtx);
}

void debug_bench_logdump_all()
{
    pthread_mutex_lock(&debug_bench_mtx);
    debug_bench_s *p = debug_bench_first;
    while(p != NULL)
    {
        double min = p->time_min;
        min /= ONE_SECOND_US_F;
        double max = p->time_max;
        max /= ONE_SECOND_US_F;
        double total = p->time_total;
        total /= ONE_SECOND_US_F;
        u32 count = p->time_count;
        if(logger_is_running())
        {
            log_info("bench: %12s: [%9.6fs:%9.6fs] total=%9.6fs mean=%9.6fs rate=%-12.3f/s calls=%9u", p->name, min, max, total, total / count, count / total, count);
        }
        else
        {
            formatln("bench: %12s: [%9.6fs:%9.6fs] total=%9.6fs mean=%9.6fs rate=%-12.3f/s calls=%9u", p->name, min, max, total, total / count, count / total, count);
        }
        p = p->next;
    }
    pthread_mutex_unlock(&debug_bench_mtx);
}

void debug_bench_unregister_all()
{
    pthread_mutex_lock(&debug_bench_mtx);
    debug_bench_s *p = debug_bench_first;
    while(p != NULL)
    {
        debug_bench_s *tmp = p;
        p = p->next;
#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
        debug_free((void*)tmp->name,__FILE__,__LINE__);
#else
        free((void*)tmp->name);
#endif
    }
    debug_bench_first = NULL;
    pthread_mutex_unlock(&debug_bench_mtx);
}
#else

void
debug_bench_init()
{
}

void
debug_bench_register(debug_bench_s *bench, const char *name)
{
    (void)bench;
    (void)name;
}

void
debug_bench_commit(debug_bench_s *bench, u64 delta)
{
    (void)bench;
    (void)delta;
}

void debug_bench_logdump_all()
{
}

void
debug_bench_unregister_all()
{
}

#endif

void
debug_nop_hook()
{
    // this function does nothing but help putting a breakpoint
    puts("HOOK");fflush(NULL);
}

/** @} */
