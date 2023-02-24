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
#include "dnscore/dnscore-config-features.h"
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
#if DNSCORE_HAS_BFD_DEBUG_SUPPORT
#include <bfd.h>
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

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#if DNSCORE_HAS_BFD_DEBUG_SUPPORT

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

bool
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

void
debug_bfd_clear()
{
    pthread_mutex_lock(&bfd_mtx);
    ptr_set_debug_callback_and_destroy(&bfd_collection, debug_bfd_clear_delete);
    pthread_mutex_unlock(&bfd_mtx);
}

#endif

/** @} */

