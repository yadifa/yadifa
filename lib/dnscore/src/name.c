/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2019, EURid vzw. All rights reserved.
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
/** @defgroup tools
 *  @ingroup dnscore
 *  @brief 
 *
 *  A central storage of strings to avoid unnecessary duplicates.
 *  Names are never released.
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"
#include "dnscore/name.h"
#include "dnscore/string_set.h"
#include "dnscore/mutex.h"

#define NAMENAME_TAG 0x454d414e454d414e

static const size_t text_buffer_size = 1024 * 1024;
static mutex_t name_fqdn_set_mtx = MUTEX_INITIALIZER;
static mutex_t name_text_set_mtx = MUTEX_INITIALIZER;
static mutex_t text_buffer_mtx = MUTEX_INITIALIZER;
static string_set name_fqdn_set = STRING_SET_EMPTY;
static string_set name_text_set = STRING_SET_EMPTY;
static u8* text_buffer = NULL;
static u8* text_buffer_limit = NULL;
static u8* text_buffer_current = NULL;

static void* name_allocate(size_t len)
{
    assert(len < text_buffer_size);
    
    mutex_lock(&text_buffer_mtx);
    size_t avail = text_buffer_current - text_buffer_limit;
    
    if(avail < len)
    {
        u8 *next;
        MALLOC_OR_DIE(u8*, next, text_buffer_size, NAMENAME_TAG);
        void** chain = (void**)next;
        *chain = text_buffer;
        text_buffer = next;
        text_buffer_limit = &text_buffer[text_buffer_size];
        text_buffer_current = &text_buffer[sizeof(void**)];
    }
    
    void *ret = text_buffer_current;
    text_buffer_current += len;
    mutex_unlock(&text_buffer_mtx);
    return ret;
}

/**
 * Returns a copy of the name
 */

const u8*
name_get_fqdn(const u8 *name)
{
    mutex_lock(&name_fqdn_set_mtx);
    string_node *node = string_set_avl_insert(&name_fqdn_set, (const char *)name);
    if(node->value == 0)
    {
        size_t len = dnsname_len(name);
        u8 *key = (u8*)name_allocate(len);
        memcpy(key, name, len);
        node->key = (char*)key;
        node->value = 1;
    }
    mutex_unlock(&name_fqdn_set_mtx);
    
    return (const u8*)node->key;
}

/**
 * Returns a copy of the name
 */

const char*
name_get_text(const char *name)
{
    mutex_lock(&name_text_set_mtx);
    string_node *node = string_set_avl_insert(&name_text_set, name);
    if(node->value == 0)
    {
        size_t len = strlen(name) + 1;
        char *key = (char*)name_allocate(len);
        memcpy(key, name, len);
        node->key = key;
        node->value = 1;
    }
    mutex_unlock(&name_text_set_mtx);
    return node->key;
}

/**
 * @}
 */
