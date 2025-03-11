/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/fdtools.h"
#include "dnscore/zalloc.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/timems.h"
#include "dnscore/logger.h"
#include "dnscore/mutex.h"
#include "dnscore/file_mtime_set.h"

#define FILE_MTIME_C_ 1

#define MTIMESET_TAG  0x544553454d49544d

struct file_mtime_set_s
{
    ptr_treemap_t files_mtime;
    char         *name;
    bool          is_new;
};

typedef struct file_mtime_set_s file_mtime_set_t;

static ptr_treemap_t            file_mtime_sets = {NULL, ptr_treemap_asciizp_node_compare};
static mutex_t                  file_mtime_sets_mtx;

file_mtime_set_t               *file_mtime_set_get_for_file(const char *filename)
{
    file_mtime_set_t *ret;
    mutex_lock(&file_mtime_sets_mtx);
    ptr_treemap_node_t *sets_node = ptr_treemap_insert(&file_mtime_sets, (char *)filename);
    if(sets_node->value != NULL)
    {
        ret = (file_mtime_set_t *)sets_node->value;
    }
    else
    {
        sets_node->key = strdup(filename);
        ZALLOC_OBJECT_OR_DIE(ret, file_mtime_set_t, MTIMESET_TAG);
        ret->files_mtime.root = NULL;
        ret->files_mtime.compare = ptr_treemap_asciizp_node_compare;
        ret->name = strdup(filename);
        ret->is_new = true;
        sets_node->value = ret;
        file_mtime_set_add_file(ret, filename);
    }
    mutex_unlock(&file_mtime_sets_mtx);
    return ret;
}

void file_mtime_set_add_file(file_mtime_set_t *ctx, const char *filename)
{
    int64_t mtime;

    if(FAIL(file_mtime(filename, &mtime)))
    {
        mtime = S64_MIN;
    }

    ptr_treemap_node_t *node = ptr_treemap_insert(&ctx->files_mtime, (char *)filename);
    if(node->value == NULL)
    {
        node->key = strdup(filename);
        node->value_s64 = mtime;
    }
}

bool file_mtime_set_modified(file_mtime_set_t *ctx)
{
    if(ctx->is_new)
    {
        ctx->is_new = false;
        return true;
    }

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&ctx->files_mtime, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        const char         *filename = (const char *)node->key;
        int64_t             mtime;
        if(ISOK(file_mtime(filename, &mtime)))
        {
            if(node->value_s64 < mtime)
            {
                return true;
            }
        }
        else
        {
            return true;
        }
    }
    return false;
}

void file_mtime_set_clear(file_mtime_set_t *ctx)
{
    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&ctx->files_mtime, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        free(node->key);
    }
    ptr_treemap_finalise(&ctx->files_mtime);
    file_mtime_set_add_file(ctx, ctx->name);
}

void file_mtime_set_delete(file_mtime_set_t *ctx)
{
    mutex_lock(&file_mtime_sets_mtx);
    ptr_treemap_delete(&file_mtime_sets, ctx->name);
    mutex_unlock(&file_mtime_sets_mtx);
    file_mtime_set_clear(ctx);
    free(ctx->name);
    ZFREE_OBJECT(ctx);
}

/** @} */
