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
 *----------------------------------------------------------------------------*/

#include "yatest.h"
#include <dnscore/dnscore.h>
#include <dnscore/list_dl_nodata.h>

struct item_s
{
    list_dl_nodata_node_t node;
    char                  text[20];
};

typedef struct item_s item_t;

static item_t        *item_new(int id)
{
    item_t *item = (item_t *)malloc(sizeof(item_t));
    snprintf(item->text, sizeof(item_t), "%i", id);
    return item;
}

static void item_delete(void *p) { free(p); }

static int  list_dl_nodata_test()
{
    item_t *items[8];
    dnscore_init();

    for(int i = 0; i < 8; ++i)
    {
        items[i] = item_new(i);
    }

    list_dl_nodata_t *list = list_dl_nodata_new_instance();

    list_dl_nodata_append_node(list, &items[4]->node);
    list_dl_nodata_append_node(list, &items[5]->node);
    list_dl_nodata_append_node(list, &items[6]->node);
    list_dl_nodata_append_node(list, &items[7]->node);
    list_dl_nodata_insert_node(list, &items[3]->node);
    list_dl_nodata_insert_node(list, &items[2]->node);
    list_dl_nodata_insert_node(list, &items[1]->node);
    list_dl_nodata_insert_node(list, &items[0]->node);

    if(list_dl_nodata_size(list) != 8)
    {
        yatest_err("list_dl_nodata_size did not return 8, returned %i instead (a)", list_dl_nodata_size(list));
        return 1;
    }

    for(int i = 0; i < 4; ++i)
    {
        void *item;
        item = list_dl_nodata_first_node(list);
        if(item != items[i])
        {
            yatest_err("list_dl_nodata_first_node didn't return item %i (a)", i);
            return 1;
        }

        item = list_dl_nodata_last_node(list);
        if(item != items[7 - i])
        {
            yatest_err("list_dl_nodata_first_node didn't return item %i (a)", 7 - i);
            return 1;
        }

        item = list_dl_nodata_remove_first_node(list);
        if(item != items[i])
        {
            yatest_err("list_dl_nodata_remove_first_node didn't return item %i (a)", i);
            return 1;
        }

        item = list_dl_nodata_remove_last_node(list);
        if(item != items[7 - i])
        {
            yatest_err("list_dl_nodata_first_node didn't return item %i (a)", 7 - i);
            return 1;
        }
    }

    if(list_dl_nodata_size(list) != 0)
    {
        yatest_err("list_dl_nodata_size did not return 0, returned %i instead (a)", list_dl_nodata_size(list));
        return 1;
    }

    list_dl_nodata_insert_node(list, &items[3]->node);
    list_dl_nodata_insert_node(list, &items[2]->node);
    list_dl_nodata_insert_node(list, &items[1]->node);
    list_dl_nodata_insert_node(list, &items[0]->node);
    list_dl_nodata_append_node(list, &items[4]->node);
    list_dl_nodata_append_node(list, &items[5]->node);
    list_dl_nodata_append_node(list, &items[6]->node);
    list_dl_nodata_append_node(list, &items[7]->node);

    if(list_dl_nodata_size(list) != 8)
    {
        yatest_err("list_dl_nodata_size did not return 8, returned %i instead (b)", list_dl_nodata_size(list));
        return 1;
    }

    for(int i = 0; i < 4; ++i)
    {
        void *item;
        item = list_dl_nodata_first_node(list);
        if(item != items[i])
        {
            yatest_err("list_dl_nodata_first_node didn't return item %i (b)", i);
            return 1;
        }

        item = list_dl_nodata_last_node(list);
        if(item != items[7 - i])
        {
            yatest_err("list_dl_nodata_first_node didn't return item %i (b)", 7 - i);
            return 1;
        }

        item = list_dl_nodata_remove_first_node(list);
        if(item != items[i])
        {
            yatest_err("list_dl_nodata_remove_first_node didn't return item %i (b)", i);
            return 1;
        }

        item = list_dl_nodata_remove_last_node(list);
        if(item != items[7 - i])
        {
            yatest_err("list_dl_nodata_first_node didn't return item %i (b)", 7 - i);
            return 1;
        }
    }

    if(list_dl_nodata_size(list) != 0)
    {
        yatest_err("list_dl_nodata_size did not return 0, returned %i instead (b)", list_dl_nodata_size(list));
        return 1;
    }

    list_dl_nodata_insert_node(list, &items[3]->node);
    list_dl_nodata_append_node(list, &items[4]->node);
    list_dl_nodata_append_node(list, &items[5]->node);
    list_dl_nodata_append_node(list, &items[6]->node);
    list_dl_nodata_append_node(list, &items[7]->node);
    list_dl_nodata_append_node(list, &items[2]->node);
    list_dl_nodata_append_node(list, &items[1]->node);
    list_dl_nodata_append_node(list, &items[0]->node);

    list_dl_nodata_move_node_to_first_position(list, &items[2]->node);
    list_dl_nodata_move_node_to_first_position(list, &items[1]->node);
    list_dl_nodata_move_node_to_first_position(list, &items[0]->node);

    for(int i = 0; i < 4; ++i)
    {
        void *item;
        item = list_dl_nodata_first_node(list);
        if(item != items[i])
        {
            yatest_err("list_dl_nodata_first_node didn't return item %i (c)", i);
            return 1;
        }

        item = list_dl_nodata_last_node(list);
        if(item != items[7 - i])
        {
            yatest_err("list_dl_nodata_first_node didn't return item %i (c)", 7 - i);
            return 1;
        }

        list_dl_nodata_remove_node(list, &items[i]->node);
        list_dl_nodata_remove_node(list, &items[7 - i]->node);
    }

    if(list_dl_nodata_size(list) != 0)
    {
        yatest_err("list_dl_nodata_size did not return 0, returned %i instead (c)", list_dl_nodata_size(list));
        return 1;
    }

    void *item;
    if((item = list_dl_nodata_first_node(list)) != NULL)
    {
        yatest_err("list_dl_nodata_first_node expected to return NULL, returned %p instead", item);
        return 1;
    }

    if((item = list_dl_nodata_remove_first_node(list)) != NULL)
    {
        yatest_err("list_dl_nodata_remove_first_node expected to return NULL, returned %p instead", item);
        return 1;
    }

    if((item = list_dl_nodata_last_node(list)) != NULL)
    {
        yatest_err("list_dl_nodata_last_node expected to return NULL, returned %p instead", item);
        return 1;
    }

    if((item = list_dl_nodata_remove_last_node(list)) != NULL)
    {
        yatest_err("list_dl_nodata_remove_last_node expected to return NULL, returned %p instead", item);
        return 1;
    }

    for(int i = 0; i < 8; ++i)
    {
        item_delete(items[i]);
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(list_dl_nodata_test)
YATEST_TABLE_END
