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
#include <dnscore/list_sl_debug.h>

static char *item_new(int id)
{
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%i", id);
    return strdup(tmp);
}

static void item_delete(void *p) { free(p); }

static int  item_compare(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }

static int  item_search_comparator(void *item_, void *parm_)
{
    const char *item = (const char *)item_;
    const char *parm = (const char *)parm_;
    /*
     * COLLECTION_ITEM_SKIP                 : go to next item
     * COLLECTION_ITEM_STOP                 : stop processing, return NULL
     * COLLECTION_ITEM_PROCESS_THEN_STOP    : stop processing, return node data
     */
    int n = item_compare(item, parm);
    if(n < 0)
    {
        return COLLECTION_ITEM_SKIP;
    }
    else if(n > 0)
    {
        return COLLECTION_ITEM_STOP;
    }
    else
    {
        return COLLECTION_ITEM_PROCESS_THEN_STOP;
    }
}

static int item_search_comparator_multiple(void *item_, void *parm_)
{
    const char *item = (const char *)item_;
    const char *parm = (const char *)parm_;
    /*
     * COLLECTION_ITEM_SKIP                 : go to next item
     * COLLECTION_ITEM_STOP                 : stop processing, return NULL
     * COLLECTION_ITEM_PROCESS_THEN_STOP    : stop processing, return node data
     */
    int n = item_compare(item, parm);
    if(n < 0)
    {
        return COLLECTION_ITEM_SKIP;
    }
    else if(n > 0)
    {
        return COLLECTION_ITEM_STOP;
    }
    else
    {
        return COLLECTION_ITEM_PROCESS;
    }
}
/*
static int item_match_delete(void *item_, void *parm_)
{
    const char *item = (const char*)item_;
    const char *parm = (const char*)parm_;
    return item_equals(item, parm);
}
*/
static int list_sl_debug_test()
{
    char *items[8];
    dnscore_init();

    for(int i = 0; i < 8; ++i)
    {
        items[i] = item_new(i);
    }

    list_sl_debug_t *list = list_sl_debug_new_instance();
    list_sl_debug_add(list, items[3]);
    list_sl_debug_push(list, items[2]);
    list_sl_debug_insert(list, items[1]);
    list_sl_debug_add(list, items[0]);

    if(list_sl_debug_size(list) != 4)
    {
        yatest_err("expected size 4, got %i", list_sl_debug_size(list));
        return 1;
    }

    for(int i = 0; i < 4; ++i)
    {
        char *popped;
        popped = (char *)list_sl_debug_pop(list);
        yatest_log("popped '%s'", popped);
        if(popped != items[i])
        {
            yatest_err("popped #%i expected %s got %s", i, items[i], popped);
            return 1;
        }
    }

    if(list_sl_debug_size(list) != 0)
    {
        yatest_err("expected size 0, got %i", list_sl_debug_size(list));
        return 1;
    }

    for(int i = 0; i < 8; ++i)
    {
        list_sl_debug_push(list, items[7 - i]);
    }

    if(!list_sl_debug_remove(list, items[2]))
    {
        yatest_err("list_sl_debug_remove 2 failed");
        return 1;
    }

    if(list_sl_debug_remove(list, items[2]))
    {
        yatest_err("list_sl_debug_remove 2 succeeded");
        return 1;
    }

    if(!list_sl_debug_remove(list, items[1]))
    {
        yatest_err("list_sl_debug_remove 1 failed");
        return 1;
    }

    if(list_sl_debug_remove(list, items[1]))
    {
        yatest_err("list_sl_debug_remove 1 succeeded");
        return 1;
    }

    if(!list_sl_debug_remove(list, items[6]))
    {
        yatest_err("list_sl_debug_remove 6 failed");
        return 1;
    }

    if(list_sl_debug_remove(list, items[6]))
    {
        yatest_err("list_sl_debug_remove 6 succeeded");
        return 1;
    }

    if(!list_sl_debug_remove(list, items[7]))
    {
        yatest_err("list_sl_debug_remove 7 failed");
        return 1;
    }

    if(list_sl_debug_remove(list, items[7]))
    {
        yatest_err("list_sl_debug_remove 7 succeeded");
        return 1;
    }

    if(!list_sl_debug_remove(list, items[0]))
    {
        yatest_err("list_sl_debug_remove 0 failed");
        return 1;
    }

    if(list_sl_debug_remove(list, items[0]))
    {
        yatest_err("list_sl_debug_remove 0 succeeded");
        return 1;
    }

    list_sl_debug_clear(list);

    for(int i = 0; i < 8; ++i)
    {
        list_sl_debug_push(list, items[7 - i]);
    }

    if(list_sl_debug_size(list) != 8)
    {
        yatest_err("expected size 8, got %i", list_sl_debug_size(list));
        return 1;
    }

    for(int i = 0; i < 8; ++i)
    {
        char *popped;
        popped = (char *)list_sl_debug_pop(list);
        yatest_log("popped '%s'", popped);
        if(popped != items[i])
        {
            yatest_err("popped #%i expected %s got %s", i, items[i], popped);
            return 1;
        }
    }
    {
        char *popped;
        popped = (char *)list_sl_debug_pop(list);
        if(popped != NULL)
        {
            yatest_err("popped #%i expected NULL got %s", 9, popped);
            return 1;
        }
    }

    for(int i = 0; i < 8; ++i)
    {
        list_sl_debug_push(list, items[7 - i]);
    }

    if(!list_sl_debug_remove_match(list, item_search_comparator, items[2]))
    {
        yatest_err("list_sl_debug_remove_match 2 failed");
        return 1;
    }

    if(list_sl_debug_remove_match(list, item_search_comparator, items[2]))
    {
        yatest_err("list_sl_debug_remove_match 2 succeeded");
        return 1;
    }

    if(!list_sl_debug_remove_match(list, item_search_comparator, items[1]))
    {
        yatest_err("list_sl_debug_remove_match 1 failed");
        return 1;
    }

    if(list_sl_debug_remove_match(list, item_search_comparator, items[1]))
    {
        yatest_err("list_sl_debug_remove_match 1 succeeded");
        return 1;
    }

    if(!list_sl_debug_remove_match(list, item_search_comparator, items[6]))
    {
        yatest_err("list_sl_debug_remove_match 6 failed");
        return 1;
    }

    if(list_sl_debug_remove_match(list, item_search_comparator, items[6]))
    {
        yatest_err("list_sl_debug_remove_match 6 succeeded");
        return 1;
    }

    if(!list_sl_debug_remove_match(list, item_search_comparator, items[7]))
    {
        yatest_err("list_sl_debug_remove_match 7 failed");
        return 1;
    }

    if(list_sl_debug_remove_match(list, item_search_comparator, items[7]))
    {
        yatest_err("list_sl_debug_remove_match 7 succeeded");
        return 1;
    }

    if(!list_sl_debug_remove_match(list, item_search_comparator, items[0]))
    {
        yatest_err("list_sl_debug_remove_match 0 failed");
        return 1;
    }

    if(list_sl_debug_remove_match(list, item_search_comparator, items[0]))
    {
        yatest_err("list_sl_debug_remove_match 0 succeeded");
        return 1;
    }

    list_sl_debug_push(list, items[0]);
    list_sl_debug_push(list, items[0]);
    list_sl_debug_push(list, items[0]);

    if(!list_sl_debug_remove_match(list, item_search_comparator_multiple, items[0]))
    {
        yatest_err("list_sl_debug_remove_match 0 failed");
        return 1;
    }

    if(list_sl_debug_remove_match(list, item_search_comparator_multiple, items[0]))
    {
        yatest_err("list_sl_debug_remove_match 0 succeeded");
        return 1;
    }

    for(int i = 0; i < 8; ++i)
    {
        list_sl_debug_push(list, items[7 - i]);
    }

    for(int i = 0; i < 8; ++i)
    {
        char *item = (char *)list_sl_debug_search(list, item_search_comparator, items[i]);
        if(item != items[i])
        {
            yatest_err("list_sl_debug_search %i didn't return the expected item");
            return 1;
        }
    }

    list_sl_debug_delete(list);

    for(int i = 0; i < 8; ++i)
    {
        item_delete(items[i]);
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(list_sl_debug_test)
YATEST_TABLE_END
