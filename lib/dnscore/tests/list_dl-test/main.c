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

#include "yatest.h"
#include <dnscore/dnscore.h>
#include <dnscore/list_dl.h>

static char *item_new(int id)
{
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%i", id);
    return strdup(tmp);
}

static void item_delete(void *p) { free(p); }

static int  item_compare(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }

static bool item_equals(const void *a, const void *b) { return item_compare(a, b) == 0; }

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

static int item_match_delete(void *item_, void *parm_)
{
    const char *item = (const char *)item_;
    const char *parm = (const char *)parm_;
    return item_equals(item, parm);
}

static int item_concat(void *item_, void *parm_)
{
    char word[16];
    snprintf(word, sizeof(word), "<%s>", (char *)item_);
    strcat((char *)parm_, word);
    return 0;
}

static int list_dl_test()
{
    char  tmp[256];
    char *items[4];
    dnscore_init();

    for(int i = 0; i < 4; ++i)
    {
        items[i] = item_new(i);
    }

    list_dl_t *list = list_dl_new_instance();
    list_dl_add(list, items[2]);
    list_dl_insert(list, items[1]);
    list_dl_insert(list, items[0]);
    list_dl_add(list, items[3]);

    if(list_dl_size(list) != 4)
    {
        yatest_err("expected size 4, got %i", list_dl_size(list));
        return 1;
    }

    tmp[0] = '\0';
    list_dl_iterator_t iter;
    list_dl_iterator_init(list, &iter);
    while(list_dl_iterator_has_next(&iter))
    {
        char  word[8];
        char *item = (char *)list_dl_iterator_next(&iter);
        snprintf(word, sizeof(word), "<%s>", item);
        strcat(tmp, word);
    }

    static const char *const iterator_expected = "<0><1><2><3>";
    if(strcmp(tmp, iterator_expected) != 0)
    {
        yatest_err("iterator gives different content than expected: '%s' != '%s'", tmp, iterator_expected);
        return 1;
    }

    char *item6 = item_new(6);
    char *item7 = item_new(7);
    list_dl_iterator_append(&iter, item7);
    list_dl_iterator_insert(&iter, item6);
    tmp[0] = '\0';
    list_dl_iterator_init(list, &iter);
    while(list_dl_iterator_has_next(&iter))
    {
        char  word[8];
        char *item = (char *)list_dl_iterator_next(&iter);
        snprintf(word, sizeof(word), "<%s>", item);
        strcat(tmp, word);
    }

    static const char *const iterator_expected2 = "<0><1><2><6><3><7>";
    if(strcmp(tmp, iterator_expected2) != 0)
    {
        yatest_err("iterator gives different content than expected: '%s' != '%s'", tmp, iterator_expected2);
        return 1;
    }

    list_dl_iterator_remove(&iter);

    tmp[0] = '\0';
    list_dl_iterator_init(list, &iter);
    while(list_dl_iterator_has_next(&iter))
    {
        char  word[8];
        char *item = (char *)list_dl_iterator_next(&iter);
        snprintf(word, sizeof(word), "<%s>", item);
        strcat(tmp, word);
    }

    static const char *const iterator_expected3 = "<0><1><2><6><3>";
    if(strcmp(tmp, iterator_expected3) != 0)
    {
        yatest_err("iterator gives different content than expected: '%s' != '%s'", tmp, iterator_expected3);
        return 1;
    }

    list_dl_remove_matching_ptr(list, item6);

    for(int i = 0; i < 4; ++i)
    {
        int index = list_dl_indexof(list, items[i]);
        if(index != i)
        {
            yatest_err("expected index %i, got %i", i, index);
            return 1;
        }

        char *item_get = (char *)list_dl_get(list, i);
        if(!item_equals(items[i], item_get))
        {
            yatest_err("list_dl_get didn't return the expected item '%s', got '%s'", items[i], item_get);
            return 1;
        }
    }

    const char *item3 = (const char *)list_dl_search(list, item_search_comparator, "3");
    if(item3 != items[3])
    {
        yatest_err("list_dl_search didn't return item 3");
        return 1;
    }

    char *item4 = item_new(4);
    char *item5 = item_new(5);
    char *itemN = item_new(-1);
    list_dl_add(list, item5);
    list_dl_insert(list, itemN);

    char *peek_last = list_dl_peek_last(list);
    if(peek_last != item5)
    {
        yatest_err("list_dl_peek_last didn't return expected value");
        return 1;
    }
    char *peek_first = list_dl_peek_first(list);
    if(peek_first != itemN)
    {
        yatest_err("list_dl_peek_first didn't return expected value");
        return 1;
    }

    char *removed_first = list_dl_remove_first(list);
    if(removed_first != itemN)
    {
        yatest_err("list_dl_remove_first didn't return expected value");
        return 1;
    }
    char *removed_last = list_dl_remove_last(list);
    if(removed_last != item5)
    {
        yatest_err("list_dl_remove_last didn't return expected value");
        return 1;
    }

    list_dl_add(list, item5);
    if(!list_dl_remove(list, item5))
    {
        yatest_err("list_dl_remove failed");
        return 1;
    }
    if(list_dl_remove(list, item5))
    {
        yatest_err("list_dl_remove succeeded");
        return 1;
    }

    list_dl_add(list, item5);
    if(!list_dl_remove_matching_ptr(list, item5))
    {
        yatest_err("list_dl_remove_matching_ptr failed");
        return 1;
    }
    if(list_dl_remove_matching_ptr(list, item5))
    {
        yatest_err("list_dl_remove_matching_ptr succeeded");
        return 1;
    }

    list_dl_add(list, item5);
    if(!list_dl_remove_matching(list, item_match_delete, item5))
    {
        yatest_err("list_dl_remove_matching failed");
        return 1;
    }
    if(list_dl_remove_matching(list, item_match_delete, item5))
    {
        yatest_err("list_dl_remove_matching succeeded");
        return 1;
    }

    list_dl_add(list, item5);
    list_dl_add(list, item5);
    list_dl_add(list, item5);
    if(!list_dl_remove_all_matching(list, item_match_delete, item5))
    {
        yatest_err("list_dl_remove_all_matching failed");
        return 1;
    }
    if(list_dl_remove_all_matching(list, item_match_delete, item5))
    {
        yatest_err("list_dl_remove_all_matching succeeded");
        return 1;
    }

    tmp[0] = '\0';
    list_dl_foreach(list, item_concat, tmp);
    if(strcmp(tmp, iterator_expected) != 0)
    {
        yatest_err("iterator gives different content than expected: '%s' != '%s'", tmp, iterator_expected);
        return 1;
    }

    list_dl_move_last_to_first(list);
    list_dl_move_to_first_position(list, items[2]);

    tmp[0] = '\0';
    list_dl_foreach(list, item_concat, tmp);

    static const char *const iterator_expected4 = "<2><3><0><1>";
    if(strcmp(tmp, iterator_expected4) != 0)
    {
        yatest_err("iterator gives different content than expected: '%s' != '%s'", tmp, iterator_expected4);
        return 1;
    }

    list_dl_move_to_first_position(list, item4);

    tmp[0] = '\0';
    list_dl_foreach(list, item_concat, tmp);

    static const char *const iterator_expected5 = "<4><2><3><0><1>";
    if(strcmp(tmp, iterator_expected5) != 0)
    {
        yatest_err("iterator gives different content than expected: '%s' != '%s'", tmp, iterator_expected5);
        return 1;
    }

    list_dl_enqueue(list, item5);
    if(!item_equals(list_dl_dequeue(list), items[1]))
    {
        yatest_err("list_dl_dequeue didn't return '1'");
        return 1;
    }

    tmp[0] = '\0';
    list_dl_foreach(list, item_concat, tmp);

    static const char *const iterator_expected6 = "<5><4><2><3><0>";
    if(strcmp(tmp, iterator_expected6) != 0)
    {
        yatest_err("iterator gives different content than expected: '%s' != '%s'", tmp, iterator_expected6);
        return 1;
    }

    if(!item_equals(list_dl_first_node(list)->data, item5))
    {
        yatest_err("list_dl_first_node didn't return the node of '5'");
        return 1;
    }

    list_dl_clear(list);

    item_delete(itemN);
    item_delete(item5);
    item_delete(item4);
    item_delete(item7);
    item_delete(item6);
    for(int i = 0; i < 4; ++i)
    {
        item_delete(items[i]);
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(list_dl_test)
YATEST_TABLE_END
