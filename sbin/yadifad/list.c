/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
* DOCUMENTATION */
/** @defgroup list Routines for list_data struct
 *  @ingroup yadifad
 *  @brief list functions
 *
 *  Implementation of routines for the list_data struct
 *   - add
 *   - length
 *   - print
 *   - remove
 *   - search
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <dnscore/sys_types.h>
#include <dnscore/dnscore.h>
#include <dnscore/format.h>

#include "list.h"

#define LISTDATA_TAG 0x415441445453494c

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Add a new list_data struct to the existing one
 *
 *  New struct will be added at the front of the linked list
 *
 *  @param[in]  src data to be added in linked list
 *  @param[out] dst linked list
 *
 *  @return a pointer to linked list
 *  @return NULL on error
 */
int
list_add(list_data **dst, const char *src)
{
    list_data *tmp = NULL;

    /*    ------------------------------------------------------------    */

    /* Alloc & clear list_data structure */
    MALLOC_OR_DIE(list_data*, tmp, sizeof (list_data), LISTDATA_TAG);

    ZEROMEMORY(tmp, sizeof (list_data));

    /* Add new struct */
    tmp->next = *dst;
    *dst = tmp;
    Strcpy(tmp->data, src);

    return OK;
}

/** @brief  Search of the total amount of elements in linked list
 *
 *  @param[in] src linked list
 *
 *  @retval count total amount of elements in list
 */
size_t
list_length(list_data *src)
{
    list_data *p = src;
    size_t count = 0;

    /*    ------------------------------------------------------------    */

    while(p != NULL)
    {
        count++;
        p = p->next;
    }
    return count;
}

/** @brief  Print the linked list to standard out
 *
 *  @param[in] src  linked list
 *  @param[in] text string to be sent to stdout with the linked list
 *
 *
 *  @return NONE
 */
void
list_print(list_data *src, const char *text, output_stream* os)
{
    /* No struct found */
    if(src == NULL)
    {
        osformat(os, "%s empty\n", text);
    }

    while(src != NULL)
    {
        if(text != NULL)
        {
            osformat(os, "%s%s\n", text, src->data);
        }
        else
        {
            osformat(os, "%s\n", src->data);
        }

        src = src->next;
    }
}

/** @brief  Remove  1 element of the linked list
 *
 *  @param[in] src linked list
 *
 *  @return NONE
 */
void
list_remove(list_data **src)
{
    if(*src != NULL)
    {
        list_data *tmp = *src;
        *src           = (*src)->next;

        free(tmp);
    }
}

/** @brief Remove all elements of linked list
 *
 *  @param[in] src linked list
 *
 *  @return NONE
 */
void
list_remove_all(list_data **src)
{
    while(*src != NULL)
    {
        list_remove(src);
    }
}

/** @brief Search in linked list for the correct data
 *
 *  @param[in,out] n
 *  @param[in] data data to be found in linked list
 *
 *  @return NULL if nothing found
 *  @return pointer of the correct struct
 */
list_data **
list_search(list_data **n, const char *src)
{
    while(*n != NULL)
    {
        if(!strcmp((*n)->data, src))
        {
            return n;
        }
        n = &(*n)->next;
    }
    return NULL;
}

/** @} */

/*----------------------------------------------------------------------------*/
