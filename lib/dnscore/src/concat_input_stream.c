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

/** @defgroup streaming Streams
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/concat_input_stream.h"
#include "dnscore/zalloc.h"

#define CONCAT_INPUT_STREAM_TAG 0x53495441434e4f43 /* CONCATIS */
#define CONCAT_INPUT_STREAM_NODE_TAG 0x5349444e54434e43 /* CNCTNDIS */

typedef struct concat_input_stream_data_node concat_input_stream_data_node;

struct concat_input_stream_data_node
{
    struct concat_input_stream_data_node *next;
    input_stream filtered;
};
typedef struct concat_input_stream_data concat_input_stream_data;

struct concat_input_stream_data
{
    concat_input_stream_data_node* current;
    concat_input_stream_data_node** lastlink;
};

static ya_result
concat_read(input_stream* stream, void* buffer_, u32 len)
{
    concat_input_stream_data *data = (concat_input_stream_data*)stream->data;
    u8 *buffer = (u8*)buffer_;
    
    ya_result total = 0;
    ya_result return_value = SUCCESS;
    
    while(len > 0)
    {   
        if(data->current == NULL)
        {
            return_value = SUCCESS;
            break;
        }
        
        if(FAIL(return_value = input_stream_read(&data->current->filtered, &buffer[total], len)))
        {
            break;
        }
        
        if(return_value == 0) /* EOF */
        {
            concat_input_stream_data_node *next = data->current->next;
            input_stream_close(&data->current->filtered);
            ZFREE(data->current, concat_input_stream_data_node);
            data->current = next;

            if(data->current == NULL)
            {
                data->lastlink = &data->current;
            }

            continue;
        }

        total += return_value;
        len -= return_value;
    }
    
    if((total == 0) && FAIL(return_value))
    {
        total = return_value;
    }
    
    return total;
}

static void
concat_close(input_stream* stream)
{
    concat_input_stream_data* data = (concat_input_stream_data*)stream->data;
    
    while(data->current != NULL)
    {
        input_stream_close(&data->current->filtered);
        concat_input_stream_data_node *next = data->current->next;
        ZFREE(data->current, concat_input_stream_data_node);
        data->current = next;
    }
    
    ZFREE(data, concat_input_stream_data);

    input_stream_set_void(stream);
}

static ya_result
concat_skip(input_stream* stream, u32 len)
{
    concat_input_stream_data *data = (concat_input_stream_data*)stream->data;
    
    ya_result total = 0;
    ya_result return_value = SUCCESS;
    
    while(len > 0)
    {
        if(data->current == NULL)
        {
            return_value = -1;
            break;
        }
        
        if(FAIL(return_value = input_stream_skip(&data->current->filtered, len)))
        {
            if(return_value == -1)
            {
                concat_input_stream_data_node *next = data->current->next;
                input_stream_close(&data->current->filtered);
                ZFREE(data->current, concat_input_stream_data_node);
                data->current = next;
                
                if(data->current == NULL)
                {
                    data->lastlink = &data->current;
                }
                
                continue;
            }

            break;
        }

        total += return_value;
        len -= return_value;
    }
    
    if((total == 0) && FAIL(return_value))
    {
        total = return_value;
    }
    
    return total;
}

static const input_stream_vtbl concat_input_stream_vtbl =
{
    concat_read,
    concat_skip,
    concat_close,
    "concat_input_stream"
};

/**
 * 
 * @param cis
 */
    
void concat_input_stream_init(input_stream *cis)
{
    concat_input_stream_data* data;

    ZALLOC_OBJECT_OR_DIE( data, concat_input_stream_data, CONCAT_INPUT_STREAM_TAG);
    data->current = NULL;
    data->lastlink = &data->current;

    cis->data = data;
    cis->vtbl = &concat_input_stream_vtbl;
}

/**
 * 
 * @param cis
 * @param added_stream
 */

void concat_input_stream_add(input_stream *cis, input_stream *added_stream)
{
    concat_input_stream_data* data = (concat_input_stream_data*)cis->data;
    concat_input_stream_data_node *node;
    
    ZALLOC_OBJECT_OR_DIE( node, concat_input_stream_data_node, CONCAT_INPUT_STREAM_NODE_TAG);
    node->filtered.data = added_stream->data;
    node->filtered.vtbl = added_stream->vtbl;
    node->next = NULL;
    added_stream->data = NULL;
    added_stream->vtbl = NULL;
    *data->lastlink = node;
    data->lastlink = &node->next;
}


/** @} */

/*----------------------------------------------------------------------------*/

