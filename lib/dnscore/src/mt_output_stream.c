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
#include "dnscore/mt_output_stream.h"
#include "dnscore/mutex.h"
#include "dnscore/ptr_set.h"
#include "dnscore/bytearray_output_stream.h"

#define MT_OUTPUT_STREAM_TAG 0x534F544D /* MTOS */

#define MT_OUTPUT_STREAM_BUFFER_INITIAL_SIZE 128U

typedef struct mt_output_stream_data mt_output_stream_data;

struct mt_output_stream_data
{
    output_stream filtered;
    mutex_t mutex;
    ptr_set writers;
};

static ya_result
mt_write(output_stream *stream, const u8 *buffer, u32 len)
{
    ya_result ret;

    mt_output_stream_data *data = (mt_output_stream_data *) stream->data;

    mutex_lock(&data->mutex);
    ptr_node *writer_node = ptr_set_insert(&data->writers, (void*)pthread_self());
    output_stream* osp;
    if(writer_node->value != NULL)
    {
        osp = (output_stream*)writer_node->value;
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(osp, output_stream, GENERIC_TAG);
        bytearray_output_stream_init_ex(osp, NULL, MT_OUTPUT_STREAM_BUFFER_INITIAL_SIZE, BYTEARRAY_DYNAMIC);
        writer_node->value = osp;
    }
    mutex_unlock(&data->mutex);

    ret = len;

    ya_result err;
    ya_result written = 0;

    while(len > 0)
    {
        u8 *lfp = (u8*)memchr(buffer, '\n', len);

        if(lfp != NULL)
        {
            mutex_lock(&data->mutex);
            if(bytearray_output_stream_size(osp) > 0)
            {
                if(FAIL(err = output_stream_write(&data->filtered, bytearray_output_stream_buffer(osp), bytearray_output_stream_size(osp))))
                {
                    mutex_unlock(&data->mutex);

                    if(written == 0)
                    {
                        return err;
                    }
                    else
                    {
                        return written;
                    }
                }

                bytearray_output_stream_reset(osp);
            }
            ++lfp;
            size_t n = lfp - buffer;
            if(ISOK(err = output_stream_write(&data->filtered, buffer, n)))
            {
                written += err;
            }
            else
            {
                mutex_unlock(&data->mutex);

                if(written == 0)
                {
                    return err;
                }
                else
                {
                    return written;
                }
            }
            mutex_unlock(&data->mutex);
            buffer = lfp;
            len -= n;
        }
        else
        {
            mutex_lock(&data->mutex);
            err = output_stream_write(osp, buffer, len);
            mutex_unlock(&data->mutex);
            if(ISOK(err))
            {
                return  ret;
            }
            else
            {
                if(written == 0)
                {
                    return err;
                }
                else
                {
                    return written;
                }
            }
        }
    }

    return ret;
}

static ya_result
mt_flush(output_stream *stream)
{
    mt_output_stream_data *data = (mt_output_stream_data *) stream->data;
    ya_result ret = SUCCESS;

    mutex_lock(&data->mutex);

    FOREACH_PTR_SET(output_stream*,osp, &data->writers)
    {
        if(bytearray_output_stream_size(osp) > 0)
        {
            ret = output_stream_write(&data->filtered, bytearray_output_stream_buffer(osp), bytearray_output_stream_size(osp));
            bytearray_output_stream_reset(osp);
        }
    }

    output_stream_flush(&data->filtered);

    mutex_unlock(&data->mutex);

    return ret;
}

static void
mt_close(output_stream *stream)
{
    mt_output_stream_data *data = (mt_output_stream_data *) stream->data;

    mutex_lock(&data->mutex);

    FOREACH_PTR_SET(output_stream*,osp, &data->writers)
    {
        if(bytearray_output_stream_size(osp) > 0)
        {
            output_stream_write(&data->filtered, bytearray_output_stream_buffer(osp), bytearray_output_stream_size(osp));
            bytearray_output_stream_reset(osp);
            output_stream_close(osp);
            free(osp);
        }
    }
    ptr_set_destroy(&data->writers);
    output_stream_set_void(stream);
    output_stream_close(&data->filtered);
    mutex_unlock(&data->mutex);
    mutex_destroy(&data->mutex);
    free(data);
}

static const output_stream_vtbl mt_output_stream_vtbl =
{
        mt_write,
        mt_flush,
        mt_close,
        "mt_output_stream",
};

ya_result
mt_output_stream_init(output_stream *stream, output_stream *filtered)
{
    mt_output_stream_data *data;

    if(filtered->vtbl == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    MALLOC_OBJECT_OR_DIE(data, mt_output_stream_data, MT_OUTPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;
    data->writers.compare = ptr_set_ptr_node_compare;
    data->writers.root = NULL;

    filtered->data = NULL;            /* Clean the filtered BEFORE setting up the stream */
    filtered->vtbl = NULL;

    mutex_init(&data->mutex);

    stream->data = data;
    stream->vtbl = &mt_output_stream_vtbl;

    return SUCCESS;
}

output_stream *
mt_output_stream_get_filtered(output_stream *bos)
{
    output_stream *ret;
    mt_output_stream_data *data = (mt_output_stream_data *) bos->data;
    mutex_lock(&data->mutex);
    ret = &data->filtered;
    mutex_unlock(&data->mutex);

    return ret;
}

void mt_output_stream_detach_filtered(output_stream *bos, output_stream *detached_filtered)
{
    mt_output_stream_data *data = (mt_output_stream_data *) bos->data;
    mutex_lock(&data->mutex);
    *detached_filtered = data->filtered;
    output_stream_set_sink(&data->filtered);
    mutex_unlock(&data->mutex);
}

void
mt_output_stream_set_filtered(output_stream *bos, output_stream *new_os, bool also_close)
{
    output_stream *os;
    mt_output_stream_data *data = (mt_output_stream_data *) bos->data;
    mutex_lock(&data->mutex);
    os = &data->filtered;

    output_stream_flush(os);
    if(also_close)
    {
        output_stream_close(os);
    }
    data->filtered = *new_os;
    output_stream_set_sink(new_os);

    mutex_unlock(&data->mutex);
}

bool
is_mt_output_stream(const output_stream* bos)
{
    return (bos != NULL) && (bos->vtbl == &mt_output_stream_vtbl);
}

/** @} */
