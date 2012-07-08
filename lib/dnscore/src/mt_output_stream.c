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
/** @defgroup streaming Streams
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/mt_output_stream.h"

#define MT_OUTPUT_STREAM_TAG 0x534F544D /* MTOS */

typedef struct mt_output_stream_data mt_output_stream_data;


struct mt_output_stream_data
{
    output_stream filtered;
	pthread_mutex_t mutex;
};

static ya_result 
mt_write(output_stream* stream, const u8* buffer, u32 len)
{
    mt_output_stream_data* data = (mt_output_stream_data*) stream->data;

	pthread_mutex_lock(&data->mutex);
	ya_result ret = output_stream_write(&data->filtered, buffer, len);
	pthread_mutex_unlock(&data->mutex);

    return ret;
}

static ya_result 
mt_flush(output_stream* stream)
{
    mt_output_stream_data* data = (mt_output_stream_data*) stream->data;

	pthread_mutex_lock(&data->mutex);
	ya_result ret = output_stream_flush(&data->filtered);
	pthread_mutex_unlock(&data->mutex);

    return ret;
}

static void 
mt_close(output_stream* stream)
{
    mt_output_stream_data* data = (mt_output_stream_data*) stream->data;

	pthread_mutex_lock(&data->mutex);
    output_stream_close(&data->filtered);
	pthread_mutex_unlock(&data->mutex);

	pthread_mutex_destroy(&data->mutex);

    free(data);
    stream->data = NULL;
}

static output_stream_vtbl mt_output_stream_vtbl =
{    
    mt_write,
    mt_flush,
    mt_close,
    "mt_output_stream",
};

ya_result
mt_output_stream_init(output_stream* filtered, output_stream* stream)
{
    mt_output_stream_data* data;

    if(filtered->vtbl == NULL)
    {
		return ERROR;
    }

    MALLOC_OR_DIE(mt_output_stream_data*, data, sizeof (mt_output_stream_data), MT_OUTPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;

    filtered->data = NULL;		    /* Clean the filtered BEFORE setting up the stream */
    filtered->vtbl = NULL;

	pthread_mutex_init(&data->mutex, NULL);

    stream->data = data;
    stream->vtbl = &mt_output_stream_vtbl;

    return SUCCESS;
}

/** @} */

/*----------------------------------------------------------------------------*/

