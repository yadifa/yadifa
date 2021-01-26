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
#pragma once

#include <dnscore/output_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

    /*
     * The buffer will be freed (free) on close.
     */

    #define BYTEARRAY_OWNED             1

    /*
     * The buffer's size can be changed.
     */

    #define BYTEARRAY_DYNAMIC           2

    /*
     * The internal context has been allocated by a malloc (the default except if the _static variant is used)
     * YOU MOSTLY WILL NOT USE THAT FLAG
     */
    
    #define BYTEARRAY_ZALLOC_CONTEXT    4

    typedef char bytearray_output_stream_context[sizeof(void*) + 9];

    void bytearray_output_stream_init(output_stream* out_stream, u8* array,u32 size);
    void bytearray_output_stream_init_ex(output_stream* out_stream, u8* array,u32 size, u8 flags);
    
    /*
     * most of bytearray_output_stream usages function-enclosed : init, work on, close
     * this variant of initialisation avoids an malloc
     */
    
    void bytearray_output_stream_init_ex_static(output_stream* out_stream, u8* array,u32 size, u8 flags, bytearray_output_stream_context *ctx);

    void bytearray_output_stream_reset(output_stream* out_stream);
    // can only work if the buffer is owned
    ya_result bytearray_output_stream_ensure(output_stream* out_stream, u32 size);
    u32 bytearray_output_stream_size(output_stream* out_stream);
    u8* bytearray_output_stream_buffer(output_stream* out_stream);
    u8* bytearray_output_stream_detach(output_stream* out_stream);
    
    void bytearray_output_stream_set(output_stream* out_stream, u8 *buffer, u32 buffer_size, bool owned);

    /**
     
     * @param out_stream
     * @param by
     * @return the actual rewind_count
     */
    
    u32 bytearray_output_stream_rewind(output_stream* out_stream, u32 rewind_count);
    
    u8* bytearray_output_stream_zdup(output_stream* out_stream);
    u8* bytearray_output_stream_dup(output_stream* out_stream);
    
#ifdef	__cplusplus
}
#endif

/** @} */
