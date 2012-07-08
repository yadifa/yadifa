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
#ifndef _BYTEARRAY_OUTPUT_STREAM_H
#define	_BYTEARRAY_OUTPUT_STREAM_H

#include <dnscore/output_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

    /*
     * The buffer will be freed (free) on close.
     */

    #define BYTEARRAY_OWNED	1

    /*
     * The buffer's size can be changed.
     */

    #define BYTEARRAY_DYNAMIC   2

    void bytearray_output_stream_init(u8* array,u32 size, output_stream* out_stream);
    void bytearray_output_stream_init_ex(u8* array,u32 size, output_stream* out_stream, u8 flags);

    void bytearray_output_stream_reset(output_stream* out_stream);
    u32 bytearray_output_stream_size(output_stream* out_stream);
    u8* bytearray_output_stream_buffer(output_stream* out_stream);
    u8* bytearray_output_stream_detach(output_stream* out_stream);

#ifdef	__cplusplus
}
#endif

#endif	/* _BYTEARRAY_OUTPUT_STREAM_H */
/** @} */

/*----------------------------------------------------------------------------*/

