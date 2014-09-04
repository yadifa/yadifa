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
*/
/** @defgroup logger Logging functions
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
#include <stdarg.h>

#include "dnscore/bytearray_output_stream.h"
#include "dnscore/logger.h"
#include "dnscore/format.h"

static u32 log_memdump_ex_layout_mask = 0x000003ff;

void
log_memdump_set_layout(u32 group_mask, u32 separator_mask)
{
    log_memdump_ex_layout_mask = ((group_mask <<  OSPRINT_DUMP_LAYOUT_GROUP_SHIFT) & OSPRINT_DUMP_LAYOUT_GROUP_MASK)            |
                                 ((separator_mask << OSPRINT_DUMP_LAYOUT_SEPARATOR_SHIFT) & OSPRINT_DUMP_LAYOUT_SEPARATOR_MASK);
}

void
log_memdump_ex(logger_handle* hndl, u32 level, const void* data_pointer_, size_t size_, size_t line_size, u32 flags)
{
    /*
     * ensure there is an output for this handle/level
     */
    
    if((hndl == NULL) || (level >= MSG_LEVEL_COUNT) || (hndl->channels[level].offset < 0))
    {
        return;
    }
    
    output_stream os;
    bytearray_output_stream_context os_context;
    
    char buffer[1024];
    
#ifdef DEBUG
    assert(line_size > 0);
    assert(line_size < sizeof(buffer) / 8);
    memset(buffer, 0xba, sizeof(buffer));
#endif
    
    flags |= log_memdump_ex_layout_mask;

    bytearray_output_stream_init_ex_static(&os, (u8*)buffer, sizeof (buffer), 0, &os_context);

    const u8* data_pointer = (const u8*)data_pointer_;
    s32 size = size_;
    
    while(size > line_size)
    {
        osprint_dump(&os, data_pointer, line_size, line_size, flags);        
        
        u32 buffer_size = bytearray_output_stream_size(&os);
        
        logger_handle_msg_text(hndl, level, buffer, buffer_size);
        
        bytearray_output_stream_reset(&os);
        
        data_pointer += line_size;
        size -= line_size;
    }
    
    if(size > 0)
    {
        osprint_dump(&os, data_pointer, size, line_size, flags);        
        
        u32 buffer_size = bytearray_output_stream_size(&os);
        
        logger_handle_msg_text(hndl, level, buffer, buffer_size);
    }

    output_stream_close(&os);
}

void
log_memdump(logger_handle* hndl, u32 level, const void* data_pointer_, size_t size_, size_t line_size)
{
    log_memdump_ex(hndl, level, data_pointer_, size_, line_size, OSPRINT_DUMP_HEXTEXT);
}

/** @} */

/*----------------------------------------------------------------------------*/

