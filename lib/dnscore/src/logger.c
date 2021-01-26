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

/** @defgroup logger Logging functions
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
log_memdump_ex(logger_handle* hndl, u32 level, const void* data_pointer_, ssize_t size_, ssize_t line_size, u32 flags)
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
    
#if DEBUG
    assert(line_size > 0);
    assert(line_size < (ssize_t)sizeof(buffer) / 8);
    memset(buffer, 0xba, sizeof(buffer));
#endif
    
    flags |= log_memdump_ex_layout_mask;

    bytearray_output_stream_init_ex_static(&os, (u8*)buffer, sizeof(buffer), 0, &os_context);

    const u8* data_pointer = (const u8*)data_pointer_;
    ssize_t size = size_;
    
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
log_memdump(logger_handle* hndl, u32 level, const void* data_pointer_, ssize_t size_, ssize_t line_size)
{
    log_memdump_ex(hndl, level, data_pointer_, size_, line_size, OSPRINT_DUMP_HEXTEXT);
}

#ifndef WIN32
void log_msghdr(logger_handle* hndl, u32 level, struct msghdr *hdr)
{
    logger_handle_msg(hndl, level, "udp message header:");

    if(hdr->msg_name != NULL )
    {
        logger_handle_msg(hndl, level, "msg_name: %{sockaddr}", hdr->msg_name);
        log_memdump_ex(hndl, level, hdr->msg_name, hdr->msg_namelen, 32, OSPRINT_DUMP_ALL);
        
    }
    else
    {
        logger_handle_msg(hndl, level, "msg_name is NULL");
    }

    if(hdr->msg_iov != NULL)
    {
        for(size_t i = 0; i < hdr->msg_iovlen; i++)
        {
            struct iovec *msg_iov = &hdr->msg_iov[i];
            if(msg_iov->iov_base != NULL)
            {
                logger_handle_msg(hndl, level, "msg_iov[%i]:", i);
                log_memdump_ex(hndl, level, msg_iov->iov_base, msg_iov->iov_len, 32, OSPRINT_DUMP_ALL);
            }
            else
            {
                logger_handle_msg(hndl, level, "msg_iov[%i] is NULL", i);
            }
        }
    }
    else
    {
        logger_handle_msg(hndl, level, "msg_iov is NULL");
    }

    if(hdr->msg_control != NULL)
    {
        logger_handle_msg(hndl, level, "msg_control:");
        log_memdump_ex(hndl, level, hdr->msg_control, hdr->msg_controllen, 32, OSPRINT_DUMP_ALL);
    }
    else
    {
        logger_handle_msg(hndl, level, "msg_control is NULL");
    }

    logger_handle_msg(hndl, level, "msg_flags: %x", hdr->msg_flags);
}
#endif

/** @} */

