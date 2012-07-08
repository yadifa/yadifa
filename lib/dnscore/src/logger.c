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

void
log_memdump_ex(logger_handle* hndl, u32 level, const void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text, bool address)
{
    if((hndl == NULL) || (level >= MSG_LEVEL_COUNT) || (hndl->channels[level].offset < 0))
    {
        return;
    }

    output_stream os;
    char buffer[4096];

    bytearray_output_stream_init((u8*)buffer, sizeof (buffer), &os);

    u8* data_pointer = (u8*)data_pointer_;
    s32 size = size_;


    int dump_size;
    int i;

    do
    {
        dump_size = MIN(line_size, size);

        u8* data;

        if(address)
        {
            osformat(&os, "%p ", data_pointer);
        }

        if(hex)
        {
            data = data_pointer;
            for(i = 0; i < dump_size; i++)
            {
                osformat(&os, "%02x", *data++);
                if((i & 3) == 3)
                {
                    output_stream_write_u8(&os, (u8)' ');
                }
            }

            for(; i < line_size; i++)
            {
                osprint(&os, "  ");
                if((i & 3) == 0)
                {
                    osprint(&os, " ");
                }
            }
        }

        if(hex & text)
        {
            output_stream_write(&os, (u8*)" | ", 3);
        }

        if(text)
        {
            data = data_pointer;
            for(i = 0; i < dump_size; i++)
            {
                char c = *data++;
                if(c < ' ')
                {
                    c = '.';
                }
                else if(c == '%')
                {
                    output_stream_write_u8(&os, '%');
                }

                output_stream_write_u8(&os, (u8)c);
            }
        }

        data_pointer += dump_size;
        size -= dump_size;

        if(size != 0)
        {
            output_stream_write_u8(&os, 0);
            logger_handle_msg(hndl, level, "%s", bytearray_output_stream_buffer(&os));
            bytearray_output_stream_reset(&os);
        }
    }
    while(size > 0);

    //if(size_ > line_size)
    if(bytearray_output_stream_size(&os) > 0)
    {
        output_stream_write_u8(&os, 0);
        logger_handle_msg(hndl, level, "%s", bytearray_output_stream_buffer(&os));
    }

    output_stream_close(&os);
}

void
log_memdump(logger_handle* hndl, u32 level, const void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text)
{
    log_memdump_ex(hndl, level, data_pointer_, size_, line_size, hex, text, FALSE);
}

/** @} */

/*----------------------------------------------------------------------------*/

