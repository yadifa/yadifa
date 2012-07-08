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
#ifndef _LOGGER_HANDLE_H
#define	_LOGGER_HANDLE_H

#include <dnscore/logger.h>
#include <dnscore/ptr_vector.h>

#ifdef	__cplusplus
extern "C"
{
#endif

typedef ptr_vector logger_channel_array;

struct logger_channel;

typedef struct logger_handle logger_handle;

struct logger_handle
{
    logger_channel_array channels[MSG_LEVEL_COUNT];
    const char *name;
    const char *formatted_name;
    u8 formatted_name_len;
};
    
#define LOGGER_MESSAGE_STD      0
#define LOGGER_MESSAGE_TIMEMS   1
#define LOGGER_MESSAGE_PREFIX   2

void logger_handle_msg(logger_handle* handle, u32 level, const char* fmt, ...);

void logger_handle_msg_text(logger_handle *handle, u32 level, const char* text, u32 text_len);
void logger_handle_msg_text_ext(logger_handle *handle, u32 level, const char* text, u32 text_len, const char* prefix, u32 prefix_len, u16 flags);

logger_handle* logger_handle_add(const char *name);
logger_handle* logger_handle_get(const char *name);

void logger_handle_exit_level(u32 level);

void logger_handle_finalize();

void log_memdump_ex(logger_handle* hndl, u32 level, const void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text, bool address);
void log_memdump(logger_handle* hndl, u32 level, const void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text);

void logger_handle_add_channel(logger_handle *handle, int level, struct logger_channel *chan);

#ifdef	__cplusplus
}
#endif


#endif	/* _LOGGER_HANDLE_H */
/** @} */

/*----------------------------------------------------------------------------*/

