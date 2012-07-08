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
#ifndef _LOGGER_CHANNEL_H
#define	_LOGGER_CHANNEL_H

#include <stdarg.h>

#include <dnscore/sys_types.h>
#include <dnscore/ptr_vector.h>

#ifdef	__cplusplus
extern "C"
{
#endif
    
struct logger_handle;
    
typedef struct logger_message logger_message;

struct logger_message
{
    struct logger_handle* handle;   // 0
    u8* text;                       // 8
    
    u32 text_length;            // 12/4
    pthread_t thread_id;        // 16/8
    
    struct timeval tv;          // 24/8
    
    pid_t pid;                  // 32/8
    u16 level;                  // 36/4
    u16 flags;                  // 38/2
    
    const u8* prefix;           // 40/8
    u16 prefix_length;          // 48
    s16 rc;                     // 50   reference count for the repeats
                                // 52
};
    
struct logger_channel_vtbl;

struct logger_channel
{
    void *data;
    struct logger_channel_vtbl *vtbl;
    logger_message *last_message;
    u32 last_message_count;
};

typedef struct logger_channel logger_channel;

typedef ya_result logger_channel_constmsg_method(logger_channel* chan, int level, char* text, u32 text_len, u32 date_offset);
typedef ya_result logger_channel_msg_method(logger_channel* chan, int level, char* text, ...);
typedef ya_result logger_channel_vmsg_method(logger_channel* chan, int level, char* text, va_list args);
typedef void logger_channel_flush_method(logger_channel* chan);
typedef void logger_channel_close_method(logger_channel* chan);
typedef ya_result logger_channel_reopen_method(logger_channel* chan);

typedef struct logger_channel_vtbl logger_channel_vtbl;


struct logger_channel_vtbl
{
    logger_channel_constmsg_method *constmsg;
    logger_channel_msg_method *msg;
    logger_channel_vmsg_method *vmsg;
    logger_channel_flush_method *flush;
    logger_channel_close_method *close;
    logger_channel_reopen_method *reopen; /* So a HUP will flush, close then reopen/create the log files again */
    const char *__class__;
};

#define logger_channel_msg(channel_,level_,text_, text_len_, date_offs_) (channel_)->vtbl->constmsg((channel_),(level_),(text_),(text_len_),(date_offs_))
#define logger_channel_msgf(channel_,level_,text_, ...) (channel_)->vtbl->msg((channel_),(level_),(text_),__VA_ARGS__)
#define logger_channel_vmsgf(channel_,level_,text_, args_) (channel_)->vtbl->msg((channel_),(level_),(text_),(args_))
#define logger_channel_flush(channel_) (channel_)->vtbl->flush(channel_)
#define logger_channel_reopen(channel_) (channel_)->vtbl->reopen(channel_)
#define logger_channel_close(channel_) (channel_)->vtbl->close(channel_)


logger_channel* logger_channel_alloc();

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGGER_CHANNEL_H */
/** @} */

/*----------------------------------------------------------------------------*/

