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
#ifndef _LOGGER_HANDLE_H
#define	_LOGGER_HANDLE_H

#include <syslog.h>

#include <dnscore/ptr_vector.h>
#include <dnscore/format.h>

/*
 * Basically a copy from syslog
 */

#define MSG_EMERG      0   /* system is unusable                      */
#define MSG_ALERT      1   /* action must be taken immediately        */
#define MSG_CRIT       2   /* critical conditions                     */
#define MSG_ERR        3   /* error conditions                        */
#define MSG_WARNING    4   /* warning conditions                      */
#define MSG_NOTICE     5   /* normal, but significant, condition      */
#define MSG_INFO       6   /* informational message                   */
#define MSG_DEBUG      7   /* debug-level message                     */
#define MSG_DEBUG1     8   /* debug-level message                     */
#define MSG_DEBUG2     9   /* debug-level message                     */
#define MSG_DEBUG3     10  /* debug-level message                     */
#define MSG_DEBUG4     11  /* debug-level message                     */
#define MSG_DEBUG5     12  /* debug-level message                     */
#define MSG_DEBUG6     13  /* debug-level message                     */
#define MSG_DEBUG7     14  /* debug-level message                     */

#define MSG_ALL        15   /* all message levels                     */
#define MSG_ALL_MASK   0xffff   /* all message levels as a bitmap     */
#define MSG_PROD_MASK  0x007f   /// non-debug message levels as a bitmap


#define MSG_LEVEL_COUNT 16

/**
 * The default buffer size (0-cost) made available for each line.
 * If the line is bigger the buffer's size is raised at a certain (non-nul)
 * cost.
 *
 */

#define DEFAULT_MAX_LINE_SIZE	128

#define LOG_QUEUE_MIN_SIZE              0x00000400              //  1K
#define LOG_QUEUE_MAX_SIZE              0x01000000              // 16M
#define LOG_QUEUE_DEFAULT_SIZE          0x00100000              //  1M


#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * Handle
 */
    
typedef ptr_vector logger_channel_array;

struct logger_channel;

typedef struct logger_handle logger_handle;

struct logger_handle
{
    logger_channel_array channels[MSG_LEVEL_COUNT];
    const char *name;
    const char *formatted_name;
    struct logger_handle **global_reference;
    u8 formatted_name_len;
};

/**
 * Channel
 */

struct logger_channel_vtbl;
union logger_message;

struct logger_channel
{
    void *data;
    const struct logger_channel_vtbl *vtbl;
    union logger_message *last_message;
    u32 last_message_count;
    s32 linked_handles;
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

/**
 * Message flags
 */

#define LOGGER_MESSAGE_STD      0
#define LOGGER_MESSAGE_TIMEMS   1
#define LOGGER_MESSAGE_PREFIX   2

/**
 * Allocates an empty channel
 * Meant to be used by channels implementation
 */

logger_channel* logger_channel_alloc();

s32 logger_channel_get_usage_count(const char* channel_name);
void logger_channel_register(const char* channel_name, struct logger_channel *channel);
void logger_channel_unregister(const char* channel_name);

void logger_channel_close_all();

void logger_handle_create(const char *logger_name, logger_handle **handle_holder);
void logger_handle_add_channel(const char* logger_name, int level, const char* channel_name);
void logger_handle_remove_channel(const char *logger_name, const char *channel_name);
void logger_handle_close(const char *logger_name);

/**
 * 
 * Sends a formatted text to the logger
 * 
 * @param handle        handle to use, can be NULL
 * @param level         level of the message
 * @param fmt           format string
 * @param args          parameters for the format
 */

void logger_handle_vmsg(logger_handle* handle, u32 level, const char* fmt, va_list args);

/**
 * 
 * Sends a formatted text to the logger
 * 
 * @param handle        handle to use, can be NULL
 * @param level         level of the message
 * @param fmt           format string
 * @param ...           parameters for the format
 */

void logger_handle_msg(logger_handle* handle, u32 level, const char* fmt, ...);

/**
 * 
 * Sends a text to the logger
 * 
 * @param handle        handle to use, can be NULL
 * @param level         level of the message
 * @param text          text to send
 * @param text_len      length of the text to send
 */

void logger_handle_msg_text(logger_handle *handle, u32 level, const char* text, u32 text_len);

/**
 * 
 * Sends a text to the logger with a prefix
 * 
 * @param handle        handle to use, can be NULL
 * @param level         level of the message
 * @param text          text to send
 * @param text_len      text length
 * @param prefix        prefix
 * @param prefix_len    prefix length
 * @param flags         LOGGER_MESSAGE_* flags
 */

void logger_handle_msg_text_ext(logger_handle *handle, u32 level, const char* text, u32 text_len, const char* prefix, u32 prefix_len, u16 flags);

/**
 * Sets the layout for the logged memory dumps
 * Values MUST be set to (2^n)-1 with n >= 0
 * Values MUST be < 256
 * 
 * @param group_mask        The mask to group the bytes together (ie: 3 for making groups of 4)
 * @param separator_mask    the mask to put a space separator every few bytes (ie: 3 for every 4 bytes)
 * 
 */

void log_memdump_set_layout(u32 group_mask, u32 separator_mask);

/**
 * Dumps memory in to the logger
 * 
 * @param hndl          handle to use, can be NULL
 * @param level         level of the message
 * @param data_pointer  memory to dump
 * @param size          size of the memory to dump
 * @param line_size     length of a line
 * @param flags         see osprint_dump for details: OSPRINT_DUMP_ADDRESS, OSPRINT_DUMP_HEX, OSPRINT_DUMP_TEXT
 */

void log_memdump_ex(logger_handle* hndl, u32 level, const void* data_pointer, size_t size, size_t line_size, u32 flags);
void log_memdump(logger_handle* hndl, u32 level, const void* data_pointer, size_t size, size_t line_size);

void logger_handle_exit_level(u32 level);

void logger_handle_finalize();

void logger_set_level(u8 level);

#define LOG_MEMDUMP_LAYOUT_DENSE 0xff,0xff
#define LOG_MEMDUMP_LAYOUT_ERIC 3,0xff
#define LOG_MEMDUMP_LAYOUT_GERY 0,3
    
/*
 * GCC style :
 *
 * #define debug(vararg...) logger_handle_msg(NULL,MSG_DEBUG,vararg)
 *
 * C99 style :
 *
 * #define debug(...) logger_handle_msg(NULL,MSG_DEBUG,__VA_ARGS__)
 *
 */

#if defined(MODULE_MSG_HANDLE)
    #define debug(...)  logger_handle_msg((MODULE_MSG_HANDLE),MSG_DEBUG,__VA_ARGS__)
#else
    #define debug(...)  logger_handle_msg(NULL,MSG_DEBUG,__VA_ARGS__)
#endif

/**
 * LOG_TEXT_PREFIX is a text constant that will be prefixed to every text logged in the current source file.
 * It is a constant that MUST be set before including logger_handle.h (or any logger header)
 */

#if !defined(LOG_TEXT_PREFIX)
#define LOG_TEXT_PREFIX
#endif

#define log_debug7(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG7,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug6(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG6,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug5(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG5,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug4(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG4,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug3(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG3,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug2(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG2,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug1(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG1,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug(...)  logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_notice(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_NOTICE,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_info(...)   logger_handle_msg(MODULE_MSG_HANDLE,MSG_INFO,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_warn(...)   logger_handle_msg(MODULE_MSG_HANDLE,MSG_WARNING,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_err(...)    logger_handle_msg(MODULE_MSG_HANDLE,MSG_ERR,LOG_TEXT_PREFIX __VA_ARGS__)
/* Obsolete, Critical error: quit */
#define log_quit(...)   logger_handle_msg(MODULE_MSG_HANDLE,MSG_CRIT,LOG_TEXT_PREFIX __VA_ARGS__)
/* Critical error: quit */
#define log_crit(...)   logger_handle_msg(MODULE_MSG_HANDLE,MSG_CRIT,LOG_TEXT_PREFIX __VA_ARGS__)
/* Emergency: quit      */
#define log_emerg(...)  logger_handle_msg(MODULE_MSG_HANDLE,MSG_EMERG,LOG_TEXT_PREFIX __VA_ARGS__)

/* -7----------------------------------------------------------------------------
 *
 *      MACROS
 */

#ifdef DEBUG
#define DERROR_MSG(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_ERR,__VA_ARGS__)
#else
#define DERROR_MSG(...)   /* nothing */
#endif /* DEBUG */

/**
 * For practical reasons, the code for logger_init() is in logger_handle.c
 */

void logger_init();

/**
 * For practical reasons, the code for logger_start() is in logger_handle.c
 */

void logger_start();

/**
 * For practical reasons, the code for logger_stop() is in logger_handle.c
 */

void logger_stop();

/**
 * For practical reasons, the code for logger_finalize() is in logger_handle.c
 */

void logger_finalize();

/**
 * For practical reasons, the code for logger_flush() is in logger_handle.c
 */

void logger_flush();

/**
 * For practical reasons, the code for logger_reopen() is in logger_handle.c
 */

void logger_reopen();

bool logger_is_running();

/**
 * Sets the logger queue size
 */

u32  logger_set_queue_size(u32 n);

void logger_set_path(const char *path);
const char* logger_get_path();

void logger_set_uid(uid_t uid);
uid_t logger_get_uid();

void logger_set_gid(uid_t gid);
gid_t logger_get_gid();

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGGER_HANDLE_H */
/** @} */

/*----------------------------------------------------------------------------*/
