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
#ifndef _LOGGER_H
#define	_LOGGER_H

#include <syslog.h>
#include <dnscore/sys_types.h>

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

/*#define MSG_ALL       0 *//* all message levels                     */
#define MSG_ALL        15   /* all message levels                     */
#define MSG_ALL_MASK   0xffff   /* all message levels as a bitmap     */


#define MSG_LEVEL_COUNT 16 /* Not thread-safe */

/**
 * The default buffer size (0-cost) made available for each line.
 * If the line is bigger the buffer's size is raised at a certain (non-nul)
 * cost.
 *
 */
#define DEFAULT_MAX_LINE_SIZE	128

#define LOG_QUEUE_MIN_SIZE 0x400
#define LOG_QUEUE_MAX_SIZE 0x1000000
#define LOG_QUEUE_DEFAULT_SIZE 0x100000

#include <dnscore/logger_handle.h>

#ifdef	__cplusplus
extern "C" {
#endif
    
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

#define log_debug7(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG7,__VA_ARGS__)
#define log_debug6(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG6,__VA_ARGS__)
#define log_debug5(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG5,__VA_ARGS__)
#define log_debug4(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG4,__VA_ARGS__)
#define log_debug3(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG3,__VA_ARGS__)
#define log_debug2(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG2,__VA_ARGS__)
#define log_debug1(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG1,__VA_ARGS__)
#define log_debug(...)  logger_handle_msg(MODULE_MSG_HANDLE,MSG_DEBUG,__VA_ARGS__)
#define log_notice(...) logger_handle_msg(MODULE_MSG_HANDLE,MSG_NOTICE,__VA_ARGS__)
#define log_info(...)   logger_handle_msg(MODULE_MSG_HANDLE,MSG_INFO,__VA_ARGS__)
#define log_warn(...)   logger_handle_msg(MODULE_MSG_HANDLE,MSG_WARNING,__VA_ARGS__)
#define log_err(...)    logger_handle_msg(MODULE_MSG_HANDLE,MSG_ERR,__VA_ARGS__)
/* Obsolete, Critical error: quit */
#define log_quit(...)   logger_handle_msg(MODULE_MSG_HANDLE,MSG_CRIT,__VA_ARGS__)
/* Critical error: quit */
#define log_crit(...)   logger_handle_msg(MODULE_MSG_HANDLE,MSG_CRIT,__VA_ARGS__)
/* Emergency: quit      */
#define log_emerg(...)  logger_handle_msg(MODULE_MSG_HANDLE,MSG_EMERG,__VA_ARGS__)

/* -7----------------------------------------------------------------------------
 *
 *      MACROS
 */

#ifndef NDEBUG
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

/**
 * Sets the logger queue size
 */

u32  logger_set_queue_size(u32 n);

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGGER_H */

/** @} */

/*----------------------------------------------------------------------------*/

