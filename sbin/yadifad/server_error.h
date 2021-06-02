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

/** @defgroup server Server
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#ifndef _SERVER_ERROR_H
#define	_SERVER_ERROR_H

#include <dnscore/format.h>
#include <dnscore/logger.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/*    ------------------------------------------------------------
 *
 *      VALUES
 */

#define	    YDF_ERROR_BASE                  0x80080000
#define	    YDF_ERROR_CODE(code_)			((s32)(YDF_ERROR_BASE+(code_)))

#define     YDF_ERROR                               YDF_ERROR_CODE(0)
#define     YDF_ALREADY_RUNNING                     YDF_ERROR_CODE(1)
#define     YDF_PID_PATH_IS_WRONG                   YDF_ERROR_CODE(2)
    
/* Main errorcodes */
    
#define     ZONE_LOAD_ERROR_BASE (YDF_ERROR_BASE + 0x10)
#define	    ZONE_LOAD_ERROR_CODE(code_)		    ((s32)(ZONE_LOAD_ERROR_BASE+(code_)))

#define     ZONE_LOAD_MASTER_TYPE_EXPECTED          ZONE_LOAD_ERROR_CODE(0)
#define     ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED    ZONE_LOAD_ERROR_CODE(1)
#define     ZONE_LOAD_SLAVE_TYPE_EXPECTED           ZONE_LOAD_ERROR_CODE(2)
#define     ZONE_NOT_DEFINED                        ZONE_LOAD_ERROR_CODE(3)
#define     ZRE_NO_VALID_FILE_FOUND                 ZONE_LOAD_ERROR_CODE(4)

#define     ANSWER_ERROR_BASE (ZONE_LOAD_ERROR_BASE + 0x10)
#define	    ANSWER_ERROR_CODE(code_)		    ((s32)(ANSWER_ERROR_BASE+(code_)))
    
#define     ANSWER_NOT_ACCEPTABLE                   ANSWER_ERROR_CODE(0)
#define     ANSWER_UNEXPECTED_EOF                   ANSWER_ERROR_CODE(1)

#define     NOTIFY_ERROR_BASE (ANSWER_ERROR_BASE + 0x10)
#define	    NOTIFY_ERROR_CODE(code_)		    ((s32)(NOTIFY_ERROR_BASE+(code_)))
    
#define     NOTIFY_QUERY_TO_MASTER                  NOTIFY_ERROR_CODE(0)
#define     NOTIFY_QUERY_TO_UNKNOWN                 NOTIFY_ERROR_CODE(1)
#define     NOTIFY_QUERY_FROM_UNKNOWN               NOTIFY_ERROR_CODE(2)

#define     POLICY_ERROR_BASE (NOTIFY_ERROR_BASE + 0x10)
#define	    POLICY_ERROR_CODE(code_)		    ((s32)(POLICY_ERROR_BASE+(code_)))
    
#define     POLICY_ILLEGAL_DATE                     POLICY_ERROR_CODE(0)
#define     POLICY_ILLEGAL_DATE_TYPE                POLICY_ERROR_CODE(1)
#define     POLICY_ILLEGAL_DATE_PARAMETERS          POLICY_ERROR_CODE(2)
#define     POLICY_ILLEGAL_DATE_COMPARE             POLICY_ERROR_CODE(3)
#define     POLICY_UNDEFINED                        POLICY_ERROR_CODE(4)
#define     POLICY_KEY_SUITE_UNDEFINED              POLICY_ERROR_CODE(5)
#define     POLICY_NULL_REQUESTED                   POLICY_ERROR_CODE(6)
#define     POLICY_ZONE_NOT_READY                   POLICY_ERROR_CODE(7)
    
// executable return codes
    
#define     EXIT_CONFIG_ERROR                10
#define     EXIT_CODE_DATABASE_LOAD_ERROR    11
#define     EXIT_CODE_SYSCLEANUP_ERROR       12
    
#ifndef MODULE_MSG_HANDLE
extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger
#endif
    
static inline void
ttylog_err(const char *format, ...)
{
    va_list args;
    
    
    if(logger_is_running())
    {
        va_start(args, format);
        logger_handle_vmsg(MODULE_MSG_HANDLE, MSG_ERR, format, args);
        va_end(args);
        logger_flush();
    }
    // else 
    {
        flushout();
        osprint(termerr, "error: ");
        va_start(args, format);
        vosformat(termerr, format, args);
        va_end(args);
        osprintln(termerr, "");
        flusherr();
    }
}

static inline void
ttylog_warn(const char *format, ...)
{
    va_list args;


    if(logger_is_running())
    {
        va_start(args, format);
        logger_handle_vmsg(MODULE_MSG_HANDLE, MSG_WARNING, format, args);
        va_end(args);
        logger_flush();
    }
    // else
    {
        flushout();
        osprint(termerr, "warning: ");
        va_start(args, format);
        vosformat(termerr, format, args);
        va_end(args);
        osprintln(termerr, "");
        flusherr();
    }
}

static inline void
ttylog_notice(const char *format, ...)
{
    va_list args;

    if(logger_is_running())
    {
        va_start(args, format);
        logger_handle_vmsg(MODULE_MSG_HANDLE, MSG_NOTICE, format, args);
        va_end(args);
        logger_flush();
    }
    // else
    {
        flushout();
        osprint(termerr, "notice: ");
        va_start(args, format);
        vosformat(termerr, format, args);
        va_end(args);
        osprintln(termerr, "");
        flusherr();
    }
}
    
#ifdef	__cplusplus
}
#endif

#endif	/* _SERVER_ERROR_H */

/** @} */

