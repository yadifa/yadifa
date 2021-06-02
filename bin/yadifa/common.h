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

#pragma once



#include <stdio.h>
#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/timems.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YADIFA_ERROR_BASE               0x82000000
#define YADIFA_ERROR_CODE(code_)        ((s32)(YADIFA_ERROR_BASE+(code_)))
#define YADIFA_MODULE_HELP_REQUESTED    YADIFA_ERROR_CODE(1)

typedef int symbol_t;

#define THRESHOLD_DEFAULT 1.9f

static inline void print_name(FILE *f, const u8 *pname, u8 padding)
{
    //fputc('"', f);
    u8 len = pname[0];
    if(len < padding)
    {
        
        for(u8 i = padding - len; i > 0 ; --i)
        {
            fputc(' ', f);
        }
    }
    fwrite(&pname[1], len, 1, f);
    //fputc('"', f);
}

static inline u64 timeus_delta(u64 start, u64 stop)
{
    return (start < stop)?stop-start:0;
}

static inline double timeus_delta_s(u64 start, u64 stop)
{
    double ret = timeus_delta(start, stop);
    ret /= ONE_SECOND_US_F;
    return ret;
}

static inline void
ttylog_out(const char *format, ...)
{
    va_list args;
    
    
#ifdef MODULE_MSG_HANDLE
    if(logger_is_running())
    {
        va_start(args, format);
        logger_handle_vmsg(MODULE_MSG_HANDLE, MSG_INFO, format, args);
        va_end(args);
        logger_flush();
    }
    // else 
#endif
    {
        flushout();
        osprint(termout, "info: ");
        va_start(args, format);
        vosformat(termout, format, args);
        va_end(args);
        osprintln(termout, "");
        flusherr();
    }
}

static inline void
ttylog_err(const char *format, ...)
{
    va_list args;
    
    
#ifdef MODULE_MSG_HANDLE
    if(logger_is_running())
    {
        va_start(args, format);
        logger_handle_vmsg(MODULE_MSG_HANDLE, MSG_ERR, format, args);
        va_end(args);
        logger_flush();
    }
    // else 
#endif
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


 /**
 *  @fn const char * file_name_from_path ()
 *  @brief base_of_path
 *
 *  @param const char *
 *
 *  @return char *
 */
const char *filename_from_path(const char *fullpath);

int module_verbosity_level();

#ifdef __cplusplus
}
#endif

