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
/** @defgroup dnscore System core functions
 *  @brief System core functions
 *
 * @{ */
#ifndef _DNSCORE_H
#define	_DNSCORE_H

#include <dnscore/output_stream.h>
#include <dnscore/logger.h>

#ifndef __DNSCORE_C__
#ifdef	__cplusplus
extern "C" output_stream __termout__;
extern "C" output_stream __termerr__;
extern "C" logger_handle *g_system_logger;
#else
extern output_stream __termout__;
extern output_stream __termerr__;
struct logger_handle;
extern struct logger_handle *g_system_logger;
#endif

static inline void flushout()
{
    output_stream_flush(&__termout__);
}

static inline void flusherr()
{
    output_stream_flush(&__termerr__);
}

#define termout &__termout__
#define termerr &__termerr__

#endif

#ifdef	__cplusplus
extern "C"
{
#endif

/*
 * This fingerprint feature has been added so libraries could check they are compatible
 */

typedef enum
{
    DNSLIB_TSIG=1,
    DNSLIB_ACL=2,
    DNSLIB_NSEC=4,
    DNSLIB_NSEC3=8
} dnslib_fingerprint;

u32 dnscore_fingerprint_mask();

dnslib_fingerprint dnscore_getfingerprint();

void dnscore_init();

u32 dnscore_timer_get_tick();

void dnscore_reset_timer();

void dnscore_stop_timer();

void dnscore_finalize();

void dnscore_shutdown();

bool dnscore_shuttingdown();

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSCORE_H */
/** @} */

/*----------------------------------------------------------------------------*/

