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
/** @defgroup ### #######
 *  @ingroup dnsdb
 *  @brief 
 *
 *   Incremental-fileS-to-ICMTL input stream.
 *   Takes the 3 files translates them into an incremental stream.
 *   An incremntal stream is ALMOST an IXFR.
 *
 * @{
 */
#ifndef _ICMTL_INPUT_STREAM_H
#define	_ICMTL_INPUT_STREAM_H
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <dnscore/input_stream.h>

#ifdef	__cplusplus
extern "C"
{
#endif

ya_result
icmtl_input_stream_open(u8* origin, u32 from, u32 to, input_stream* out_is, const char* folder);

void
icmtl_input_stream_skip_headtail(input_stream* out_is);

#ifdef	__cplusplus
}
#endif

#endif	/* _IXFR_INPUT_STREAM_H */


    /*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/
