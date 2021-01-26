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

/** @defgroup nsec3 NSEC3 functions
 *  @ingroup dnsdbdnssec
 *  @brief 
 *
 *  The low level digest functions
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/sys_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif
    
/**
 * Hashing function signature
 */

typedef ya_result nsec3_hash_function(const u8*, u32, const u8*, u32, u32, u8*, bool);

/** 
 *
 * Returns the (NSEC3) hashing function for an algorithm
 * 
 * If the algorithm is not supported, the returned function will
 * always return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM.
 * 
 * A typical usage for this is :
 *
 * get_nsec3_hash_function(NSEC3_ZONE_ALGORITHM(n3))(name, ...... )
 * |_______________________________________________||_____________|
 *  Get the digest function pointer		    Call the returned function
 * 
 * @param algorithm the algorithm id
 * @return the hashing function
 * 
 * 8 uses
 */

nsec3_hash_function* nsec3_hash_get_function(u8 algorithm);

/**
 * Returns the size in bytes of the hash computed by hashing function algorithm
 * 
 * @param algorithm the algorithm id
 * @return size in bytes of the computed hash or 0 if the function is not supported
 * 
 * 10 uses
 */

u8 nsec3_hash_len(u8 algorithm);

#ifdef	__cplusplus
}
#endif

/** @} */
