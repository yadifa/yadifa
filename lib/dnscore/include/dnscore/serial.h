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

/** @defgroup dnscore
 *  @ingroup dnscore
 *  @brief serial arithmetic
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _SERIAL_H
#define	_SERIAL_H

#include <dnscore/sys_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

    /*
     * SERIAL ARITHMETIC
     */

    /*
     * Returns TRUE if a >,<,>=,<= b
     */
    
    /**
     * 
     * Returns TRUE iff a > b in serial arithmetic, else FALSE
     * 
     * @param a
     * @param b
     * @return a > b
     */

    bool serial_gt(u32 a, u32 b);
    
    /**
     * 
     * Returns TRUE iff a < b in serial arithmetic, else FALSE
     * 
     * @param a
     * @param b
     * @return a < b
     */
    
    bool serial_lt(u32 a, u32 b);
    
    /**
     * 
     * Returns TRUE iff a >= b in serial arithmetic, else FALSE
     * 
     * @param a
     * @param b
     * @return a >= b
     */
    
    bool serial_ge(u32 a, u32 b);
    
    /**
     * 
     * Returns TRUE iff a <= b in serial arithmetic, else FALSE
     * 
     * @param a
     * @param b
     * @return a <= b
     */
    
    bool serial_le(u32 a, u32 b);
    
    static inline bool serial_eq(u32 a, u32 b)
    {
        return a == b;
    }
    
    static inline u32 serial_max(u32 a, u32 b)
    {
        return serial_ge(a,b) ? a : b;
    }

    static inline u32 serial_min(u32 a, u32 b)
    {
        return serial_le(a,b) ? a : b;
    }
    
#ifdef	__cplusplus
}
#endif

#endif	/* _SERIAL_H */
/** @} */

/*----------------------------------------------------------------------------*/

