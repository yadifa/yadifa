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

/** @defgroup config Configuration handling
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef _CONFIG_ERROR_H
#define	_CONFIG_ERROR_H

#ifdef	__cplusplus
extern "C"
{
#endif

#define     CFG_ERROR_BASE            0x80070000
#define     CFG_ERROR_CODE(code_)     ((s32)(CFG_ERROR_BASE+(code_)))

    /* Config errorcodes */
#define     CONFIG_ZONE_ERR             CFG_ERROR_CODE(50)	/* Error in config file */

    /* Zone errorcondes */


#define     CONFIG_WRONG_SIG_TYPE       CFG_ERROR_CODE(201)
#define     CONFIG_WRONG_SIG_VALIDITY   CFG_ERROR_CODE(202)
#define     CONFIG_WRONG_SIG_REGEN      CFG_ERROR_CODE(203)

#define     DATABASE_ZONE_MISSING_DOMAIN CFG_ERROR_CODE(301)
#define     DATABASE_ZONE_MISSING_MASTER CFG_ERROR_CODE(302)
#define     DATABASE_ZONE_MISSING_TYPE   CFG_ERROR_CODE(303)
#define     DATABASE_ZONE_CONFIG_DUP     CFG_ERROR_CODE(304)
#define     DATABASE_ZONE_CONFIG_CLONE   CFG_ERROR_CODE(306)

#ifdef	__cplusplus
}
#endif

#endif	/* _CONFIG_ERROR_H */

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/
