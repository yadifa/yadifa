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
/** @defgroup name Functions used to manipulate dns formatted names and labels
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate dns formatted names and labels
 *
 * @{
 */
#ifndef _ZDB_DNSNAME_H
#define	_ZDB_DNSNAME_H

#include <dnscore/dnsname.h>

#define ZDB_NAME_TAG  0x454d414e42445a       /* "ZDBNAME" */
#define ZDB_LABEL_TAG 0x4c424c42445a         /* "ZDBLBL" */

#ifdef	__cplusplus
extern "C" {
#endif

/** @brief (Z-)Allocates and duplicates a name.
 *
 *  (Z-)Allocates and duplicates a name.
 *
 *  @param[in] name a pointer to the dnsname
 *
 *  @return A new instance of the dnsname.
 */

u8* dnsname_zdup(const u8* name);

/** @brief (Z-)Allocates and duplicates a label.
 *
 *  (Z-)Allocates and duplicates a label.
 *
 *  @param[in] name a pointer to the label
 *
 *  @return A new instance of the label
 */

u8* dnslabel_dup(const u8* name);

#ifdef	__cplusplus
}
#endif

#endif	/* _NAME_H */

/** @} */
