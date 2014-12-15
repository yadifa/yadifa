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
/** @defgroup acl Access Control List
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#pragma once

#include "acl.h"

/** @brief ACL value parser
 *
 *  @param[in] value
 *  @param[in] config_command
 *  @param[out] config
 *
 *  @return an error code
 */

ya_result config_set_acl_item(const char *value, address_match_set *dest, anytype notused);

/// @note In order to use these macros, CONFIG_TYPE has to be defined

#define CONFIG_ACL(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, ac) + offsetof(access_control,fieldname_), (config_set_field_function*)config_set_acl_item, defaultvalue_,{._intptr=0}, CONFIG_TABLE_SOURCE_NONE},
#define CONFIG_ACL_FILTER(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_acl_item, defaultvalue_,{._intptr=0}, CONFIG_TABLE_SOURCE_NONE},

/** @} */

