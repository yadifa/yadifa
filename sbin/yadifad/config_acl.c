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
/** @defgroup config Configuration handling
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

/*
 * DYNAMIC SECTION
 */


#include <stdio.h>
#include <stdlib.h>

#include "config.h"

#include <dnscore/format.h>
#include <dnscore/config_settings.h>

#if !HAS_ACL_SUPPORT
#error "ACL support should not be compiled in"
#endif

#include "acl.h"
#include "config_acl.h"

static bool
config_section_acl_print_item(output_stream *os, const char *name, void *ptr)
{
    address_match_set* ams = (address_match_set*)ptr;
    if(ams != NULL)
    {
        osformat(os, "%24s", name);
        acl_address_match_set_to_stream(os, ams);                    
        osprintln(os,"");
    }
    
    return TRUE;
}

/*
 *  ACL is a dynamic section so there is no config_table
 *
 *  Each processed section will just add acl lines in the named rules set
 */

static ya_result
config_section_acl_init(struct config_section_descriptor_s *csd)
{
    // NOP
    
    config_section_struct_register_type_handler((config_set_field_function*)config_set_acl_item, config_section_acl_print_item);
    
    return SUCCESS;
}

static ya_result
config_section_acl_start(struct config_section_descriptor_s *csd)
{
    // NOP
    
    return SUCCESS;
}

static ya_result
config_section_acl_stop(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_acl_postprocess(struct config_section_descriptor_s *csd)
{
    return SUCCESS;
}

static ya_result
config_section_acl_finalise(struct config_section_descriptor_s *csd)
{
    return SUCCESS;
}

static ya_result
config_section_acl_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    if((strcasecmp(key, "none") == 0) || strcasecmp(key, "any") == 0)
    {
        /**
         * Reserved keyword
         */

        return ACL_RESERVED_KEYWORD;
    }

    ya_result result_code = acl_add_definition(key, value);

    return result_code;
}

static ya_result
config_section_acl_print_wild(struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

static const config_section_descriptor_vtbl_s config_section_acl_descriptor_vtbl =
{
    "acl",
    NULL,                               // no table
    config_section_acl_set_wild,
    config_section_acl_print_wild,
    config_section_acl_init,
    config_section_acl_start,
    config_section_acl_stop,
    config_section_acl_postprocess,
    config_section_acl_finalise
};

static const config_section_descriptor_s config_section_acl_descriptor =
{
    NULL,
    &config_section_acl_descriptor_vtbl
};

/// register the acl configuration
ya_result
config_register_acl(const char *null_or_acl_name, s32 priority)
{
    //null_or_acl_name = "acl";
    (void)null_or_acl_name;

    if(priority < 0)
    {
        priority = 0;
    }
    
    ya_result return_code;
    
    return_code = config_register(&config_section_acl_descriptor, priority + 0);
    
    return return_code;
}

/** @brief ACL value parser
 *
 *  @param[in] value
 *  @param[in] config_command
 *  @param[out] config
 *
 *  @return an error code
 */

ya_result
config_set_acl_item(const char *value, address_match_set *dest, anytype notused)
{
    ya_result return_code = SUCCESS;

    //if(*dest != NULL)
    {
        return_code = acl_build_access_control_item(dest, value);
    }

    return return_code;
}

/** @} */
