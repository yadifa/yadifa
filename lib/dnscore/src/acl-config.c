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

/*
 * DYNAMIC SECTION
 */


#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <dnscore/format.h>
#include <dnscore/config_settings.h>

#if !HAS_ACL_SUPPORT
#error "ACL support should not be compiled in"
#endif

#include <dnscore/acl.h>
#include <dnscore/acl-config.h>

static bool
acl_config_section_print_item(output_stream *os, const char *name, void *ptr)
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
acl_config_section_init(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    config_section_struct_register_type_handler((config_set_field_function*)acl_config_set_item, acl_config_section_print_item);
    
    return SUCCESS;
}

static ya_result
acl_config_section_start(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
acl_config_section_stop(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
acl_config_section_postprocess(struct config_section_descriptor_s *csd)
{
    (void)csd;
    return SUCCESS;
}

static ya_result
acl_config_section_finalize(struct config_section_descriptor_s *csd)
{
    (void)csd;
    return SUCCESS;
}

static ya_result
acl_config_section_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;

    if((strcasecmp(key, "none") == 0) || strcasecmp(key, "any") == 0)
    {
        /**
         * Reserved keyword
         */

        return ACL_RESERVED_KEYWORD;
    }

    ya_result result_code = acl_definition_add(key, value);

    return result_code;
}

static ya_result
acl_config_section_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    (void)csd;
    (void)os;
    (void)key;

    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

static const config_section_descriptor_vtbl_s acl_config_section_descriptor_vtbl =
{
    "acl",
    NULL,                               // no table
    acl_config_section_set_wild,
    acl_config_section_print_wild,
    acl_config_section_init,
    acl_config_section_start,
    acl_config_section_stop,
    acl_config_section_postprocess,
    acl_config_section_finalize
};

static const config_section_descriptor_s acl_config_section_descriptor =
{
    NULL,
    &acl_config_section_descriptor_vtbl
};

/// register the acl configuration
ya_result
acl_config_register(const char *null_or_acl_name, s32 priority)
{
    //null_or_acl_name = "acl";
    (void)null_or_acl_name;

    if(priority < 0)
    {
        priority = 0;
    }
    
    ya_result return_code;
    
    return_code = config_register_const(&acl_config_section_descriptor, priority + 0);
    
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
acl_config_set_item(const char *value, address_match_set *dest, anytype notused)
{
    (void)notused;
    ya_result ret;

    ret = acl_access_control_item_init_from_text(dest, value);

    return ret;
}

ya_result
acl_config_set_access_control_item(const char *value, access_control **acp, anytype offset)
{
    if(*acp == NULL)
    {
        // allocate a fresh one
        *acp = acl_access_control_new_instance();
    }

    ya_result return_code;
    
    address_match_set tmp = ADDRESS_MATCH_SET_INITIALIZER;
    return_code = acl_config_set_item(value, &tmp, offset);
    address_match_set *old = (address_match_set*)(((u8*)*acp) + offset._intptr);
    
    if(!acl_address_match_set_equals(&tmp, old))
    {
        // all the references to this have to be updated
        acl_address_match_set_clear(old);
        *old = tmp;
    }
    else
    {
        acl_address_match_set_clear(&tmp);
    }

    return return_code;
}

/** @} */
