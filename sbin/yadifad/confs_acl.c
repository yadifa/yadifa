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
* DOCUMENTATION */
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

#include <dnscore/format.h>

#include "confs.h"

#include "acl.h"


/*
 *  ACL is a dynamic section so there is no config_table
 *
 *  Each processed section will just add acl lines in the named rules set
 */

typedef struct acl_data acl_data;
struct acl_data
{
    struct acl_data						 *next;
    char							     *name;
    char							     *text;
};

static ya_result
config_acl_section_init(config_data *config)
{
    return SUCCESS;
}

static ya_result
config_acl_section_assign(config_data *config)
{
    return SUCCESS;
}

static ya_result
config_acl_section_free(config_data *config)
{
    acl_free_definitions();
    return SUCCESS;
}

static ya_result
config_acl_section_print(config_data *config)
{
    return SUCCESS;
}

static ya_result
set_variable_acl(char *variable, char *value, char *argument)
{
    /*
     * Variable is the name of the ACL
     * value + arument is the list of parameters
     */

    if((strcasecmp(variable, "none") == 0) || strcasecmp(variable, "any") == 0)
    {
	/**
	 * Reserved keyword
	 *
	 * @todo Maybe instead I could add a normal acl called none that rejects everything.
	 *
	 */

        return ACL_RESERVED_KEYWORD;
    }

    ya_result result_code = acl_add_definition(variable, value);

    return result_code;
}

static config_section_descriptor section_acl=
{
    "acl",
    set_variable_acl,
    config_acl_section_init,
    config_acl_section_assign,
    config_acl_section_free,
    config_acl_section_print,
    FALSE
};

const config_section_descriptor *confs_acl_get_descriptor()
{
    return &section_acl;
}

/** @} */
