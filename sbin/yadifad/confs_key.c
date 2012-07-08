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

#include <dnscore/base64.h>
#include <dnscore/format.h>
#include <dnscore/tsig.h>

#include "config_error.h"
#include "confs.h"

/******************** Key *************************/

/*
 * A structure to hold the currently processed section
 */

struct key_data_section
{
    char *name;
    char *algorithm;
    char *secret;
};

static struct key_data_section tmp_key =
{
					  NULL,
					  NULL,
					  NULL
};

static ya_result set_key_string(const char *value, const int config_command, void *config)
{
    char **target;
    switch(config_command)
    {
	case KC_NAME:
	    target = &tmp_key.name;
	    break;
	case KC_ALGORITHM:
	    target = &tmp_key.algorithm;
	    break;
	case KC_SECRET:
	    target = &tmp_key.secret;
	    break;
	default:
	    return CONFIG_KEY_WRONG_FIELD;   /* wrong field */
    }

    free(*target);
    *target = strdup(value);

    return SUCCESS;
}

/*
 *  Table with the parameters that can be set in the config file
 *  key containers.
 *
 *  In order to stay consistent with the other sections, I use only one
 *  function by type for the fields. (With only three fields I could use
 *  one function each)
 * 
 */

static const config_table key_tab[] ={
    { "name",                 set_key_string,     KC_NAME              },
    { "algorithm",            set_key_string,     KC_ALGORITHM         },
    { "secret",               set_key_string,     KC_SECRET            },
    { NULL, NULL, 0}
};

static ya_result
config_key_section_assign(config_data *config)
{
    struct key_data_section *key = &tmp_key;

    if((key->algorithm == NULL) || (key->name == NULL) || (key->secret == NULL))
    {
        if((key->algorithm == NULL) && (key->name == NULL) && (key->secret == NULL))
        {
            return SUCCESS; /* nothing to do */
        }
        
        return CONFIG_KEY_INCOMPLETE_KEY; /* Incomplete */
    }

    if(strcasecmp(key->algorithm, "hmac-md5") != 0)
    {
        return CONFIG_KEY_UNSUPPORTED_ALGORITHM; /* Unsupported algorithm */
    }

    ya_result return_code;

    u32 len = strlen(key->secret);
    u8* tmp_secret;

    MALLOC_OR_DIE(u8*, tmp_secret, len, GENERIC_TAG);

    if(FAIL(return_code = base64_decode(key->secret, len, tmp_secret)))
    {
        free(tmp_secret);

        return return_code;
    }

    len = return_code;

    u8 fqdn[MAX_DOMAIN_LENGTH];

    if(ISOK(return_code = cstr_to_dnsname_with_check(fqdn, key->name)))
    {
        return_code = tsig_register(fqdn, tmp_secret, len, HMAC_MD5);
    }

    free(tmp_secret);

    return return_code;
}

static ya_result
config_key_section_init(config_data *config)
{
    struct key_data_section *key = &tmp_key;
    
    ya_result return_code;

    /* Clears */

    if((key->algorithm == NULL) && (key->name == NULL) && (key->secret == NULL))
    {
        return SUCCESS;
    }

    if(FAIL(return_code = config_key_section_assign(config)))
    {
        return return_code;
    }

    free(key->algorithm);
    key->algorithm = NULL;

    free(key->name);
    key->name = NULL;

    free(key->secret);
    key->secret = NULL;

    return SUCCESS;
}

static ya_result
config_key_section_free(config_data *config)
{
    struct key_data_section *key = &tmp_key;
    
    free(key->algorithm);
    key->algorithm = NULL;

    free(key->name);
    key->name = NULL;

    free(key->secret);
    key->secret = NULL;
    return SUCCESS;
}

static ya_result
set_variable_keys(char *variable, char *value, char *argument)
{
    /*OSDEBUG(termout, "Set key variable   : %s (%s: %s)\n", variable, value, argument);*/

    ya_result return_value;
    
    if(ISOK(return_value = config_get_entry_index(variable, key_tab, "keys")))
    {
        key_tab[return_value].set_function(value, key_tab[return_value].config_command, NULL);
    }
    
    struct key_data_section *key = &tmp_key;
    
    if((key->algorithm != NULL) && (key->name != NULL) && (key->secret != NULL))
    {
        /* config is not used */
        config_key_section_init(NULL);
    }
    
    return return_value;
}

static ya_result config_keys_section_print(config_data *config)
{
    return SUCCESS;
}

static config_section_descriptor section_key =
{
       "key",
       set_variable_keys,
       config_key_section_init,
       config_key_section_assign,
       config_key_section_free,
       config_keys_section_print,
       FALSE
};

const config_section_descriptor *
confs_key_get_descriptor()
{
    return &section_key;
}

/** @} */
