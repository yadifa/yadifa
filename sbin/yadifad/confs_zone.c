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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <dnscore/format.h>

#include "config_error.h"
#include "confs.h"
#include "zone.h"

/*
 *
 */

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

/******************** Zones *************************/

static value_name_table zone_type_enum_table[]=
{
    {ZT_HINT,       ZT_STRING_HINT},
    {ZT_MASTER,     ZT_STRING_MASTER},
    {ZT_SLAVE,      ZT_STRING_SLAVE},
    {ZT_STUB,       ZT_STRING_STUB},
    {ZT_UNKNOWN,    ZT_STRING_UNKNOWN},
    {0, NULL}
};

static value_name_table dnssec_enum[]=
{
    {ZONE_DNSSEC_FL_NOSEC       , "none"        },
    {ZONE_DNSSEC_FL_NOSEC       , "no"          },
    {ZONE_DNSSEC_FL_NOSEC       , "off"         },
    {ZONE_DNSSEC_FL_NOSEC       , "0"           },
    {ZONE_DNSSEC_FL_NSEC        , "nsec"        },
    {ZONE_DNSSEC_FL_NSEC3       , "nsec3"       },
    {ZONE_DNSSEC_FL_NSEC3_OPTOUT, "nsec3-optout"},
    {0, NULL}
};


/*  Table with the parameters that can be set in the config file
 *  zone containers
 */

#define CONFS_TYPE zone_data

CONFS_BEGIN(zone_tab)
//CONFS_STRING(acl, ZC_ACL)
CONFS_STRING(domain, NULL)
CONFS_STRING(file_name, NULL)
CONFS_HOST_LIST(masters, NULL)
CONFS_HOST_LIST(notifies, NULL)
CONFS_ENUM(type, NULL, zone_type_enum_table)

#if HAS_ACL_SUPPORT != 0
CONFS_ACL(allow_query, NULL)
CONFS_ACL(allow_update, NULL)
CONFS_ACL(allow_transfer, NULL)
CONFS_ACL(allow_update_forwarding, NULL)
CONFS_ACL(allow_notify, NULL)
CONFS_ACL(allow_control, NULL)
#endif

#if HAS_DNSSEC_SUPPORT != 0
CONFS_U32(sig_validity_interval, S_S32_VALUE_NOT_SET)
CONFS_U32(sig_validity_regeneration, S_S32_VALUE_NOT_SET)
CONFS_U32(sig_validity_jitter, S_S32_VALUE_NOT_SET)

CONFS_ENUM(dnssec_mode, S_ZONE_DNSSEC_DNSSEC, dnssec_enum)

CONFS_ALIAS(sig_jitter, sig_validity_jitter)
#endif

CONFS_U32(notify.retry_count, S_NOTIFY_RETRY_COUNT)
CONFS_U32(notify.retry_period, S_NOTIFY_RETRY_PERIOD)
CONFS_U32(notify.retry_period_increase, S_NOTIFY_RETRY_PERIOD_INCREASE)

#if HAS_CTRL
CONFS_U8(ctrl_flags, "0")  // SHOULD ONLY BE IN THE DYNAMIC CONTEXT
#endif // HAS_CTRL

/* alias , aliased-real-name */
CONFS_ALIAS(master,masters)
CONFS_ALIAS(notify,notifies)
CONFS_ALIAS(also_notify,notifies)
CONFS_ALIAS(file,file_name)
CONFS_FLAG8(notify_auto , S_ZONE_NOTIFY_AUTO, notify_flags, ZONE_NOTIFY_AUTO)
CONFS_END(zone_tab)

static zone_data *tmp_zones = NULL;
static int tmp_zone_idx = 0;

static void
config_zone_section_register(config_data *config)
{
    if(tmp_zones != NULL)
    {
        ya_result return_code;
        
        if(FAIL(return_code = zone_register(&config->zones, tmp_zones)))
        {
            switch(return_code)
            {
                case DATABASE_ZONE_MISSING_DOMAIN:
                case DATABASE_ZONE_MISSING_MASTER:
                {
                    log_err("config: zone: section #%d: %r", tmp_zone_idx, return_code);
                    exit(EXIT_FAILURE);
                    break;
                }
                default:
                {
                    log_err("config: zone: section #%d: %r", tmp_zone_idx, return_code);
                    zone_free(tmp_zones);
                    break;
                }
            }
        }

        tmp_zones = NULL;
    }
}

static ya_result
config_zone_section_init(config_data *config)
{
    ya_result return_code;

    tmp_zone_idx++;

    /* store the previously configured zone, if any */

    config_zone_section_register(config);

    /* make a new zone section ready */

    tmp_zones = zone_alloc();
    
    if(FAIL(return_code = confs_init(zone_tab, tmp_zones)))
    {
        zone_free(tmp_zones);
        tmp_zones = NULL;

        osformatln(termerr, "config: zone: configuration initialize (zone): %r", return_code);
    }
    
    return return_code;
}

static ya_result
config_zone_section_assign(config_data *config)
{
    u32 port = 0;
    ya_result return_code;

    config_zone_section_register(config);

    if(FAIL(return_code = parse_u32_check_range(config->server_port, &port, 1, MAX_U16, 10)))
    {
        osformatln(termerr, "config: zone: wrong dns port set in main '%s': %r", config->server_port, return_code);
        
        return return_code;
    }
    
    zone_set_lock(&config->zones);
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&config->zones.set, &iter);
    
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_data *zone = (zone_data *)zone_node->data;            
        
        zone_setdefaults(zone);

        if(!config_check_bounds_s32(SIGNATURE_VALIDITY_INTERVAL_MIN, SIGNATURE_VALIDITY_INTERVAL_MAX, zone->sig_validity_interval, "sig-validity-interval"))
        {
            return ERROR;
        }

        if(!config_check_bounds_s32(SIGNATURE_VALIDITY_REGENERATION_MIN, SIGNATURE_VALIDITY_REGENERATION_MAX, zone->sig_validity_regeneration, "sig-validity-regeneration"))
        {
            return ERROR;
        }

        if(!config_check_bounds_s32(SIGNATURE_VALIDITY_JITTER_MIN, SIGNATURE_VALIDITY_JITTER_MAX, zone->sig_validity_jitter, "sig-validity-jitter"))
        {
            return ERROR;
        }

        if(!config_check_bounds_s32(NOTIFY_RETRY_COUNT_MIN, NOTIFY_RETRY_COUNT_MAX, zone->notify.retry_count, "notify-retry-count"))
        {
            return ERROR;
        }
        
        if(!config_check_bounds_s32(NOTIFY_RETRY_PERIOD_MIN, NOTIFY_RETRY_PERIOD_MAX, zone->notify.retry_period, "notify-period-count"))
        {
            return ERROR;
        }
        
        if(!config_check_bounds_s32(NOTIFY_RETRY_PERIOD_INCREASE_MIN, NOTIFY_RETRY_PERIOD_INCREASE_MAX, zone->notify.retry_period_increase, "notify-period-increase"))
        {
            return ERROR;
        }
        
        zone->ctrl_flags |= ZONE_CTRL_FLAG_READ_FROM_CONF;
    }
    
    zone_set_unlock(&config->zones);
    
    return SUCCESS;
}

static ya_result
config_zone_section_free(config_data *config)
{
    zone_free_all(&config->zones);
    
    return SUCCESS;
}

/** @brief Function for setting the parameters found in the zone container
 *
 *  @code
 *  <zone>
 *  ...
 *  </zone>
 *  @endcode
 *
 *  @param[in] variable
 *  @param[in] value
 *  @param[out] config
 *
 *  @retval OK
 *  @retval NONE
 */
static ya_result
set_variable_zone(char *variable, char *value, char *argument)
{
    ya_result return_code = confs_set(zone_tab, tmp_zones, variable, value);

    if(FAIL(return_code))
    {
        osformatln(termerr, "error: setting variable: zone.%s = '%s': %r", variable, value, return_code);
    }

    return return_code;
}

static ya_result config_zone_section_print(config_data *config)
{
    zone_set_lock(&config->zones);
    
    if(!treeset_avl_isempty(&config->zones.set))
    {        
        treeset_avl_iterator iter;
        treeset_avl_iterator_init(&config->zones.set, &iter);

        while(treeset_avl_iterator_hasnext(&iter))
        {
            treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
            zone_data *zone_desc = (zone_data*)zone_node->data;
            print("<zone>\n");
            confs_print(zone_tab, zone_desc);
            print("</zone>\n");
        }
        
        zone_set_unlock(&config->zones);
    }
    else
    {
        zone_set_unlock(&config->zones);
        
        print("# no zone\n");
    }
    
    return SUCCESS;
}

static config_section_descriptor section_zone =
{
    "zone",
    set_variable_zone,
    config_zone_section_init,
    config_zone_section_assign,
    config_zone_section_free,
    config_zone_section_print,
    FALSE
};

const config_section_descriptor *
confs_zone_get_descriptor()
{
    return &section_zone;
}

ya_result
confs_zone_write(output_stream *os, zone_data *zone_desc)
{
    return confs_write(os, zone_tab, zone_desc);
}

/** @} */
