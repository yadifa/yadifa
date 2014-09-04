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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "config.h"

#include <dnscore/format.h>

#include "config_error.h"
#include "config_acl.h"

#include "confs.h"
#include "zone.h"

#include "database-service.h"

/*
 *
 */

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

extern zone_data_set database_zone_desc;

/******************** Zones *************************/

static value_name_table zone_type_enum_table[]=
{
//    {ZT_HINT,       ZT_STRING_HINT},
#if HAS_MASTER_SUPPORT
    {ZT_MASTER,     ZT_STRING_MASTER},
#endif
    {ZT_SLAVE,      ZT_STRING_SLAVE},
//    {ZT_STUB,       ZT_STRING_STUB},
//    {ZT_UNKNOWN,    ZT_STRING_UNKNOWN},
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

#define CONFIG_TYPE zone_desc_s

CONFIG_BEGIN(config_section_zone_desc)
CONFIG_STRING(domain, NULL)
CONFIG_STRING(file_name, NULL)
CONFIG_HOST_LIST(masters, NULL)
CONFIG_HOST_LIST(notifies, NULL)
CONFIG_ENUM(type, NULL, zone_type_enum_table)

#if ZDB_HAS_ACL_SUPPORT
CONFIG_ACL(allow_query, NULL)
CONFIG_ACL(allow_update, NULL)
CONFIG_ACL(allow_transfer, NULL)
CONFIG_ACL(allow_update_forwarding, NULL)
CONFIG_ACL(allow_notify, NULL)
CONFIG_ACL(allow_control, NULL)
#endif

// master

CONFIG_FLAG32(notify_auto , S_ZONE_NOTIFY_AUTO, flags, ZONE_FLAG_NOTIFY_AUTO)
CONFIG_FLAG32(no_master_updates , S_ZONE_NO_MASTER_UPDATES, flags, ZONE_FLAG_NO_MASTER_UPDATES)
CONFIG_U32_RANGE(notify.retry_count, S_NOTIFY_RETRY_COUNT, NOTIFY_RETRY_COUNT_MIN, NOTIFY_RETRY_COUNT_MAX)
CONFIG_U32_RANGE(notify.retry_period, S_NOTIFY_RETRY_PERIOD, NOTIFY_RETRY_PERIOD_MIN, NOTIFY_RETRY_PERIOD_MAX)
CONFIG_U32_RANGE(notify.retry_period_increase, S_NOTIFY_RETRY_PERIOD_INCREASE, NOTIFY_RETRY_PERIOD_INCREASE_MIN, NOTIFY_RETRY_PERIOD_INCREASE_MAX)

#if HAS_DNSSEC_SUPPORT
        
#if HAS_RRSIG_MANAGEMENT_SUPPORT
CONFIG_U32_RANGE(signature.sig_validity_interval, S_S32_VALUE_NOT_SET, SIGNATURE_VALIDITY_INTERVAL_MIN, SIGNATURE_VALIDITY_INTERVAL_MAX)
CONFIG_U32_RANGE(signature.sig_validity_regeneration, S_S32_VALUE_NOT_SET, SIGNATURE_VALIDITY_REGENERATION_MIN, SIGNATURE_VALIDITY_REGENERATION_MAX)
CONFIG_U32_RANGE(signature.sig_validity_jitter, S_S32_VALUE_NOT_SET, SIGNATURE_VALIDITY_JITTER_MIN, SIGNATURE_VALIDITY_JITTER_MAX)
#endif
 
CONFIG_ENUM(dnssec_mode, S_ZONE_DNSSEC_DNSSEC, dnssec_enum)

#if HAS_RRSIG_MANAGEMENT_SUPPORT
CONFIG_ALIAS(signature.sig_jitter, sig_validity_jitter)
#endif
        
CONFIG_ALIAS(dnssec,dnssec_mode)
#endif

#if HAS_CTRL
//CONFIG_U8(ctrl_flags, "0")  // SHOULD ONLY BE IN THE DYNAMIC CONTEXT
CONFIG_BYTES(dynamic_provisioning, "AAA=", sizeof(dynamic_provisioning_s))
CONFIG_HOST_LIST(slaves, NULL)
#endif // HAS_CTRL

/* alias , aliased-real-name */
CONFIG_ALIAS(master,masters)
CONFIG_ALIAS(notify,notifies)
CONFIG_ALIAS(also_notify,notifies)
CONFIG_ALIAS(file,file_name)
CONFIG_END(config_section_zone_desc)

#undef CONFIG_TYPE

#include <dnscore/tsig.h>
#include <dnscore/base64.h>
#include <dnscore/config_settings.h>

#include "zone_desc.h"

static ya_result
config_section_zone_init(struct config_section_descriptor_s *csd)
{
    // NOP
    
    if(csd->base != NULL)
    {
        return ERROR; // base SHOULD be NULL at init
    }
        
    return SUCCESS;
}

static ya_result
config_section_zone_start(struct config_section_descriptor_s *csd)
{
    if(csd->base != NULL)
    {
        return ERROR;
    }
    
    zone_desc_s *zone_desc = zone_alloc();
    csd->base = zone_desc;
    
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: zone: start");
#endif
    
    return SUCCESS;
}

static ya_result
config_section_zone_filter_accept(zone_desc_s *unused, void *unused_params)
{
    (void)unused;
    (void)unused_params;
    
    return 1;       // ACCEPT
}

static config_section_zone_filter_callback *config_section_zone_filter = config_section_zone_filter_accept;
static void *config_section_zone_filter_params = NULL;

void
config_section_zone_set_filter(config_section_zone_filter_callback *cb, void *p)
{
    if(cb == NULL)
    {
        config_section_zone_filter = config_section_zone_filter_accept;
        config_section_zone_filter_params = NULL;
    }
    else
    {
        config_section_zone_filter = cb;
        config_section_zone_filter_params = p;
    }
}

static ya_result
config_section_zone_stop(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: zone: stop");
#endif
    
    // NOP
    zone_desc_s *zone_desc = (zone_desc_s*)csd->base;
    ya_result return_code;
    
    // ensure the descriptor is valid
    
    if(ISOK(return_code = zone_complete_settings(zone_desc)))
    {            
        zone_setdefaults(zone_desc);
        // load the descriptor (most likely offline)

        if(config_section_zone_filter(zone_desc, config_section_zone_filter_params) == 1)
        {
            database_zone_desc_load(zone_desc);
        }
    }
    else
    {
        zone_free(zone_desc);
    }
        
    csd->base = NULL;
    
    return return_code;
}

static ya_result
config_section_zone_postprocess(struct config_section_descriptor_s *csd)
{
    return SUCCESS;
}

static ya_result
config_section_zone_finalise(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        free(csd->base);
        free(csd);
    }
    
    return SUCCESS;
}

static ya_result
config_section_zone_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    return CONFIG_UNKNOWN_SETTING;
}

static ya_result
config_section_zone_print_wild(struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    if(key != NULL)
    {
        return ERROR;
    }
    
    // for all zones, print table of the zone
    
    zone_set_lock(&database_zone_desc);
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&database_zone_desc.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->data;
        
        config_section_struct_print(csd, zone_desc, os);
    }
    
    zone_set_unlock(&database_zone_desc);
    
    return SUCCESS;
}

static const config_section_descriptor_vtbl_s config_section_zone_descriptor_vtbl =
{
    "zone",
    config_section_zone_desc,                               // no table
    config_section_zone_set_wild,
    config_section_zone_print_wild,
    config_section_zone_init,
    config_section_zone_start,
    config_section_zone_stop,
    config_section_zone_postprocess,
    config_section_zone_finalise
};

ya_result
config_register_zone(const char *null_or_key_name, s32 priority)
{
    //null_or_key_name = "zone";
    (void)null_or_key_name;
    
    config_section_descriptor_s *desc;
    MALLOC_OR_DIE(config_section_descriptor_s*, desc, sizeof(config_section_descriptor_s), GENERIC_TAG);
    desc->base = NULL;
    desc->vtbl = &config_section_zone_descriptor_vtbl;
    
    ya_result return_code = config_register(desc, priority);
    
    if(FAIL(return_code))
    {
        free(desc);
    }
    
    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}

void
config_zone_print(zone_desc_s *zone_desc, output_stream *os)
{
    config_section_descriptor_s desc = {zone_desc, &config_section_zone_descriptor_vtbl};
    config_section_struct_print(&desc, zone_desc, os);
}


/** @} */
