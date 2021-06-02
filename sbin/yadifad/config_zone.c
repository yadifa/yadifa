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

#include "server-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <dnscore/format.h>

#include "config_error.h"
#include <dnscore/acl-config.h>

#include "confs.h"
#include "zone.h"

#include "database-service.h"
#include "zone-signature-policy.h"

/*
 *
 */

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#define DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS 0
#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
#pragma message("WARNING: DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS enabled !")
#endif

extern zone_data_set database_zone_desc;

/******************** Zones *************************/

static value_name_table zone_type_enum_table[]=
{
#if HAS_MASTER_SUPPORT
    {ZT_MASTER,     ZT_STRING_MASTER},
    {ZT_MASTER,     ZT_STRING_PRIMARY},
#endif
    {ZT_SLAVE,      ZT_STRING_SLAVE},
    {ZT_SLAVE,      ZT_STRING_SECONDARY},

    {0, NULL}
};

#if ZDB_HAS_DNSSEC_SUPPORT
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
#endif

/*  Table with the parameters that can be set in the config file
 *  zone containers
 */

#define CONFIG_TYPE zone_desc_s

CONFIG_BEGIN(config_section_zone_desc)
CONFIG_STRING(domain, NULL)
CONFIG_STRING(file_name, NULL)
CONFIG_PATH(keys_path, NULL)
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
CONFIG_FLAG32(drop_before_load, S_ZONE_FLAG_DROP_BEFORE_LOAD, flags, ZONE_FLAG_DROP_BEFORE_LOAD)
CONFIG_FLAG32(no_master_updates , S_ZONE_NO_MASTER_UPDATES, flags, ZONE_FLAG_NO_MASTER_UPDATES)
#if HAS_MASTER_SUPPORT
CONFIG_FLAG32(true_multimaster, S_ZONE_FLAG_TRUE_MULTIMASTER, flags, ZONE_FLAG_TRUE_MULTIMASTER)
CONFIG_FLAG32(maintain_dnssec, S_ZONE_FLAG_MAINTAIN_DNSSEC, flags, ZONE_FLAG_MAINTAIN_DNSSEC)
CONFIG_FLAG32(maintain_zone_before_mount, "1", flags, ZONE_FLAG_MAINTAIN_ZONE_BEFORE_MOUNT) // used nowhere
#endif

CONFIG_U32_RANGE(notify.retry_count, S_NOTIFY_RETRY_COUNT, NOTIFY_RETRY_COUNT_MIN, NOTIFY_RETRY_COUNT_MAX)
CONFIG_U32_RANGE(notify.retry_period, S_NOTIFY_RETRY_PERIOD, NOTIFY_RETRY_PERIOD_MIN, NOTIFY_RETRY_PERIOD_MAX)
CONFIG_U32_RANGE(notify.retry_period_increase, S_NOTIFY_RETRY_PERIOD_INCREASE, NOTIFY_RETRY_PERIOD_INCREASE_MIN, NOTIFY_RETRY_PERIOD_INCREASE_MAX)
        
CONFIG_U8(multimaster_retries, S_MULTIMASTER_RETRIES)

#if HAS_DNSSEC_SUPPORT
        
#if HAS_RRSIG_MANAGEMENT_SUPPORT
        
#if HAS_MASTER_SUPPORT
CONFIG_DNSSEC_POLICY(dnssec_policy)
#endif
        
CONFIG_U32_RANGE(signature.sig_validity_interval, S_S32_VALUE_NOT_SET, SIGNATURE_VALIDITY_INTERVAL_MIN, SIGNATURE_VALIDITY_INTERVAL_MAX)
CONFIG_U32_RANGE(signature.sig_validity_regeneration, S_S32_VALUE_NOT_SET, SIGNATURE_VALIDITY_REGENERATION_MIN, SIGNATURE_VALIDITY_REGENERATION_MAX)
CONFIG_U32_RANGE(signature.sig_validity_jitter, S_S32_VALUE_NOT_SET, SIGNATURE_VALIDITY_JITTER_MIN, SIGNATURE_VALIDITY_JITTER_MAX)

#if HAS_MASTER_SUPPORT
CONFIG_FLAG32(rrsig_nsupdate_allowed, S_ZONE_FLAG_RRSIG_NSUPDATE_ALLOWED, flags, ZONE_FLAG_RRSIG_NSUPDATE_ALLOWED)
#endif
        
CONFIG_ALIAS(signature_validity_interval, signature.sig_validity_interval)
CONFIG_ALIAS(signature_regeneration, signature.sig_validity_regeneration)
CONFIG_ALIAS(signature_jitter, signature.sig_validity_jitter)
#endif

CONFIG_ENUM(dnssec_mode, S_ZONE_DNSSEC_DNSSEC, dnssec_enum)

#if HAS_RRSIG_MANAGEMENT_SUPPORT
CONFIG_ALIAS(signature.sig_jitter, sig_validity_jitter)
#endif

CONFIG_ALIAS(dnssec,dnssec_mode)
CONFIG_ALIAS(rrsig_push_allowed, rrsig_nsupdate_allowed)
#endif

CONFIG_U32_RANGE(journal_size_kb, S_JOURNAL_SIZE_KB_DEFAULT, S_JOURNAL_SIZE_KB_MIN, S_JOURNAL_SIZE_KB_MAX)

#if HAS_CTRL
//CONFIG_U8(ctrl_flags, "0")  // SHOULD ONLY BE IN THE DYNAMIC CONTEXT
CONFIG_BYTES(dynamic_provisioning, "AAA=", sizeof(dynamic_provisioning_s))
CONFIG_HOST_LIST(slaves, NULL)
#endif // HAS_CTRL

/* CONFIG ALIAS: alias , aliased-real-name */
CONFIG_ALIAS(also_notify,notifies)
CONFIG_ALIAS(file,file_name)
CONFIG_ALIAS(keyspath, keys_path)
CONFIG_ALIAS(journal_size,journal_size_kb)
CONFIG_ALIAS(master,masters)
CONFIG_ALIAS(notify,notifies)
CONFIG_ALIAS(auto_notify,notify_auto)

CONFIG_ALIAS(primary,masters)
CONFIG_ALIAS(primaries,masters)
CONFIG_ALIAS(true_multiprimary, true_multimaster)
CONFIG_ALIAS(multiprimary_retries, multimaster_retires)
CONFIG_ALIAS(no_primary_updates, no_master_updates)

CONFIG_END(config_section_zone_desc)

#undef CONFIG_TYPE

#include <dnscore/tsig.h>
#include <dnscore/base64.h>
#include <dnscore/config_settings.h>

#if DNSCORE_HAS_TCP_MANAGER
#include <dnscore/tcp_manager.h>
#endif

#include "zone_desc.h"

static ya_result
config_section_zone_init(struct config_section_descriptor_s *csd)
{
    // NOP
    
    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR; // base SHOULD be NULL at init
    }
        
    return SUCCESS;
}

static ya_result
config_section_zone_start(struct config_section_descriptor_s *csd)
{
    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR;
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

        if(logger_is_running())
        {
            log_debug("config: %{dnsname}: zone section parsed", zone_origin(zone_desc));
        }

#if ZDB_HAS_MASTER_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
        if(zone_rrsig_nsupdate_allowed(zone_desc) && (zone_desc->dnssec_policy != NULL))
        {
            if(logger_is_running())
            {
                log_err("config: %{dnsname}: policies and allowing RRSIG over dynamic updates are mutually exclusive.", zone_origin(zone_desc));
            }
            else
            {
                formatln("config: %{dnsname}: policies and allowing RRSIG over dynamic updates are mutually exclusive.", zone_origin(zone_desc));
            }

            return_code = INVALID_STATE_ERROR;
        }
#endif

#if DNSCORE_HAS_TCP_MANAGER
        for(host_address *ha = zone_desc->notifies; ha != NULL; ha = ha->next)
        {
            socketaddress sa;
            socklen_t sa_len = host_address2sockaddr(ha, &sa);
            tcp_manager_host_register(&sa, sa_len, g_config->max_secondary_tcp_queries);
        }
#endif
        
        // load the descriptor (most likely offline)

#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
        zone_desc->signature.sig_validity_interval = 1;
        zone_desc->signature.sig_validity_jitter = 5;
        zone_desc->signature.sig_validity_regeneration = 1;
#endif
        if(config_section_zone_filter(zone_desc, config_section_zone_filter_params) == 1)
        {
            if(logger_is_running())
            {
                log_debug("config: %{dnsname}: sending zone to service", zone_origin(zone_desc));
            }
            database_zone_desc_load(zone_desc);
        }
        else
        {
            zone_desc_s *current_zone_desc = zone_acquirebydnsname(zone_origin(zone_desc));
            if(current_zone_desc != NULL)
            {
                if(logger_is_running())
                {
                    log_debug("config: %{dnsname}: clearing original zone drop status", zone_origin(zone_desc));
                }
                zone_lock(current_zone_desc, ZONE_LOCK_REPLACE_DESC);
                zone_clear_status(current_zone_desc, ZONE_STATUS_DROP_AFTER_RELOAD);
                zone_unlock(current_zone_desc, ZONE_LOCK_REPLACE_DESC);
                
                zone_release(current_zone_desc);
            }
            
            zone_release(zone_desc);
        }
    }
    else
    {
        zone_release(zone_desc);
    }
        
    csd->base = NULL;
    
    return return_code;
}

static ya_result
config_section_zone_postprocess(struct config_section_descriptor_s *csd)
{
    (void)csd;

    return SUCCESS;
}

static ya_result
config_section_zone_finalize(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->base != NULL)
        {
            zone_desc_s *zone_desc = (zone_desc_s*)csd->base;
            zone_release(zone_desc);
#if DEBUG
            csd->base = NULL;
#endif
        }

        free(csd);
    }
    
    return SUCCESS;
}

static ya_result
config_section_zone_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;
    (void)key;
    (void)value;

    return CONFIG_UNKNOWN_SETTING;
}

static ya_result
config_section_zone_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    if(key != NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    // for all zones, print table of the zone
    
    zone_set_lock(&database_zone_desc); // unlock checked
    
    ptr_set_iterator iter;
    ptr_set_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;
        
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
    config_section_zone_finalize
};

ya_result
config_register_zone(const char *null_or_key_name, s32 priority)
{
    //null_or_key_name = "zone";
    (void)null_or_key_name;
    
    config_section_descriptor_s *desc;
    MALLOC_OBJECT_OR_DIE(desc, config_section_descriptor_s, CFGSDESC_TAG);
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
