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

#include <dnscore/format.h>
#include <dnscore/sys_get_cpu_count.h>
#include <dnsdb/dnssec.h>

#include "confs.h"
#include "config_error.h"
#include "server_error.h"

/*
 *
 */

#define CONFS_MAIN_C_


config_data						       *g_config = NULL;

/*------------------------------------------------------------------------------
 * MACROS */

/*
    tmp_config->process_flags      |= PROCESS_FL_AUTHORITY_AUTH   * S_AUTHORITY_AUTH;
    tmp_config->process_flags      |= PROCESS_FL_AUTHORITY_CACHE  * S_AUTHORITY_CACHE;
 */

/*  Table with the parameters that can be set in the config file
 *  main container
 */

#define CONFS_TYPE config_data

CONFS_BEGIN(config_tab)
/* Switch for additional response             */
CONFS_FLAG16(   additional_from_auth        , S_ADDITIONAL_AUTH         , process_flags, PROCESS_FL_ADDITIONAL_AUTH    )
/* Switch for authority response              */
CONFS_FLAG16(   additional_from_cache       , S_ADDITIONAL_CACHE        , process_flags, PROCESS_FL_ADDITIONAL_CACHE   )
/* Switch for authority response with cache   */
CONFS_FLAG16(   authority_from_auth        , S_ADDITIONAL_AUTH          , process_flags, PROCESS_FL_AUTHORITY_AUTH     )
/* Switch for authority response with cache   */
CONFS_FLAG16(   authority_from_cache        , S_ADDITIONAL_AUTH          , process_flags, PROCESS_FL_AUTHORITY_CACHE    )
/* Switch for turning chroot, uid & gid off   */
CONFS_FLAG16(   chroot                      , S_CHROOT                  , server_flags,  SERVER_FL_CHROOT              )
/* Path to chroot, will be used if chroot is on */
CONFS_PATH(     chroot_path                 , S_CHROOTPATH               )
CONFS_U32(      cpu_count_override          , S_CPU_COUNT_OVERRIDE       )
CONFS_U32(      thread_count_by_address     , S_THREAD_COUNT_BY_ADDRESS  )
CONFS_STRING(   config_file                 , S_CONFIGDIR S_CONFIGFILE   )
CONFS_STRING(   config_file_dynamic         , S_CONFIGDIR S_CONFIGFILEDYNAMIC )
/* Path to data which will be used for relative data */
CONFS_PATH(     data_path                   , S_DATAPATH                 )
CONFS_PATH(     xfr_path                    , S_XFRPATH                  )
CONFS_U32(      dnssec_thread_count         , S_DNSSEC_THREAD_COUNT      )
/* Interactive mode or not                      */
CONFS_FLAG16(   daemon                      , S_DAEMONRUN               , server_flags,  SERVER_FL_DAEMON              )
/* size of an EDNS0 packet */
CONFS_U32(      edns0_max_size              , S_EDNS0_MAX_SIZE           )
/* gid to chroot, will be used if chroot is on */
CONFS_GID(      gid                         , S_GID                      )
/* Use ipv4 interfaces                         */
CONFS_FLAG8(    ipv4                        , S_IPV4                    , ip, IP_FLAGS_IPV4 )
/* Use ipv6 interfaces                         */
CONFS_FLAG8(    ipv6                        , S_IPV6                    , ip, IP_FLAGS_IPV6 )
/* Path to keys                                */
CONFS_PATH(     keys_path                   , S_KEYSPATH                 )
/* Listening to interfaces                     */
CONFS_HOST_LIST(listen                      , S_LISTEN                   )
/* Path which will be used for relative logs   */
CONFS_PATH(     log_path                    , S_LOGPATH                  )
CONFS_U32(      max_axfr                    , S_MAX_AXFR                 )
/* Max number of TCP queries  */
CONFS_U32(      max_tcp_queries             , S_MAX_TCP_QUERIES          )
CONFS_U32(      tcp_query_min_rate          , S_TCP_QUERY_MIN_RATE       )
/* Ignores messages that would be answered by a FORMERR */ 
CONFS_FLAG16(   answer_formerr_packets      , S_ANSWER_FORMERR_PACKETS  , server_flags,  SERVER_FL_ANSWER_FORMERR)
/* PID file folder                             */
CONFS_PATH(     pid_path                    , S_PIDPATH                  )
CONFS_STRING(   pid_file                    , S_PIDFILE                  )
/* Listen to port (eg 53)                      */
CONFS_STRING(   server_port                 , S_SERVERPORT               )
/* uid to chroot, will be used if chroot is on */
CONFS_UID(      uid                         , S_UID                      )
/* Switch for cache server or not              */
CONFS_FLAG16(   recursion                   , S_RECURSION               , process_flags, PROCESS_FL_RECURSION
/* Switch for loging statistics                */)
CONFS_FLAG16(   statistics                  , S_STATISTICS              , server_flags,  SERVER_FL_STATISTICS
/* Maximum number of seconds between two statistics lines */)
CONFS_U32(      statistics_max_period       , S_STATISTICS_MAX_PERIOD    )

CONFS_U32(      xfr_connect_timeout         , S_XFR_CONNECT_TIMEOUT      )

CONFS_U32(      queries_log_type            , S_QUERIES_LOG_TYPE         )

 /* ip address used as source for transfers     */
/* CONFS_STRING(   transfer_source             , S_TRANSFER_SOURCE          ) */

 /* string used for query of version            */
CONFS_STRING(   version_chaos               , S_VERSION_CHAOS            )
#if HAS_ACL_SUPPORT != 0
CONFS_ACL(      allow_query                 , S_ALLOW_QUERY              )
CONFS_ACL(      allow_update                , S_ALLOW_UPDATE             )
CONFS_ACL(      allow_transfer              , S_ALLOW_TRANSFER           )
CONFS_ACL(      allow_update_forwarding     , S_ALLOW_UPDATE_FORWARDING  )
CONFS_ACL(      allow_notify                , S_ALLOW_NOTIFY             )
CONFS_ACL(      allow_control               , S_ALLOW_CONTROL            )
#endif

#if HAS_DNSSEC_SUPPORT != 0
CONFS_U32(      sig_signing_type            , S_SIG_SIGNING_TYPE         )
CONFS_U32(      sig_validity_interval       , S_SIG_VALIDITY_INTERVAL    ) /* 7 to 365 days = 30 */
CONFS_U32(      sig_validity_regeneration   , S_SIG_VALIDITY_REGENERATION) /* 24 hours to 168 hours */
CONFS_U32(      sig_validity_jitter         , S_SIG_VALIDITY_JITTER      ) /* 0 to 86400 = 3600*/
CONFS_ALIAS(sig_jitter, sig_validity_jitter)
#endif

CONFS_U32(      axfr_max_record_by_packet   , S_AXFR_MAX_RECORD_BY_PACKET)
CONFS_U32(      axfr_max_packet_size        , S_AXFR_PACKET_SIZE_MAX     )
CONFS_U32(      axfr_compress_packets       , S_AXFR_COMPRESS_PACKETS    )
CONFS_U32(      axfr_retry_delay            , S_AXFR_RETRY_DELAY         )
CONFS_U32(      axfr_retry_jitter           , S_AXFR_RETRY_JITTER        )

CONFS_ALIAS(port, server_port)
CONFS_ALIAS(version, version_chaos)
CONFS_ALIAS(chrootpath, chroot_path)
CONFS_ALIAS(configfile, config_file)
CONFS_ALIAS(keyspath, keys_path)
CONFS_ALIAS(datapath, data_path)
CONFS_ALIAS(xfrpath, xfr_path)
CONFS_ALIAS(logpath, log_path)
CONFS_ALIAS(pidpath, pid_path)
CONFS_ALIAS(pidfile, pid_file)
CONFS_ALIAS(daemonize, daemon)

CONFS_ALIAS(axfr_maxrecordbypacket, axfr_max_record_by_packet)
CONFS_ALIAS(axfr_maxpacketsize, axfr_max_packet_size)
CONFS_ALIAS(axfr_compresspackets, axfr_compress_packets)

CONFS_END(config_tab)

static ya_result
config_main_check_dir_exists(config_data *config, const char *dir)
{
    char tmp[4096];
    if((config->server_flags & SERVER_FL_CHROOT) != 0)
    {
        snprintf(tmp, sizeof(tmp),"/%s/%s", config->chroot_path, dir);
        dir = tmp;
    }

    struct stat ds;

    if(stat(dir, &ds) < 0)
    {
        osformatln(termerr, "error: '%s': %s\n", dir, strerror(errno));
        
        return ERROR;
    }

    if((ds.st_mode & S_IFMT) != S_IFDIR)
    {
        osformatln(termerr, "error: '%s' is not a directory\n", dir);
        
        return ERROR;
    }

    return SUCCESS;
}

ya_result
config_main_section_init(config_data *config)
{
    ya_result return_code;

    if(g_config != NULL)
    {
        return SUCCESS;
    }

    /*
     * Allocate the memory
     */

    config_data                                          *tmp_config = NULL;

    /* Alloc & clear config */
    MALLOC_OR_DIE(config_data*, tmp_config, sizeof (config_data), GENERIC_TAG);
    ZEROMEMORY(tmp_config, sizeof (config_data));

    zone_init(&tmp_config->zones);
    zone_init(&tmp_config->dynamic_zones);

    /*
     * Set automatic default values
     */

    if(FAIL(return_code = confs_init(config_tab, tmp_config)))
    {
        free(tmp_config);
        
        osformatln(termerr, "error: initialising configuration (main): %r", return_code);
        return return_code;
    }

    if(!IS_TYPE_PRIVATE(tmp_config->sig_signing_type))
    {
        osformatln(termerr, "error: signing type is not in the accepted range");
        return CONFIG_WRONG_SIG_TYPE;
    }

    if(tmp_config->sig_validity_interval > SIGNATURE_VALIDITY_INTERVAL_MAX)
    {
        osformatln(termerr, "error: signature validity interval too high");
        return CONFIG_WRONG_SIG_VALIDITY;
    }

    if(tmp_config->sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S * 2 > tmp_config->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S)
    {
        osformatln(termerr, "error: default signature regeneration is more than half the interval (%ds * 2 > %ds)", tmp_config->sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S, tmp_config->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S);
        return CONFIG_WRONG_SIG_REGEN;
    }

    tmp_config->tcp_query_min_rate_us = tmp_config->tcp_query_min_rate * 0.000001;
    
    tmp_config->run_mode            = S_RUNMODE;

    tmp_config->gid                 = getgid();
    tmp_config->uid                 = getuid();

    /* Add S_LISTEN to linked list
     * Those are the interfaces used default for listening
     */
/*
    list_add(&tmp_config->listen,     S_LISTEN);
  	tmp_config->total_interfaces    = S_TOTALINTERFACES;
*/ 
	tmp_config->total_interfaces	= host_address_count(tmp_config->listen);


    /* Should be :
     *
     * 1 for each hardware thread (cores/...)
     * +
     * 2 for database signature processing
     * +
     * N for the server's personal use
     *	_ tcp queries
     *  _ ...
     */
    
    tmp_config->thread_count        = (sys_get_cpu_count() + 2 ) + /* database & dnssec */
                                       tmp_config->max_tcp_queries;

    g_config                        = tmp_config;

    return SUCCESS;
}

static ya_result config_main_section_assign(config_data *config)
{
    u32 port = 0;

    if(FAIL(parse_u32_check_range(config->server_port, &port, 1, MAX_U16, 10)))
    {
        port = DNS_DEFAULT_PORT;
        osformatln(termerr, "config: main: wrong dns port set in main '%s', defaulted to %d", config->server_port, port);
    }
    
    host_set_default_port_value(config->listen, ntohs(port));

    if(config->server_flags & SERVER_FL_CHROOT)
    {
        uid_t euid = geteuid();
        
        if(euid != 0)
        {
            osformatln(termerr, "config: main: chroot has been enabled but euid is not root (%i != 0)", (int)euid);
            return ERROR;
        }
    }
    
    if(!config_check_bounds_s32(SIGNATURE_VALIDITY_INTERVAL_MIN, SIGNATURE_VALIDITY_INTERVAL_MAX, config->sig_validity_interval, "sig-validity-interval"))
    {
        return ERROR;
    }
    
    if(!config_check_bounds_s32(SIGNATURE_VALIDITY_REGENERATION_MIN, SIGNATURE_VALIDITY_REGENERATION_MAX, config->sig_validity_regeneration, "sig-validity-regeneration"))
    {
        return ERROR;
    }
    
    if(!config_check_bounds_s32(SIGNATURE_VALIDITY_JITTER_MIN, SIGNATURE_VALIDITY_JITTER_MAX, config->sig_validity_jitter, "sig-validity-jitter"))
    {
        return ERROR;
    }
    
    if(!config_check_bounds_s32(EDNS0_MIN_LENGTH, EDNS0_MAX_LENGTH, config->edns0_max_size, "edns0-max-size"))
    {
        return ERROR;
    }
    
    message_edns0_setmaxsize(config->edns0_max_size);    
    
    config->total_interfaces = host_address_count(config->listen);
    
    if(config->total_interfaces > MAX_INTERFACES)
    {
        osformat(termerr,"error: more than %d listening addresses defined.", MAX_INTERFACES);
        return ERROR;
    }
    
    if(!config_check_bounds_s32(TCP_QUERIES_MIN, TCP_QUERIES_MAX, config->max_tcp_queries, "max-tcp-queries"))
    {
        return ERROR;
    }
    
    if(!config_check_bounds_s32(AXFR_PACKET_SIZE_MIN, AXFR_PACKET_SIZE_MAX, config->axfr_max_packet_size, "axfr-max-packet-size"))
    {
        return ERROR;
    }
    
    if(!config_check_bounds_s32(AXFR_RECORD_BY_PACKET_MIN, AXFR_RECORD_BY_PACKET_MAX, config->axfr_max_record_by_packet, "axfr-max-record-by-packet"))
    {
        return ERROR;
    }
    
    if(!config_check_bounds_s32(AXFR_RETRY_DELAY_MIN, AXFR_RETRY_DELAY_MAX, config->axfr_retry_delay, "axfr-retry-delay"))
    {
        return ERROR;
    }
        
    config->axfr_retry_jitter = BOUND(AXFR_RETRY_JITTER_MIN, config->axfr_retry_jitter,config->axfr_retry_delay);
    
    config->dnssec_thread_count = BOUND(1, config->dnssec_thread_count, sys_get_cpu_count());
    
    config->thread_count = sys_get_cpu_count() + 2;
    config->thread_count += config->max_tcp_queries;                   /* else the pool will starve */
    config->thread_count += config->dnssec_thread_count + 2;           /* else the pool will starve */
    config->thread_count = BOUND(2, config->thread_count, THREAD_POOL_SIZE_MAX);    /* and if it's too much, then too bad : it'll wait */
    
    if(strcmp(config->config_file, config->config_file_dynamic) == 0)
    {
        return ERROR;
    }
        
    if(FAIL(config_main_check_dir_exists(config, config->data_path)))
    {
        return ERROR;
    }
    
    if(FAIL(config_main_check_dir_exists(config, config->keys_path)))
    {
        return ERROR;
    }
    
    if(FAIL(config_main_check_dir_exists(config, config->log_path)))
    {
        return ERROR;
    }
    
    if(FAIL(config_main_check_dir_exists(config, config->pid_path)))
    {
        return ERROR;
    }
    
    if(FAIL(config_main_check_dir_exists(config, config->xfr_path)))
    {
        return ERROR;
    }
    
    dnssec_set_xfr_path(config->xfr_path);

    return SUCCESS;
}

static ya_result
config_main_section_free(config_data *config)
{
    acl_empties_access_control(&config->ac);
    host_address_delete_list(config->listen);
    config->listen = NULL;
    
    return SUCCESS;
}

/** @brief Adjusting the parameters found in the containers of the config file
 *
 *  Adjusting the default parameters with settings found in the config file
 *  or at the command line for the main container "<main>...</main>"
 *
 *  @param[in] kind
 *  @param[in] value
 *  @param[out] config
 *
 *  M
 *  @retval OK
 */
ya_result
config_adjust(const char *name, const void *value, config_data *config)
{
    ya_result return_code = confs_set(config_tab, config, name, value);
    
    return return_code;
}

/** @brief Main function for setting parameters, other functions can be used for
 *         other containers
 *         Other containers can be defined with plug-in
 *
 *  @param[in] variable
 *  @param[in] value
 *  @param[out] config
 *
 *  @retval OK
 *  @retval NONE
 */
static ya_result
set_variable_main(char *variable, char *value, char *argument)
{
    ya_result return_code = confs_set(config_tab, g_config, variable, value);
    
    if(FAIL(return_code))
    {
        osformatln(termerr, "error setting variable: main.%s = '%s': %r", variable, value, return_code);

        return return_code;
    }

    return OK;
}

static ya_result
config_main_section_print(config_data *config)
{
    confs_print(config_tab, config);

    return SUCCESS;
}


static config_section_descriptor section_main =
{
    "main",
    set_variable_main,
    config_main_section_init,
    config_main_section_assign,
    config_main_section_free,
    config_main_section_print,
    FALSE
};

const config_section_descriptor *
confs_main_get_descriptor()
{
    return &section_main;
}

/** @} */
