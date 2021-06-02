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

#define ZDB_JOURNAL_CODE 1

#include "server-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include <dnscore/format.h>
#include <dnscore/sys_get_cpu_count.h>
#include <dnscore/config_settings.h>
#include <dnscore/parsing.h>
#include <dnscore/fdtools.h>
#include <dnscore/chroot.h>

#include <dnsdb/journal.h>
#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnsdb/dnssec.h>
#include <dnsdb/dnssec-keystore.h>
#endif

#include "confs.h"
#include "config_error.h"
#include <dnscore/acl-config.h>
#include "server_error.h"
#include "process_class_ch.h"
#include "server_context.h"

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic-module-handler.h"
#endif

#if DNSCORE_HAS_TCP_MANAGER
#include <dnscore/tcp_manager.h>
#endif

/*
 *
 */

#define CONFS_MAIN_C_

config_data						       *g_config = NULL;

static value_name_table network_model_enum[]=
{
    {0, "single"  },
    {0, "0"  },
    {1, "buffered"},
    {1, "1"},
    {2, "multi"   },
    {2, "2"   },
    {0, NULL}
};

/*------------------------------------------------------------------------------
 * MACROS */

/*  Table with the parameters that can be set in the config file
 *  main container
 */

#define CONFIG_TYPE config_data

CONFIG_BEGIN(config_main_desc)
CONFIG_FILE(     config_file                 , S_CONFIGDIR S_CONFIGFILE   )

#ifndef WIN32
/* Path to chroot, will be used if chroot is on */
CONFIG_CHROOT(   chroot_path                 , S_CHROOTPATH               ) // doc
#endif
/* Path to data which will be used for relative data */
CONFIG_PATH(     data_path                   , S_DATAPATH                 ) // doc
/* Path which will be used for logs */
CONFIG_LOGPATH(  log_path                    , S_LOGPATH                  ) // doc
CONFIG_PATH(     xfr_path                    , S_XFRPATH                  ) // doc
/* Path to keys                                */
CONFIG_PATH(     keys_path                   , S_KEYSPATH                 ) // doc
/* PID file */
CONFIG_STRING(   pid_file                    , S_PIDFILE                  ) // doc
/* Switch for turning chroot, uid & gid off   */
CONFIG_FLAG16(   daemon                      , S_DAEMONRUN               , server_flags,  SERVER_FL_DAEMON              ) // doc
CONFIG_FLAG16(   chroot                      , S_CHROOT                  , server_flags,  SERVER_FL_CHROOT              ) // doc
CONFIG_FLAG16(   log_unprocessable           , S_LOG_UNPROCESSABLE       , server_flags,  SERVER_FL_LOG_UNPROCESSABLE   ) // doc

CONFIG_FLAG16(   log_from_start              , S_LOG_FROM_START          , server_flags,  SERVER_FL_LOG_FROM_START      ) // for the command line
// if set, disables checking the log-path directory for existence and writing rights.
CONFIG_FLAG16(   log_files_disabled          , S_LOG_FILES_DISABLED      , server_flags,  SERVER_FL_LOG_FILE_DISABLED   ) // doc
CONFIG_UID(      uid                         , S_UID                      ) // doc
CONFIG_GID(      gid                         , S_GID                      ) // doc

// Above settings probably cannot be changed at run time

// Below settings may be changed at runtime

 /* string used for query of version            */
CONFIG_STRING(   version_chaos               , S_VERSION_CHAOS            ) // doc
CONFIG_STRING(   hostname_chaos              , S_HOSTNAME_CHAOS           ) // doc
CONFIG_STRING(   serverid_chaos              , S_SERVERID_CHAOS           ) // doc
#if ZDB_HAS_ACL_SUPPORT
CONFIG_ACL_PTR(  allow_query                 , S_ALLOW_QUERY              ) // doc
CONFIG_ACL_PTR(  allow_update                , S_ALLOW_UPDATE             ) // doc
CONFIG_ACL_PTR(  allow_transfer              , S_ALLOW_TRANSFER           ) // doc
CONFIG_ACL_PTR(  allow_update_forwarding     , S_ALLOW_UPDATE_FORWARDING  ) // doc
CONFIG_ACL_PTR(  allow_notify                , S_ALLOW_NOTIFY             ) // doc
CONFIG_ACL_PTR(  allow_control               , S_ALLOW_CONTROL            ) // doc
#endif

/* Listening to interfaces                     */
CONFIG_HOST_LIST(listen                      , S_LISTEN                   ) // doc
CONFIG_HOST_LIST(do_not_listen               , S_DO_NOT_LISTEN            ) // doc
CONFIG_HOST_LIST(known_hosts                 , S_LISTEN                   )
/* size of an EDNS0 packet */
CONFIG_U32_RANGE(edns0_max_size              , S_EDNS0_MAX_SIZE          ,EDNS0_MIN_LENGTH, EDNS0_MAX_LENGTH ) // doc
// overrides the cpu detection
CONFIG_U32(      cpu_count_override          , S_CPU_COUNT_OVERRIDE       ) // doc
// how many threads by address (UDP)
CONFIG_S32(      thread_count_by_address     , S_THREAD_COUNT_BY_ADDRESS  ) // doc

CONFIG_U32_RANGE(thread_affinity_base        , "0", 0, 3  )                 // first virtual cpu // doc
CONFIG_U32_RANGE(thread_affinity_multiplier  , "0", 0, 4  )                 // dual thread // doc

// how many threads for the dnssec processing)
#if DATABASE_ZONE_RRSIG_THREAD_POOL
CONFIG_U32(      dnssec_thread_count         , S_DNSSEC_THREAD_COUNT      ) /// @note 20180712 edf -- THIS PARAMETER IS OBSOLETE
#else
CONFIG_OBSOLETE(dnssec_thread_count) /// @note 20180712 edf -- THIS PARAMETER IS OBSOLETE
#endif

CONFIG_U32_RANGE(zone_load_thread_count      , S_ZONE_LOAD_THREAD_COUNT, ZONE_LOAD_THREAD_COUNT_MIN, ZONE_LOAD_THREAD_COUNT_MAX) // doc
CONFIG_U32_RANGE(zone_store_thread_count      , S_ZONE_SAVE_THREAD_COUNT, ZONE_SAVE_THREAD_COUNT_MIN, ZONE_SAVE_THREAD_COUNT_MAX) // doc
CONFIG_U32_RANGE(zone_download_thread_count  , S_ZONE_DOWNLOAD_THREAD_COUNT , ZONE_DOWNLOAD_THREAD_COUNT_MIN, ZONE_DOWNLOAD_THREAD_COUNT_MAX) // doc
CONFIG_U32_RANGE(zone_unload_thread_count    , S_ZONE_UNLOAD_THREAD_COUNT, ZONE_UNLOAD_THREAD_COUNT_MIN, ZONE_UNLOAD_THREAD_COUNT_MAX  ) // doc
CONFIG_ENUM(     network_model               ,S_NETWORK_MODEL, network_model_enum) // doc
/* Max number of TCP queries  */
CONFIG_U32_RANGE(max_tcp_queries             , S_MAX_TCP_QUERIES          ,TCP_QUERIES_MIN, TCP_QUERIES_MAX) // doc
CONFIG_U32_RANGE(max_secondary_tcp_queries   , S_MAX_SECONDARY_TCP_QUERIES,TCP_QUERIES_MIN, TCP_QUERIES_MAX) // doc
CONFIG_U32(      tcp_query_min_rate          , S_TCP_QUERY_MIN_RATE       ) // doc
CONFIG_U32_RANGE(tcp_queue_size              , S_TCP_QUEUE_SIZE           , S_TCP_QUEUE_SIZE_MIN, S_TCP_QUEUE_SIZE_MAX)
/* Ignores messages that would be answered by a FORMERR */ 
CONFIG_FLAG16(   answer_formerr_packets      , S_ANSWER_FORMERR_PACKETS  , server_flags,  SERVER_FL_ANSWER_FORMERR) // doc
/* Listen to port (eg 53)                      */
CONFIG_STRING(   server_port                 , S_SERVERPORT               ) // doc
/* Switch for cache server or not              */

CONFIG_FLAG16(   statistics                  , S_STATISTICS              , server_flags,  SERVER_FL_STATISTICS) /* Maximum number of seconds between two statistics lines */ // doc

CONFIG_U32(      statistics_max_period       , S_STATISTICS_MAX_PERIOD    ) // doc
CONFIG_U32(      xfr_connect_timeout         , S_XFR_CONNECT_TIMEOUT      ) // doc
CONFIG_U32(      queries_log_type            , S_QUERIES_LOG_TYPE         ) // doc

#if HAS_DNSSEC_SUPPORT
#if CONFIG_SIGNATURE_TYPE_CONFIGURABLE
CONFIG_U16(      sig_signing_type            , S_SIG_SIGNING_TYPE          )
#endif
CONFIG_U32_RANGE(sig_validity_interval       , S_SIG_VALIDITY_INTERVAL    , SIGNATURE_VALIDITY_INTERVAL_MIN     , SIGNATURE_VALIDITY_INTERVAL_MAX    ) /* 7 to 366 days = 30 */ // doc
CONFIG_U32_RANGE(sig_validity_regeneration   , S_SIG_VALIDITY_REGENERATION, SIGNATURE_VALIDITY_REGENERATION_MIN , SIGNATURE_VALIDITY_REGENERATION_MAX) /* 24 hours to 168 hours */ // doc
CONFIG_U32_RANGE(sig_validity_jitter         , S_SIG_VALIDITY_JITTER      , SIGNATURE_VALIDITY_JITTER_MIN       , SIGNATURE_VALIDITY_JITTER_MAX      ) /* 0 to 86400 = 3600*/ // doc
CONFIG_ALIAS(sig_jitter, sig_validity_jitter) // doc
#endif

CONFIG_U32_RANGE(axfr_max_record_by_packet   , S_AXFR_MAX_RECORD_BY_PACKET , AXFR_RECORD_BY_PACKET_MIN , AXFR_RECORD_BY_PACKET_MAX ) // doc
CONFIG_U32_RANGE(axfr_max_packet_size        , S_AXFR_PACKET_SIZE_MAX      , AXFR_PACKET_SIZE_MIN      , AXFR_PACKET_SIZE_MAX      ) // doc
CONFIG_BOOL(axfr_compress_packets            , S_AXFR_COMPRESS_PACKETS    ) // doc
CONFIG_BOOL(axfr_strict_authority, S_AXFR_STRICT_AUTHORITY) // doc
CONFIG_U32_RANGE(axfr_retry_delay            , S_AXFR_RETRY_DELAY          , AXFR_RETRY_DELAY_MIN      , AXFR_RETRY_DELAY_MAX      ) // doc
CONFIG_U32(      axfr_retry_jitter           , S_AXFR_RETRY_JITTER        ) // doc
CONFIG_U32_RANGE(axfr_retry_failure_delay_multiplier, S_AXFR_RETRY_FAILURE_DELAY_MULTIPLIER, AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MIN, AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX) // doc
CONFIG_U32_RANGE(axfr_retry_failure_delay_max, S_AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX, AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX_MIN, AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX_MAX) // doc
CONFIG_U32_RANGE(worker_backlog_queue_size   , S_SERVER_RW_BACKLOG_QUEUE_SIZE, SERVER_RW_BACKLOG_QUEUE_SIZE_MIN, SERVER_RW_BACKLOG_QUEUE_SIZE_MAX ) // doc

CONFIG_BOOL(check_policies, "0")

#if HAS_EVENT_DYNAMIC_MODULE
CONFIG_STRING_ARRAY(dynamic_modules, NULL,128)
CONFIG_ALIAS(module, dynamic_modules)
#endif

CONFIG_BOOL(hidden_master, "0") // doc

//CONFIG_U32_RANGE(multimaster_

          /* alias, aliased */
CONFIG_ALIAS(port, server_port) // doc
CONFIG_ALIAS(version, version_chaos) // doc
CONFIG_ALIAS(hostname, hostname_chaos) // doc
CONFIG_ALIAS(serverid, serverid_chaos) // doc
CONFIG_ALIAS(chrootpath, chroot_path) // doc
CONFIG_ALIAS(configfile, config_file) // cmdline
CONFIG_ALIAS(keyspath, keys_path) // doc
CONFIG_ALIAS(datapath, data_path) // doc
CONFIG_ALIAS(xfrpath, xfr_path) // doc
CONFIG_ALIAS(logpath, log_path) // doc
CONFIG_ALIAS(pidpath, pid_path)
CONFIG_ALIAS(pidfile, pid_file) // doc
CONFIG_ALIAS(daemonize, daemon) // doc

//CONFIG_ALIAS(zone_save_thread_count, zone_store_thread_count)

CONFIG_ALIAS(axfr_maxrecordbypacket, axfr_max_record_by_packet) // doc
CONFIG_ALIAS(axfr_maxpacketsize, axfr_max_packet_size) // doc
CONFIG_ALIAS(axfr_compresspackets, axfr_compress_packets) // doc

#if HAS_DNSSEC_SUPPORT
CONFIG_ALIAS(signature_validity_interval, sig_validity_interval)
CONFIG_ALIAS(signature_regeneration, sig_validity_regeneration)
CONFIG_ALIAS(signature_jitter, sig_validity_jitter)
#endif

CONFIG_ALIAS(xfr_maxrecordbypacket, axfr_max_record_by_packet) // doc
CONFIG_ALIAS(xfr_maxpacketsize, axfr_max_packet_size) // doc
CONFIG_ALIAS(xfr_compresspackets, axfr_compress_packets) // doc
CONFIG_ALIAS(xfr_retry_delay, axfr_retry_delay) // doc
CONFIG_ALIAS(xfr_retry_jitter, axfr_retry_jitter) // doc
CONFIG_ALIAS(xfr_retry_failure_delay_multiplier, axfr_retry_failure_delay_multiplier) // doc
CONFIG_ALIAS(xfr_retry_failure_delay_max, axfr_retry_failure_delay_max) // doc

CONFIG_ALIAS(user, uid) // doc
CONFIG_ALIAS(group, gid) // doc
CONFIG_ALIAS(max_tcp_connections, max_tcp_queries) // doc
CONFIG_ALIAS(network_model_worker_backlog_size, worker_backlog_queue_size)

CONFIG_END(config_main_desc)
#undef CONFIG_TYPE

static ya_result
config_main_verify_and_update_directory(const char *base_path, char **dirp)
{
    char fullpath[PATH_MAX];
    char tempfile[PATH_MAX];
    
    if(dirp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    char *dir = *dirp;
    
    if(dir == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    ya_result fullpath_len = snprintf(fullpath, sizeof(fullpath),"/%s/%s", base_path, dir);
    
    if(FAIL(fullpath_len))
    {
        return fullpath_len;
    }

    bool dirsep = TRUE;
    int j = 1;
    for(int i = 1; i <= fullpath_len; i++)
    {
        char c = fullpath[i];
        if(c == '/')
        {
            if(!dirsep)
            {
                fullpath[j++] = c;
            }
            dirsep = TRUE;
        }
        else
        {
            fullpath[j++] = fullpath[i];
            dirsep = FALSE;
        }
    }
    
    struct stat ds;

    if(stat(fullpath, &ds) < 0)
    {
        int err = errno;
        ttylog_err("error: '%s': %s", fullpath, strerror(err));

        return MAKE_ERRNO_ERROR(err);
    }

    if((ds.st_mode & S_IFMT) != S_IFDIR)
    {
        ttylog_err("error: '%s' is not a directory", dir);
        
        return INVALID_PATH;
    }
    
    snformat(tempfile, sizeof(tempfile), "%s/ydf.XXXXXX", fullpath);
    int tempfd;
    if((tempfd = mkstemp_ex(tempfile)) < 0)
    {
        int ret = ERRNO_ERROR;
#ifndef WIN32
        ttylog_err("error: '%s' is not writable as (%d:%d): %r", fullpath, getuid(), getgid(), ret);
#else
        ttylog_err("error: '%s' is not writable: %r", fullpath, ret);
#endif
        return ret;
    }
    unlink(tempfile);
    close_ex(tempfd);
    
    free(dir);
#ifndef WIN32
    *dirp = strdup(fullpath);
    chroot_manage_path(dirp, fullpath, FALSE);
#endif
    return SUCCESS;
}

static ya_result
config_main_verify_and_update_file(const char *base_path, char **dirp)
{
    if(dirp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    char *p = *dirp;
    
    if(p == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    char *e = p + strlen(p) - 1;
    while((*e != '/') && (e > p))
    {
        e--;
    }
    
    if((*e == '/') || (e == p))
    {
        char filename[PATH_MAX];
        
        if(*e == '/')
        {
            *e = '\0';
            e++;
            strcpy_ex(filename, e, sizeof(filename));
            *e = '\0';
        }
        else
        {
            strcpy_ex(filename, e, sizeof(filename));
            *e = '\0';
        }
        
        ya_result ret;
        
        if(ISOK(ret = config_main_verify_and_update_directory(base_path, dirp)))
        {
            size_t pathlen = strlen(*dirp);
            memmove(&filename[pathlen + 1], filename, strlen(filename) + 1);
            memcpy(filename, *dirp, pathlen);
            filename[pathlen] = '/';
#ifndef WIN32
            chroot_unmanage_path(dirp);
#endif
            free(*dirp);
            *dirp = NULL;
#ifndef WIN32
            *dirp = strdup(filename);
            chroot_manage_path(dirp, filename, FALSE);
#endif
            return SUCCESS;
        }
        else
        {
            return ret;
        }
    }
    
    return SUCCESS;
}

#if DNSCORE_HAS_TCP_MANAGER
static ya_result
config_main_section_postprocess_tcp_manager_register_callback(const char* itf_name, const socketaddress* sa, void* data)
{

    (void)itf_name;
    (void)data;
    socklen_t sa_len;
    if(sa->sa.sa_family == AF_INET)
    {
        sa_len = sizeof(sa->sa4);
        tcp_manager_host_register(sa, sa_len, g_config->max_secondary_tcp_queries);
    }
    else if(sa->sa.sa_family == AF_INET6)
    {
        sa_len = sizeof(sa->sa6);
        tcp_manager_host_register(sa, sa_len, g_config->max_secondary_tcp_queries);
    }
    return SUCCESS;
}
#endif

static ya_result
config_main_section_postprocess(struct config_section_descriptor_s *csd)
{
    (void)csd;

    u32 port = 0;
    u32 cpu_per_core = (sys_has_hyperthreading())?2:1;
    int ret;
#if _BSD_SOURCE || _XOPEN_SOURCE >= 500 || /* Since glibc 2.12: */ _POSIX_C_SOURCE >= 200112L 
    char tmp[PATH_MAX];
#endif

#if DNSCORE_HAS_TCP_MANAGER
/**
 * Sets the allowed connections total for all unregistered connections.
 */

    tcp_manager_connection_max(g_config->max_tcp_queries);

    for(host_address *ha = g_config->known_hosts; ha != NULL; ha = ha->next)
    {
        if((ha->version == HOST_ADDRESS_IPV4) || (ha->version == HOST_ADDRESS_IPV6))
        {
            network_interfaces_forall(config_main_section_postprocess_tcp_manager_register_callback, NULL);
        }
    }
#endif

    g_server_context.worker_backlog_queue_size = g_config->worker_backlog_queue_size;

    if(FAIL(parse_u32_check_range(g_config->server_port, &port, 1, MAX_U16, BASE_10)))
    {
        port = DNS_DEFAULT_PORT;
        ttylog_err("config: main: wrong dns port set in main '%s', defaulted to %d", g_config->server_port, port);
    }

    g_config->server_port_value = port;
    
    if(g_config->hostname_chaos == NULL)
    {
#if _BSD_SOURCE || _XOPEN_SOURCE >= 500 || /* Since glibc 2.12: */ _POSIX_C_SOURCE >= 200112L 
        if(gethostname(tmp, sizeof(tmp)) == 0)
        {
            g_config->hostname_chaos = strdup(tmp);
        }
        else
        {
            osformatln(termerr,"config: main: unable to get hostname: %r", ERRNO_ERROR);
            g_config->hostname_chaos = strdup("not disclosed");
        }
#else
        g_config->hostname_chaos = strdup("not disclosed");
#endif
    }
       
    if(g_config->thread_affinity_multiplier == 0)
    {
        g_config->thread_affinity_multiplier = cpu_per_core;
    }
    
    class_ch_set_hostname(g_config->hostname_chaos);    
    class_ch_set_id_server(g_config->serverid_chaos);
    class_ch_set_version(g_config->version_chaos);
    
    host_address_set_default_port_value(g_config->listen, ntohs(port));
    host_address_set_default_port_value(g_config->do_not_listen, ntohs(port));

#ifndef WIN32
    if(g_config->server_flags & SERVER_FL_CHROOT)
    {
        uid_t euid = geteuid();
        
        if(euid != 0)
        {
            ttylog_err("config: main: chroot has been enabled but euid is not root (%i != 0)", (int)euid);
            return INVALID_STATE_ERROR;
        }
    }
    else // disables the base-path/chroot-path feature
    {
        if(strcmp(g_config->chroot_path, "/") != 0)
        {
            free(g_config->chroot_path);
            g_config->chroot_path = strdup("/");
            chroot_set_path(g_config->chroot_path);
        }
    }
#endif
    message_edns0_setmaxsize(g_config->edns0_max_size);    
    
    g_config->total_interfaces = host_address_count(g_config->listen);
    
    if(g_config->total_interfaces > MAX_INTERFACES)
    {
        ttylog_err("error: more than %d listening addresses defined.", MAX_INTERFACES);
        return CONFIG_TOO_MANY_HOSTS;
    }

#ifndef SO_REUSEPORT
    if(g_config->network_model == 1)
    {
#if 0 /* fix */
#else
        ttylog_err("warning: network-model 1 requires SO_REUSEPORT which is not available on this system. Reducing worker units to 1");
        g_config->thread_count_by_address = 1;
#endif
    }
#endif
    
    g_config->axfr_retry_jitter = BOUND(AXFR_RETRY_JITTER_MIN, g_config->axfr_retry_jitter, g_config->axfr_retry_delay);

#if DATABASE_ZONE_RRSIG_THREAD_POOL
    g_config->dnssec_thread_count = BOUND(1, g_config->dnssec_thread_count, sys_get_cpu_count());
#endif
    
    if(g_config->cpu_count_override > 0)
    {
        sys_set_cpu_count(g_config->cpu_count_override);
    }

    if(g_config->thread_count_by_address == 0)
    {
        ttylog_err("config: single thread engine has been removed, thread-count-by-address set to 1");
        g_config->thread_count_by_address = 1;
    }

    if(g_config->thread_count_by_address < 0)
    {
        g_config->thread_count_by_address = MAX(sys_get_cpu_count() / cpu_per_core, 1);
    }
    else if((g_config->thread_count_by_address > (s32)sys_get_cpu_count()))
    {
        g_config->thread_count_by_address = MAX(sys_get_cpu_count() / cpu_per_core, 1);
        ttylog_warn("config: bounding down thread-count-by-address to the number of physical CPUs (%d)", g_config->thread_count_by_address);
    }
    
    g_config->tcp_query_min_rate_us = 0.000001 * g_config->tcp_query_min_rate;
    message_set_minimum_troughput_default(g_config->tcp_query_min_rate_us);
    
#if HAS_DNSSEC_SUPPORT
#if DATABASE_ZONE_RRSIG_THREAD_POOL
    g_config->dnssec_thread_count = BOUND(1, g_config->dnssec_thread_count, sys_get_cpu_count());
#endif

#if CONFIG_SIGNATURE_TYPE_CONFIGURABLE
    if(!IS_TYPE_PRIVATE(g_config->sig_signing_type))
    {
        ttylog_err("error: signing type is not in the accepted range: %hx", g_config->sig_signing_type);
        return CONFIG_WRONG_SIG_TYPE;
    }
#endif
    
    if(g_config->sig_validity_interval > SIGNATURE_VALIDITY_INTERVAL_MAX)
    {
        ttylog_err("error: signature validity interval too high");
        return CONFIG_WRONG_SIG_VALIDITY;
    }

    if(g_config->sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S * 2 >
       g_config->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S)
    {
        ttylog_err("error: default signature regeneration is more than half the interval (%ds * 2 > %ds)",
                g_config->sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S,
                g_config->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S);
        return CONFIG_WRONG_SIG_REGEN;
    }
#endif


    
    /// @note config_main_verify_and_update_directory updates the folder with the base_path
    
    /**
     * 
     * @note All base paths are updated with the chroot variable so it does not
     *       need to be added all the time.
     * 
     */
#ifndef WIN32
    const char *base_path = g_config->chroot_path;
#else
    const char* base_path = "C:\\";
#endif

    if(FAIL(ret = config_main_verify_and_update_directory(base_path, &g_config->data_path)))
    {
        return ret;
    }
    
    if(FAIL(ret = config_main_verify_and_update_directory(base_path, &g_config->keys_path)))
    {
        return ret;
    }

    if((g_config->server_flags & SERVER_FL_LOG_FILE_DISABLED) == 0)
    {
        if(FAIL(ret = config_main_verify_and_update_directory(base_path, &g_config->log_path)))
        {
            return ret;
        }
    }

    if(FAIL(ret = config_main_verify_and_update_file(base_path, &g_config->pid_file)))
    {
        return ret;
    }

    g_config->reloadable = TRUE;
    
#ifndef WIN32
    if((g_config->server_flags & SERVER_FL_CHROOT) != 0)
    {
        if(FAIL(chroot_manage_path(&g_config->config_file, g_config->config_file, FALSE)))
        {
            log_warn("config file '%s' will not be accessible within the chroot jail '%s' : config reload will not work", g_config->config_file, base_path);
            g_config->reloadable = FALSE;
        }
    }
#endif
    if(FAIL(ret = config_main_verify_and_update_directory(base_path, &g_config->xfr_path)))
    {
        return ret;
    }
    
#if ZDB_HAS_DNSSEC_SUPPORT
    dnssec_keystore_setpath(g_config->keys_path);
    journal_set_xfr_path(g_config->xfr_path);
#endif
    
#if HAS_EVENT_DYNAMIC_MODULE
    if(ptr_vector_last_index(&g_config->dynamic_modules) >= 0)
    {
        log_debug("config file: loading modules");
        
        for(int i = 0; i <= ptr_vector_last_index(&g_config->dynamic_modules); ++i)
        {
            const char *cmd = ptr_vector_get(&g_config->dynamic_modules, i);
            
            if(ISOK(ret = dynamic_module_handler_load_from_command(cmd)))
            {
                log_info("config file: loaded %s", cmd);
            }
            else
            {
                log_err("config file: failed to load %s", cmd);
                return ret;
            }
        }
    }
#endif
    
    if((logger_get_uid() != g_config->uid) || (logger_get_gid() != g_config->gid))
    {
        logger_set_uid(g_config->uid);
        logger_set_gid(g_config->gid);
        
        logger_reopen();
    }
    
    return SUCCESS;
}

ya_result
config_register_main(s32 priority)
{
    MALLOC_OBJECT_OR_DIE(g_config, config_data, YGCONFIG_TAG);
    ZEROMEMORY(g_config, sizeof(config_data));
    
    g_config->gid = getgid();
    g_config->uid = getuid();

#if HAS_EVENT_DYNAMIC_MODULE
    ptr_vector_init(&g_config->dynamic_modules);
#endif
    const char *section_name = "main";
    
    ya_result return_code = config_register_struct(section_name, config_main_desc, g_config, priority);
    
    if(ISOK(return_code))
    {    
        // hook a new finaliser before the standard one
        
        config_section_descriptor_s *section_desc = config_section_get_descriptor(section_name);
        config_section_descriptor_vtbl_s *vtbl = (config_section_descriptor_vtbl_s*)section_desc->vtbl;
        vtbl->postprocess = config_main_section_postprocess;
    }
    
    return return_code;
}

void config_unregister_main()
{
    //chroot_unmanage_all();
    config_data *g_config = config_unregister_struct("main", config_main_desc);
    free(g_config);
}

/** @} */
