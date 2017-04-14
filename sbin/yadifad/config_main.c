/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2017, EURid. All rights reserved.
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

#include "config.h"

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
#include "config_acl.h"
#include "server_error.h"
#include "process_class_ch.h"

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

#define CONFIG_TYPE config_data

CONFIG_BEGIN(config_main_desc)

CONFIG_FILE(     config_file                 , S_CONFIGDIR S_CONFIGFILE   )

/* Path to chroot, will be used if chroot is on */
CONFIG_CHROOT(   chroot_path                 , S_CHROOTPATH               )
/* Path to data which will be used for relative data */
CONFIG_PATH(     data_path                   , S_DATAPATH                 )
/* Path which will be used for relative logs   */
CONFIG_LOGPATH(  log_path                    , S_LOGPATH                  )
CONFIG_PATH(     xfr_path                    , S_XFRPATH                  )
/* Path to keys                                */
CONFIG_PATH(     keys_path                   , S_KEYSPATH                 )
/* PID file */
CONFIG_STRING(   pid_file                    , S_PIDFILE                  )
/* Switch for turning chroot, uid & gid off   */
CONFIG_FLAG16(   daemon                      , S_DAEMONRUN               , server_flags,  SERVER_FL_DAEMON              )
CONFIG_FLAG16(   chroot                      , S_CHROOT                  , server_flags,  SERVER_FL_CHROOT              )
#ifdef DEBUG
CONFIG_FLAG16(   log_unprocessable           , S_LOG_UNPROCESSABLE       , server_flags,  SERVER_FL_LOG_UNPROCESSABLE   )
#endif

CONFIG_FLAG16(   log_from_start              , S_LOG_FROM_START          , server_flags,  SERVER_FL_LOG_FROM_START      )
CONFIG_UID(      uid                         , S_UID                      )
CONFIG_GID(      gid                         , S_GID                      )

// Above settings probably cannot be changed at run time

// Below settings may be changed at runtime

 /* string used for query of version            */
CONFIG_STRING(   version_chaos               , S_VERSION_CHAOS            )
CONFIG_STRING(   hostname_chaos              , S_HOSTNAME_CHAOS           )
CONFIG_STRING(   serverid_chaos              , S_SERVERID_CHAOS           )
#if ZDB_HAS_ACL_SUPPORT
CONFIG_ACL(      allow_query                 , S_ALLOW_QUERY              )
CONFIG_ACL(      allow_update                , S_ALLOW_UPDATE             )
CONFIG_ACL(      allow_transfer              , S_ALLOW_TRANSFER           )
CONFIG_ACL(      allow_update_forwarding     , S_ALLOW_UPDATE_FORWARDING  )
CONFIG_ACL(      allow_notify                , S_ALLOW_NOTIFY             )
CONFIG_ACL(      allow_control               , S_ALLOW_CONTROL            )
#endif

/* Listening to interfaces                     */
CONFIG_HOST_LIST(listen                      , S_LISTEN                   )
/* size of an EDNS0 packet */
CONFIG_U32_RANGE(edns0_max_size              , S_EDNS0_MAX_SIZE          ,EDNS0_MIN_LENGTH, EDNS0_MAX_LENGTH )
// overrides the cpu detection
CONFIG_U32(      cpu_count_override          , S_CPU_COUNT_OVERRIDE       )
// how many threads by address (UDP)
CONFIG_U32(      thread_count_by_address     , S_THREAD_COUNT_BY_ADDRESS  )
// how many threads for the dnssec processing)
CONFIG_U32(      dnssec_thread_count         , S_DNSSEC_THREAD_COUNT      )
CONFIG_U32(      zone_load_thread_count      , S_ZONE_LOAD_THREAD_COUNT      )
CONFIG_U32(      zone_download_thread_count  , S_ZONE_DOWNLOAD_THREAD_COUNT  )
CONFIG_U32_RANGE(network_model               , S_NETWORK_MODEL, 0, 1      )

/* Max number of TCP queries  */
CONFIG_U32_RANGE(max_tcp_queries             , S_MAX_TCP_QUERIES          ,TCP_QUERIES_MIN, TCP_QUERIES_MAX)
CONFIG_U32(      tcp_query_min_rate          , S_TCP_QUERY_MIN_RATE       )
/* Ignores messages that would be answered by a FORMERR */ 
CONFIG_FLAG16(   answer_formerr_packets      , S_ANSWER_FORMERR_PACKETS  , server_flags,  SERVER_FL_ANSWER_FORMERR)
/* Listen to port (eg 53)                      */
CONFIG_STRING(   server_port                 , S_SERVERPORT               )
/* Switch for cache server or not              */

CONFIG_FLAG16(   statistics                  , S_STATISTICS              , server_flags,  SERVER_FL_STATISTICS) /* Maximum number of seconds between two statistics lines */

CONFIG_U32(      statistics_max_period       , S_STATISTICS_MAX_PERIOD    )
CONFIG_U32(      xfr_connect_timeout         , S_XFR_CONNECT_TIMEOUT      )
CONFIG_U32(      queries_log_type            , S_QUERIES_LOG_TYPE         )

#if HAS_DNSSEC_SUPPORT
CONFIG_U16(      sig_signing_type            , S_SIG_SIGNING_TYPE          )
CONFIG_U32_RANGE(sig_validity_interval       , S_SIG_VALIDITY_INTERVAL    , SIGNATURE_VALIDITY_INTERVAL_MIN     , SIGNATURE_VALIDITY_INTERVAL_MAX    ) /* 7 to 366 days = 30 */
CONFIG_U32_RANGE(sig_validity_regeneration   , S_SIG_VALIDITY_REGENERATION, SIGNATURE_VALIDITY_REGENERATION_MIN , SIGNATURE_VALIDITY_REGENERATION_MAX) /* 24 hours to 168 hours */
CONFIG_U32_RANGE(sig_validity_jitter         , S_SIG_VALIDITY_JITTER      , SIGNATURE_VALIDITY_JITTER_MIN       , SIGNATURE_VALIDITY_JITTER_MAX      ) /* 0 to 86400 = 3600*/
CONFIG_ALIAS(sig_jitter, sig_validity_jitter)
#endif

CONFIG_U32_RANGE(axfr_max_record_by_packet   , S_AXFR_MAX_RECORD_BY_PACKET , AXFR_RECORD_BY_PACKET_MIN , AXFR_RECORD_BY_PACKET_MAX )
CONFIG_U32_RANGE(axfr_max_packet_size        , S_AXFR_PACKET_SIZE_MAX      , AXFR_PACKET_SIZE_MIN      , AXFR_PACKET_SIZE_MAX      )
CONFIG_BOOL(axfr_compress_packets            , S_AXFR_COMPRESS_PACKETS    )
CONFIG_U32_RANGE(axfr_retry_delay            , S_AXFR_RETRY_DELAY          , AXFR_RETRY_DELAY_MIN      , AXFR_RETRY_DELAY_MAX      )
CONFIG_U32(      axfr_retry_jitter           , S_AXFR_RETRY_JITTER        )
CONFIG_U32_RANGE(axfr_retry_failure_delay_multiplier, S_AXFR_RETRY_FAILURE_DELAY_MULTIPLIER, AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MIN, AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX)
CONFIG_U32_RANGE(axfr_retry_failure_delay_max, S_AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX, AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX_MIN, AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX_MAX)
//CONFIG_U32_RANGE(multimaster_

          /* alias, aliased */
CONFIG_ALIAS(port, server_port)
CONFIG_ALIAS(version, version_chaos)
CONFIG_ALIAS(hostname, hostname_chaos)
CONFIG_ALIAS(serverid, serverid_chaos)
CONFIG_ALIAS(chrootpath, chroot_path)
//CONFIG_ALIAS(basepath, chroot_path)
CONFIG_ALIAS(configfile, config_file)
CONFIG_ALIAS(keyspath, keys_path)
CONFIG_ALIAS(datapath, data_path)
CONFIG_ALIAS(xfrpath, xfr_path)
CONFIG_ALIAS(logpath, log_path)
CONFIG_ALIAS(pidpath, pid_path)
CONFIG_ALIAS(pidfile, pid_file)
CONFIG_ALIAS(daemonize, daemon)

CONFIG_ALIAS(axfr_maxrecordbypacket, axfr_max_record_by_packet)
CONFIG_ALIAS(axfr_maxpacketsize, axfr_max_packet_size)
CONFIG_ALIAS(axfr_compresspackets, axfr_compress_packets)

CONFIG_ALIAS(xfr_maxrecordbypacket, axfr_max_record_by_packet)
CONFIG_ALIAS(xfr_maxpacketsize, axfr_max_packet_size)
CONFIG_ALIAS(xfr_compresspackets, axfr_compress_packets)
CONFIG_ALIAS(xfr_retry_delay, axfr_retry_delay)
CONFIG_ALIAS(xfr_retry_jitter, axfr_retry_jitter)
CONFIG_ALIAS(xfr_retry_failure_delay_multiplier, axfr_retry_failure_delay_multiplier)
CONFIG_ALIAS(xfr_retry_failure_delay_max, axfr_retry_failure_delay_max)

CONFIG_ALIAS(user, uid)
CONFIG_ALIAS(group, gid)
CONFIG_ALIAS(max_tcp_connections, max_tcp_queries)

CONFIG_END(config_main_desc)
#undef CONFIG_TYPE

static ya_result
config_main_verify_and_update_directory(const char *base_path, char **dirp)
{
    char fullpath[PATH_MAX];
    char tempfile[PATH_MAX];
    
    if(dirp == NULL)
    {
        return ERROR;
    }
    
    char *dir = *dirp;
    
    if(dir == NULL)
    {
        return ERROR;
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
        ttylog_err("error: '%s': %s", fullpath, strerror(errno));

        return ERROR;
    }

    if((ds.st_mode & S_IFMT) != S_IFDIR)
    {
        ttylog_err("error: '%s' is not a directory", dir);
        
        return ERROR;
    }
    
    snformat(tempfile, sizeof(tempfile), "%s/ydf.XXXXXX", fullpath);
    int tempfd;
    if((tempfd = mkstemp(tempfile)) < 0)
    {
        int return_code = ERRNO_ERROR;
        
        ttylog_err("error: '%s' is not writable: %r", fullpath, return_code);
        
        return return_code;
    }
    unlink(tempfile);
    close_ex(tempfd);
    
    free(dir);
    *dirp = strdup(fullpath);
    
    chroot_manage_path(dirp, fullpath, FALSE);
    
    return SUCCESS;
}

static ya_result
config_main_verify_and_update_file(const char *base_path, char **dirp)
{
    if(dirp == NULL)
    {
        return ERROR;
    }
    
    char *p = *dirp;
    
    if(p == NULL)
    {
        return ERROR;
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
            strncpy(filename, e, sizeof(filename));
            *e = '\0';
        }
        else
        {
            strncpy(filename, e, sizeof(filename));
            *e = '\0';
        }
        
        
        if(ISOK(config_main_verify_and_update_directory(base_path, dirp)))
        {        
            chroot_unmanage_path(dirp);
            int pathlen = strlen(*dirp);
            memmove(&filename[pathlen + 1], filename, strlen(filename) + 1);
            memcpy(filename, *dirp, pathlen);
            filename[pathlen] = '/';
            free(*dirp);
            *dirp = strdup(filename);
            chroot_manage_path(dirp, filename, FALSE);
            
            return SUCCESS;
        }
        
        return ERROR;
    }
    
    return SUCCESS;
}

static ya_result
config_main_section_postprocess(struct config_section_descriptor_s *csd)
{
    u32 port = 0;
    char tmp[PATH_MAX];



    if(FAIL(parse_u32_check_range(g_config->server_port, &port, 1, MAX_U16, 10)))
    {
        port = DNS_DEFAULT_PORT;
        ttylog_err("config: main: wrong dns port set in main '%s', defaulted to %d", g_config->server_port, port);
    }
    
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
    
    class_ch_set_hostname(g_config->hostname_chaos);    
    class_ch_set_id_server(g_config->serverid_chaos);
    class_ch_set_version(g_config->version_chaos);
    
    host_set_default_port_value(g_config->listen, ntohs(port));

    if(g_config->server_flags & SERVER_FL_CHROOT)
    {
        uid_t euid = geteuid();
        
        if(euid != 0)
        {
            ttylog_err("config: main: chroot has been enabled but euid is not root (%i != 0)", (int)euid);
            return ERROR;
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
    
    message_edns0_setmaxsize(g_config->edns0_max_size);    
    
    g_config->total_interfaces = host_address_count(g_config->listen);
    
    if(g_config->total_interfaces > MAX_INTERFACES)
    {
        ttylog_err("error: more than %d listening addresses defined.", MAX_INTERFACES);
        return ERROR;
    }

#ifndef SO_REUSEPORT
    if(g_config->network_model == 1)
    {
        ttylog_err("error: network-model 1 requires features not available on this system (SO_REUSEPORT)");
        return ERROR;
    }
#endif
    
    g_config->axfr_retry_jitter = BOUND(AXFR_RETRY_JITTER_MIN, g_config->axfr_retry_jitter, g_config->axfr_retry_delay);
    
    g_config->dnssec_thread_count = BOUND(1, g_config->dnssec_thread_count, sys_get_cpu_count());
    
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
        g_config->thread_count_by_address = sys_get_cpu_count();
    }
    else if((g_config->thread_count_by_address > sys_get_cpu_count()))
    {
        osformatln(termerr,"config: bounding down thread-count-by-address to the number of cpus (%d)", sys_get_cpu_count());
        g_config->thread_count_by_address = sys_get_cpu_count();
    }
    
    g_config->tcp_query_min_rate_us = g_config->tcp_query_min_rate * 0.000001;
    
#if HAS_DNSSEC_SUPPORT
    g_config->dnssec_thread_count = BOUND(1, g_config->dnssec_thread_count, sys_get_cpu_count());

    if(!IS_TYPE_PRIVATE(g_config->sig_signing_type))
    {
        ttylog_err("error: signing type is not in the accepted range: %hx", g_config->sig_signing_type);
        return CONFIG_WRONG_SIG_TYPE;
    }
    
    if(g_config->sig_validity_interval > SIGNATURE_VALIDITY_INTERVAL_MAX)
    {
        ttylog_err("error: signature validity interval too high");
        return CONFIG_WRONG_SIG_VALIDITY;
    }

    if(g_config->sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S * 2 > g_config->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S)
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
    
    const char *base_path = g_config->chroot_path;

    if(FAIL(config_main_verify_and_update_directory(base_path, &g_config->data_path)))
    {
        return ERROR;
    }
    
    if(FAIL(config_main_verify_and_update_directory(base_path, &g_config->keys_path)))
    {
        return ERROR;
    }
    
    if(FAIL(config_main_verify_and_update_directory(base_path, &g_config->log_path)))
    {
        return ERROR;
    }
#if 0 /* fix */
#else
    if(FAIL(config_main_verify_and_update_file(base_path, &g_config->pid_file)))
    {
        return ERROR;
    }
#endif
    
    g_config->reloadable = TRUE;
    
    if((g_config->server_flags & SERVER_FL_CHROOT) != 0)
    {
        if(FAIL(chroot_manage_path(&g_config->config_file, g_config->config_file, FALSE)))
        {
            log_warn("config file '%s' will not be accessible within the chroot jail '%s' : config reload will not work", g_config->config_file, base_path);
            g_config->reloadable = FALSE;
        }
    }
    
    if(FAIL(config_main_verify_and_update_directory(base_path, &g_config->xfr_path)))
    {
        return ERROR;
    }
    
#if ZDB_HAS_DNSSEC_SUPPORT
    dnssec_keystore_setpath(g_config->keys_path);
    dnssec_set_xfr_path(g_config->xfr_path);
    journal_set_xfr_path(g_config->xfr_path);
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
    MALLOC_OR_DIE(config_data*, g_config, sizeof(config_data), YGCONFIG_TAG);
    ZEROMEMORY(g_config, sizeof(config_data));
    
    g_config->gid = getgid();
    g_config->uid = getuid();

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

/** @} */
