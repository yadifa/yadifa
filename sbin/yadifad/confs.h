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
/*----------------------------------------------------------------------------*/
#ifndef CONFS_H_
#define CONFS_H_

#ifdef __cplusplus
extern "C" {
#endif

    /*    ------------------------------------------------------------    */

#include <string.h>
#include <errno.h>
#include <stddef.h>

#include "server-config.h"

#include <dnscore/rfc.h>
#include <dnscore/ptr_set.h>
#include <dnscore/acl.h>
#include <dnscore/dnscore-release-date.h>
#include <dnsdb/zdb_types.h>

    /*    ------------------------------------------------------------    */

#define     PREPROCESSOR_INT2STR(x) #x

#define     THREAD_POOL_SIZE_MAX        255 /* 8 bits ! */
#define     TCP_QUERIES_MIN             0
#define     TCP_QUERIES_MAX             255
#define     AXFR_PACKET_SIZE_MIN        512
#define     AXFR_PACKET_SIZE_MAX        65535
#define     AXFR_RECORD_BY_PACKET_MIN   0
#define     AXFR_RECORD_BY_PACKET_MAX   65535
#define     AXFR_RETRY_DELAY_MIN        60
#define     AXFR_RETRY_DELAY_MAX        86400
#define     AXFR_RETRY_JITTER_MIN       60
#define     AXFR_RETRY_JITTER_MAX       "don't use me, use the axfr_retry_delay value instead"
    
#define     MAX_CONFIG_STRING           50
#define     PRINTARGLEN                 10

#define     PROGRAM_NAME                "yadifad"
#define     PROGRAM_VERSION             PACKAGE_VERSION
#define     RELEASEDATE                 YADIFA_DNSCORE_RELEASE_DATE

    /* List of default values for the different configuration parameters */
#define     S_CONFIGDIR                 SYSCONFDIR "/"
#define     S_CONFIGFILE                PROGRAM_NAME ".conf"
#define     S_CONFIGFILEDYNAMIC         PROGRAM_NAME ".conf.dyn"
#define     S_DATAPATH                  LOCALSTATEDIR "/zones/"
#define     S_XFRPATH                   LOCALSTATEDIR "/zones/xfr/"
#define     S_KEYSPATH                  LOCALSTATEDIR "/zones/keys/"        /** Keys should not be in "shared" */
#define     S_LOGPATH                   LOGDIR
#define     S_PIDFILE                   LOCALSTATEDIR "/run/" PROGRAM_NAME ".pid" /// @TODO 20200623 edf -- use RUNSTATEDIR instead

#define     S_VERSION_CHAOS             PACKAGE_VERSION                  /* limit the size */ 
#define     S_HOSTNAME_CHAOS            NULL
#define     S_SERVERID_CHAOS            NULL

#define     S_DEBUGLEVEL                "0"

    /* default values for SERVER_FL */
#define     S_SYSLOG                    "0"
#define     S_STATISTICS                "1"
#define     S_STATISTICS_MAX_PERIOD     "60" /* 1 -> 31 * 86400 */
#define     S_DAEMONRUN                 "0"
#define     S_ANSWER_FORMERR_PACKETS    "1"
#define     S_DYNAMIC_PROVISIONING      "0"

    /** \def S_RUNMODE
     *       Run mode of the program */
#define     S_RUNMODE                   RUNMODE_CONTINUE_CLEAN
    
#define     S_NETWORK_MODEL             "2"
#define     S_INTERACTIVE               "0"
#define     S_LOG_FROM_START            "0"
#define     S_LOG_FILES_DISABLED        "0"

    /* */
#define     S_CPU_COUNT_OVERRIDE        "0" /* max 256 */
#define     S_THREAD_COUNT_BY_ADDRESS   "-1" /* -1 for auto */
#define     S_DNSSEC_THREAD_COUNT       "0" /* max 1024 */

#define     S_ZONE_LOAD_THREAD_COUNT    "1"     // disk
#define     ZONE_LOAD_THREAD_COUNT_MIN 1
#define     ZONE_LOAD_THREAD_COUNT_MAX 4
    
#define     S_ZONE_SAVE_THREAD_COUNT    "1"     // disk
#define     ZONE_SAVE_THREAD_COUNT_MIN 1
#define     ZONE_SAVE_THREAD_COUNT_MAX 4

#define     S_ZONE_UNLOAD_THREAD_COUNT    "1"     // cpu
#define     ZONE_UNLOAD_THREAD_COUNT_MIN 1
#define     ZONE_UNLOAD_THREAD_COUNT_MAX 4

#define     S_ZONE_DOWNLOAD_THREAD_COUNT "4"    // network
#define     ZONE_DOWNLOAD_THREAD_COUNT_MIN 1
#define     ZONE_DOWNLOAD_THREAD_COUNT_MAX 16
    
    /* Chroot, uid and gid */
#define     S_CHROOT                    "0"
#define     S_LOG_UNPROCESSABLE         "0"
#define     S_CHROOTPATH                "/"
#define     S_UID                       "0"
#define     S_GID                       "0"

    /** \def S_LISTEN
     *       Listening to all interfaces */
#define     S_LISTEN                    "0.0.0.0;::0"

#if HAS_SYSTEMD_RESOLVED_AVOIDANCE
#define     S_DO_NOT_LISTEN             "127.0.0.53 port 53"
#else
#define     S_DO_NOT_LISTEN             ""
#endif
    
#define     MAX_INTERFACES              256
    
#define     S_TOTALINTERFACES           1
#define     S_MAX_TCP_QUERIES           "128"   /* max 255 */
#define     S_MAX_SECONDARY_TCP_QUERIES "16"
#define     S_TCP_QUERY_MIN_RATE        "512"   /* bytes per second minimum rate */
    
#define     S_TCP_QUEUE_SIZE            "1024"
#define     S_TCP_QUEUE_SIZE_MIN        64
#define     S_TCP_QUEUE_SIZE_MAX        65536

#define     S_MAX_AXFR                  "10"

#define     S_AXFR_MAX_RECORD_BY_PACKET "0"    /** No limit.  Old applications can only work with this set to 1 */
#define     S_AXFR_PACKET_SIZE_MAX      "4096" /** plus TSIG */
#define     S_AXFR_COMPRESS_PACKETS     "1"
#define     S_AXFR_RETRY_DELAY          "600"
#define     S_AXFR_RETRY_JITTER         "180"

#if HAS_NON_AA_AXFR_SUPPORT
#define     S_AXFR_STRICT_AUTHORITY     "0"
#else
#define     S_AXFR_STRICT_AUTHORITY     "1"
#endif

#define     S_AXFR_RETRY_FAILURE_DELAY_MULTIPLIER "5"
#define     AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MIN 0
#define     AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX 86400
    
#define     S_AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX "3600"
#define     AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX_MIN 0
#define     AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX_MAX 604800

#define     S_SERVER_RW_BACKLOG_QUEUE_SIZE   "16384"
#define     SERVER_RW_BACKLOG_QUEUE_SIZE_MIN 0x001000
#define     SERVER_RW_BACKLOG_QUEUE_SIZE_MAX 0x100000

#define     S_XFR_CONNECT_TIMEOUT       "5"    /* seconds */
    
#define     S_QUERIES_LOG_TYPE          "1"    /* 0: none, 1: YADIFA, 2: bind 3:both */

#define     S_ALLOW_QUERY               "any"
#define     S_ALLOW_UPDATE              "none"
#define     S_ALLOW_TRANSFER            "none"
#define     S_ALLOW_UPDATE_FORWARDING   "none"
#define     S_ALLOW_NOTIFY              "any"
#define     S_ALLOW_CONTROL             "none"

    /** \def S_SERVERPORT
     *       Standard port for listening udp and tcp */
#define     S_SERVERPORT                "53" /* PREPROCESSOR_INT2STR(DNS_DEFAULT_PORT) */
#define     S_TRANSFER_SOURCE           "0.0.0.0"

    /* IP FLAGS */
#define     S_IPV4                      "1"
#define     S_IPV6                      "1"

    /* QUERIES FLAGS */
#define     S_ADDITIONAL_AUTH           "1"
#define     S_AUTHORITY_AUTH            "1"
#define     S_ADDITIONAL_CACHE          "1"
#define     S_AUTHORITY_CACHE           "1"
#define     S_EDNS0                     "1"
#define     S_EDNS0_MAX_SIZE            "4096"
#define     S_RECURSION                 "1"

#define     S_S32_VALUE_NOT_SET         NULL
#define     S_SIG_VALIDITY_INTERVAL     "30"            /* 30 days in days           */
#define     S_SIG_VALIDITY_REGENERATION "168"           /*  7 days in hours  24->168 */
#define     S_SIG_VALIDITY_JITTER       "3600"          /*  1 hour in seconds        */
#define     S_SIG_SIGNING_TYPE          "65534"
    
#define     S_NOTIFY_RETRY_COUNT           "5"          /* 5 retries */
#define     S_NOTIFY_RETRY_PERIOD          "1"          /* first after 1 minute */
#define     S_NOTIFY_RETRY_PERIOD_INCREASE "0"          /* period increased by "0" after every try */

#define     S_ZONE_NOTIFY_AUTO           "1"
#define     S_ZONE_FLAG_DROP_BEFORE_LOAD "0"
#define     S_ZONE_NO_MASTER_UPDATES     "0"
#define     S_ZONE_FLAG_MAINTAIN_DNSSEC  "1"
#define     S_ZONE_FLAG_TRUE_MULTIMASTER "0"
#define     S_ZONE_FLAG_RRSIG_NSUPDATE_ALLOWED "0"
    
#define     S_MULTIMASTER_RETRIES       "0"             // in a multimaster setup, how many retries before changing master
                                                        // 0 is perfectly fine except in true-multimaster mode where the resource cost
                                                        // asks for some caution.  In that case 60 would be a good choice. Maximum is 255
#define     S_ZONE_DNSSEC_DNSSEC        "off"
    
#define     S_JOURNAL_SIZE_KB_DEFAULT   "0"             // 0 means "automatic"
#define     S_JOURNAL_SIZE_KB_MIN       0               // less than 64KB is asking for trouble (0 means "automatic")
#define     S_JOURNAL_SIZE_KB_MAX       3698688         // 3GB

    /*    ------------------------------------------------------------    */

    /* List of cases for adjusting the keys configuration parameters */
#define     KC_NAME                     1
#define     KC_ALGORITHM                2
#define     KC_SECRET                   3

    /* List of cases for adjusting the control configuration parameters */
#define     CC_NET                      1
#define     CC_KEYS                     2

#define     CONTAINER_MAIN              1
#define     CONTAINER_ZONE              2
#define     CONTAINER_CHANNELS          3
#define     CONTAINER_LOGGERS           4
#define     CONTAINER_KEYS              5
#define     CONTAINER_CONTROL           6

    /* Run modes of the program,
     * only RUNMODE_DAEMON can be asked via the configuration file
     */
#define     RUNMODE_FLAG                0x0F
    /* Only one of these can be active */
#define     RUNMODE_EXIT_CLEAN          0x01
#define     RUNMODE_CONTINUE_CLEAN      0x02    /* normal mode                           */
#define     RUNMODE_DAEMON              0x03    /* daemon mode                           */
#define     RUNMODE_INTERACTIVE         0x04    /* interactive mode                      */

#define     RUNMODE_SWITCH_FLAG         0xF0

    /* Server flags */
#define     SERVER_FL_CHROOT            0x01
#define     SERVER_FL_DAEMON            0x02
#define     SERVER_FL_STATISTICS        0x04
#define     SERVER_FL_ANSWER_FORMERR    0x08
#define     SERVER_FL_LOG_UNPROCESSABLE 0x10
#define     SERVER_FL_INTERACTIVE       0x20   
#define     SERVER_FL_DYNAMIC_PROVISIONING 0x40
#define     SERVER_FL_LOG_FROM_START    0x8000
#define     SERVER_FL_LOG_FILE_DISABLED 0x4000

    /* IP flags */
#define     IP_FLAGS_IPV4               0x01
#define     IP_FLAGS_IPV6               0x02

#if 0 /* fix */
#else
#define     SIGNATURE_VALIDITY_INTERVAL_MIN     7       /* 7  days */
#endif
#define     SIGNATURE_VALIDITY_INTERVAL_MAX     366     /* 366 days */
#define     SIGNATURE_VALIDITY_INTERVAL_S       86400   /* seconds for that unit */

#if 0 /* fix */
#else
#define     SIGNATURE_VALIDITY_REGENERATION_MIN 24      /* 1 day  */
#endif
#define     SIGNATURE_VALIDITY_REGENERATION_MAX 168     /* 7 days */
#define     SIGNATURE_VALIDITY_REGENERATION_S   3600    /* seconds for that unit */
    
#define     SIGNATURE_VALIDITY_JITTER_MIN       0
#define     SIGNATURE_VALIDITY_JITTER_MAX       86400
#define     SIGNATURE_VALIDITY_JITTER_S         1       /* seconds for that unit */
    
#define     NOTIFY_RETRY_COUNT_MIN              0
#define     NOTIFY_RETRY_COUNT_MAX              10
    
#define     NOTIFY_RETRY_PERIOD_MIN             1
#define     NOTIFY_RETRY_PERIOD_MAX             600
    
#define     NOTIFY_RETRY_PERIOD_INCREASE_MIN    0
#define     NOTIFY_RETRY_PERIOD_INCREASE_MAX    600

/*    ------------------------------------------------------------    */

typedef struct udp udp;
struct udp
{
    struct addrinfo *addr;
    int sockfd;
};

typedef struct tcp tcp;
struct tcp
{
    struct addrinfo *addr;
    int sockfd;
};

#ifdef WIN32
#ifdef interface
#undef interface
#endif
#endif // WIN32

typedef struct interface interface;
struct interface
{
    udp   udp;
    tcp   tcp;
};

typedef struct scheduler scheduler;
struct scheduler
{
    int sockfd;
};

#define CONFIG_READER_CONTEXT_MAX_DEPTH 128

typedef struct config_reader_context config_reader_context;

struct config_reader_context
{
    s32 top;        // -1
    bool dynamic;
    FILE* data[CONFIG_READER_CONTEXT_MAX_DEPTH];
    char* file_name[CONFIG_READER_CONTEXT_MAX_DEPTH];
};

/** \struct config_data
 *          Struct with the configuration data. This data can be the default
 *          data, data from a configuration file, or data as arguments on
 *          the command line
 */
typedef struct config_data config_data;

#define YGCONFIG_TAG 0x4749464e4f434759

#define CONFIG_SIGNATURE_TYPE_CONFIGURABLE 0

struct config_data
{
    // Which are the interfaces to listen to
    host_address                                                *listen;
    // Which are the interfaces to not listen to
    host_address                                         *do_not_listen;
    // List of hosts registered by the TCP manager
    host_address                                           *known_hosts;

    /* General variables */
    char                                                     *data_path; /* zones */
    char                                                      *xfr_path; /* full and incremental images base ... */
#ifndef WIN32
    char                                                   *chroot_path; /* chroot point */
#endif
    char                                                      *log_path; /* log files */
    char                                                     *keys_path; /* keys */
    char                                                   *config_file; /* config */

    char                                                      *pid_file; /* pid file path and name */

    char                                                 *version_chaos;
    char                                                *hostname_chaos;
    char                                                *serverid_chaos;
    char                                                   *server_port;
    
#if HAS_EVENT_DYNAMIC_MODULE
    ptr_vector                                          dynamic_modules;
#endif

    pid_t                                                           pid;

    /* Server variables */

    u16                                                    server_flags;

    int                                                total_interfaces;
    int                                              cpu_count_override;
    s32                                         thread_count_by_address;
    int                                            thread_affinity_base;
    int                                      thread_affinity_multiplier;
#if DATABASE_ZONE_RRSIG_THREAD_POOL
    int                                             dnssec_thread_count;
#endif
    int                                          zone_load_thread_count;
    int                                         zone_store_thread_count;
    int                                        zone_unload_thread_count;
    int                                      zone_download_thread_count;
    int                                                 max_tcp_queries;
    int                                       max_secondary_tcp_queries;
    int                                              tcp_query_min_rate;
    int                                                  tcp_queue_size;
    int                                       axfr_max_record_by_packet;
    int                                            axfr_max_packet_size;
    int                                                axfr_retry_delay;
    int                                               axfr_retry_jitter;
    u32                             axfr_retry_failure_delay_multiplier;
    u32                                    axfr_retry_failure_delay_max;
    int                                             xfr_connect_timeout;
    u32                                           statistics_max_period;
    int                                                  edns0_max_size;
    int                                                   network_model; // 0: default MT, 1: experimental RqW
    u32                                       worker_backlog_queue_size;
    bool                                          axfr_compress_packets;
    bool                                          axfr_strict_authority; // if the AA bit isn't set, AXFR is rejected

    /**/

    access_control                                                  *ac;

    /**/

    gid_t                                                           gid;
    uid_t                                                           uid;

    u16                                                   process_flags;
    u16                                               server_port_value;

    //u8                                                               ip;

    /*
     * The pid of the only child (a.k.a the server)
     */

    zdb                                                         *database;

    u32                                                  queries_log_type;

#if HAS_DNSSEC_SUPPORT
    u32                                             sig_validity_interval;
    u32                                         sig_validity_regeneration;
    u32                                               sig_validity_jitter;
#if CONFIG_SIGNATURE_TYPE_CONFIGURABLE
    u16                                                  sig_signing_type;
#endif
#endif

    double                                          tcp_query_min_rate_us;

    bool                                                         chrooted;
    bool                                                       reloadable;

    bool                                                    hidden_master;

    bool                                                   check_policies;
};

/**
 * zone_desc filter callback,
 * The second argument is the proprietary data passed to the
 * 
 * Must return 1 for accept, 0 for reject, or an error code.
 * 
 */

struct zone_desc_s;
typedef struct zone_desc_s zone_desc_s;

typedef ya_result config_section_zone_filter_callback(zone_desc_s *, void *);

#ifndef CONFS_MAIN_C_

extern config_data                         *g_config;

#endif


/**
 * @brief Tool function printing all the known names in a table.
 */

/*    ------------------------------------------------------------    */

void config_logger_setdefault();
void config_logger_cleardefault();

/*    ------------------------------------------------------------    */

ya_result yadifad_config_init();
ya_result yadifad_config_cmdline(int argc, char **argv);
ya_result yadifad_config_read(const char *config_file);
ya_result yadifad_config_finalize();

ya_result yadifad_config_update(const char *config_file);

ya_result yadifad_config_update_zone(const char *config_file, const ptr_set *fqdn);

void yadifad_print_usage(const char *name);

/*    ------------------------------------------------------------    */

ya_result confs_set_dnssec(const char *value, u32 *dest, anytype notused);

void config_zone_print(zone_desc_s *zone_desc, output_stream *os);

/**
 * 
 * Enables a callback filter that is called before pushing a zone_desc to the database service.
 * 
 * @param cb a callback function or NULL to reset to the "accept all" filter.
 * @param params a pointer that will be passed to the callback
 */

void config_section_zone_set_filter(config_section_zone_filter_callback *cb, void *params);

bool config_check_bounds_s32(s32 minval, s32 maxval, s32 val, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* CONFS_H_ */

/** @} */
