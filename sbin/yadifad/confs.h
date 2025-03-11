/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup config Configuration handling
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef CONFS_H_
#define CONFS_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*    ------------------------------------------------------------    */

#include <string.h>
#include <errno.h>
#include <stddef.h>

#include "server_config.h"

#include <dnscore/rfc.h>
#include <dnscore/ptr_treemap.h>
#include <dnscore/acl.h>
#include <dnscore/dnscore_release_date.h>
#include <dnsdb/zdb_types.h>

/*    ------------------------------------------------------------    */

#define PREPROCESSOR_INT2STR(x)   #x

#define TCP_QUERIES_MIN           0
#define TCP_QUERIES_MAX           0x20000
#define AXFR_PACKET_SIZE_MIN      512
#define AXFR_PACKET_SIZE_MAX      65535
#define AXFR_RECORD_BY_PACKET_MIN 0
#define AXFR_RECORD_BY_PACKET_MAX 65535
#define AXFR_RETRY_DELAY_MIN      60
#define AXFR_RETRY_DELAY_MAX      86400
#define AXFR_RETRY_JITTER_MIN     60
#define AXFR_RETRY_JITTER_MAX     "don't use me, use the axfr_retry_delay value instead"

#define CONFIG_STRING_MAX         50
#define PRINTARGLEN               10

#define PROGRAM_NAME              "yadifad"
#define PROGRAM_VERSION           PACKAGE_VERSION
#define RELEASEDATE               YADIFA_DNSCORE_RELEASE_DATE

#ifndef RUNSTATEDIR
#define RUNSTATEDIR LOCALSTATEDIR "/run"
#endif

/* List of default values for the different configuration parameters */
#define S_CONFIGDIR              SYSCONFDIR "/"
#define S_CONFIGFILE             PROGRAM_NAME ".conf"
#define S_CONFIGFILEDYNAMIC      PROGRAM_NAME ".conf.dyn"
#define S_DATAPATH               LOCALSTATEDIR "/zones/"
#define S_XFRPATH                LOCALSTATEDIR "/zones/xfr/"
#define S_KEYSPATH               LOCALSTATEDIR "/zones/keys/" /** Keys should not be in "shared" */
#define S_LOGPATH                LOGDIR
#define S_PIDFILE                RUNSTATEDIR "/" PROGRAM_NAME ".pid"

#define S_VERSION_CHAOS          PACKAGE_VERSION /* limit the size */
#define S_HOSTNAME_CHAOS         NULL
#define S_SERVERID_CHAOS         NULL

#define S_DEBUGLEVEL             "0"

/* default values for SERVER_FL */
#define S_SYSLOG                 "0"
#define S_STATISTICS             "1"
#define S_STATISTICS_MAX_PERIOD  "60" /* 1 -> 31 * 86400 */
#define S_DAEMONRUN              "0"
#define S_ANSWER_FORMERR_PACKETS "1"
#define S_DYNAMIC_PROVISIONING   "0"

/** \def S_RUNMODE
 *       Run mode of the program */
#define S_RUNMODE                RUNMODE_CONTINUE_CLEAN

#if !__FreeBSD__
#define S_NETWORK_MODEL "2"
#else
#define S_NETWORK_MODEL "0"
#endif

#define S_INTERACTIVE                  "0"
#define S_LOG_FROM_START               "0"
#define S_LOG_FILES_DISABLED           "0"

/* */
#define S_CPU_COUNT_OVERRIDE           "0"  /* max 256 */
#define S_THREAD_COUNT_BY_ADDRESS      "-1" /* -1 for auto */
#define S_DNSSEC_THREAD_COUNT          "0"  /* max 1024 */

#define S_ZONE_LOAD_THREAD_COUNT       "1" // disk
#define ZONE_LOAD_THREAD_COUNT_MIN     1
#define ZONE_LOAD_THREAD_COUNT_MAX     256

#define S_ZONE_SAVE_THREAD_COUNT       "1" // disk
#define ZONE_SAVE_THREAD_COUNT_MIN     1
#define ZONE_SAVE_THREAD_COUNT_MAX     256

#define S_ZONE_UNLOAD_THREAD_COUNT     "1" // cpu
#define ZONE_UNLOAD_THREAD_COUNT_MIN   1
#define ZONE_UNLOAD_THREAD_COUNT_MAX   256

#define S_ZONE_DOWNLOAD_THREAD_COUNT   "4" // network
#define ZONE_DOWNLOAD_THREAD_COUNT_MIN 1
#define ZONE_DOWNLOAD_THREAD_COUNT_MAX 256

/* Chroot, uid and gid */
#define S_CHROOT                       "0"
#define S_LOG_UNPROCESSABLE            "0"
#define S_CHROOTPATH                   "/"
#define S_UID                          "0"
#define S_GID                          "0"

/** \def S_LISTEN
 *       Listening to all interfaces */
#define S_LISTEN                       "0.0.0.0;::0"

#define S_TRANSFER_SOURCE              NULL

#if HAS_SYSTEMD_RESOLVED_AVOIDANCE
#define S_DO_NOT_LISTEN "127.0.0.53 port 53"
#else
#define S_DO_NOT_LISTEN ""
#endif

#define NETWORK_INTERFACES_MAX        256

#define S_TOTALINTERFACES             1
#define S_MAX_TCP_QUERIES             "512" /* max : 65536 */
#define S_MAX_TCP_QUERIES_PER_ADDRESS "2"
#define S_MAX_SECONDARY_TCP_QUERIES   "128"
#define S_TCP_QUERY_MIN_RATE          "512" /* bytes per second minimum rate */

#define S_TCP_QUEUE_SIZE              "1024"
#define S_TCP_QUEUE_SIZE_MIN          64
#define S_TCP_QUEUE_SIZE_MAX          65536

#define S_MAX_AXFR                    "10"

#define S_AXFR_MAX_RECORD_BY_PACKET   "0"    /** No limit.  Old applications can only work with this set to 1 */
#define S_AXFR_PACKET_SIZE_MAX        "4096" /** plus TSIG */
#define S_AXFR_COMPRESS_PACKETS       "1"
#define S_AXFR_RETRY_DELAY            "600" // 10 minutes
#define S_AXFR_RETRY_JITTER           "180" // 3 minutes
#define S_AXFR_MEMORY_THREHOLD        "65536"
#define AXFR_MEMORY_THREHOLD_MIN      0x00000000 // 0MB
#define AXFR_MEMORY_THREHOLD_MAX      0x00100000 // 1MB

#if HAS_NON_AA_AXFR_SUPPORT
#define S_AXFR_STRICT_AUTHORITY "0"
#else
#define S_AXFR_STRICT_AUTHORITY "1"
#endif

#define S_AXFR_RETRY_FAILURE_DELAY_MULTIPLIER       "5"
#define AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MIN     0
#define AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX     86400

#define S_AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX   "3600"
#define AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX_MIN 0
#define AXFR_RETRY_FAILURE_DELAY_MULTIPLIER_MAX_MAX 604800

#define S_SERVER_RW_BACKLOG_QUEUE_SIZE              "16384"
#define SERVER_RW_BACKLOG_QUEUE_SIZE_MIN            0x001000
#define SERVER_RW_BACKLOG_QUEUE_SIZE_MAX            0x100000

#define S_XFR_CONNECT_TIMEOUT                       "5" /* seconds */

#define S_QUERIES_LOG_TYPE                          "1" /* 0: none, 1: YADIFA, 2: bind 3:both */

#define S_ALLOW_QUERY                               "any"
#define S_ALLOW_UPDATE                              "none"
#define S_ALLOW_TRANSFER                            "none"
#define S_ALLOW_UPDATE_FORWARDING                   "none"
#define S_ALLOW_NOTIFY                              "any"
#define S_ALLOW_CONTROL                             "none"

/** \def S_SERVERPORT
 *       Standard port for listening udp and tcp */
#define S_SERVERPORT                                "53"  /* PREPROCESSOR_INT2STR(DNS_DEFAULT_PORT) */
#define S_SERVERTLSPORT                             "853" /* PREPROCESSOR_INT2STR(DNS_DEFAULT_TLS_PORT) */

/* IP FLAGS */
#define S_IPV4                                      "1"
#define S_IPV6                                      "1"

/* QUERIES FLAGS */
#define S_ADDITIONAL_AUTH                           "1"
#define S_AUTHORITY_AUTH                            "1"
#define S_ADDITIONAL_CACHE                          "1"
#define S_AUTHORITY_CACHE                           "1"
#define S_EDNS0                                     "1"
#define S_EDNS0_MAX_SIZE                            "4096"
#define S_RECURSION                                 "1"

#define S_S32_VALUE_NOT_SET                         NULL
#define S_SIG_VALIDITY_INTERVAL                     "30"   /* 30 days in days           */
#define S_SIG_VALIDITY_REGENERATION                 "168"  /*  7 days in hours  24->168 */
#define S_SIG_VALIDITY_JITTER                       "3600" /*  1 hour in seconds        */
#define S_SIG_SIGNING_TYPE                          "65534"

#define S_NOTIFY_RETRY_COUNT                        "5" /* 5 retries */
#define S_NOTIFY_RETRY_PERIOD                       "1" /* first after 1 minute */
#define S_NOTIFY_RETRY_PERIOD_INCREASE              "0" /* period increased by "0" after every try */

#define S_ZONE_NOTIFY_AUTO                          "1"
#define S_ZONE_FLAG_DROP_BEFORE_LOAD                "0"
#define S_ZONE_NO_PRIMARY_UPDATES                   "0"
#define S_ZONE_FLAG_FULL_ZONE_TRANSFER_ONLY         "0"
#define S_ZONE_FLAG_MAINTAIN_DNSSEC                 "1"
#define S_ZONE_FLAG_TRUE_MULTIPRIMARY               "0"
#define S_ZONE_FLAG_RRSIG_NSUPDATE_ALLOWED          "0"

#define S_MULTIPRIMARY_RETRIES                                                                                                                                                                                                                 \
    "0" // in a multiprimary setup, how many retries before changing primary
        // 0 is perfectly fine except in true-multiprimary mode where the resource cost
        // asks for some caution.  In that case 60 would be a good choice. Maximum is 255
#define S_ZONE_DNSSEC_DNSSEC                "off"

#define S_JOURNAL_SIZE_KB_DEFAULT           "0"     // 0 means "automatic"
#define S_JOURNAL_SIZE_KB_MIN               0       // less than 64KB is asking for trouble (0 means "automatic")
#define S_JOURNAL_SIZE_KB_MAX               3698688 // 3GB

/*    ------------------------------------------------------------    */

/* List of cases for adjusting the keys configuration parameters */
#define KC_NAME                             1
#define KC_ALGORITHM                        2
#define KC_SECRET                           3

/* List of cases for adjusting the control configuration parameters */
#define CC_NET                              1
#define CC_KEYS                             2

#define CONTAINER_MAIN                      1
#define CONTAINER_ZONE                      2
#define CONTAINER_CHANNELS                  3
#define CONTAINER_LOGGERS                   4
#define CONTAINER_KEYS                      5
#define CONTAINER_CONTROL                   6

/* Run modes of the program,
 * only RUNMODE_DAEMON can be asked via the configuration file
 */
#define RUNMODE_FLAG                        0x0F
/* Only one of these can be active */
#define RUNMODE_EXIT_CLEAN                  0x01
#define RUNMODE_CONTINUE_CLEAN              0x02 /* normal mode                           */
#define RUNMODE_DAEMON                      0x03 /* daemon mode                           */
#define RUNMODE_INTERACTIVE                 0x04 /* interactive mode                      */

#define RUNMODE_SWITCH_FLAG                 0xF0

/* Server flags */
#define SERVER_FL_CHROOT                    0x0001
#define SERVER_FL_DAEMON                    0x0002
#define SERVER_FL_STATISTICS                0x0004
#define SERVER_FL_ANSWER_FORMERR            0x0008
#define SERVER_FL_LOG_UNPROCESSABLE         0x0010
#define SERVER_FL_INTERACTIVE               0x0020
#define SERVER_FL_DYNAMIC_PROVISIONING      0x0040
#define SERVER_FL_ENABLE_TLS                0x0080
#define SERVER_FL_LOG_FILE_DISABLED         0x4000
#define SERVER_FL_LOG_FROM_START            0x8000

/* IP flags */
#define IP_FLAGS_IPV4                       0x01
#define IP_FLAGS_IPV6                       0x02

#define SIGNATURE_VALIDITY_INTERVAL_MIN     7     /* 7  days */
#define SIGNATURE_VALIDITY_INTERVAL_MAX     366   /* 366 days */
#define SIGNATURE_VALIDITY_INTERVAL_S       86400 /* seconds for that unit */

#define SIGNATURE_VALIDITY_REGENERATION_MIN 24   /* 1 day  */
#define SIGNATURE_VALIDITY_REGENERATION_MAX 168  /* 7 days */
#define SIGNATURE_VALIDITY_REGENERATION_S   3600 /* seconds for that unit */

#define SIGNATURE_VALIDITY_JITTER_MIN       0
#define SIGNATURE_VALIDITY_JITTER_MAX       86400
#define SIGNATURE_VALIDITY_JITTER_S         1 /* seconds for that unit */

#define NOTIFY_RETRY_COUNT_MIN              0
#define NOTIFY_RETRY_COUNT_MAX              10

#define NOTIFY_RETRY_PERIOD_MIN             1
#define NOTIFY_RETRY_PERIOD_MAX             600

#define NOTIFY_RETRY_PERIOD_INCREASE_MIN    0
#define NOTIFY_RETRY_PERIOD_INCREASE_MAX    600

/*    ------------------------------------------------------------    */

#define CONFIG_READER_CONTEXT_DEPTH_MAX     128

struct config_reader_context_s
{
    int32_t top; // -1
    bool    dynamic;
    FILE   *data[CONFIG_READER_CONTEXT_DEPTH_MAX];
    char   *file_name[CONFIG_READER_CONTEXT_DEPTH_MAX];
};

typedef struct config_reader_context_s config_reader_context_t;

/** \struct config_data
 *          Struct with the configuration data. This data can be the default
 *          data, data from a configuration file, or data as arguments on
 *          the command line
 */
typedef struct yadifad_config_main_s yadifad_config_main_t;

#define YGCONFIG_TAG                       0x4749464e4f434759

#define CONFIG_SIGNATURE_TYPE_CONFIGURABLE 0

struct yadifad_config_main_s
{
    // Which are the interfaces to listen to
    host_address_t *listen;
    // Which are the interfaces to not listen to
    host_address_t *do_not_listen;
    // List of hosts registered by the TCP manager
    host_address_t *known_hosts;
    // List of hosts for default transfer sources, can be empty
    host_address_t *transfer_source;

    /* General variables */
    char *data_path; /* zones */
    char *xfr_path;  /* full and incremental images base ... */
#if __unix__
    char *chroot_path; /* chroot point */
#endif
    char *log_path;    /* log files */
    char *keys_path;   /* keys */
    char *config_file; /* config */

    char *pid_file; /* pid file path and name */

    char *tls_cert;
    char *tls_key;
    char *tls_ciphers;

    char *version_chaos;
    char *hostname_chaos;
    char *serverid_chaos;
    char *server_port;
    char *server_tls_port;

#if HAS_EVENT_DYNAMIC_MODULE
    ptr_vector_t dynamic_modules;
#endif

    pid_t pid;

    /* Server variables */

    uint16_t server_flags;

    int      total_interfaces;
    int      cpu_count_override;
    int32_t  thread_count_by_address;
    int      thread_affinity_base;
    int      thread_affinity_multiplier;
#if DATABASE_ZONE_RRSIG_THREAD_POOL
    int dnssec_thread_count;
#endif
    int      zone_load_thread_count;
    int      zone_store_thread_count;
    int      zone_unload_thread_count;
    int      zone_download_thread_count;
    int      max_tcp_queries;
    int      max_tcp_queries_per_address;
    int      max_secondary_tcp_queries;
    int      tcp_query_min_rate;
    int      tcp_queue_size;
    int      axfr_max_record_by_packet;
    int      axfr_max_packet_size;
    int      axfr_retry_delay;
    int      axfr_retry_jitter;
    uint32_t axfr_retry_failure_delay_multiplier;
    uint32_t axfr_retry_failure_delay_max;
    uint32_t axfr_memory_threshold;
    int      xfr_connect_timeout;
    uint32_t statistics_max_period;
    int      edns0_max_size;
    int      network_model; // 0: default MT, 1: experimental RqW
    uint32_t worker_backlog_queue_size;
    int32_t  set_nofile;
    int32_t  nsec3param_ttl_override;
    bool     axfr_compress_packets;
    bool     axfr_strict_authority; // if the AA bit isn't set, AXFR is rejected

    /**/

    access_control_t *ac;

    /**/

    gid_t    gid;
    uid_t    uid;

    uint16_t server_port_value;
    uint16_t server_tls_port_value;

    /*
     * The pid of the only child (a.k.a the server)
     */

    zdb_t   *database;

    uint32_t queries_log_type;

#if DNSCORE_HAS_DNSSEC_SUPPORT
    uint32_t sig_validity_interval;
    uint32_t sig_validity_regeneration;
    uint32_t sig_validity_jitter;
#if CONFIG_SIGNATURE_TYPE_CONFIGURABLE
    uint16_t sig_signing_type;
#endif
#endif

    double tcp_query_min_rate_us;

    bool   chrooted;
    bool   reloadable;

    bool   hidden_primary;

    bool   check_policies;
#if DEBUG
    bool print_config;
#endif
};

/**
 * zone_desc filter callback,
 * The second argument is the proprietary data passed to the
 *
 * Must return 1 for accept, 0 for reject, or an error code.
 *
 */

struct zone_desc_s;

typedef struct zone_desc_s zone_desc_t;

typedef ya_result          config_section_zone_filter_callback(zone_desc_t *, void *);

#ifndef CONFS_MAIN_C_

extern yadifad_config_main_t *g_config;

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

ya_result yadifad_config_update_zone(const char *config_file, const ptr_treemap_t *fqdn);

void      yadifad_print_usage(const char *name);

/*    ------------------------------------------------------------    */

ya_result confs_set_dnssec(const char *value, uint32_t *dest, anytype notused);

void      config_zone_print(zone_desc_t *zone_desc, output_stream_t *os);

/**
 *
 * Enables a callback filter that is called before pushing a zone_desc to the database service.
 *
 * @param cb a callback function or NULL to reset to the "accept all" filter.
 * @param params a pointer that will be passed to the callback
 */

void config_section_zone_set_filter(config_section_zone_filter_callback *cb, void *params);

bool config_check_bounds_s32(int32_t minval, int32_t maxval, int32_t val, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* CONFS_H_ */

/** @} */
