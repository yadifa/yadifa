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

#include "config.h"

#include <dnscore/rfc.h>
#include <dnscore/treeset.h>
    
#include <dnsdb/zdb_types.h>
    
#include "zone.h"
#include "database.h"
#include "acl.h"

    /*    ------------------------------------------------------------    */

#define     PREPROCESSOR_INT2STR(x) #x

#define     THREAD_POOL_SIZE_MAX        255 /* 8 bits ! */
#define     TCP_QUERIES_MIN             0
#define     TCP_QUERIES_MAX             512
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

#define     PROGRAM_NAME                PACKAGE
#define     PROGRAM_VERSION             PACKAGE_VERSION
#define     RELEASEDATE                 "2014-12-16"
#define     COMPILEDATE                 __DATE__

    /* List of default values for the different configuration parameters */
#define     S_CONFIGDIR                 SYSCONFDIR "/"
#define     S_CONFIGFILE                PACKAGE ".conf"
#define     S_CONFIGFILEDYNAMIC         PACKAGE ".conf.dyn"
#define     S_DATAPATH                  LOCALSTATEDIR "/zones/"
#define     S_XFRPATH                   LOCALSTATEDIR "/zones/xfr/"
#define     S_KEYSPATH                  LOCALSTATEDIR "/zones/keys/"        /** Keys should not be in "shared" */
#define     S_LOGPATH                   LOGDIR                              /** defined at configure time, see: --with-logdir (default is /var/log/yadifa) */
#define     S_PIDFILE                   LOCALSTATEDIR "/run/" PACKAGE ".pid"

#define     S_VERSION_CHAOS             PACKAGE_VERSION                  /* limit the size */ 

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

    /* */
#define     S_CPU_COUNT_OVERRIDE        "0" /* max 256 */
#define     S_THREAD_COUNT_BY_ADDRESS   "-1" /* -1 for auto */
#define     S_DNSSEC_THREAD_COUNT       "0" /* max 1024 */

    /* Chroot, uid and gid */
#define     S_CHROOT                    "0"
#define     S_CHROOTPATH                "/"
#define     S_UID                       "0"
#define     S_GID                       "0"

    /** \def S_LISTEN
     *       Listening to all interfaces */
#define     S_LISTEN                    "0.0.0.0"
#define     S_TOTALINTERFACES           1
#define     S_MAX_TCP_QUERIES           "16"    /* max 512 */
#define     S_TCP_QUERY_MIN_RATE        "512"   /* bytes per second minimum rate */

#define     S_MAX_AXFR                  "10"

#define     S_AXFR_MAX_RECORD_BY_PACKET "0"    /** No limit.  Old applications can only work with this set to 1 */
#define     S_AXFR_PACKET_SIZE_MAX      "4096" /** plus TSIG */
#define     S_AXFR_COMPRESS_PACKETS     "1"
#define     S_AXFR_RETRY_DELAY          "600"
#define     S_AXFR_RETRY_JITTER         "180"
    
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

    
#define     S_ZONE_NOTIFY_AUTO          "1"
#define     S_ZONE_NO_MASTER_UPDATES    "0"
    
#define     S_ZONE_DNSSEC_DNSSEC        "off"
    

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
    
#define     SERVER_FL_DYNAMIC_PROVISIONING 0x10

    /* IP flags */
#define     IP_FLAGS_IPV4               0x01
#define     IP_FLAGS_IPV6               0x02

#define     SIGNATURE_VALIDITY_INTERVAL_MIN     7       /* 7  days */
#define     SIGNATURE_VALIDITY_INTERVAL_MAX     30      /* 30 days */
#define     SIGNATURE_VALIDITY_INTERVAL_S       86400   /* seconds for that unit */
    
#define     SIGNATURE_VALIDITY_REGENERATION_MIN 24      /* 1 day  */
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
struct config_data
{
    /* Which are the interfaces to listen at */
    host_address                                                *listen;

    /* General variables */
    char                                                     *data_path; /* zones */
    char                                                      *xfr_path; /* .axfr & .ix */
    char                                                   *chroot_path; /* chroot point */
    char                                                      *log_path; /* log files */
    char                                                     *keys_path; /* keys */
    char                                                   *config_file; /* config */
    char                                           *config_file_dynamic; /* dynamic config */
    //char                                                      *pid_path; /* OBSOLETE: pid file path */
    char                                                      *pid_file; /* pid file path and name */

    char                                                 *version_chaos;
    char                                                   *server_port;

    pid_t                                                           pid;

    /* Server variables */

    u16                                                    server_flags;

    int                                                total_interfaces;
    int                                              cpu_count_override;
    int                                         thread_count_by_address;
    int                                             dnssec_thread_count;
    int                                                 max_tcp_queries;
    int                                              tcp_query_min_rate;

    int                                       axfr_max_record_by_packet;
    int                                            axfr_max_packet_size;
    int                                                axfr_retry_delay;
    int                                               axfr_retry_jitter;
    int                                             xfr_connect_timeout;
    int                                           statistics_max_period;
    int                                                  edns0_max_size;
    bool                                          axfr_compress_packets;

    /**/

    access_control                                                   ac;

    /**/

    gid_t                                                           gid;
    uid_t                                                           uid;

    u16                                                   process_flags;

    //u8                                                               ip;

    /*
     * The pid of the only child (a.k.a the server)
     */

    struct
    {
        pid_t pid;
    } child;

    struct
    {
        pid_t pid;
    } parent;

    interface                                  interfaces[MAX_INTERFACES];
    interface                                           *interfaces_limit;

    zdb                                                         *database;

    u32                                                  queries_log_type;

#if HAS_DNSSEC_SUPPORT
    u32                                             sig_validity_interval;
    u32                                         sig_validity_regeneration;
    u32                                               sig_validity_jitter;
    u16                                                  sig_signing_type;
#endif

    double                                          tcp_query_min_rate_us;

    bool                                                         chrooted;
    bool                                                       reloadable;
};

/**
 * zone_desc filter callback,
 * The second argument is the proprietary data passed to the
 * 
 * Must return 1 for accept, 0 for reject, or an error code.
 * 
 */

typedef ya_result config_section_zone_filter_callback(zone_desc_s *, void *);

#ifndef CONFS_MAIN_C_

extern config_data                         *g_config;

#endif

#include    "zone.h"

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
ya_result yadifad_config_finalise();

ya_result yadifad_config_update(const char *config_file);
ya_result yadifad_config_update_zone(const char *config_file, const u8 *fqdn);

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
