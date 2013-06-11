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

#include <config.h>


#include <dnscore/rfc.h>
#include <dnscore/treeset.h>

#include "zone.h"
#include "database.h"
#include "list.h"
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
#define     RELEASEDATE                 "2013-06-10"
#define     COMPILEDATE                 __DATE__

    /* List of default values for the different configuration parameters */
#define     S_CONFIGDIR                 PREFIX "/etc/"
#define     S_CONFIGFILE                "yadifad.conf"
#define     S_CONFIGFILEDYNAMIC         "yadifad.conf.dyn"
#define     S_DATAPATH                  PREFIX "/var/zones/"
#define     S_XFRPATH                   PREFIX "/var/zones/xfr/"
#define     S_KEYSPATH                  PREFIX "/var/zones/keys/"        /** Keys should not be in "shared" */
#define     S_LOGPATH                   PREFIX "/var/log/"
#define     S_PIDPATH                   PREFIX "/var/run/"
#define     S_PIDFILE                   PACKAGE ".pid"

#define     S_VERSION_CHAOS             PACKAGE_VERSION                  /* limit the size */ 

#define     S_DEBUGLEVEL                "0"

    /* default values for SERVER_FL */
#define     S_SYSLOG                    "0"
#define     S_STATISTICS                "1"
#define     S_STATISTICS_MAX_PERIOD     "60" /* 1 -> 31 * 86400 */
#define     S_DAEMONRUN                 "0"
#define     S_ANSWER_FORMERR_PACKETS    "1"

    /** \def S_RUNMODE
     *       Run mode of the program */
#define     S_RUNMODE                   RUNMODE_CONTINUE_CLEAN

    /* */
#define     S_CPU_COUNT_OVERRIDE        "0" /* max 256 */
#define     S_THREAD_COUNT_BY_ADDRESS   "0" /* -1 for auto */
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
#define     S_MAX_TCP_QUERIES           "5"     /* max 512 */
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

#define     S_S32_VALUE_NOT_SET         "2147483647"
#define     S_SIG_VALIDITY_INTERVAL     "30"            /* 30 days in days           */
#define     S_SIG_VALIDITY_REGENERATION "168"           /*  7 days in hours  24->168 */
#define     S_SIG_VALIDITY_JITTER       "3600"          /*  1 hour in seconds        */
#define     S_SIG_SIGNING_TYPE          "65534"
    
#define     S_NOTIFY_RETRY_COUNT           "5"          /* 5 retries */
#define     S_NOTIFY_RETRY_PERIOD          "1"          /* first after 1 minute */
#define     S_NOTIFY_RETRY_PERIOD_INCREASE "0"          /* period increased by "0" after every try */

    
#define     S_ZONE_NOTIFY_AUTO          "1"
    
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

    /* IP flags */
#define     IP_FLAGS_IPV4               0x01
#define     IP_FLAGS_IPV6               0x02

#define     SIGNATURE_VALIDITY_INTERVAL_MIN     7       /* 7  days */
#define     SIGNATURE_VALIDITY_INTERVAL_MAX     30      /* 30 days */
#define     SIGNATURE_VALIDITY_INTERVAL_S       86400
    
#define     SIGNATURE_VALIDITY_REGENERATION_MIN 24
#define     SIGNATURE_VALIDITY_REGENERATION_MAX 168
#define     SIGNATURE_VALIDITY_REGENERATION_S   3600
    
#define     SIGNATURE_VALIDITY_JITTER_MIN       0
#define     SIGNATURE_VALIDITY_JITTER_MAX       86400
#define     SIGNATURE_VALIDITY_JITTER_S         1
    
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
        char                                                      *pid_path; /* pid file path */
        char                                                      *pid_file; /* pid file name */

        char                                                 *version_chaos;
        char                                                   *server_port;

        pid_t                                                           pid;

        u16                                                        run_mode;
        /* Server variables */

        u16                                                    server_flags;

        int                                                total_interfaces;
        int                                              cpu_count_override;
        int                                         thread_count_by_address;
        int                                             dnssec_thread_count;
        int                                                 max_tcp_queries;
        int                                              tcp_query_min_rate;
        int                                                        max_axfr;
        int                                       axfr_max_record_by_packet;
        int                                            axfr_max_packet_size;
        int                                           axfr_compress_packets;
        int                                                axfr_retry_delay;
        int                                               axfr_retry_jitter;
        int                                             xfr_connect_timeout;
        int                                                    thread_count;
        int                                           statistics_max_period;
        int                                                  edns0_max_size;

        /* Zone file variables */

        zone_data_set                                                 zones;
        
        /* Zones meant to be merged with zones */
        
        zone_data_set                                         dynamic_zones;

        /**/

        access_control                                                   ac;

        /**/

        gid_t                                                           gid;
        uid_t                                                           uid;

        u16                                                   process_flags;

        u8                                                               ip;

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

        scheduler                                                   scheduler;

        database_t                                                  *database;

        u32                                                  queries_log_type;
        
#if HAS_DNSSEC_SUPPORT != 0
        u32                                             sig_validity_interval;
        u32                                         sig_validity_regeneration;
        u32                                               sig_validity_jitter;
        u16                                                  sig_signing_type;
#endif

        double                                          tcp_query_min_rate_us;
        
        bool                                                         chrooted;
    };

#ifndef CONFS_MAIN_C_

    extern config_data                         *g_config;

#endif

#include    "zone.h"

    /** \struct config_table
     *          Struct with the method to set the different configuration
     *          parameters
     */

    typedef int config_table_function(const char *, const int, void*);

    typedef struct config_table config_table;
    struct config_table
    {
        /* Variable to add in the config */
        char                                                      *variable;

        /* Function to use for parsing the variable */
        config_table_function                                 *set_function;

        /* Switch case to use for adding the variable into the config */
        int                                                  config_command;
    };

    /*    ------------------------------------------------------------    */

    /*    ------------------------------------------------------------    */

    /* Get's the index of the "name" entry in the given config_table */

    ya_result config_get_entry_index(const char *name, const config_table *table, const char *section_name);

    /*
     * Called before a new section X is read (closes the previous one and readies a new one)
     */

    typedef ya_result config_section_init(config_data *config);

    /*
     * Called to set an entry in the current section
     */

    typedef ya_result config_section_setter(char *, char *, char *);

    /*
     * Called when all sections X have been read
     */

    typedef ya_result config_section_assign(config_data *config);

    /*
     * Called when the sections X are not needed anymore
     */

    typedef ya_result config_section_free(config_data *config);

    /*
     * Print the config
     */

    typedef ya_result config_section_print(config_data *config);

    typedef struct config_section_descriptor config_section_descriptor;

    struct config_section_descriptor
    {
        const char                                                *name;
        config_section_setter                             *function_set;
        config_section_init                              *function_init;
        config_section_assign                          *function_assign;
        config_section_free                              *function_free;
        config_section_print                            *function_print;
        bool has_params;
    };

    /**
     * @brief Tool function printing all the known names in a table.
     */

    /*    ------------------------------------------------------------    */

    void print_value_name_table_names(value_name_table *table);

    /*    ------------------------------------------------------------    */

    void show_usage();
    void print_version();
    void command_line_reset();
    int command_line_next(int argc, char **argv);

    /*    ------------------------------------------------------------    */

    ya_result   config_adjust(const char *name, const void *value, config_data *config);
    ya_result   config_init();
    void        config_print();

    int         config_read(const char *);
    ya_result   config_read_all();

    ya_result   config_file_read(const char *, config_reader_context *ctx);

    void        config_remove();
    ya_result   config_check_data(u_char *, u_char **, int *);

    ya_result   config_get_file(int argc, char **argv);

    ya_result   config_update();
    void        config_free();

    /*    ------------------------------------------------------------    */

    union anytype_u
    {
        /* DO NOT ADD THIS bool    _bool; */
        intptr  _intptr;
        u8      _u8;
        u16     _u16;
        u32     _u32;
        u64     _u64;
        s8      _s8;
        s16     _s16;
        s32     _s32;
        s64     _s64;
        void*   _voidp;
        char*   _charp;
    };

    typedef union anytype_u anytype;

    typedef ya_result confs_set_field_function(const char*, void*, anytype);

    ya_result confs_set_dnssec(const char *value, u32 *dest, anytype notused);
    
    ya_result confs_set_bool(const char *value, bool *dest, anytype notused);
    ya_result confs_set_flag8(const char *value, u8 *dest, anytype mask8);
    ya_result confs_set_flag16(const char *value, u16 *dest, anytype mask16);
    ya_result confs_set_flag32(const char *value, u32 *dest, anytype mask32);
    ya_result confs_set_flag64(const char *value, u64 *dest, anytype mask64);
    ya_result confs_set_u32(const char *value,u32 *dest, anytype notused);
    ya_result confs_set_u16(const char *value,u16 *dest, anytype notused);
    ya_result confs_set_u8(const char *value,u8 *dest, anytype notused);
    ya_result confs_set_string(const char *value, char **dest, anytype notused);
    ya_result confs_set_path(const char *value, char **dest, anytype notused);
    ya_result confs_set_uid_t(const char *value, uid_t *dest, anytype notused);
    ya_result confs_set_gid_t(const char *value, gid_t *dest, anytype notused);
    ya_result confs_set_acl_item(const char *value, address_match_set *dest, anytype notused);
    ya_result confs_add_list_item(const char *value, list_data **dest, anytype notused);
    ya_result confs_set_enum_value(const char *value, u32 *dest, anytype enum_value_name_table);
    ya_result confs_set_host_list(const char *value, host_address **dest, anytype notused);

    struct config_table_desc_s
    {
        const char *name;
        size_t field_offset;
        confs_set_field_function *setter;
        const char *default_value_string;
        anytype function_specific;
    };

    typedef struct config_table_desc_s config_table_desc;

    ya_result confs_init(const config_table_desc *table, void *configbase);
    ya_result confs_set(const config_table_desc *table, void *configbase, const char *name, const char *value);
    ya_result confs_print(const config_table_desc *table, void *configbase);
    ya_result confs_write(output_stream *os, const config_table_desc *table, void *configbase);

#define CONFS_BEGIN(name_) static const config_table_desc name_[] = {

#undef CONFS_TYPE /* please_define_me */
    
#define CONFS_BOOL(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_bool, defaultvalue_,{._intptr=0}},
#define CONFS_FLAG8(fieldname_,defaultvalue_, realfieldname_, mask_) {#fieldname_,offsetof(CONFS_TYPE, realfieldname_), (confs_set_field_function*)confs_set_flag8, defaultvalue_,{(u8)mask_}},
#define CONFS_FLAG16(fieldname_,defaultvalue_, realfieldname_,mask_) {#fieldname_,offsetof(CONFS_TYPE, realfieldname_), (confs_set_field_function*)confs_set_flag16, defaultvalue_,{(u16)mask_}},
#define CONFS_FLAG32(fieldname_,defaultvalue_, realfieldname_,mask_) {#fieldname_,offsetof(CONFS_TYPE, realfieldname_), (confs_set_field_function*)confs_set_flag32, defaultvalue_,{(u32)mask_}},
#define CONFS_FLAG64(fieldname_,defaultvalue_, realfieldname_,mask_) {#fieldname_,offsetof(CONFS_TYPE, realfieldname_), (confs_set_field_function*)confs_set_flag64, defaultvalue_,{(u64)mask_}},
#define CONFS_U32(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_u32, defaultvalue_,{._intptr=0}},
#define CONFS_U16(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_u16, defaultvalue_,{._intptr=0}},
#define CONFS_U8(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_u8, defaultvalue_,{._intptr=0}},
#define CONFS_STRING(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_string, defaultvalue_,{._intptr=0}},
#define CONFS_PATH(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_path, defaultvalue_,{._intptr=0}},
#define CONFS_UID(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_uid_t, defaultvalue_,{._intptr=0}},
#define CONFS_GID(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_gid_t, defaultvalue_,{._intptr=0}},
#define CONFS_ACL(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, ac) + offsetof(access_control,fieldname_), (confs_set_field_function*)confs_set_acl_item, defaultvalue_,{._intptr=0}},
#define CONFS_LIST_ITEM(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_add_list_item, defaultvalue_,{._intptr=0}},
#define CONFS_ENUM(fieldname_,defaultvalue_,enumtable_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_enum_value, defaultvalue_, {(intptr)enumtable_}},
#define CONFS_HOST_LIST(fieldname_,defaultvalue_) {#fieldname_, offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_host_list, defaultvalue_,{._intptr=0}},
//#define CONFS_DNSSEC(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFS_TYPE, fieldname_), (confs_set_field_function*)confs_set_dnssec, defaultvalue_,{._intptr=0}},
    
#define CONFS_ALIAS(fieldname_, aliasname_) {#fieldname_, 0, NULL, #aliasname_, {._intptr=0}},
    /*#define CONFS_CATEGORY(fieldname_, category_) {#fieldname_, 0, NULL, NULL, #category},*/

#define CONFS_END(name_) {NULL,0,NULL,NULL, {._intptr=0}} }; // name_
    
ya_result confs_zone_write(output_stream *os, zone_data *zone_desc);

bool config_check_bounds_s32(s32 minval, s32 maxval, s32 val, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* CONFS_H_ */

/** @} */
