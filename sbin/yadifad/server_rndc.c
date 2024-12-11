/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup server Server
 * @ingroup yadifad
 * @brief multithreaded reader-writer server
 *
 *  Multiples threads for UDP on a different socket per interface.
 *  One thread per interface for TCP, dispatching accepts to worker threads. (for now)
 *
 *  One weakness: every single test of a similar mechanism shows that this is MUCH slower than the simple "mt" model.
 *
 *              This is tested in hope that although the maximum throughput will be reduced, no packets will be lost
 *              in case of long DB locks.
 *
 *              As a side note, it is trivial that a different model of database would also solve the issue.
 *              The most obvious one being using two zones images, alternating the visible and edited one.
 *              This solution is of course unacceptable for a big zone as it greatly increases the resident memory
 *usage.
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
// keep this order -->
 *
 *----------------------------------------------------------------------------*/

#include "server_config.h"
#include <dnscore/dnscore_config_features.h>

#if __unix__
#ifndef __USE_GNU
#define __USE_GNU 1
#endif
#define _GNU_SOURCE 1
#include <sched.h>
#endif

#if defined __FreeBSD__
#include <sys/param.h>
#include <sys/cpuset.h>
typedef cpuset_t cpu_set_t;
#endif

// <-- keep this order

#include "server_context.h"

#include <dnscore/sys_types.h>
#include <dnscore/logger.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/dns_message.h>
#include <dnscore/timems.h>
#include <dnscore/thread_pool.h>
#include <dnscore/sys_get_cpu_count.h>
#include <dnscore/host_address.h>
#include <dnscore/process.h>
#include <dnscore/error_state.h>

#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb_zone_lock.h>

#define ZDB_JOURNAL_CODE          1

// #define THREAD_POOL_START_TIMEOUT (ONE_SECOND_US * 5)
#define THREAD_POOL_START_TIMEOUT (ONE_SECOND_US * 30)

#include <dnsdb/journal.h>

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
#include "dnsdb/zdb_zone_lock_monitor.h"
#endif

#include "server.h"
#include "log_query.h"
#include "rrl.h"
#include "process_class_ch.h"
#include "notify.h"
#include "log_statistics.h"
#include "signals.h"
#include "dynupdate_query_service.h"
#include "axfr.h"

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic_module_handler.h"
#endif

#include "server_rndc.h"
#include "dnscore/rndc.h"
#include "dnscore/parsing.h"
#include "dnscore/ctrl_rfc.h"
#if HAS_CTRL
#include "ctrl_zone.h"

#define RWNTCTXS_TAG 0x53585443544e5752
#define RWNTCTX_TAG  0x585443544e5752
#define NETTHCTX_TAG 0x585443485454454e

//
// note: MODULE_MSG_HANDLE is defined in server_error.h
//

static error_state_t        server_rndc_error_state = ERROR_STATE_INITIALIZER;

static rndc_server_config_t rndc_server_config = {NULL, NULL, NULL, 1, false};

void                        rndc_server_listen_set(host_address_t *listen) { rndc_server_config.listen = listen; }

void                        rndc_server_tsig_set(tsig_key_t *tsig_key) { rndc_server_config.key = tsig_key; }

void                        rndc_server_queries_max(uint32_t qm) { rndc_server_config.queries_max = qm; }

void                        rndc_server_enable(bool enabled) { rndc_server_config.enabled = enabled; }

struct network_thread_context_s
{
    network_thread_context_base_t base;

    // should be aligned with 64

    mutex_t mtx;
    cond_t  cond;

    // should be aligned with 64

#if __unix__
#if !USE_SERVER_STATISTICS_ATOMICS
    server_statistics_t statistics __attribute__((aligned(SERVER_L1_DATA_LINE_ALIGNED_SIZE)));
#endif
#else
    server_statistics_t statistics;
#endif
};

typedef struct network_thread_context_s network_thread_context_t;

struct server_rndc_data_s
{
    struct service_s          service_handler;
    int                      *sockets;
    int                       socket_count;
    int                       thread_count_by_address;
    network_thread_context_t *contexts; // socket_count times
};

static struct server_rndc_data_s server_rndc_data = {UNINITIALIZED_SERVICE, NULL, 0, 0, NULL};

struct server_rndc_thread_parm
{
    network_thread_context_t *ctx;
    int                       sockfd;
};

typedef struct server_rndc_thread_parm server_rndc_thread_parm;
static struct thread_pool_s           *server_rndc_thread_pool = NULL;

static const char                     *on_off_words[2] = {"on", "off"};

// possible:
//   addzone zone [class [view]] { zone-options }
//                 Add zone to given view. Requires allow-new-zones option.

// possible:
//   delzone [-clean] zone [class [view]]
//                 Removes zone from given view.

// no idea what this does:
//   dnssec -checkds [-key id [-alg algorithm]] [-when time] (published|withdrawn) zone [class [view]]
//                 Mark the DS record for the KSK of the given zone as seen
//                 in the parent.  If the zone has multiple KSKs, select a
//                 specific key by providing the keytag with -key id and
//                 optionally the key's algorithm with -alg algorithm.
//                 Requires the zone to have a dnssec-policy.

// may be possible:
//   dnssec -rollover -key id [-alg algorithm] [-when time] zone [class [view]]
//                 Rollover key with id of the given zone. Requires the zone
//                 to have a dnssec-policy.

// possible:
//   dnssec -status zone [class [view]]
//                 Show the DNSSEC signing state for the specified zone.
//                 Requires the zone to have a dnssec-policy.

// not possible:
//   dnstap -reopen
//                 Close, truncate and re-open the DNSTAP output file.

// not possible:
//   dnstap -roll count
//                 Close, rename and re-open the DNSTAP output file(s).

// not possible:
//   dumpdb [-all|-cache|-zones|-adb|-bad|-expired|-fail] [view ...]
//                 Dump cache(s) to the dump file (named_dump.db).

// not possible:
//   flush         Flushes all of the server's caches.

// not possible:
//   flush [view]  Flushes the server's cache for a view.

// not possible:
//   flushname name [view]
//                 Flush the given name from the server's cache(s)

// not possible:
//   flushtree name [view]
//                 Flush all names under the given name from the server's cache(s)

// done:
//   freeze        Suspend updates to all dynamic zones.

// done:
//   freeze zone [class [view]]
//                 Suspend updates to a dynamic zone.

// possible ?:
//   halt          Stop the server without saving pending updates.

// possible ?:
//   halt -p       Stop the server without saving pending updates reporting
//                 process id.

//   loadkeys zone [class [view]]
//                 Update keys without signing immediately.
//   managed-keys refresh [class [view]]
//                 Check trust anchor for RFC 5011 key changes
//   managed-keys status [class [view]]
//                 Display RFC 5011 managed keys information
//   managed-keys sync [class [view]]
//                 Write RFC 5011 managed keys to disk
//   modzone zone [class [view]] { zone-options }
//                 Modify a zone's configuration.
//                 Requires allow-new-zones option.

// done:
//   notify zone [class [view]]
//                 Resend NOTIFY messages for the zone.

// done:
//   notrace       Set debugging level to 0.

//   nta -dump
//                 List all negative trust anchors.
//   nta [-lifetime duration] [-force] domain [view]
//               Set a negative trust anchor, disabling DNSSEC validation
//                 for the given domain.
//                 Using -lifetime specifies the duration of the NTA, up
//                 to one week.
//                 Using -force prevents the NTA from expiring before its
//                 full lifetime, even if the domain can validate sooner.
//   nta -remove domain [view]
//                 Remove a negative trust anchor, re-enabling validation
//                 for the given domain.

// done:
//   querylog [ on | off ]
//                 Enable / disable query logging.

// possible ?:
//   reconfig      Reload configuration file and new zones only.

// not possible:
//   recursing     Dump the queries that are currently recursing (named.recursing)

// possible:
//   refresh zone [class [view]]
//                 Schedule immediate maintenance for a zone.

// possible: (current one not correct)
//   reload        Reload configuration file and zones.

// done:
//   reload zone [class [view]]
//                 Reload a single zone.

// possible:
//   retransfer zone [class [view]]
//                 Retransfer a single zone without checking serial number.

// possible ?:
//   scan          Scan available network interfaces for changes.

// ?:
//   secroots [view ...]
//                 Write security roots to the secroots file.

// ?:
//   serve-stale [ on | off | reset | status ] [class [view]]
//                 Control whether stale answers are returned

// possible:
//   showzone zone [class [view]]
//                 Print a zone's configuration.

// possible:
//   sign zone [class [view]]
//                 Update zone keys, and sign as needed.

// ?
//   signing -clear all zone [class [view]]
//                 Remove the private records for all keys that have
//                 finished signing the given zone.
//   signing -clear <keyid>/<algorithm> zone [class [view]]
//                 Remove the private record that indicating the given key
//                 has finished signing the given zone.
//   signing -list zone [class [view]]
//                 List the private records showing the state of DNSSEC
//                 signing in the given zone.
//   signing -nsec3param hash flags iterations salt zone [class [view]]
//                 Add NSEC3 chain to zone if already signed.
//                 Prime zone with NSEC3 chain if not yet signed.
//   signing -nsec3param none zone [class [view]]
//                 Remove NSEC3 chains from zone.
//   signing -serial <value> zone [class [view]]
//                 Set the zones's serial to <value>.

// possible:
//   stats         Write server statistics to the statistics file.

// done:
//   status        Display status of the server.

// done:
//   stop          Save pending updates to primary files and stop the server.

// done:
//   stop -p       Save pending updates to primary files and stop the server
//                 reporting process id.

// done:
//   sync [-clean] Dump changes to all dynamic zones to disk, and optionally
//                 remove their journal files.

// done:
//   sync [-clean] zone [class [view]]
//                 Dump a single zone's changes to disk, and optionally
//                 remove its journal file.

//   tcp-timeouts  Display the tcp-*-timeout option values
//   tcp-timeouts initial idle keepalive advertised
//                 Update the tcp-*-timeout option values

// done:
//   thaw          Enable updates to all dynamic zones and reload them.

// done:
//   thaw zone [class [view]]
//                 Enable updates to a frozen dynamic zone and reload it.

// done:
//   trace         Increment debugging level by one.

// done:
//   trace level   Change the debugging level.

//   tsig-delete keyname [view]
//                 Delete a TKEY-negotiated TSIG key.
//   tsig-list     List all currently active TSIG keys, including both statically
//                 configured and TKEY-negotiated keys.
//   validation [ on | off | status ] [view]
//                 Enable / disable DNSSEC validation.

// done: (kind of ...)
//   zonestatus zone [class [view]]
//                 Display the current status of a zone.

#if 0
version: BIND 9.18.12 (Extended Support Version) <id:99783f9> (named 127.0.53.6)
running on orochi: Linux x86_64 6.2.2-artix1-1 #1 SMP PREEMPT_DYNAMIC Fri, 03 Mar 2023 18:24:33 +0000
boot time: Thu, 16 Mar 2023 07:58:14 GMT
last configured: Thu, 16 Mar 2023 07:58:14 GMT
configuration file: /tmp/yadifad-server-test/s3/etc/named.conf
CPUs found: 32
worker threads: 32
UDP listeners per interface: 32
number of zones: 54 (0 automatic)
debug level: 0
xfers running: 2
xfers deferred: 49
soa queries in progress: 51
query logging is ON
recursive clients: 0/900/1000
tcp clients: 0/150
TCP high-water: 0
server is up and running
#endif
static void server_rndc_send_status(rndc_message_t *rndcmsg)
{
    char *text_buffer;
    char  hostname[FQDN_LENGTH_MAX];
    strcpy(hostname, "localhost");
    gethostname(hostname, sizeof(hostname));
    int text_buffer_size = asformat(&text_buffer,
                                    "version: YADIFA " PROGRAM_VERSION " (" PROGRAM_NAME
                                    ")\n"
                                    "running on %s\n"
                                    "boot time: %lT\n"
                                    "CPUs found: %u\n"
                                    "number of zones: %u\n"
                                    "debug level: %u\n"
                                    "query logging is O%s",
                                    hostname,
                                    dnscore_init_timestamp(),
                                    sys_get_cpu_count(),
                                    zone_count(),
                                    MAX((logger_get_level() - LOG_DEBUG), 0),
                                    (log_query_mode() != LOG_QUERY_MODE_NONE) ? "N" : "FF");
    rndc_message_text_set(rndcmsg, text_buffer, text_buffer_size);
    free(text_buffer);
}

#if 0
name: dnssec-none.eu
type: secondary
files: dnssec-none.eu
serial: 1
nodes: 30088
next refresh: Thu, 16 Mar 2023 09:16:16 GMT
expires: Thu, 27 Apr 2023 00:26:56 GMT
secure: no
dynamic: no
reconfigurable via modzone: no
// or
rndc: 'zonestatus' failed: not found
no matching zone 'dnssec-none.xeu' in any view
#endif

static ya_result server_rndc_send_zonestatus(rndc_message_t *rndcmsg, const uint8_t *fqdn)
{
    char        *text_buffer;
    uint32_t     serial = 0;
    zone_desc_t *zone_desc = zone_acquirebydnsname(fqdn);
    if(zone_desc != NULL)
    {
        zdb_zone_getserial(zone_desc->loaded_zone, &serial);
        int64_t next_refresh = ONE_SECOND_US * zone_desc->refresh.refreshed_time;
        int     text_buffer_size = asformat(&text_buffer,
                                        "name: %{dnsname}\n"
                                            "type: %s\n"
                                            "files: %s\n" // why plural?
                                        "serial: %u\n"
                                            "next refresh: %lT\n"
                                            "expires: %lT\n"
                                            "secure: %s\n"
                                            "dynamic %s\n",
                                        fqdn,
                                        (zone_desc->type == ZT_PRIMARY) ? ZT_PRIMARY_STRING : ZT_SECONDARY_STRING,
                                        zone_desc->file_name,
                                        serial,
                                        next_refresh,
                                        0,
                                        "?",
                                        "?");
        zone_release(zone_desc);
        rndc_message_text_set(rndcmsg, text_buffer, text_buffer_size);
        free(text_buffer);
        return SUCCESS;
    }
    else
    {
        rndc_message_err_set(rndcmsg, "not found", 9);
        int text_buffer_size = asformat(&text_buffer, "no matching zone '%{dnsname}'", fqdn);
        rndc_message_text_set(rndcmsg, text_buffer, text_buffer_size);
        free(text_buffer);
        return UNKNOWN_NAME;
    }
}

static void server_rndc_thread_context_init(network_thread_context_t *ctx, struct service_worker_s *worker, uint16_t sockfd_idx)
{
    assert(ctx != NULL);

    memset(ctx, 0, sizeof(network_thread_context_t));
    ctx->base.worker = worker;
    ctx->base.idx = sockfd_idx;
    ctx->base.sockfd = server_rndc_data.sockets[sockfd_idx];
    // ctx->base.must_stop = false; // implicit with the memset
#if USE_SERVER_STATISTICS_ATOMICS
    ctx->base.statisticsp = log_statistics_get();
#else
    ctx->base.statisticsp = log_statistics_alloc_register();
#endif

    mutex_init(&ctx->mtx);
    cond_init(&ctx->cond);
}

struct zone_class_view_s
{
    uint8_t *fqdn;
    uint16_t qclass;
    uint8_t  fqdn_buffer[FQDN_LENGTH_MAX];
};

typedef struct zone_class_view_s zone_class_view_t;

/**
 * Tries to match one of the words in "words" in [*textp ; text_limit[.
 * If a word is matched, then it is removed.
 */

static int server_rndc_eat_one_of_words(const char **textp, const char *text_limit, const char **words, int count)
{
    if(((intptr_t)textp & (intptr_t)text_limit & (intptr_t)words) == 0)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    const char *text = *textp;
    int         text_size = text_limit - text;

    for(int_fast32_t i = 0; i < count; ++i)
    {
        const char *word = words[i];
        int         word_len = strlen(word);
        if(text_size >= word_len)
        {
            if((text[word_len] == '\0') || isspace(text[word_len]))
            {
                if(memcmp(text, word, word_len) == 0)
                {
                    // found it
                    text = parse_skip_spaces(text);
                    *textp = text;
                    return i;
                }
            }
        }
    }

    // not a match
    return -1;
}

static bool server_rndc_eat_word(const char **textp, const char *text_limit, char *word)
{
    if(((intptr_t)textp & (intptr_t)text_limit & (intptr_t)word) == 0)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    const char *text = *textp;
    while((*word != '\0') && (text < text_limit))
    {
        if(*word != *text)
        {
            return false;
        }
        ++word;
        ++text;
    }

    if((text == text_limit) || isblank(*text))
    {
        // the word has been eten, move to the next word
        text = parse_skip_spaces(text);
        *textp = text;
        return true;
    }
    else
    {
        // not a match
        return false;
    }
}

static ya_result server_rndc_parse_zone_class_view(zone_class_view_t *zone_class_view, char *text, char *text_limit, ya_result (*zone_operation)(zone_desc_t *zone_desc, bool dolock))
{
    ya_result ret = ERROR;
    zone_class_view->fqdn = NULL;
    zone_class_view->qclass = CLASS_IN;

    bool empty_parameters = (text_limit - text) == 0;

    if(!empty_parameters)
    {
        char *fqdn = text;
        char *class_text = (char *)parse_next_blank(text);
        char *fqdn_limit = class_text;
        // class_text = parse_skip_spaces(class_text + 1); // not used here
        *fqdn_limit = '\0';
        if(FAIL(ret = dnsname_init_check_star_with_cstr(zone_class_view->fqdn_buffer, fqdn)))
        {
            // rndc_message_err_set(rndcmsg, "not found", 9);
            return ZONE_NOT_DEFINED;
        }
        if((zone_class_view->qclass != CLASS_IN))
        {
            // rndc_message_err_set(rndcmsg, "not found", 9);
            return ZONE_NOT_DEFINED;
        }
        zone_class_view->fqdn = zone_class_view->fqdn_buffer;

        zone_desc_t *zone_desc = zone_acquirebydnsname(zone_class_view->fqdn);
        if(zone_desc != NULL)
        {
            ret = zone_operation(zone_desc, true);
            zone_release(zone_desc);
        }
        else
        {
            // rndc_message_err_set(rndcmsg, "not found", 9);
            ret = ZONE_NOT_DEFINED;
        }
    }
    else
    {
        /*
        if(g_config->reloadable)
        {
            log_debug1("server_rndc_parse_zone_class_view(): reloading configuration");

            ret = yadifad_config_update(g_config->config_file);
            if(FAIL(ret))
            {
                log_err("failed to reconfigure: %r", ret);
            }
        }

        ret = SUCCESS;
        zone_set_iterator_t iter;
        zone_set_iterator_init(&iter);
        while(zone_set_iterator_hasnext(&iter))
        {
            zone_desc_s *zone_desc = zone_set_iterator_next(&iter);
            ya_result local_ret = zone_operation(zone_desc, true);
            if(FAIL(local_ret))
            {
                ret = local_ret;
            }
        }
        zone_set_iterator_finalise(&iter);
        */
    }

    return ret;
}

static ya_result server_rndc_parse_zone_class_view_flag(zone_class_view_t *zone_class_view, char *text, char *text_limit, bool flag, ya_result (*zone_operation)(zone_desc_t *zone_desc, bool dolock, bool flag))
{
    ya_result ret;
    zone_class_view->fqdn = NULL;
    zone_class_view->qclass = CLASS_IN;

    char *fqdn = text;
    char *class_text = (char *)parse_next_blank_ex(text, text_limit);

    if(class_text == NULL)
    {
        return PARSEWORD_NOMATCH_ERROR;
    }

    char *fqdn_limit = class_text;
    class_text = (char *)parse_skip_spaces_ex(class_text + 1, text_limit);

    if(class_text == NULL)
    {
        return PARSEWORD_NOMATCH_ERROR;
    }

    *fqdn_limit = '\0';

    if(ISOK(ret = dnsname_init_check_star_with_cstr(zone_class_view->fqdn_buffer, fqdn)))
    {
        zone_class_view->fqdn = zone_class_view->fqdn_buffer;

        if(*class_text == 0)
        {
            if(zone_class_view->qclass == CLASS_IN)
            {
                if(zone_class_view->fqdn != NULL)
                {
                    zone_desc_t *zone_desc = zone_acquirebydnsname(zone_class_view->fqdn);
                    if(zone_desc != NULL)
                    {
                        ret = zone_operation(zone_desc, true, flag);
                        zone_release(zone_desc);
                    }
                    else
                    {
                        ret = ZONE_NOT_DEFINED;
                    }
                }
                else
                {

                    zone_set_iterator_t iter;
                    zone_set_iterator_init(&iter);
                    while(zone_set_iterator_hasnext(&iter))
                    {
                        zone_desc_t *zone_desc = zone_set_iterator_next(&iter);
                        ya_result    local_ret = zone_operation(zone_desc, true, flag);
                        if(FAIL(local_ret))
                        {
                            ret = local_ret;
                        }
                    }
                    zone_set_iterator_finalise(&iter);
                }
            }
            else
            {
                ret = INVALID_ARGUMENT_ERROR;
            }
        }
        else
        {
            ret = INVALID_ARGUMENT_ERROR;
        }
    }

    return ret;
}

static ya_result server_rndc_recv_process_callback(rndc_message_t *rndcmsg, void *args)
{
    (void)args;
    char             *command;
    char             *command_limit;
    char             *text;
    char             *text_limit;
    uint32_t          text_size;
    ya_result         ret;
    zone_class_view_t zone_class_view;

    if(ISOK(ret = rndc_message_type_get(rndcmsg, (const void **)&text, &text_size)))
    {
        // analyse the command
        // read token

        text_limit = &text[text_size];
        command = (char *)parse_skip_spaces(text);
        command_limit = (char *)parse_next_blank(command);
        text = (char *)parse_skip_spaces(command_limit);
        *command_limit = '\0';

        ret = FEATURE_NOT_IMPLEMENTED_ERROR;

        // process the command

        if(strcmp(command, "freeze") == 0)
        {
            if(ISOK(ret = server_rndc_parse_zone_class_view(&zone_class_view, text, text_limit, ctrl_zone_freeze)))
            {
            }
        }
        else if(strcmp(command, "notify") == 0)
        {
            if(ISOK(ret = server_rndc_parse_zone_class_view(&zone_class_view, text, text_limit, ctrl_zone_notify)))
            {
            }
        }
        else if(strcmp(command, "notrace") == 0)
        {
            logger_set_level(MSG_INFO); // 0 debug => info
            ret = SUCCESS;
        }
        else if(strcmp(command, "querylog") == 0)
        {
            int match = server_rndc_eat_one_of_words((const char **)&text, text_limit, on_off_words, 2);
            if(match >= 0)
            {
                if(match == 0)
                {
                    // enable the query log
                    if(g_config->queries_log_type != 0)
                    {
                        log_query_mode_set(g_config->queries_log_type);
                    }
                    else
                    {
                        log_query_mode_set(1); // yadifa
                    }
                }
                else
                {
                    // disable the query log
                    log_query_mode_set(0);
                }
            }
            else
            {
                ret = INVALID_ARGUMENT_ERROR;
            }
        }
        if(strcmp(command, "refresh") == 0)
        {
            if(ISOK(ret = server_rndc_parse_zone_class_view(&zone_class_view, text, text_limit, ctrl_zone_refresh)))
            {
            }
        }
        else if(strcmp(command, "reload") == 0)
        {
            ret = ctrl_config_reload();
            /*
            if(ISOK(ret = server_rndc_parse_zone_class_view(&zone_class_view, text, text_limit, ctrl_zone_reload)))
            {

            }
            */
        }
        else if(strcmp(command, "showzone") == 0)
        {
        }
        else if(strcmp(command, "stats") == 0)
        {
        }
        else if(strcmp(command, "status") == 0)
        {
            server_rndc_send_status(rndcmsg);
        }
        else if(strcmp(command, "stop") == 0)
        {
            if(!dnscore_shuttingdown())
            {
                log_debug("rndc: shutdown: in progress");

                bool print_pid = server_rndc_eat_word((const char **)&text, text_limit, "-p");

                if(print_pid)
                {
                    char pid_text[12];
                    int  pid_size = snprintf(pid_text, sizeof(pid_text), "%i", getpid());
                    rndc_message_text_set(rndcmsg, pid_text, pid_size);
                }

                program_mode = SA_SHUTDOWN;
                dnscore_shutdown();
                server_service_stop_nowait();
                ret = SUCCESS;
            }
            else
            {
                log_info("rndc shutdown: already shutting down");
                ret = INVALID_STATE_ERROR;
            }
        }
        else if(strcmp(command, "sync") == 0)
        {
            bool flag = server_rndc_eat_word((const char **)&text, text_limit, "-clean");
            if(ISOK(ret = server_rndc_parse_zone_class_view_flag(&zone_class_view, text, text_limit, flag, ctrl_zone_sync)))
            {
            }
        }
        else if(strcmp(command, "thaw") == 0)
        {
            if(ISOK(ret = server_rndc_parse_zone_class_view(&zone_class_view, text, text_limit, ctrl_zone_unfreeze)))
            {
            }
        }
        else if(strcmp(command, "trace") == 0)
        {
            if(text == text_limit)
            {
                logger_set_level(logger_get_level() + 1);
                ret = SUCCESS;
            }
            else
            {
                // 0 to 8
                unsigned int level = 0;
                if(sscanf(text, "%u", &level) == 1)
                {
                    if(level <= 8)
                    {
                        logger_set_level(LOG_INFO + level);
                        ret = SUCCESS;
                    }
                    else
                    {
                        ret = CONFIG_VALUE_OUT_OF_RANGE;
                    }
                }
                else
                {
                    ret = PARSEINT_ERROR;
                }
            }
        }
        else if(strcmp(command, "zonestatus") == 0)
        {
            uint8_t fqdn[FQDN_LENGTH_MAX];
            if(ISOK(ret = dnsname_init_check_nostar_with_charp(fqdn, text, text_limit - text)))
            {
                ret = server_rndc_send_zonestatus(rndcmsg, fqdn);
            }
        }

        // do a set

        rndc_message_result_set(rndcmsg, yadifa_error_to_named_error(ret));
    }
    return ret;
}

static void server_rndc_thread(void *parm)
{
#if DEBUG
    log_debug("rndc: begin");
#endif
    server_rndc_thread_parm *rndc_parm = (server_rndc_thread_parm *)parm;

    ya_result                ret;
    rndc_message_t           rndcmsg;
    tsig_key_t              *tsig_key = rndc_server_config.key;
    if(tsig_key != NULL)
    {
        ret = rndc_init_and_recv_from_socket(&rndcmsg, rndc_parm->sockfd, tsig_key);
        if(ISOK(ret))
        {
            if(ISOK(ret = rndc_recv_process(&rndcmsg, server_rndc_recv_process_callback, NULL)))
            {
                // use the value
                log_debug("rndc_command: %s", STRNULL(rndcmsg.type_value));
            }
            rndc_disconnect(&rndcmsg);
        }
        else
        {
            socketclose_ex(rndc_parm->sockfd);
        }
    }
    else
    {
        socketclose_ex(rndc_parm->sockfd);
    }

    ZFREE_OBJECT(rndc_parm);

#if DEBUG
    log_debug("rndc: end");
#endif
}

void        tcp_manager_accept_epoll_wake_all();

static void server_rndc_worker_wakeup(struct service_s *desc)
{
    (void)desc;

    for(uint_fast32_t i = 0; i < desc->worker_count; ++i)
    {
        struct service_worker_s  *worker = &desc->worker[i];
        network_thread_context_t *ctx = &server_rndc_data.contexts[worker->worker_index];
        log_debug("server_dns_tls_worker_wakeup: socket %i", ctx->base.sockfd);
        socketclose_ex(ctx->base.sockfd);
    }
}

static int server_rndc_worker_thread(struct service_worker_s *worker)
{
    network_thread_context_t *ctx = &server_rndc_data.contexts[worker->worker_index];

    ctx->base.idr = thread_self();

    int sockfd = ctx->base.sockfd;

    log_debug("server_rndc_worker_thread(%i, %i): started", ctx->base.idx, sockfd);

    socketaddress_t sa;
    socklen_t       sa_len = sizeof(sa);
    getsockname(sockfd, &sa.sa, &sa_len);
    log_info("waiting to accept connections for %{sockaddr}", &sa);

    while(service_should_run(worker))
    {
        socketaddress_t sa;
        socklen_t       sa_len = sizeof(sa);

        int             clientfd = accept_ex(sockfd, &sa.sa, &sa_len);

        if(clientfd >= 0)
        {
            error_state_clear(&server_rndc_error_state, MODULE_MSG_HANDLE, MSG_NOTICE, "rndc: accept call");

            log_debug("server_rndc_accept: scheduling job");

            server_rndc_thread_parm *parm = NULL;
            ZALLOC_OBJECT_OR_DIE(parm, server_rndc_thread_parm, TPROCPRM_TAG);
            parm->ctx = ctx; // server fd to find the ip back
            parm->sockfd = clientfd;

            thread_pool_enqueue_call(server_rndc_thread_pool, server_rndc_thread, parm, NULL, "server_rndc_thread_start");
        }
        else
        {
            int ret = ERRNO_ERROR;
            if(error_state_log(&server_rndc_error_state, ret))
            {
                log_err("rndc: accept returned %r", MAKE_ERRNO_ERROR(ret));
            }

            log_debug("server_rndc_accept: %r", ret);
        }
    }

#if DEBUG
    log_debug("server_rndc_worker_thread(%i, %i): stopped", ctx->base.idx, sockfd);
#endif
    return SUCCESS;
}

static ya_result server_rndc_deconfigure(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rndc_data));
    (void)server;

    if(!rndc_server_config.enabled)
    {
        return SUCCESS;
    }

    service_stop(&server_rndc_data.service_handler);
    service_finalise(&server_rndc_data.service_handler);

    server_context_socket_close_multiple(server_rndc_data.sockets, server_rndc_data.socket_count);
    free(server_rndc_data.sockets);
    server_rndc_data.sockets = NULL;
    server_rndc_data.socket_count = 0;

    if(server_rndc_thread_pool != NULL)
    {
        thread_pool_destroy(server_rndc_thread_pool);
        server_rndc_thread_pool = NULL;
    }

    axfr_process_finalise();
    return SUCCESS;
}

static ya_result server_rndc_configure(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rndc_data));

    if(server->data != NULL)
    {
        // return INVALID_STATE_ERROR;
    }

    if(!rndc_server_config.enabled)
    {
        return SUCCESS;
    }

    ya_result      ret;
    uint32_t       rndc_interface_count = host_address_count(rndc_server_config.listen);
    const uint32_t worker_per_interface = 1; // <---------------------------- ONE worker per interface
    int            socket_count = host_address_count(rndc_server_config.listen) * worker_per_interface;
    if(socket_count <= 0)
    {
        return INVALID_STATE_ERROR;
    }
    int *sockets;

    MALLOC_OBJECT_ARRAY_OR_DIE(sockets, int, socket_count, SOCKET_TAG);

    int socket_index = 0;
    for(host_address_t *ha = rndc_server_config.listen; ha != NULL; ha = ha->next, ++socket_index)
    {
        struct addrinfo *addrinfo = NULL;

        if(FAIL(ret = host_address2addrinfo(ha, &addrinfo)) || FAIL(ret = server_context_socket_open_bind_multiple(addrinfo, SOCK_STREAM, true, &sockets[socket_index * worker_per_interface], worker_per_interface)))
        {
            server_context_socket_close_multiple(sockets, socket_index * worker_per_interface);
            free(sockets);
            return ret;
        }

        free(addrinfo);
    }

    if((server_rndc_thread_pool == NULL) && (rndc_server_config.queries_max > 0))
    {
        uint32_t max_thread_pool_size = thread_pool_get_max_thread_per_pool_limit();
        if(max_thread_pool_size < (uint32_t)rndc_server_config.queries_max)
        {
            log_warn("updating the maximum thread pool size to match the number of rndc queries (from %i to %i)", max_thread_pool_size, rndc_server_config.queries_max);
            thread_pool_set_max_thread_per_pool_limit(rndc_server_config.queries_max);
        }

        server_rndc_thread_pool = thread_pool_init_ex(rndc_server_config.queries_max, rndc_server_config.queries_max * 2, "rndc");

        if(server_rndc_thread_pool == NULL)
        {
            log_err("rndc thread pool init failed");

            server_context_socket_close_multiple(sockets, rndc_interface_count);
            free(sockets);
            return THREAD_CREATION_ERROR;
        }
    }

    server_rndc_data.sockets = sockets;
    server_rndc_data.socket_count = socket_count;
    ret = service_init_ex2(&server_rndc_data.service_handler, server_rndc_worker_thread, server_rndc_worker_wakeup, "rndc", socket_count);

    if(ISOK(ret))
    {
        MALLOC_OBJECT_ARRAY_OR_DIE(server_rndc_data.contexts, network_thread_context_t, socket_count, NETTHCTX_TAG);

        for(int_fast32_t i = 0; i < socket_count; ++i)
        {
            struct service_worker_s *worker = service_get_worker(&server_rndc_data.service_handler, i);
            if(worker != NULL)
            {
                server_rndc_thread_context_init(&server_rndc_data.contexts[i], worker, i);
            }
        }

        server->data = &server_rndc_data;
    }
    else
    {
        server_rndc_deconfigure(server);
    }

    return ret;
}

static ya_result server_rndc_start(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rndc_data));
    (void)server;

    if(!rndc_server_config.enabled)
    {
        return SUCCESS;
    }

    ya_result ret;
    ret = service_start(&server_rndc_data.service_handler);
    return ret;
}

static ya_result server_rndc_join(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rndc_data));
    (void)server;

    if(!rndc_server_config.enabled)
    {
        return SUCCESS;
    }

    ya_result ret;
    ret = service_wait(&server_rndc_data.service_handler);
    return ret;
}

static ya_result server_rndc_stop(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rndc_data));
    (void)server;

    if(!rndc_server_config.enabled)
    {
        return SUCCESS;
    }

    ya_result ret;
    ret = service_stop(&server_rndc_data.service_handler);
    return ret;
}

static ya_result server_rndc_finalise(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rndc_data));

    if(!rndc_server_config.enabled)
    {
        return SUCCESS;
    }

    network_server_t uninitialised = NETWORK_SERVICE_UNINITIALISED;
    *server = uninitialised;
    return 0;
}

static ya_result server_rndc_state(network_server_t *server)
{
    (void)server;
    return 0;
}

static const char                        *server_rndc_long_name() { return "rndc server"; }

static const struct network_server_vtbl_s server_rndc_vtbl = {server_rndc_configure,
                                                              server_rndc_start,
                                                              server_rndc_join,
                                                              server_rndc_stop, // could return instantly, only waits in finalise & start
                                                              server_rndc_deconfigure,
                                                              server_rndc_finalise,
                                                              server_rndc_state,
                                                              server_rndc_long_name};

/**
 * Initialises the object, not the server
 */

ya_result server_rndc_init_instance(network_server_t *server)
{
    server_rndc_data.thread_count_by_address = MAX(g_config->thread_count_by_address, 1);
    server->data = &server_rndc_data;
    server->vtbl = &server_rndc_vtbl;
    return SUCCESS;
}

network_server_t *server_rndc_new_instance()
{
    network_server_t *server;
    ZALLOC_OBJECT_OR_DIE(server, network_server_t, SVRINSTS_TAG);
    if(ISOK(server_rndc_init_instance(server)))
    {
        return server;
    }
    else
    {
        ZFREE_OBJECT(server);
        return NULL;
    }
}

#endif // HAS_CTRL

/**
 * @}
 */
