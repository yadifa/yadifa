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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include <stdint.h>

/**
 * Modules are meant for easy integration with existing infrastructure beyond the scope of what a name server has to do
 * 
 * The basic rules for the module:
 *
 * _ check sizeof_struct field to match what you expect
 * _ never cast a const, if you do you could as well call abort() and be done with it
 * _ you don't own anything and can expect all pointer values to be destroyed at the instant you return
 * _ be quick : if you need to spend time (a millisecond is an insane amount of time), use a queue/thread and give up if the queue is full
 * _ there are threads : you can fork() => exec(), but you cannot simply fork().
 * _ be instance-aware: more than one instance of the module could be running at the same time, not all instances 
 * 
 * Failing to respect these rules will have detrimental consequences on yadifad
 * 
 * There is no plan yet to support "unload" as it may be very complex and is not needed for our requirements.
 * Once a module is loaded, it's until shutdown.
 */

#define DYNAMIC_MODULE_INTERFACE_ID 0

struct dynamic_module_settings_args
{
    size_t sizeof_struct;     // sizeof(struct dynamic_module_on_dnskey_created_args)
    char **argv;              // the parameters given to the module
    char *data_path;          // the data path as configured for yadifad
    int argc;                 // the parameters count given to the module
};

typedef void dynamic_module_startup_callback();
typedef void dynamic_module_settings_callback(const struct dynamic_module_settings_args *);
typedef void dynamic_module_shutdown_callback();

static inline void dynamic_module_startup_callback_nop() {}
static inline void dynamic_module_settings_callback_nop(const struct dynamic_module_settings_args *args) {(void) args;}
static inline void dynamic_module_shutdown_callback_nop() {}

struct dynamic_module_interface
{
    size_t sizeof_struct;
    dynamic_module_startup_callback *on_startup;
    dynamic_module_settings_callback *on_settings_updated;
    dynamic_module_shutdown_callback *on_shutdown;
};

// no: no typedef,  thanks

#define DYNAMIC_MODULE_DNSKEY_INTERFACE_ID 1

struct dynamic_module_on_dnskey_args
{
    size_t sizeof_struct;     // sizeof(struct dynamic_module_on_dnskey_args)
    
    const char *caller_name;        // the name of the caller
    const uint8_t *origin;          // the origin of the key
    const uint8_t *rdata;           // the rdata record 
    
    time_t epoch_created;
    time_t epoch_publish;           // if not published yet, at that time, it needs to be added in the zone
    time_t epoch_activate;          // if not activated yet, at that time, it needs to be used for signatures
    time_t epoch_revoke;            // not handled yet
    time_t epoch_inactive;          // if active, at that time, it needs to stop being used for signatures
    time_t epoch_delete;            // if still in the zone, at that time, it needs to be removed from the zone
    
    uint16_t rdata_size;    
    uint16_t flags;                 // the flags (network endian)
    uint16_t tag;                   //
    uint8_t algorithm;              // dnskey algorithm
};

// no: no typedef,  thanks

typedef void dynamic_module_on_dnskey_callback(const struct dynamic_module_on_dnskey_args *);

static inline void dynamic_module_on_dnskey_callback_nop(const struct dynamic_module_on_dnskey_args *args) {(void)args;}

struct dynamic_module_dnskey_interface
{
    size_t sizeof_struct;
    
    dynamic_module_on_dnskey_callback *on_dnskey_created;
    dynamic_module_on_dnskey_callback *on_dnskey_publish;
    dynamic_module_on_dnskey_callback *on_dnskey_activate;
    dynamic_module_on_dnskey_callback *on_dnskey_revoke;
    dynamic_module_on_dnskey_callback *on_dnskey_inactive;
    dynamic_module_on_dnskey_callback *on_dnskey_delete;
};

// no: no typedef,  thanks

#define DYNAMIC_MODULE_STATISTICS_ID 2

enum dynamic_module_rcode_index
{
    NOERROR = 0,    // RCODE
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    YXRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10,
    BADVERS = 16,   // OPT
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22
};

enum dynamic_module_tsig_rcode_index
{
    BADSIG = 16 - 16,    // TSIG
    BADKEY = 17 - 16,
    BADTIME = 18 - 16
};

struct dynamic_module_statistics_args
{
    size_t sizeof_struct;
    
    uint64_t epoch_us;                  // epoch in microseconds
    
    uint64_t input_loop_count;
    uint64_t input_timeout_count;

    uint64_t loop_rate_counter;
    uint64_t loop_rate_elapsed;
    
    /* udp */

    uint64_t udp_input_count;
    uint64_t udp_queries_count;
    uint64_t udp_notify_input_count;
    uint64_t udp_updates_count;
    uint64_t udp_dropped_count;
    uint64_t udp_output_size_total;
    uint64_t udp_undefined_count;
    uint64_t udp_referrals_count;
    
    /* tcp */

    uint64_t tcp_input_count;    
    uint64_t tcp_queries_count;
    uint64_t tcp_notify_input_count;
    uint64_t tcp_updates_count;
    uint64_t tcp_dropped_count;
    uint64_t tcp_output_size_total;
    uint64_t tcp_undefined_count;
    uint64_t tcp_referrals_count;
    
    uint64_t tcp_axfr_count;
    uint64_t tcp_ixfr_count;
    uint64_t tcp_overflow_count;    
    
    /* rrl */
    
    uint64_t rrl_slip;
    uint64_t rrl_drop;
    
    /* answers RCODEs */
    
    uint64_t *udp_rcode_count;
    uint64_t *tcp_rcode_count;
    uint64_t *udp_tsig_rcode_count;
    uint64_t *tcp_tsig_rcode_count;
    uint32_t rcode_count_size;
    uint32_t tsig_rcode_count_size;
};

// no: no typedef,  thanks

typedef void dynamic_module_statistics_callback(const struct dynamic_module_statistics_args *);

static inline void dynamic_module_statistics_callback_nop(const struct dynamic_module_statistics_args *args) {(void)args;}

struct dynamic_module_statistics_interface
{
    size_t sizeof_struct;
    
    dynamic_module_statistics_callback *on_statistics_update;
};

// no: no typedef,  thanks

union dynamic_module_interfaces
{
    struct dynamic_module_interface interface;
    struct dynamic_module_dnskey_interface dnskey_interface;
    struct dynamic_module_statistics_interface statistics_interface;
};

/**
 * The module will be called with this signature to return the relevant interface.
 * 
 * Typically, at least id=0 will be called and should be returned (or not)
 * 
 * The entry point will have to be specified at configuration or tried, in order, as:
 * 
 * _ module_interface_init
 * _ "shared object file name with '-' replaced by '_'" + _interface_init
 */

typedef int dynamic_module_interface_init(int id, union dynamic_module_interfaces *out_interface);

/**
 * @}
 */
