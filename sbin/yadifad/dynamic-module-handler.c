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

#include "server-config.h"

#define DYNAMIC_MODULE_HANDLER_C 1

#include <dlfcn.h>

#include <dnscore/logger.h>
#include <dnscore/parsing.h>
#include <dnscore/mutex.h>
#include <dnscore/ptr_set.h>

#include "confs.h"

struct dynamic_module_interface_chain;
struct dynamic_module_dnskey_interface_chain;

struct dynamic_module_interface_chain *g_dynamic_module_interface_chain = NULL;
struct dynamic_module_dnskey_interface_chain *g_dynamic_module_dnskey_interface_chain = NULL;
struct dynamic_module_statistics_interface_chain *g_dynamic_module_statistics_interface_chain = NULL;

#include "dynamic-module-handler.h"
#include "server.h"

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

logger_handle *g_module_logger = LOGGER_HANDLE_SINK;
#define CALLER_NAME "yadifad"

struct dynamic_module
{
    void *so;
    dynamic_module_interface_init *entry_point;
    char *path;
    struct dynamic_module_settings_args args;
    int rc;
};

struct dynamic_module_interface_chain
{
    struct dynamic_module_interface_chain *next;
    struct dynamic_module *module;
    struct dynamic_module_interface itf;
};

struct dynamic_module_dnskey_interface_chain
{
    struct dynamic_module_dnskey_interface_chain *next;
    struct dynamic_module *module;
    struct dynamic_module_dnskey_interface itf;
};


struct dynamic_module_statistics_interface_chain
{
    struct dynamic_module_statistics_interface_chain *next;
    struct dynamic_module *module;
    struct dynamic_module_statistics_interface itf;
};

static ptr_set dynamic_module_set = PTR_SET_ASCIIZ_EMPTY;
static mutex_t dynamic_module_mtx = MUTEX_INITIALIZER;

/**
 * Trivial.
 */

ya_result
dynamic_module_handler_init()
{
    return SUCCESS;
}

/**
 * Trivial.
 */

ya_result
dynamic_module_handler_finalize()
{
    return SUCCESS;
}

/**
 * Loads a module given its full path name (with luck relative may work too ... so yes: full path)
 * Don't forget to take into account the choot.
 * 
 * Modules should only be loaded AFTER the last fork.
 */

ya_result
dynamic_module_handler_load(int argc, const char **argv)
{
    if(argc <= 0)
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    const char *shared_object_path = argv[0];
    
    log_debug("module: checking module '%s'", shared_object_path);
    
    ptr_node *node;
    mutex_lock(&dynamic_module_mtx);
    node = ptr_set_find(&dynamic_module_set, shared_object_path);
    
    if(node != NULL)
    {
        // already known
        
        mutex_unlock(&dynamic_module_mtx);
        return SUCCESS;
    }
    
    void *so = dlopen(shared_object_path, RTLD_NOLOAD);
    
    if(so == NULL)
    {    
        so = dlopen(shared_object_path, RTLD_NOW/*|RTDL_LOCAL*/);
        
        if(so != NULL)
        {
            log_info("module: '%s': loaded", shared_object_path);
            
            // loaded
            
            // try to find the entry point
            
            void *f = dlsym(so, "module_interface_init");
            
            if(f == NULL)
            {
                static const char suffix[] = "_interface_init";
                char module_interface_init_name[48];
                
                // get the last '/'
                const char *start = parse_skip_until_chars(shared_object_path, "/", 1);
                // get the first '.'
                const char *stop = parse_skip_until_chars(stop, ".", 1);
                
                if(stop == start)
                {
                    stop = start + strlen(start);
                }
                
                size_t len = stop - start;
                
                if(len <= sizeof(module_interface_init_name) - sizeof(suffix))
                {
                    memcpy(module_interface_init_name, start, len);
                    memcpy(&module_interface_init_name[len], suffix, sizeof(suffix));
                    
                    f = dlsym(so, module_interface_init_name);
                }
            }
            
            if(f == NULL)
            {
                mutex_unlock(&dynamic_module_mtx);
                
                log_err("module: '%s': failed to find the entry point", shared_object_path);
                dlclose(so);
                return INVALID_STATE_ERROR;
            }
            
            log_debug("module: '%s': got the entry point", shared_object_path);
            
            struct dynamic_module *module;
            MALLOC_OBJECT_OR_DIE(module, struct dynamic_module, GENERIC_TAG);
            MALLOC_OBJECT_ARRAY_OR_DIE(module->args.argv, char*, argc, GENERIC_TAG);
            module->so = so;
            module->entry_point = (dynamic_module_interface_init*)f;
            module->path = strdup(shared_object_path);
            module->rc = 0;
            
            struct dynamic_module_settings_args *args = &module->args;
            args->sizeof_struct = sizeof(*args);
            args->argc = argc;
            memcpy(args->argv, argv, argc * sizeof(char*));
            args->data_path = g_config->data_path;
            
            union dynamic_module_interfaces itfu;
            
            // DYNAMIC_MODULE_INTERFACE_ID
            {
                itfu.interface.sizeof_struct = sizeof(itfu.interface);
                
                if(ISOK(module->entry_point(DYNAMIC_MODULE_INTERFACE_ID, &itfu)))
                {
                    // interface is supported
                    log_debug("module: '%s': dynamic_module_interface is supported", shared_object_path);
                    
                    if(itfu.interface.on_startup == NULL)
                    {
                        itfu.interface.on_startup = dynamic_module_startup_callback_nop;
                    }
                    
                    if(itfu.interface.on_settings_updated == NULL)
                    {
                        itfu.interface.on_settings_updated = dynamic_module_settings_callback_nop;
                    }
                    
                    if(itfu.interface.on_shutdown == NULL)
                    {
                        itfu.interface.on_shutdown = dynamic_module_shutdown_callback_nop;
                    }
                    
                    struct dynamic_module_interface_chain *ic;
                    MALLOC_OBJECT_OR_DIE(ic, struct dynamic_module_interface_chain, GENERIC_TAG);
                    ic->next = g_dynamic_module_interface_chain;
                    ic->module = module;
                    ++module->rc;
                    memcpy(&ic->itf, &itfu.interface, sizeof(itfu.interface));
                    g_dynamic_module_interface_chain = ic;                    
                }
                else
                {
                    log_debug("module: '%s': dynamic_module_interface is not supported", shared_object_path);
                }
            }
            
            // DYNAMIC_MODULE_DNSKEY_INTERFACE_ID
            {
                itfu.dnskey_interface.sizeof_struct = sizeof(itfu.dnskey_interface);
                
                if(ISOK(module->entry_point(DYNAMIC_MODULE_DNSKEY_INTERFACE_ID, &itfu)))
                {
                    // interface is supported
                    log_debug("module: '%s': dynamic_module_dnskey_interface is supported", shared_object_path);
                    
                    if(itfu.dnskey_interface.on_dnskey_created == NULL)
                    {
                        itfu.dnskey_interface.on_dnskey_created = dynamic_module_on_dnskey_callback_nop;
                    }
                    
                    if(itfu.dnskey_interface.on_dnskey_publish == NULL)
                    {
                        itfu.dnskey_interface.on_dnskey_publish = dynamic_module_on_dnskey_callback_nop;
                    }
                    
                    if(itfu.dnskey_interface.on_dnskey_activate == NULL)
                    {
                        itfu.dnskey_interface.on_dnskey_activate = dynamic_module_on_dnskey_callback_nop;
                    }
                    
                    if(itfu.dnskey_interface.on_dnskey_revoke == NULL)
                    {
                        itfu.dnskey_interface.on_dnskey_revoke = dynamic_module_on_dnskey_callback_nop;
                    }
                    
                    if(itfu.dnskey_interface.on_dnskey_inactive == NULL)
                    {
                        itfu.dnskey_interface.on_dnskey_inactive = dynamic_module_on_dnskey_callback_nop;
                    }
                    
                    if(itfu.dnskey_interface.on_dnskey_delete == NULL)
                    {
                        itfu.dnskey_interface.on_dnskey_delete = dynamic_module_on_dnskey_callback_nop;
                    }
                    
                    struct dynamic_module_dnskey_interface_chain *ic;
                    MALLOC_OBJECT_OR_DIE(ic, struct dynamic_module_dnskey_interface_chain, GENERIC_TAG);
                    ic->next = g_dynamic_module_dnskey_interface_chain;
                    ic->module = module;
                    ++module->rc;
                    memcpy(&ic->itf, &itfu.dnskey_interface, sizeof(itfu.dnskey_interface));
                    g_dynamic_module_dnskey_interface_chain = ic;
                }
                else
                {
                    log_debug("module: '%s': dynamic_module_dnskey_interface is not supported", shared_object_path);
                }
            }

            // DYNAMIC_MODULE_STATISTICS_ID
            {
                itfu.statistics_interface.sizeof_struct = sizeof(itfu.statistics_interface);
                
                if(ISOK(module->entry_point(DYNAMIC_MODULE_STATISTICS_ID, &itfu)))
                {
                    // interface is supported
                    log_debug("module: '%s': dynamic_module_statistics_interface is supported", shared_object_path);
                    
                    if(itfu.statistics_interface.on_statistics_update == NULL)
                    {
                        itfu.statistics_interface.on_statistics_update = dynamic_module_statistics_callback_nop;
                    }
                    
                    struct dynamic_module_statistics_interface_chain *ic;
                    MALLOC_OBJECT_OR_DIE(ic, struct dynamic_module_statistics_interface_chain, GENERIC_TAG);
                    ic->next = g_dynamic_module_statistics_interface_chain;
                    ic->module = module;
                    ++module->rc;
                    memcpy(&ic->itf, &itfu.statistics_interface, sizeof(itfu.statistics_interface));
                    g_dynamic_module_statistics_interface_chain = ic;
                }
                else
                {
                    log_debug("module: '%s': dynamic_module_statistics_interface is not supported", shared_object_path);
                }
            }
            
            node = ptr_set_insert(&dynamic_module_set, module->path);
            node->key = module->path;
            node->value = module;
            
            mutex_unlock(&dynamic_module_mtx);
            
            return SUCCESS;
        }
        else
        {
            // failed to load

            ret = ERRNO_ERROR;
            
            mutex_unlock(&dynamic_module_mtx);
            
            log_err("module: '%s': failed to load: %s", shared_object_path, dlerror());
            
            return ret;
        }
    }
    else
    {
        // already loaded, somehow

        ret = ERRNO_ERROR;
        
        mutex_unlock(&dynamic_module_mtx);
        
        log_err("module: '%s': already loaded (albeit not through this handler)", shared_object_path);
        
        return ret;
    }
}

ya_result
dynamic_module_handler_load_from_command(const char *command)
{
    //const char *command_limit = &command[strlen(command)];
    int argc = 0;
    char *argv[128];
    char tmp[PATH_MAX];
    
    s32 n;
    
    for(;;)
    {
        if(argc == sizeof(argv) / sizeof(char*))
        {
            n = -1; // too many parameters
            break;
        }
        
        n = parse_next_token(tmp, sizeof(tmp), command, " \t");

        if(n <= 0)
        {
            break;
        }
        
        command += n;
        
        command = parse_skip_spaces(command);
        
        argv[argc++] = strdup(tmp);
    }
    
    ya_result ret;
    
    if(n >= 0)
    {
        ret = dynamic_module_handler_load(argc, (const char**)argv);
    }
    else
    {
        ret = INVALID_ARGUMENT_ERROR; // too many parameters
    }
    
    for(int i = 0; i < argc; ++i)
    {
        free(argv[i]);
    }
    
    return ret;
}

// interface

void
dynamic_module_startup()
{
    struct dynamic_module_interface_chain *dc = g_dynamic_module_interface_chain;
    while(dc != NULL)
    {
        dc->itf.on_startup();
        dc = dc->next;
    }
}

void
dynamic_module_settings()
{
    struct dynamic_module_interface_chain *dc = g_dynamic_module_interface_chain;
    if(dc != NULL)
    {
        do
        {
            dc->itf.on_settings_updated(&dc->module->args);
            dc = dc->next;
        }
        while(dc != NULL);
    }
}

void
dynamic_module_shutdown()
{
    struct dynamic_module_interface_chain *dc = g_dynamic_module_interface_chain;
    while(dc != NULL)
    {
        dc->itf.on_shutdown();
        dc = dc->next;
    }
}

// dnskey_interface

ya_result
dynamic_module_on_dnskey_args_init(struct dynamic_module_on_dnskey_args *args, const dnssec_key *key, void *buffer, size_t buffer_size)
{
    args->sizeof_struct = sizeof(*args);
    args->caller_name = CALLER_NAME;
    args->origin = dnskey_get_domain(key);
    args->rdata_size = key->vtbl->dnssec_key_rdatasize(key);

    if(args->rdata_size > buffer_size)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    key->vtbl->dnssec_key_writerdata(key, buffer);
    args->rdata = buffer;
    args->epoch_created = dnskey_get_created_epoch(key);
    args->epoch_publish = dnskey_get_publish_epoch(key);
    args->epoch_activate = dnskey_get_activate_epoch(key);
    args->epoch_revoke = 0;
    args->epoch_inactive = dnskey_get_inactive_epoch(key);
    args->epoch_delete = dnskey_get_delete_epoch(key);
    args->flags = dnskey_get_flags(key);
    args->tag = dnskey_get_tag_const(key);
    args->algorithm = dnskey_get_algorithm(key);
    
    return SUCCESS;
}

void
dynamic_module_on_dnskey_args_finalize(struct dynamic_module_on_dnskey_args *args)
{
#if DEBUG
    ZEROMEMORY(args, sizeof(*args));
#else
    (void)args;
#endif
}

void
dynamic_module_on_dnskey_created(const dnssec_key *key)
{
    struct dynamic_module_dnskey_interface_chain *dc = g_dynamic_module_dnskey_interface_chain;
    if(dc != NULL)
    {
        struct dynamic_module_on_dnskey_args args;
        char buffer[2048];
        
        if(ISOK(dynamic_module_on_dnskey_args_init(&args, key, buffer, sizeof(buffer))))
        {        
            do
            {
                dc->itf.on_dnskey_created(&args);
                dc = dc->next;
            }
            while(dc != NULL);

            dynamic_module_on_dnskey_args_finalize(&args);
        }
    }
}

void
dynamic_module_on_dnskey_publish(const dnssec_key *key)
{
    struct dynamic_module_dnskey_interface_chain *dc = g_dynamic_module_dnskey_interface_chain;
    if(dc != NULL)
    {
        struct dynamic_module_on_dnskey_args args;
        char buffer[2048];
        
        dynamic_module_on_dnskey_args_init(&args, key, buffer, sizeof(buffer));
        
        do
        {
            dc->itf.on_dnskey_publish(&args);
            dc = dc->next;
        }
        while(dc != NULL);
        
        dynamic_module_on_dnskey_args_finalize(&args);
    }
}

void
dynamic_module_on_dnskey_activate(const dnssec_key *key)
{
    struct dynamic_module_dnskey_interface_chain *dc = g_dynamic_module_dnskey_interface_chain;
    if(dc != NULL)
    {
        struct dynamic_module_on_dnskey_args args;
        char buffer[2048];
        
        dynamic_module_on_dnskey_args_init(&args, key, buffer, sizeof(buffer));
        
        do
        {
            dc->itf.on_dnskey_activate(&args);
            dc = dc->next;
        }
        while(dc != NULL);
        
        dynamic_module_on_dnskey_args_finalize(&args);
    }
}

void
dynamic_module_on_dnskey_revoke(const dnssec_key *key)
{
    struct dynamic_module_dnskey_interface_chain *dc = g_dynamic_module_dnskey_interface_chain;
    if(dc != NULL)
    {
        struct dynamic_module_on_dnskey_args args;
        char buffer[2048];
        
        dynamic_module_on_dnskey_args_init(&args, key, buffer, sizeof(buffer));
        
        do
        {
            dc->itf.on_dnskey_revoke(&args);
            dc = dc->next;
        }
        while(dc != NULL);
        
        dynamic_module_on_dnskey_args_finalize(&args);
    }
}

void
dynamic_module_on_dnskey_inactive(const dnssec_key *key)
{
    struct dynamic_module_dnskey_interface_chain *dc = g_dynamic_module_dnskey_interface_chain;
    if(dc != NULL)
    {
        struct dynamic_module_on_dnskey_args args;
        char buffer[2048];
        
        dynamic_module_on_dnskey_args_init(&args, key, buffer, sizeof(buffer));
        
        do
        {
            dc->itf.on_dnskey_inactive(&args);
            dc = dc->next;
        }
        while(dc != NULL);
        
        dynamic_module_on_dnskey_args_finalize(&args);
    }
}

void
dynamic_module_on_dnskey_delete(const dnssec_key *key)
{
    struct dynamic_module_dnskey_interface_chain *dc = g_dynamic_module_dnskey_interface_chain;
    if(dc != NULL)
    {
        struct dynamic_module_on_dnskey_args args;
        char buffer[2048];
        
        dynamic_module_on_dnskey_args_init(&args, key, buffer, sizeof(buffer));
        
        do
        {
            dc->itf.on_dnskey_delete(&args);
            dc = dc->next;
        }
        while(dc != NULL);
        
        dynamic_module_on_dnskey_args_finalize(&args);
    }
}

void
dynamic_module_on_statistics_update(server_statistics_t *st, u64 epoch)
{
    struct dynamic_module_statistics_interface_chain *dc = g_dynamic_module_statistics_interface_chain;
    
    if(dc != NULL)
    {
        struct dynamic_module_statistics_args args;
        struct dynamic_module_statistics_args_buffers args_buffers;

        args.sizeof_struct = sizeof(args);
        args.epoch_us = epoch;
        
        args.input_loop_count = st->input_loop_count;
        args.input_timeout_count = st->input_timeout_count;
        args.loop_rate_counter = st->loop_rate_counter;
        args.loop_rate_elapsed = st->loop_rate_elapsed;
        
        args.udp_input_count = st->udp_input_count;
        args.udp_queries_count = st->udp_queries_count;
        args.udp_notify_input_count = st->udp_notify_input_count;
        args.udp_updates_count = st->udp_updates_count;
        args.udp_dropped_count = st->udp_dropped_count;
        args.udp_output_size_total = st->udp_output_size_total;
        args.udp_undefined_count = st->udp_undefined_count;
        args.udp_referrals_count = st->udp_referrals_count;
        
        args.tcp_input_count = st->tcp_input_count;
        args.tcp_queries_count = st->tcp_queries_count;
        args.tcp_notify_input_count = st->tcp_notify_input_count;
        args.tcp_updates_count = st->tcp_updates_count;
        args.tcp_dropped_count = st->tcp_dropped_count;
        args.tcp_output_size_total = st->tcp_output_size_total;
        args.tcp_undefined_count = st->tcp_undefined_count;
        args.tcp_referrals_count = st->tcp_referrals_count;
        
        args.tcp_axfr_count = st->tcp_axfr_count;
        args.tcp_ixfr_count = st->tcp_ixfr_count;
        args.tcp_overflow_count = st->tcp_overflow_count;
        
        args.rrl_slip = st->rrl_slip;
        args.rrl_drop = st->rrl_drop;
        
        args.udp_rcode_count = args_buffers.udp_rcode_buffer;
        args.tcp_rcode_count = args_buffers.tcp_rcode_buffer;
        args.udp_tsig_rcode_count = args_buffers.udp_tsig_rcode_buffer;
        args.tcp_tsig_rcode_count = args_buffers.tcp_tsig_rcode_buffer;
        
        args.rcode_count_size = DYNAMIC_MODULE_STATISTICS_RCODE_COUNT;
        args.tsig_rcode_count_size = DYNAMIC_MODULE_STATISTICS_TSIG_RCODE_COUNT;
        
        do
        {
            dc->itf.on_statistics_update(&args);
            dc = dc->next;
        }
        while(dc != NULL);
    }
}

/**
 * @}
 */
