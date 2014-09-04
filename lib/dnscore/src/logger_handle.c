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
/** @defgroup logger Logging functions
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <stdio.h>
#include <stdlib.h>

#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include <pthread.h>

#include "dnscore/logger_channel_stream.h"

#include "dnscore/ptr_vector.h"

#include "dnscore/file_output_stream.h"
#include "dnscore/bytearray_output_stream.h"

#include "dnscore/format.h"
#include "dnscore/dnscore.h"

#include "dnscore/async.h"

#include "dnscore/treeset.h"

#define LOGGER_HANDLE_TAG 0x4c444e48474f4c /* LOGHNDL */


#define DEBUG_LOG_HANDLER 0
#define DEBUG_LOG_MESSAGES 0

#if DEBUG_LOG_MESSAGES == 1
#pragma message("DEBUG_LOG_MESSAGES")
#endif

#define COLUMN_SEPARATOR " | "
#define COLUMN_SEPARATOR_SIZE 3

#define LOGGER_HANDLE_FORMATTED_LENGTH 8

#define MODULE_MSG_HANDLE g_system_logger
extern logger_handle *g_system_logger;

#define LOGRMSG_TAG 0x47534d52474f4c
#define LOGRTEXT_TAG 0x5458455452474f4c
    
struct logger_handle;

#define LOGGER_MESSAGE_TYPE_TEXT                        0 // send a text to output
#define LOGGER_MESSAGE_TYPE_STOP                        1 // stop the service
#define LOGGER_MESSAGE_TYPE_CHANNEL_FLUSH_ALL           2 // flush all channels
#define LOGGER_MESSAGE_TYPE_CHANNEL_REOPEN_ALL          3 // reopen all channels
#define LOGGER_MESSAGE_TYPE_CHANNEL_CLOSE_ALL          12 // close all channels
#define LOGGER_MESSAGE_TYPE_IGNORE                      4 // no operation

#define LOGGER_MESSAGE_TYPE_CHANNEL_GET_USAGE_COUNT     5 // grabs the number of uses of the channel, or -1 if not registered
#define LOGGER_MESSAGE_TYPE_CHANNEL_REGISTER            6 // register a new channel
#define LOGGER_MESSAGE_TYPE_CHANNEL_UNREGISTER          7 // unregister a channel

#define LOGGER_MESSAGE_TYPE_HANDLE_CREATE               8 // open a new handle
#define LOGGER_MESSAGE_TYPE_HANDLE_CLOSE                9 // close a handle
#define LOGGER_MESSAGE_TYPE_HANDLE_NAME_ADD_CHANNEL    10 // add a channel to a handle identified by its name
#define LOGGER_MESSAGE_TYPE_HANDLE_NAME_REMOVE_CHANNEL 11 // remove a channel from a handle identified by its name

struct logger_message_text_s
{
    u8  type;                       //  0  0
    u8  level;                      // 
    u16 flags;                      // 
    u32 text_length;                //  align 64
    
    struct logger_handle *handle;   //  8  8
    
    u8 *text;                       // 12 16
    
    struct timeval tv;              // 16 24
    const u8* prefix;               // 24 32
    u16 prefix_length;              // 28 40
    s16 rc;                         // 30 42   reference count for the repeats
#ifdef DEBUG
    pid_t pid;                      // 32 44
    pthread_t thread_id;            // 36 48
#endif
                                    // 40 56
};

struct logger_message_channel_flush_all_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
};

struct logger_message_channel_reopen_all_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
};

struct logger_message_channel_get_usage_count_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
    const char* channel_name;
    s32 *countp;
};

struct logger_message_channel_register_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
    const char* channel_name;
    struct logger_channel *channel;
};

struct logger_message_channel_unregister_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
    const char* channel_name;
};

/// @note no need for reopen

struct logger_message_stop_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
};

/// @note no need for ignore

struct logger_message_handle_create_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
    const char *logger_name;
    logger_handle **handle_holder;
};

struct logger_message_handle_close_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
    const char *logger_name;
};

struct logger_message_handle_add_channel_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
    const char *logger_name;
    const char *channel_name;
    u16 level;
};

struct logger_message_handle_remove_channel_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
    const char *logger_name;
    const char *channel_name;
};

union logger_message
{
    u8 type;
    struct logger_message_text_s text;
    struct logger_message_stop_s stop;
    // no specific data for ignore
    struct logger_message_channel_flush_all_s channel_flush_all;
    struct logger_message_channel_reopen_all_s channel_reopen_all;
    struct logger_message_channel_get_usage_count_s get_usage_count;
    struct logger_message_channel_register_s channel_register;
    struct logger_message_channel_unregister_s channel_unregister;
    struct logger_message_handle_create_s handle_create;
    struct logger_message_handle_close_s handle_close;
    struct logger_message_handle_add_channel_s handle_add_channel;
    struct logger_message_handle_remove_channel_s handle_remove_channel;
};

typedef union logger_message logger_message;

/// tree set initialised empty with a comparator for ASCIIZ char* keys
static treeset_tree logger_channels = TREESET_ASCIIZ_EMPTY;
static ptr_vector logger_handles = EMPTY_PTR_VECTOR;
static pthread_mutex_t logger_mutex;

static threaded_queue logger_commit_queue = THREADED_QUEUE_NULL;
static pthread_t logger_thread_id = 0;
static u32 exit_level = MSG_CRIT;
static const char acewnid[16 + 1] = "!ACEWNID1234567";

static volatile bool logger_started = FALSE;
static volatile bool logger_initialised = FALSE;
static volatile bool logger_queue_initialised = FALSE;
static volatile bool logger_handle_init_done = FALSE;
static volatile bool logger_reopen_requested = FALSE;
static volatile u8 logger_level = MSG_ALL;

#if DEBUG_LOG_MESSAGES != 0
static smp_int allocated_messages_count = SMP_INT_INITIALIZER;
static time_t allocated_messages_count_stats_time = 0;
#endif

static void logger_handle_trigger_shutdown()
{
    flusherr();
    logger_flush();

    kill(getpid(), SIGINT);
}

/*******************************************************************************
 *
 * Logger message functions
 *  
 *******************************************************************************/

static inline logger_message*
logger_message_alloc()
{
    /// @todo 20140523 edf -- use a better allocation mechanism
    logger_message* message;
    MALLOC_OR_DIE(logger_message*, message, sizeof (logger_message), LOGRMSG_TAG);
    
#if DEBUG_LOG_MESSAGES != 0
    smp_int_inc(&allocated_messages_count);
#endif
    
    return message;
}
static inline void
logger_message_free(logger_message *message)
{
    free(message);
    
#if DEBUG_LOG_MESSAGES != 0
    smp_int_dec(&allocated_messages_count);
#endif
}

/*******************************************************************************
 *
 * Logger handle functions
 *  
 *******************************************************************************/



static ya_result logger_service_handle_remove_channel(logger_handle *handle, const char *channel_name);
static void logger_service_handle_remove_all_channel(logger_handle *handle);

static int
logger_handle_compare(const void* a, const void* b)
{
    logger_handle* ha = *(logger_handle**)a;
    logger_handle* hb = *(logger_handle**)b;
    
    if(ha == hb)
    {
        return 0;
    }

    return strcmp(ha->name, hb->name);
}

static int
logger_handle_compare_match(const void* key, const void* value)
{
    const char* hkey = (const char*)key;
    const logger_handle* hvalue = (const logger_handle*)value;

    return strcmp(hkey, hvalue->name);
}

static void
logger_handle_free(void* ptr)
{
    logger_handle* handle = (logger_handle*)ptr;   
    
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_handle_free(%s@%p)", handle->name, ptr);
    flushout();
#endif
    
    logger_service_handle_remove_all_channel(handle);
    
    for(u8 lvl = 0; lvl < MSG_LEVEL_COUNT; lvl++)
    {
        ptr_vector_destroy(&handle->channels[lvl]);
    }
    
    if(handle->global_reference != NULL)
    {
        *handle->global_reference = NULL;
    }

#ifdef DEBUG
    memset((char*)handle->formatted_name, 0xfe, strlen(handle->formatted_name));
#endif
    free((char*)handle->formatted_name);
#ifdef DEBUG
    memset((char*)handle->name, 0xfe, strlen(handle->name));
#endif
    free((char*)handle->name);
#ifdef DEBUG
    memset(handle, 0xfe, sizeof(logger_handle));
#endif
    free(handle);
}

/*******************************************************************************
 *
 * Logger channel functions
 *  
 *******************************************************************************/

logger_channel*
logger_channel_alloc()
{
    logger_channel* chan;
    
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_channel_alloc()");
    flushout();
#endif

    MALLOC_OR_DIE(logger_channel*, chan, sizeof (logger_channel), 0x4e414843474f4c); /* LOGCHAN */

    chan->data = NULL;
    chan->vtbl = NULL;
    
    /* dummy to avoid a NULL test */
    logger_message* last_message;
    MALLOC_OR_DIE(logger_message*,last_message,sizeof(logger_message), LOGRMSG_TAG);
    last_message->type = LOGGER_MESSAGE_TYPE_TEXT;
    MALLOC_OR_DIE(u8*, last_message->text.text, 1, LOGRTEXT_TAG);
    *last_message->text.text = '\0';
    last_message->text.text_length = 0;
    last_message->text.flags = 0;
    last_message->text.rc = 1;
    
    chan->last_message = last_message;
    chan->last_message_count = 0;
    
    chan->linked_handles = 0;

    return chan;
}

static void
logger_channel_free(logger_channel *channel)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_channel_free(%p), linked to %d", channel, channel->linked_handles);
    flushout();
#endif
    
    assert(channel->linked_handles == 0); // don't yassert
    
    logger_message* last_message = channel->last_message;
    
    if(--last_message->text.rc == 0)
    {
        free(last_message->text.text);
        logger_message_free(last_message);
    }
    
    if(channel->vtbl != NULL)
    {
        logger_channel_close(channel);
    }
        
    free(channel);
}

static logger_channel*
logger_service_channel_get(const char *channel_name)
{   
    logger_channel *channel = NULL;
    
    treeset_node *node = treeset_avl_find(&logger_channels, channel_name);
    if(node != NULL)
    {
        channel = (logger_channel*)node->data;
    }
    
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_channel_get(%s) = %p", channel_name, channel);
    flushout();
#endif
    
    return channel;
}

static ya_result
logger_service_channel_register(const char *channel_name, logger_channel *channel)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_channel_register(%s,%p)", channel_name, channel);
    flushout();
#endif
    
    if(channel->linked_handles != 0)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_service_channel_register(%s,%p) ALREADY LINKED", channel_name, channel);
        flushout();
#endif
        return LOGGER_CHANNEL_HAS_LINKS;
    }
    
    if(logger_service_channel_get(channel_name) != NULL)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_service_channel_register(%s,%p) NAME ALREADY USED", channel_name, channel);
        flushout();
#endif
        return LOGGER_CHANNEL_ALREADY_REGISTERED;
    }
    
    treeset_node *node = treeset_avl_insert(&logger_channels, strdup(channel_name));
    node->data = channel;
    
    return SUCCESS;
}

static ya_result
logger_service_channel_unregister(const char *channel_name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_channel_unregister(%s)", channel_name);
    flushout();
#endif
        
    logger_channel *channel;
    
    treeset_node *node = treeset_avl_find(&logger_channels, channel_name);
    
    if(node == NULL)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_service_channel_unregister(%s) NAME NOT USED", channel_name);
        flushout();
#endif
        return LOGGER_CHANNEL_NOT_REGISTERED;
    }
    
    channel = (logger_channel*)node->data;

    if(channel->linked_handles != 0)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_service_channel_unregister(%s) STILL LINKED", channel_name);
        flushout();
#endif
        return LOGGER_CHANNEL_HAS_LINKS;
    }
    
    char *key = (char*)node->key;
    treeset_avl_delete(&logger_channels, channel_name);
    free(key);
        
    // remove the channel from all the handles
    
    for(s32 i = 0; i < ptr_vector_size(&logger_handles); i++)
    {
        logger_handle *handle = (logger_handle*)ptr_vector_get(&logger_handles, i);
        logger_service_handle_remove_channel(handle, channel_name);
    }
    
    logger_channel_free(channel);
        
    return SUCCESS;
}

static void
logger_service_channel_unregister_all()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_channel_unregister_all()");
    flushout();
#endif

    // for all channels
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&logger_channels, &iter);
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);
        logger_channel *channel = (logger_channel*)node->data;
        char *channel_name = (char*)node->key;

#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_service_channel_unregister_all() : channel %s@%p", channel_name, channel);
        flushout();
#endif
        
        // for all handles
        
        for(s32 i = 0; i < ptr_vector_size(&logger_handles); i++)
        {
            logger_handle *handle = (logger_handle*)ptr_vector_get(&logger_handles, i);
            
#if DEBUG_LOG_HANDLER != 0
            osformatln(termout, "logger_service_channel_unregister_all() : channel %s@%p : handle %s@%p", channel_name, channel, handle->name, handle);
            flushout();
#endif
            
            // remove channel from handle
            
            logger_service_handle_remove_channel(handle, channel_name);
        }
        
        assert(channel->linked_handles == 0);
        
        // I can do this since iteration and destroy does not care about
        // keys nor values
        
        node->data = NULL;
        node->key = NULL;
        
        logger_channel_free(channel);
        free(channel_name);
    }
    
    treeset_avl_destroy(&logger_channels);
}

/**
 * Used to find a channel in the channel array in a handle
 */

static int
logger_handle_channel_compare_match(const void *a, const void *b)
{
    const logger_channel* channel_a = (const logger_channel*)a;
    const logger_channel* channel_b = (const logger_channel*)b;

    if(channel_a == channel_b)
    {
        return 0;
    }

    return 1;
}

/**
 * INTERNAL: used by the service
 */

static logger_handle*
logger_service_handle_create(const char *name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_handle_create(%s)", name);
    flushout();
#endif

    logger_handle* handle = (logger_handle*)ptr_vector_search(&logger_handles, name, logger_handle_compare_match);

    if(handle == NULL)
    {
        MALLOC_OR_DIE(logger_handle*, handle, sizeof (logger_handle), LOGGER_HANDLE_TAG);

        handle->name = strdup(name);
        
        int len = strlen(name);
        handle->formatted_name_len = LOGGER_HANDLE_FORMATTED_LENGTH;
                
        MALLOC_OR_DIE(char*, handle->formatted_name, handle->formatted_name_len + 1, LOGGER_HANDLE_TAG);
        memset((char*)handle->formatted_name, ' ', LOGGER_HANDLE_FORMATTED_LENGTH);
        memcpy((char*)handle->formatted_name, name,  MIN(len , LOGGER_HANDLE_FORMATTED_LENGTH));
        char *sentinel  = (char*)&handle->formatted_name[handle->formatted_name_len];
        *sentinel = '\0';

        int i;

        for(i = 0; i < MSG_LEVEL_COUNT; i++)
        {
            ptr_vector_init(&handle->channels[i]);
        }

        ptr_vector_append(&logger_handles, handle);
        ptr_vector_qsort(&logger_handles, logger_handle_compare);
    }
    else
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termerr, "logger: '%s' already created", name);
        flusherr();
#endif
    }

    return handle;
}

static void
logger_service_handle_close(const char *name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_handle_close(%s)", name);
    flushout();
#endif
    
    //logger_handle* handle = (logger_handle*)ptr_vector_search(&logger_handles, name, logger_handle_compare_match);
    s32 handle_idx = ptr_vector_index_of(&logger_handles, name, logger_handle_compare_match);

    if(handle_idx >= 0)
    {
        logger_handle* handle = (logger_handle*)ptr_vector_get(&logger_handles, handle_idx);
        
        ptr_vector_end_swap(&logger_handles, handle_idx);
        ptr_vector_pop(&logger_handles);
                
        if(handle->global_reference != NULL)
        {
            *handle->global_reference = NULL;
        }
                
        // decrement references for all channels used
        
        for(int lvl = 0; lvl < MSG_LEVEL_COUNT; lvl++)
        {
            for(s32 idx = 0; idx < ptr_vector_size(&handle->channels[lvl]); idx++)
            {
                logger_channel *channel = (logger_channel*)ptr_vector_get(&handle->channels[lvl], idx);
                ptr_vector_end_swap(&handle->channels[lvl], idx);
                ptr_vector_pop(&handle->channels[lvl]);
                channel->linked_handles--;
            }
            
            ptr_vector_destroy(&handle->channels[lvl]);
        }
        
        if(handle->formatted_name != NULL)
        {
            handle->formatted_name_len = 0;
            free((char*)handle->formatted_name);
            handle->formatted_name = NULL;
        }
        
        if(handle->name != NULL)
        {
            free((char*)handle->name);
            handle->name = NULL;
        }
    }
}

static inline logger_handle*
logger_service_handle_get(const char *name)
{
    logger_handle* handle = (logger_handle*)ptr_vector_search(&logger_handles, name, logger_handle_compare_match);

    return handle;
}

/**
 * INTERNAL: used by the service
 */

static ya_result
logger_service_handle_add_channel(logger_handle *handle, int level, const char *channel_name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_handle_add_channel(%s@%p, %x, %s)", handle->name, handle, level, channel_name);
    flushout();
#endif
        
    assert(level >= 0 && level <= MSG_ALL_MASK);

    int lvl;
    int level_mask;
    
    logger_channel *channel = logger_service_channel_get(channel_name);
    if(channel == NULL)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_service_handle_add_channel(%s@%p, %x, %s) UNKNOWN CHANNEL", handle->name, handle, level, channel_name);
        flushout();
#endif

        return LOGGER_CHANNEL_NOT_REGISTERED;
    }

    // add the channel in every level required by the level mask
    
    for(lvl = 0, level_mask = 1; level_mask <= MSG_ALL_MASK; lvl++, level_mask <<= 1)
    {
        if((level & level_mask) != 0)
        {
            if(ptr_vector_linear_search(&handle->channels[lvl], channel, logger_handle_channel_compare_match) == NULL)
            {
                ptr_vector_append(&handle->channels[lvl], channel);
                channel->linked_handles++;
            }
        }
    }
    
    return SUCCESS;
}

static ya_result
logger_service_handle_remove_channel(logger_handle *handle, const char *channel_name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_handle_remove_channel(%s@%p, %s)", handle->name, handle, channel_name);
    flushout();
#endif
        
    logger_channel *channel = logger_service_channel_get(channel_name);
    if(channel == NULL)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_service_handle_remove_channel(%s@%p, %s) UNKNOWN CHANNEL", handle->name, handle, channel_name);
        flushout();
#endif
        
        return LOGGER_CHANNEL_NOT_REGISTERED;
    }

    for(u8 lvl = 0; lvl <= MSG_ALL; lvl++)
    {
        s32 idx = ptr_vector_index_of(&handle->channels[lvl], channel, logger_handle_channel_compare_match);
                
        if(idx >= 0)
        {
            ptr_vector_end_swap(&handle->channels[lvl], idx);
            ptr_vector_pop(&handle->channels[lvl]);
            channel->linked_handles--;
        }
    }
    
    return SUCCESS;
}

static void
logger_service_handle_remove_all_channel(logger_handle *handle)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_handle_remove_all_channel(%s@%p)", handle->name, handle);
    flushout();
#endif
    
    for(u8 lvl = 0; lvl < MSG_LEVEL_COUNT; lvl++)
    {
        for(s32 idx = 0; idx < ptr_vector_size(&handle->channels[lvl]); idx++)
        {
            logger_channel *channel = (logger_channel*)ptr_vector_get(&handle->channels[lvl], idx);
            channel->linked_handles--;
        }
        ptr_vector_empties(&handle->channels[lvl]);
    }
}


/**
 * INTERNAL: used inside the service (2)
 */

static void
logger_service_flush_all_channels()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_flush_all_channels()");
    flushout();
#endif
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&logger_channels, &iter);
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);
        logger_channel *channel = (logger_channel*)node->data;
        logger_channel_flush(channel);
    }
}

/**
 * INTERNAL: used inside the service (1)
 */

static void
logger_service_reopen_all_channels()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_service_reopen_all_channels()");
    flushout();
#endif
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&logger_channels, &iter);
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);
        logger_channel *channel = (logger_channel*)node->data;
        ya_result return_code = logger_channel_reopen(channel);
        
        if(FAIL(return_code))
        {
            log_err("could not reopen logger channel '%s': %r", STRNULL((char*)node->key), return_code);
        }
    }
}

/**
 * 
 * Create the handle tables
 * 
 * INTERNAL: used at initialisation the service
 */

void
logger_handle_exit_level(u32 level)
{
    if(level <= MSG_CRIT)
    {
        osformatln(termerr, "message level too low: %u < %u", level, MSG_CRIT);
        flusherr();
        return;
    }

    exit_level = level;
}

static void*
logger_dispatcher_thread(void* context)
{
    (void)context;
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_dispatcher_thread(%p)", context);
    flushout();
#endif
   
#ifdef HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
    pthread_setname_np(pthread_self(), "logger");
#endif
#endif
    
    output_stream baos;
    bytearray_output_stream_context baos_context;
    
    bytearray_output_stream_init_ex_static(&baos, NULL, 1024, BYTEARRAY_DYNAMIC, &baos_context);

    /*
     * Since I'll use this virtual call a lot, it's best to cache it.
     * (Actually it would be even better to use the static method)
     */
    output_stream_write_method *baos_write = baos.vtbl->write;
    
    char repeat_text[128];

    bool must_run = TRUE;
    
    while(must_run)
    {
        logger_message* message = (logger_message*)threaded_queue_dequeue(&logger_commit_queue);

        assert(message != NULL);
        
        /*
         * Reopen is not a message per se.
         * It has to be done "now" (ie: the disk is full, files have to be moved)
         * But if it was handled as a message, it would need to clear the queue before having an effect.
         * So instead a flag is used0
         */
        
        if(logger_reopen_requested)
        {
            logger_service_reopen_all_channels();
            logger_reopen_requested = FALSE;
        }

        switch(message->type)
        {
            case LOGGER_MESSAGE_TYPE_TEXT:
            {
#if DEBUG_LOG_MESSAGES != 0
                {
                    time_t now = time(NULL);
                    if(now - allocated_messages_count_stats_time > 10)
                    {
                        allocated_messages_count_stats_time = now;
                        int val = smp_int_get(&allocated_messages_count);

                        //osformatln(termerr, "messages allocated count = %d", val);
                        //flusherr();
                        osformat(&baos, "[LOGGER: %i messages allocated]\n", val);
                    }
                }
#endif

                logger_handle *handle = message->text.handle;
                u32 level = message->text.level;

                s32 channel_count = handle->channels[level].offset;

                if(channel_count < 0)
                {
                    free(message->text.text);
                    logger_message_free(message);
                    continue;
                }

                u32 date_header_len;

                if(message->text.flags == 0)
                {
                    struct tm t;
                    localtime_r(&message->text.tv.tv_sec, &t);
                    osformat(&baos, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
                            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                            t.tm_hour, t.tm_min, t.tm_sec, message->text.tv.tv_usec);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);

#ifdef DEBUG
                    osprint_u16(&baos, message->text.pid);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);

                    osprint_u32_hex(&baos, (u32)message->text.thread_id);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);
#endif

                    baos_write(&baos, (u8*)handle->formatted_name, handle->formatted_name_len);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);

                    osprint_char(&baos, acewnid[message->text.level & 15]);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);

                    date_header_len = 29;
                }
                else
                {
                    /* shortcut : assume both ones on since that's the only used case */

                    assert( (message->text.flags & (LOGGER_MESSAGE_TIMEMS | LOGGER_MESSAGE_PREFIX)) == (LOGGER_MESSAGE_TIMEMS | LOGGER_MESSAGE_PREFIX));

                    struct tm t;
                    localtime_r(&message->text.tv.tv_sec, &t);
                    osformat(&baos, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                            t.tm_hour, t.tm_min, t.tm_sec, message->text.tv.tv_usec / 1000);
                    baos_write(&baos, message->text.prefix, message->text.prefix_length);

                    date_header_len = 24;
                }

                baos_write(&baos, message->text.text, message->text.text_length);

                output_stream_write_u8(&baos, 0);                

                size_t size = bytearray_output_stream_size(&baos) - 1;
                char* buffer = (char*)bytearray_output_stream_buffer(&baos);

                logger_channel** channelp = (logger_channel**)handle->channels[level].data;

                do
                {
                    logger_channel* channel = *channelp;

                    ya_result return_code;

                    if((channel->last_message->text.text_length == message->text.text_length) && (memcmp(channel->last_message->text.text, message->text.text, message->text.text_length) == 0))
                    {
                        /* match, it's a repeat */
                        channel->last_message_count++;
                    }
                    else
                    {
                        /* no match */

                        if(channel->last_message_count > 0)
                        {
                            /* log the repeat count */

                            /* If the same line is outputted twice : filter it to say 'repeated' instead of sending everything */

                            struct tm t;
                            localtime_r(&message->text.tv.tv_sec, &t);
                            
                            return_code = snformat(repeat_text, sizeof(repeat_text), "%04d-%02d-%02d %02d:%02d:%02d.%06d" COLUMN_SEPARATOR 
#ifdef DEBUG
                                    "%-5d" COLUMN_SEPARATOR
                                    "%08x" COLUMN_SEPARATOR
#endif
                                    "--------" COLUMN_SEPARATOR
                                    "N" COLUMN_SEPARATOR
                                    "last message repeated %d times",
                                    t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                                    t.tm_hour, t.tm_min, t.tm_sec, message->text.tv.tv_usec,
#ifdef DEBUG
                                    channel->last_message->text.pid,
                                    channel->last_message->text.thread_id,
#endif
                                    channel->last_message_count);

                            if(ISOK(return_code))
                            {
                                if(FAIL(return_code = logger_channel_msg(channel, level, repeat_text, return_code, 29)))
                                {
                                    osformatln(termerr, "message write failed on channel: %r", return_code);
                                    flusherr();
                                }
                            }
                            else
                            {
                                osformatln(termerr, "message formatting failed on channel: %r", return_code);
                                flusherr();
                            }
                        }

                        /* cleanup */
                        if(--channel->last_message->text.rc == 0)
                        {
                            /* free the message */

#if DEBUG_LOG_MESSAGES != 0
                            osformatln(termout, "message rc is 0 (%s)", channel->last_message->text.text);
                            flushout();
#endif
                            
                            free(channel->last_message->text.text);
                            logger_message_free(channel->last_message);
                        }
#if DEBUG_LOG_MESSAGES != 0
                        else
                        {
                            osformatln(termout, "message rc decreased to %d (%s)", channel->last_message->text.rc, channel->last_message->text.text);
                            flushout();
                        }
#endif

                        channel->last_message = message;
                        channel->last_message_count = 0;
                        message->text.rc++;

#if DEBUG_LOG_MESSAGES != 0
                        osformatln(termout, "message rc is %d (%s)", channel->last_message->text.rc, channel->last_message->text.text);
                        flushout();
#endif

                        if(FAIL(return_code = logger_channel_msg(channel, level, buffer, size, date_header_len)))
                        {
                            osformatln(termerr, "message write failed on channel: %r", return_code);
                            flusherr();
                        }
                    }

                    channelp++;
                }
                while(--channel_count >= 0);

                if(message->text.rc == 0)
                {
#if DEBUG_LOG_HANDLER != 0
                    osformatln(termout, "message has not been used (full dup): '%s'", message->text.text);
                    flushout();
#endif
                    free(message->text.text);
                    logger_message_free(message);
                }

                bytearray_output_stream_reset(&baos);

                break;
            }

            case LOGGER_MESSAGE_TYPE_CHANNEL_CLOSE_ALL:
            {
                async_wait_s *awp = message->channel_flush_all.aw;
                
                logger_message_free(message);

                logger_service_flush_all_channels();
                //logger_service_close_all_channels();
                logger_service_channel_unregister_all();

                async_wait_progress(awp, 1);

                break;
            }
            
            case LOGGER_MESSAGE_TYPE_STOP:

                must_run = threaded_queue_size(&logger_commit_queue) > 0;
                if(must_run)
                {
                    // repost
                    threaded_queue_enqueue(&logger_commit_queue, message);
                    break;
                }

                /// @note falltrough by design
                
            case LOGGER_MESSAGE_TYPE_CHANNEL_FLUSH_ALL:
            {
                async_wait_s *awp = message->channel_flush_all.aw;
                
                logger_message_free(message);

                logger_service_flush_all_channels();

                async_wait_progress(awp, 1);

                break;
            }

            case LOGGER_MESSAGE_TYPE_CHANNEL_REOPEN_ALL:
            {
                // reopen is activated by a flag
                // this structure is just a way to fire the event
                
                async_wait_s *awp = message->channel_flush_all.aw;
                
                logger_message_free(message);
                
                async_wait_progress(awp, 1);
                
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_IGNORE:
            {
                logger_message_free(message);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_CHANNEL_GET_USAGE_COUNT:
            {
                async_wait_s *awp = message->get_usage_count.aw;
                const char *channel_name = message->get_usage_count.channel_name;
                                
                s32 *countp = message->get_usage_count.countp;
                
                assert(countp != NULL);
                
                logger_message_free(message);

                logger_channel *channel = logger_service_channel_get(channel_name);
                
                if(channel != NULL)
                {
                    *countp = channel->linked_handles;
                }
                else
                {
                    *countp = -1;
                }
                
                async_wait_progress(awp, 1);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_CHANNEL_REGISTER:
            {
                async_wait_s *awp = message->channel_register.aw;
                const char *channel_name = message->channel_register.channel_name;
                logger_channel *channel = message->channel_register.channel;
                
                logger_message_free(message);

                logger_service_channel_register(channel_name, channel);
                
                async_wait_progress(awp, 1);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_CHANNEL_UNREGISTER:
            {
                async_wait_s *awp = message->channel_unregister.aw;
                const char *channel_name = message->channel_unregister.channel_name;
                
                logger_message_free(message);

                logger_service_channel_unregister(channel_name);
                
                async_wait_progress(awp, 1);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_HANDLE_CREATE:
            {
                async_wait_s *awp = message->handle_create.aw;
                const char *name = message->handle_create.logger_name;
                logger_handle **handlep = message->handle_create.handle_holder;
                logger_handle* handle = logger_service_handle_create(name);
                handle->global_reference = handlep;
                *handlep = handle;
                logger_message_free(message);
                
                async_wait_progress(awp, 1);                
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_HANDLE_CLOSE:
            {
                async_wait_s *awp = message->handle_close.aw;
                const char *name = message->handle_close.logger_name;
                //u32 name_len = message->text_length;              
                logger_service_handle_close(name);
                
                logger_message_free(message);
                
                async_wait_progress(awp, 1);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_HANDLE_NAME_ADD_CHANNEL:
            {
                logger_handle *handle;
                async_wait_s *awp = message->handle_add_channel.aw;
                const char *name = message->handle_add_channel.logger_name;
                int level = message->handle_add_channel.level;
                const char *channel_name = message->handle_add_channel.channel_name;
                
                handle = logger_service_handle_get(name);
                if(handle != NULL)
                {
                    logger_service_handle_add_channel(handle, level, channel_name);
                }
                
                logger_message_free(message);
                
                async_wait_progress(awp, 1);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_HANDLE_NAME_REMOVE_CHANNEL:
            {
                logger_handle *handle;
                async_wait_s *awp = message->handle_remove_channel.aw;
                const char *name = message->handle_remove_channel.logger_name;
                const char *channel_name = message->handle_remove_channel.channel_name;
                
                handle = logger_service_handle_get(name);
                if(handle != NULL)
                {
                    logger_service_handle_remove_channel(handle, channel_name);
                }
                
                logger_message_free(message);
                
                async_wait_progress(awp, 1);
                break;
            }

            default:
            {
                osformatln(termerr, "unexpected message type %u in log queue", message->type);
                flusherr();
                            
                break;
            }
        }
    } // while must run

    // flush everything

    logger_service_flush_all_channels();

    // close everything
    
    output_stream_close(&baos);
    
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_dispatcher_thread(%p) END", context);
    flushout();
#endif

    return NULL;
}

s32
logger_channel_get_usage_count(const char* channel_name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_channel_get_usage_count(%s) ", channel_name);
    flushout();
#endif
    
    s32 count = -2;
    
    if(logger_is_running())
    {
        logger_message *message = logger_message_alloc();
        ZEROMEMORY(message, sizeof(logger_message));

        async_wait_s aw;
        async_wait_init(&aw, 1);
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_GET_USAGE_COUNT;
        message->get_usage_count.aw = &aw;
        message->get_usage_count.channel_name = channel_name;
        message->get_usage_count.countp = &count;

        threaded_queue_enqueue(&logger_commit_queue, message);

        async_wait(&aw);
        async_wait_finalize(&aw);
    }
    else
    {
        pthread_mutex_lock(&logger_commit_queue.mutex);

        logger_channel *channel = logger_service_channel_get(channel_name);

        if(channel != NULL)
        {
            count = channel->linked_handles;
        }
        else
        {
            count = -1;
        }

        pthread_mutex_unlock(&logger_commit_queue.mutex);
    }
    
    return count;
}

void
logger_channel_register(const char* channel_name, struct logger_channel *channel)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_channel_register(%s,%p) ", channel_name, channel);
    flushout();
#endif
    if(logger_is_running())
    {
        logger_message *message = logger_message_alloc();
        ZEROMEMORY(message, sizeof(logger_message));
        async_wait_s aw;
        async_wait_init(&aw, 1);
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_REGISTER;
        message->channel_register.aw = &aw;
        message->channel_register.channel_name = channel_name;
        message->channel_register.channel = channel;

        threaded_queue_enqueue(&logger_commit_queue, message);

        async_wait(&aw);
        async_wait_finalize(&aw);
    }
    else
    {
        pthread_mutex_lock(&logger_commit_queue.mutex);
        logger_service_channel_register(channel_name, channel);
        pthread_mutex_unlock(&logger_commit_queue.mutex);
    }
}

void
logger_channel_unregister(const char* channel_name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_channel_unregister(%s) ", channel_name);
    flushout();
#endif
    
    logger_message *message = logger_message_alloc();
    ZEROMEMORY(message, sizeof(logger_message));
    async_wait_s aw;
    async_wait_init(&aw, 1);
    message->type = LOGGER_MESSAGE_TYPE_CHANNEL_UNREGISTER;
    message->channel_unregister.aw = &aw;
    message->channel_unregister.channel_name = channel_name;
    
    threaded_queue_enqueue(&logger_commit_queue, message);
    
    async_wait(&aw);
    async_wait_finalize(&aw);
}

void
logger_handle_create(const char *logger_name, logger_handle **handle_holder)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_handle_create(%s,%p) ", logger_name, handle_holder);
    flushout();
#endif
    
    if(logger_is_running())
    {    
        logger_message *message = logger_message_alloc();
        ZEROMEMORY(message, sizeof(logger_message));
        async_wait_s aw;
        async_wait_init(&aw, 1);
        message->type = LOGGER_MESSAGE_TYPE_HANDLE_CREATE;
        message->handle_create.aw = &aw;
        message->handle_create.logger_name = logger_name;
        message->handle_create.handle_holder = handle_holder;

        threaded_queue_enqueue(&logger_commit_queue, message);

        async_wait(&aw);
        async_wait_finalize(&aw);
    }
    else
    {
        pthread_mutex_lock(&logger_commit_queue.mutex);
        logger_handle* handle = logger_service_handle_create(logger_name);
        handle->global_reference = handle_holder;
        *handle_holder = handle;
        pthread_mutex_unlock(&logger_commit_queue.mutex);
    }
}

void
logger_handle_close(const char *logger_name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_handle_close(%s) ", logger_name);
    flushout();
#endif
    
    logger_message *message = logger_message_alloc();
    ZEROMEMORY(message, sizeof(logger_message));
    async_wait_s aw;
    async_wait_init(&aw, 1);
    message->type = LOGGER_MESSAGE_TYPE_HANDLE_CLOSE;
    message->handle_close.aw = &aw;
    message->handle_close.logger_name = logger_name;
    
    threaded_queue_enqueue(&logger_commit_queue, message);

    async_wait(&aw);
    async_wait_finalize(&aw);
}

void
logger_handle_add_channel(const char *logger_name, int level, const char *channel_name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_handle_add_channel(%s,%x,%s) ", logger_name, level, channel_name);
    flushout();
#endif
    
    if(logger_is_running())
    {
        logger_message *message = logger_message_alloc();
        ZEROMEMORY(message, sizeof(logger_message));
        async_wait_s aw;
        async_wait_init(&aw, 1);
        message->type = LOGGER_MESSAGE_TYPE_HANDLE_NAME_ADD_CHANNEL;
        message->handle_add_channel.aw = &aw;
        message->handle_add_channel.logger_name = logger_name;
        message->handle_add_channel.level = level;
        message->handle_add_channel.channel_name = channel_name;

        threaded_queue_enqueue(&logger_commit_queue, message);

        async_wait(&aw);
        async_wait_finalize(&aw);
    }
    else
    {
        pthread_mutex_lock(&logger_commit_queue.mutex);
        logger_handle *handle = logger_service_handle_get(logger_name);
        if(handle != NULL)
        {
            logger_service_handle_add_channel(handle, level, channel_name);
        }
        pthread_mutex_unlock(&logger_commit_queue.mutex);
    }
}

void
logger_handle_remove_channel(const char *logger_name, const char *channel_name)
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_handle_remove_channel(%s,%s) ", logger_name, channel_name);
    flushout();
#endif
    
    logger_message *message = logger_message_alloc();
    ZEROMEMORY(message, sizeof(logger_message));
    async_wait_s aw;
    async_wait_init(&aw, 1);
    message->type = LOGGER_MESSAGE_TYPE_HANDLE_NAME_REMOVE_CHANNEL;
    message->handle_remove_channel.aw = &aw;
    message->handle_remove_channel.logger_name = logger_name;
    message->handle_remove_channel.channel_name = channel_name;
    
    threaded_queue_enqueue(&logger_commit_queue, message);

    async_wait(&aw);
    async_wait_finalize(&aw);
}

static u32 logger_queue_size = LOG_QUEUE_DEFAULT_SIZE;

u32 
logger_set_queue_size(u32 n)
{
    if(n < LOG_QUEUE_MIN_SIZE)
    {
        n = LOG_QUEUE_MIN_SIZE;
    }
    else if(n > LOG_QUEUE_MAX_SIZE)
    {
        n = LOG_QUEUE_MAX_SIZE;
    }
    
    if(logger_queue_initialised && (logger_queue_size != n))
    {
        logger_queue_size = n;
        logger_queue_size = threaded_queue_set_maxsize(&logger_commit_queue, logger_queue_size);
    }
    
    return logger_queue_size;
}

void
logger_init()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_init() ");
    flushout();
#endif
    
    if(!logger_initialised)
    {
        if(!logger_queue_initialised)
        {
            threaded_queue_init(&logger_commit_queue, logger_queue_size);
            logger_queue_initialised = TRUE;
        }

        if(!logger_handle_init_done)
        {
            logger_handle_init_done = TRUE;

            ptr_vector_init(&logger_handles);
            //ptr_vector_init(&logger_channels);

            pthread_mutex_init(&logger_mutex, NULL);

            format_class_init();
        }

        logger_set_uid(getuid());
        logger_set_gid(getgid());
        
        logger_initialised = TRUE;
    }
    else
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_init() : already initialised");
        flushout();
#endif
    }
}

void
logger_start()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_start() ");
    flushout();
#endif
    
    ya_result return_code;
    
    if(!logger_initialised)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_start() : not initialised yet : calling");
        flushout();
#endif     

        logger_init();
    }
    
    if(!logger_started)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_start() : starting");
        flushout();
#endif
        
        if((return_code = pthread_create(&logger_thread_id, NULL, logger_dispatcher_thread, NULL)) != 0)
        {
            osformatln(termerr, "logger_start: pthread_create: %r", return_code);
            DIE(LOGGER_INITIALISATION_ERROR);
        }

        logger_started = TRUE;
    }
    else
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_start() : already started");
        flushout();
#endif     
    }
    
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_start() : started");
    flushout();
#endif     
}

static void
logger_send_message_stop_wait()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_send_message_stop_wait()");
    flushout();
#endif
            
    async_wait_s aw;
    async_wait_init(&aw, 1);            
    
    logger_message* message = logger_message_alloc();
    
#ifdef DEBUG        
    ZEROMEMORY(message, sizeof (logger_message));
#endif
    message->type = LOGGER_MESSAGE_TYPE_STOP;
    message->stop.aw = &aw;

    threaded_queue_enqueue(&logger_commit_queue, message);

#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_send_message_stop_wait() : waiting");
    flushout();
#endif
    
    async_wait(&aw);
    async_wait_finalize(&aw);
    
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_send_message_stop_wait() : should be stopped");
    flushout();
#endif
}

void
logger_stop()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_stop()");
    flushout();
#endif     

    if(logger_initialised)
    {
        if(logger_started)
        {
            // send the stop order
            
            logger_send_message_stop_wait();
            
#if DEBUG_LOG_HANDLER != 0
            osformatln(termout, "logger_stop() : joining");
            flushout();
#endif     

            // wait for the end
            
            ya_result return_code;

            if((return_code = pthread_join(logger_thread_id, NULL)) != 0)
            {
                flushout();
                flusherr();
                osformatln(termerr, "logger_stop: pthread_join: %r", return_code);
                flusherr();
            }

            logger_thread_id = 0;
            logger_started = FALSE;
        }
    }
    
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_stop() : stopped");
    flushout();
#endif 
}

void
logger_finalize()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_finalize()");
    flushout();
#endif 
            
    if(!logger_initialised)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_finalize() : not initialised");
        flushout();
#endif 
        return;
    }
    
    if(threaded_queue_size(&logger_commit_queue) > 0)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_finalize() : queue is not empty : starting & flushing");
        flushout();
#endif
        logger_start();   
        logger_flush();
    }
    
    if(logger_started)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_finalize() : still running : stopping");
        flushout();
#endif
        logger_stop();
    }

    /*
     * Ensure there is nothing left at all in the queue
     */

    while(threaded_queue_size(&logger_commit_queue) > 0)
    {
        logger_message* message = threaded_queue_dequeue(&logger_commit_queue);
        
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_finalize() : freeing message of type %u", message->type);
        flushout();
#endif
        
        logger_message_free(message);
    }

    if(logger_handle_init_done)
    {
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_finalize() : flushing all channels");
        flushout();
#endif
        logger_service_flush_all_channels();
        
        // closes all handles
        
#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_finalize() : closing all handles");
        flushout();
#endif

        ptr_vector_free_empties(&logger_handles, logger_handle_free);
        ptr_vector_destroy(&logger_handles);
        
        // closes all channels

#if DEBUG_LOG_HANDLER != 0
        osformatln(termout, "logger_finalize() : closing all channels");
        flushout();
#endif
        
        logger_service_channel_unregister_all();
        
        logger_handle_init_done = FALSE;
    }
    
    if(logger_queue_initialised)
    {
        threaded_queue_finalize(&logger_commit_queue);
        logger_queue_initialised = FALSE;
    }

    logger_initialised = FALSE;
    
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_finalize() : finalised");
    flushout();
#endif
}

void
logger_flush()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_flush()");
    flushout();
#endif
    
    if(logger_initialised && logger_started)
    {
        async_wait_s aw;
        async_wait_init(&aw, 1);
        
        logger_message* message = logger_message_alloc();

#ifdef DEBUG        
        ZEROMEMORY(message, sizeof (logger_message));
#endif
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_FLUSH_ALL;
        message->channel_flush_all.aw = &aw;
        
        threaded_queue_enqueue(&logger_commit_queue, message);
        
        // avoid being stuck forever if the service is down
        
        while(logger_initialised && logger_started)
        {
            if(async_wait_timeout(&aw, 1000000))
            {
                async_wait_finalize(&aw);
                break;
            }
        }
    }
#if DEBUG_LOG_HANDLER != 0
    else
    {   
        osformatln(termout, "logger_flush() : i=%i s=%i", logger_initialised, logger_started);
        flushout();
    }
#endif
}

void
logger_channel_close_all()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_close_all_channels()");
    flushout();
#endif
    
    if(logger_initialised && logger_started)
    {
        async_wait_s aw;
        async_wait_init(&aw, 1);
        
        logger_message* message = logger_message_alloc();

#ifdef DEBUG        
        ZEROMEMORY(message, sizeof (logger_message));
#endif
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_CLOSE_ALL;
        message->channel_flush_all.aw = &aw;
        
        threaded_queue_enqueue(&logger_commit_queue, message);
        
        // avoid being stuck forever if the service is down
        
        while(logger_initialised && logger_started)
        {
            if(async_wait_timeout(&aw, 1000000))
            {
                async_wait_finalize(&aw);
                break;
            }
        }
    }
#if DEBUG_LOG_HANDLER != 0
    else
    {   
        osformatln(termout, "logger_close_all_channels() : i=%i s=%i", logger_initialised, logger_started);
        flushout();
    }
#endif
}

void
logger_reopen()
{
#if DEBUG_LOG_HANDLER != 0
    osformatln(termout, "logger_reopen()");
    flushout();
#endif
    
    if(logger_initialised && logger_started)
    {
        logger_reopen_requested = TRUE;
        
        // even for a lflag, the message NEEDS to be enqueued because
        // 1) it activates the service
        // 2) synchronises the memory between the threads (memory wall)
        
        async_wait_s aw;
        async_wait_init(&aw, 1);
        
        logger_message* message = logger_message_alloc();
        
#ifdef DEBUG
        ZEROMEMORY(message, sizeof (logger_message));
#endif
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_REOPEN_ALL;
        message->channel_reopen_all.aw = &aw;

        threaded_queue_enqueue(&logger_commit_queue, message);
        
        while(logger_initialised && logger_started)
        {
            if(async_wait_timeout(&aw, 1000000))
            {
                async_wait_finalize(&aw);
                break;
            }
        }
    }
#if DEBUG_LOG_HANDLER != 0
    else
    {
        osformatln(termout, "logger_reopen() : i=%i s=%i", logger_initialised, logger_started);
        flushout();
    }
#endif
}

bool
logger_is_running()
{
    return logger_started;
}

void
logger_handle_vmsg(logger_handle* handle, u32 level, const char* fmt, va_list args)
{
    /*
     * check that the handle has got a channel for the level
     */

#ifdef DEBUG
    if(level >= MSG_LEVEL_COUNT)
    {
        osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_shutdown();
        return;
    }
    
    if(level <= MSG_ERR)
    {
        sleep(0);
    }
    
#endif

    if(handle == NULL)
    {
        if(level <= exit_level)
        {
            logger_handle_trigger_shutdown();
        }
        return;
    }
    
    if(level > logger_level)
    {
        return;
    }

    s32 channel_count = handle->channels[level].offset;

    if(channel_count < 0) /* it's count-1 actually */
    {
        return;
    }

    /**
     * @note At this point we KNOW we have to print something.
     */

    output_stream baos;
    bytearray_output_stream_context baos_context;

    /*
     * DEFAULT_MAX_LINE_SIZE is the base size.
     *
     * The output stream has the BYTEARRAY_DYNAMIC flag set in order to allow
     * bigger sentences.
     *
     */

    /* Will use the tmp buffer, but alloc a bigger one if required. */
    bytearray_output_stream_init_ex_static(&baos, NULL, DEFAULT_MAX_LINE_SIZE, BYTEARRAY_DYNAMIC, &baos_context);

    if(FAIL(vosformat(&baos, fmt, args)))
    {
        bytearray_output_stream_reset(&baos);        
        osprint(&baos, "*** ERROR : MESSAGE FORMATTING FAILED ***");
    }

    output_stream_write_u8(&baos, 0);

    logger_message* message = logger_message_alloc();
    
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;
    
    message->text.text_length = bytearray_output_stream_size(&baos) - 1;
    
    message->text.handle = handle;
    
    message->text.text = bytearray_output_stream_detach(&baos);
    
    gettimeofday(&message->text.tv, NULL);
    
    // prefix
    // prefix_len
    
    message->text.rc = 0;
   
#ifdef DEBUG 
    message->text.pid = getpid();
    message->text.thread_id = pthread_self();
#endif
    
    threaded_queue_enqueue(&logger_commit_queue, message);

    output_stream_close(&baos); /* Frees the memory */

    if(level <= exit_level)
    {
        logger_handle_trigger_shutdown();
    }
}


void
logger_handle_msg(logger_handle* handle, u32 level, const char* fmt, ...)
{
    /*
     * check that the handle has got a channel for the level
     */

#ifdef DEBUG
    if(level >= MSG_LEVEL_COUNT)
    {
        osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_shutdown();
        return;
    }
    
    if(level <= MSG_ERR)
    {
        sleep(0);
    }
    
#endif

    if(handle == NULL)
    {
        if(level <= exit_level)
        {
            logger_handle_trigger_shutdown();
        }
        return;
    }
    
    if(level > logger_level)
    {
        return;
    }

    s32 channel_count = handle->channels[level].offset;

    if(channel_count < 0) /* it's count-1 actually */
    {
        return;
    }

    /**
     * @note At this point we KNOW we have to print something.
     */

    output_stream baos;
    bytearray_output_stream_context baos_context;

    /*
     * DEFAULT_MAX_LINE_SIZE is the base size.
     *
     * The output stream has the BYTEARRAY_DYNAMIC flag set in order to allow
     * bigger sentences.
     *
     */

    va_list args;
    va_start(args, fmt);

    /* Will use the tmp buffer, but alloc a bigger one if required. */
    bytearray_output_stream_init_ex_static(&baos, NULL, DEFAULT_MAX_LINE_SIZE, BYTEARRAY_DYNAMIC, &baos_context);

    if(FAIL(vosformat(&baos, fmt, args)))
    {
        bytearray_output_stream_reset(&baos);        
        osprint(&baos, "*** ERROR : MESSAGE FORMATTING FAILED ***");
    }

    output_stream_write_u8(&baos, 0);

    logger_message* message = logger_message_alloc();
    
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;
    
    message->text.text_length = bytearray_output_stream_size(&baos) - 1;
    
    message->text.handle = handle;
    
    message->text.text = bytearray_output_stream_detach(&baos);
    
    gettimeofday(&message->text.tv, NULL);
    
    // prefix
    // prefix_len
    
    message->text.rc = 0;
   
#ifdef DEBUG 
    message->text.pid = getpid();
    message->text.thread_id = pthread_self();
#endif
    
    threaded_queue_enqueue(&logger_commit_queue, message);

    va_end(args);

    output_stream_close(&baos); /* Frees the memory */

    if(level <= exit_level)
    {
        logger_handle_trigger_shutdown();
    }
}

void
logger_handle_msg_text(logger_handle* handle, u32 level, const char* text, u32 text_len)
{
    /*
     * check that the handle has got a channel for the level
     */

#ifdef DEBUG
    if(level >= MSG_LEVEL_COUNT)
    {
        osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_shutdown();
        return;
    }
    
    if(level <= MSG_ERR)
    {
        sleep(0);
    }
    
#endif

    if(handle == NULL)
    {
        if(level <= exit_level)
        {
            logger_handle_trigger_shutdown();
        }
        return;
    }
    
    if(level > logger_level)
    {
        return;
    }

    s32 channel_count = handle->channels[level].offset;

    if(channel_count < 0) /* it's count-1 actually */
    {
        return;
    }
 
    logger_message* message = logger_message_alloc();
    
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;
    
    message->text.text_length = text_len;
    message->text.handle = handle;
    
    MALLOC_OR_DIE(u8*, message->text.text, text_len, LOGRTEXT_TAG);
    memcpy(message->text.text, text, text_len);
    
    gettimeofday(&message->text.tv, NULL);
    
    // prefix
    // prefix_len
    
    message->text.rc = 0;

#ifdef DEBUG
    message->text.pid = getpid();
    message->text.thread_id = pthread_self();
#endif
    
    threaded_queue_enqueue(&logger_commit_queue, message);

    if(level <= exit_level)
    {
        logger_handle_trigger_shutdown();
    }
}

void
logger_handle_msg_text_ext(logger_handle* handle, u32 level, const char* text, u32 text_len, const char* prefix, u32 prefix_len, u16 flags)
{
        /*
     * check that the handle has got a channel for the level
     */

#ifdef DEBUG
    if(level >= MSG_LEVEL_COUNT)
    {
        osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_shutdown();
        return;
    }
    
    if(level <= MSG_ERR)
    {
        sleep(0);
    }
    
#endif

    if(handle == NULL)
    {
        if(level <= exit_level)
        {
            logger_handle_trigger_shutdown();
        }
        return;
    }
    
    if(level > logger_level)
    {
        return;
    }

    s32 channel_count = handle->channels[level].offset;

    if(channel_count < 0) /* it's count-1 actually */
    {
        return;
    }
 
    logger_message* message = logger_message_alloc();
    
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = flags;
    
    message->text.text_length = text_len;
    
    message->text.handle = handle;
    
    MALLOC_OR_DIE(u8*, message->text.text, text_len, LOGRTEXT_TAG);
    memcpy(message->text.text, text, text_len);
    
    gettimeofday(&message->text.tv, NULL);
        
    message->text.prefix = (const u8*)prefix;
    message->text.prefix_length = prefix_len;
    
    message->text.rc = 0;
    
#ifdef DEBUG
    message->text.pid = getpid();
    message->text.thread_id = pthread_self();
#endif
    
    threaded_queue_enqueue(&logger_commit_queue, message);

    if(level <= exit_level)
    {
        logger_handle_trigger_shutdown();
    }
}

static const char LOGGER_PATH_DEFAULT[] = "";
static const char *g_logger_path = LOGGER_PATH_DEFAULT;
static uid_t g_logger_uid = 0;
static gid_t g_logger_gid = 0;

void
logger_set_path(const char *path)
{
    if(g_logger_path != LOGGER_PATH_DEFAULT)
    {
        free((char*)g_logger_path);
    }
    if(path != NULL)
    {
        g_logger_path = strdup(path);
    }
    else
    {
        g_logger_path = LOGGER_PATH_DEFAULT;
    }
}

const char*
logger_get_path()
{
    return g_logger_path;
}

void
logger_set_uid(uid_t uid)
{
    g_logger_uid = uid;
}

uid_t
logger_get_uid()
{
    return g_logger_uid;
}

void
logger_set_gid(uid_t gid)
{
    g_logger_gid = gid;
}

gid_t
logger_get_gid()
{
    return g_logger_gid;
}

void
logger_set_level(u8 level)
{
    logger_level = MIN(level, MSG_ALL);
}

/** @} */

/*----------------------------------------------------------------------------*/
