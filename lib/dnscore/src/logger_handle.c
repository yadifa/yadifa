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

/** @defgroup logger Logging functions
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#if DEBUG
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
#include <stddef.h>

#include <dnscore/thread.h>
#include <sys/mman.h>

#include "dnscore/logger_handle.h"
#include "dnscore/logger_channel_stream.h"
#include "dnscore/ptr_vector.h"
#include "dnscore/zalloc.h"

#include "dnscore/file_output_stream.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/bytearray_output_stream.h"

#include "dnscore/format.h"
#include "dnscore/dnscore.h"
#include "dnscore/process.h"

#include "dnscore/async.h"

#include "dnscore/ptr_set.h"
#include "dnscore/thread_pool.h"

#if HAS_SHARED_QUEUE_SUPPORT
#include "dnscore/shared-circular-buffer.h"
#include "dnscore/shared-heap.h"
#include "dnscore/shared-heap-bytearray-output-stream.h"
#else
#include "dnscore/bytezarray_output_stream.h"
#include "dnscore/threaded_queue.h"
#include "dnscore/ipc.h"
#endif

#include "dnscore/buffer_output_stream.h"
#include "dnscore/buffer_input_stream.h"

#define LOGGER_HANDLE_TAG 0x4c444e48474f4c /* LOGHNDL */
#define LOGCHAN_TAG 0x4e414843474f4c /* LOGCHAN */

// If the logger thread queues a log message, and the log queue is full (ie: because the disk is full) a dead-lock may ensue.
// So queued-logging is to be avoided in the logger thread
// That being said, DEBUG_LOG_HANDLER and DEBUG_LOG_MESSAGES may trigger this issue as it is a debug, dev-only, feature.

#if DNSCORE_HAS_LOG_THREAD_TAG
void thread_tag_push_tags();
#endif

#define DEBUG_LOG_HANDLER 0     // can be: 0 1 2, don't use for production
#define DEBUG_LOG_MESSAGES 0

#if DEBUG_LOG_MESSAGES
# pragma message("DEBUG_LOG_MESSAGES") // the space after the '#' is to ignore it on #pragma search
#endif

#define COLUMN_SEPARATOR " | "
#define COLUMN_SEPARATOR_SIZE 3

#define MODULE_MSG_HANDLE g_system_logger

#define LOGRMSG_TAG 0x47534d52474f4c
#define LOGRTEXT_TAG 0x5458455452474f4c
    
struct logger_handle;

#define LOGGER_MESSAGE_TYPE_TEXT                        0 // send a text to output
#define LOGGER_MESSAGE_TYPE_STOP                        1 // stop the service
#define LOGGER_MESSAGE_TYPE_CHANNEL_FLUSH_ALL           2 // flush all channels
#define LOGGER_MESSAGE_TYPE_CHANNEL_REOPEN_ALL          3 // reopen all channels
#define LOGGER_MESSAGE_TYPE_CHANNEL_CLOSE_ALL           4 // close all channels
#define LOGGER_MESSAGE_TYPE_CHANNEL_SINK_ALL            5 // sink all channels
#define LOGGER_MESSAGE_TYPE_IGNORE                      6 // no operation

#define LOGGER_MESSAGE_TYPE_CHANNEL_GET_USAGE_COUNT     7 // grabs the number of uses of the channel, or -1 if not registered
#define LOGGER_MESSAGE_TYPE_CHANNEL_REGISTER            8 // register a new channel
#define LOGGER_MESSAGE_TYPE_CHANNEL_UNREGISTER          9 // unregister a channel

#define LOGGER_MESSAGE_TYPE_HANDLE_CREATE              10 // open a new handle
#define LOGGER_MESSAGE_TYPE_HANDLE_CLOSE               11 // close a handle
#define LOGGER_MESSAGE_TYPE_HANDLE_NAME_ADD_CHANNEL    12 // add a channel to a handle identified by its name
#define LOGGER_MESSAGE_TYPE_HANDLE_NAME_REMOVE_CHANNEL 13 // remove a channel from a handle identified by its name
#define LOGGER_MESSAGE_TYPE_HANDLE_NAME_COUNT_CHANNELS 14 // return the number of channels linked to this logger

#define LOGGER_MESSAGE_TYPE_THREAD_SET_TAG             15 // sets the tag for a thread ( + pid)
#define LOGGER_MESSAGE_TYPE_THREAD_CLEAR_TAG           16 // clears the tag for a thread ( + pid)

#define LOGGER_DISPATCHED_THREAD_STOPPED    0
#define LOGGER_DISPATCHED_THREAD_STARTED    1
#define LOGGER_DISPATCHED_THREAD_READY      2
#define LOGGER_DISPATCHED_THREAD_STOPPING   3

#define LOGGER_MESSAGE_SINK_FAKE ((logger_message*) 1)

#define LOGGER_HANDLE_COUNT_MAX 16
#define LOGGER_HANDLE_SHARED_TABLE_SIZE (((sizeof(logger_handle) + 63) & ~63) * LOGGER_HANDLE_COUNT_MAX)

static smp_int logger_thread_state = SMP_INT_INITIALIZER;

struct logger_handle LOGGER_HANDLE_SINK_;

struct logger_handle *LOGGER_HANDLE_SINK_PTR = &LOGGER_HANDLE_SINK_;

static logger_handle *g_logger_handle_shared_table = NULL;

struct logger_handle LOGGER_HANDLE_SINK_ =
{
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
    {
        PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, 
        PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, 
        PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, 
        PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY, PTR_VECTOR_EMPTY
    },
    "SINK",
    "sink",
    4,
    &LOGGER_HANDLE_SINK_PTR
#if DEBUG
    , LOGGER_HANDLE_MAGIC_CHECK
#endif
    };

struct logger_message_text_s
{
    u8  type;                       //  0  0
    u8  level;                      // 
    u16 flags;                      // 
    u16 text_length;                //  
    u16 text_buffer_length;         // align 64
    struct logger_handle *handle;   //  8  8
    
    u8 *text;                       // 12 16
    
#if SIZEOF_TIMEVAL <= 8
    struct timeval tv;              // 16 24
#else
    s64 timestamp;
#endif
    
    const u8* prefix;               // 24 32
    u16 prefix_length;              // 28 40
#if !HAS_SHARED_QUEUE_SUPPORT
    s16 rc;                         // 30 42   reference count for the repeats   
    
#if DEBUG || HAS_LOG_PID
    pid_t pid;                      // 32 44
#endif
#endif
    
#if DEBUG || HAS_SHARED_QUEUE_SUPPORT || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
    thread_t thread_id;            // 36 48
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

    thread_t tid;  // only used for debugging purposes
};

struct logger_message_channel_reopen_all_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
};

struct logger_message_channel_sink_all_s
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

struct logger_message_handle_count_channels_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    
    async_wait_s *aw;
    const char *logger_name;
    s32 *countp;
};

#if DNSCORE_HAS_LOG_THREAD_TAG

struct logger_message_thread_set_tag_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    async_wait_s *aw;
    char tag[THREAD_TAG_SIZE];
    thread_t tid;
};

struct logger_message_thread_clear_tag_s
{
    u8 type;
    u8 val8;
    u16 val16;
    u32 val32;  // align 64
    async_wait_s *aw;
    thread_t tid;
};

#endif

struct logger_message
{
#if HAS_SHARED_QUEUE_SUPPORT
    u8 reserved_for_the_queue;
    u8 align0;
    u16 align1;
    pid_t pid;                      //   4 4
#endif
    union
    {
        u8 type;
        struct logger_message_text_s text;
        struct logger_message_stop_s stop;
        // no specific data for ignore
        struct logger_message_channel_flush_all_s channel_flush_all;
        struct logger_message_channel_reopen_all_s channel_reopen_all;
        struct logger_message_channel_sink_all_s channel_sink_all;
        struct logger_message_channel_get_usage_count_s get_usage_count;
        struct logger_message_channel_register_s channel_register;
        struct logger_message_channel_unregister_s channel_unregister;
        struct logger_message_handle_create_s handle_create;
        struct logger_message_handle_close_s handle_close;
        struct logger_message_handle_add_channel_s handle_add_channel;
        struct logger_message_handle_remove_channel_s handle_remove_channel;
        struct logger_message_handle_count_channels_s handle_count_channels;
#if DNSCORE_HAS_LOG_THREAD_TAG
        struct logger_message_thread_set_tag_s thread_set_tag;
        struct logger_message_thread_clear_tag_s thread_clear_tag;
#endif
    };
};

typedef struct logger_message logger_message;

/// tree set initialised empty with a comparator for ASCIIZ char* keys
static ptr_set logger_channels = PTR_SET_ASCIIZ_EMPTY;
static ptr_vector logger_handles = PTR_VECTOR_EMPTY;
static mutex_t logger_mutex = MUTEX_INITIALIZER;

#if HAS_SHARED_QUEUE_SUPPORT
struct shared_circular_buffer* logger_shared_queue = NULL;
#else
static threaded_queue logger_commit_queue = THREADED_QUEUE_EMPTY;
#endif

struct logger_shared_space_s
{
    logger_message *_logger_sink_request_message;
    logger_message *_logger_reopen_request_message;
};

typedef struct logger_shared_space_s logger_shared_space_t;

static logger_shared_space_t logger_shared_space_null = {NULL, NULL};

static logger_shared_space_t *logger_shared_space = &logger_shared_space_null;

static thread_t logger_thread_id = 0;
static pid_t logger_thread_pid = -1;
static u32 exit_level = MSG_CRIT;
static const char acewnid[16 + 1] = "!ACEWNID1234567";

static volatile pid_t logger_handle_owner_pid = 0;
static volatile bool _logger_started = FALSE;
static volatile bool _logger_initialised = FALSE;
#if !HAS_SHARED_QUEUE_SUPPORT
static volatile bool logger_is_client = FALSE;
#endif
static volatile bool logger_queue_initialised = FALSE;
static volatile bool logger_handle_init_done = FALSE;
static volatile u8 logger_level = MSG_ALL;
static u8 logger_shared_heap_id = 0;

static bool logger_initialised()
{
    mutex_lock(&logger_mutex);
    bool ret = _logger_initialised;
    mutex_unlock(&logger_mutex);
    return ret;
}

static bool logger_started()
{
    mutex_lock(&logger_mutex);
    bool ret = _logger_started;
    mutex_unlock(&logger_mutex);
    return ret;
}

static bool logger_initialised_and_started()
{
    mutex_lock(&logger_mutex);
    bool ret = _logger_started && _logger_initialised;
    mutex_unlock(&logger_mutex);
    return ret;
}

#if DEBUG_LOG_MESSAGES
static smp_int allocated_messages_count = SMP_INT_INITIALIZER;
static time_t allocated_messages_count_stats_time = 0;
#endif

static void logger_handle_trigger_emergency_shutdown()
{
    flusherr();
    logger_flush();
    abort();
}

/*******************************************************************************
 *
 * Logger message functions
 *  
 *******************************************************************************/

static inline logger_message*
logger_message_alloc()
{
#ifdef NDEBUG
    size_t sizeof_logger_message = sizeof(logger_message);
    assert(sizeof_logger_message <= 64);
    (void)sizeof_logger_message;
#endif
    logger_message* message;
#if HAS_SHARED_QUEUE_SUPPORT
    message = (logger_message*)shared_circular_buffer_prepare_enqueue(logger_shared_queue);
#if DEBUG
    memset(((u8*)message) + 1, 'Q', sizeof(logger_message) - 1);
#endif
#else
    ZALLOC_OBJECT_OR_DIE( message, logger_message, LOGRMSG_TAG);
#if DEBUG
    memset(message, 'Q', sizeof(logger_message));
#endif
#endif
    
#if DEBUG_LOG_MESSAGES
    smp_int_inc(&allocated_messages_count);
#endif
    
    return message;
}

#if HAS_SHARED_QUEUE_SUPPORT
static inline logger_message*
logger_message_try_alloc()
{
    logger_message* message;
    message = (logger_message*)shared_circular_buffer_try_prepare_enqueue(logger_shared_queue);
#if DEBUG
    if(message != NULL)
    {
        memset(&((u8*)message)[1], 'q', sizeof(logger_message) - 1);
    }
#endif
    return message;
}
#endif

#if !HAS_SHARED_QUEUE_SUPPORT
static inline void
logger_message_free(logger_message *message)
{
    ZFREE_OBJECT(message);
    
#if DEBUG_LOG_MESSAGES
    smp_int_dec(&allocated_messages_count);
#endif
}
#endif

static inline void
logger_message_post(void* message)
{
#if HAS_SHARED_QUEUE_SUPPORT
    shared_circular_buffer_commit_enqueue(logger_shared_queue, message);
#else
    threaded_queue_enqueue(&logger_commit_queue, message);
#endif
}

/*******************************************************************************
 *
 * Logger handle functions
 *  
 *******************************************************************************/

static ya_result logger_service_handle_remove_channel(logger_handle *handle, const char *channel_name);
static void logger_service_handle_remove_all_channel(logger_handle *handle);

/**
 * Returns true iff the current thread is the logger.
 * 
 * @return true iff the current thread is the logger.
 */

bool
logger_is_self()
{
    return logger_thread_id == thread_self();
}

#if 0
static int
logger_handle_compare(const void* a, const void* b)
{
    logger_handle* ha = (logger_handle*)a;
    logger_handle* hb = (logger_handle*)b;
    
    if(ha == hb)
    {
        return 0;
    }

    return strcmp(ha->name, hb->name);
}
#endif

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
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_free(%s@%p)", handle->name, ptr);
    flushout();
#endif
    
    logger_service_handle_remove_all_channel(handle);
    
    for(u8 lvl = 0; lvl < MSG_LEVEL_COUNT; lvl++)
    {
        ptr_vector_destroy(&handle->channels[lvl]);
    }
    
    if(handle->global_reference == NULL)
    {
        debug_osformatln(termerr, "bug: logger handle '%s' must be initialised to LOGGER_HANDLE_SINK but is set to NULL", handle->name);
        flusherr();
        abort();
        return;
    }
    
    if(*handle->global_reference != LOGGER_HANDLE_SINK)
    {
        *handle->global_reference = LOGGER_HANDLE_SINK;
    }

#if DEBUG
    memset((char*)handle->formatted_name, 0xfe, strlen(handle->formatted_name));
#endif
#if !HAS_SHARED_QUEUE_SUPPORT
    free((char*)handle->formatted_name);
#endif
#if DEBUG
    memset((char*)handle->name, 0xfe, strlen(handle->name));
#endif
#if !HAS_SHARED_QUEUE_SUPPORT
    free((char*)handle->name);
#endif
#if DEBUG
    memset(handle, 0xfe, sizeof(logger_handle));
#endif
#if HAS_SHARED_QUEUE_SUPPORT
    //shared_heap_free(handle);
#else
    free(handle);
#endif
}

/*******************************************************************************
 *
 * Logger channel functions
 *  
 *******************************************************************************/

#define LOGGER_CHANNEL_COUNT_MAX 128

static logger_channel* logger_channel_shared_memory = NULL;
static size_t logger_channel_shared_memory_avail = 0;
static u8 logger_channel_allocated[LOGGER_CHANNEL_COUNT_MAX/8];

static inline size_t logger_channel_shared_memory_size()
{
    return (LOGGER_CHANNEL_COUNT_MAX * sizeof(logger_channel) + 0xfff) & ~0xfff;
}

logger_channel*
logger_channel_alloc()
{
    if(logger_handle_owner_pid == 0) // don't know our pid yet
    {
        logger_handle_owner_pid = getpid_ex(); // update it, set us as the logger process
    }
    else if(logger_handle_owner_pid != getpid_ex()) // if we are not the logger process, this is very wrong
    {
        // no can do
        debug_osformatln(termerr, "logger_channel_alloc() cannot be called from this process");
        return NULL;
    }
    
    if(logger_channel_shared_memory == NULL)
    {
        void *ptr = mmap(NULL, logger_channel_shared_memory_size(), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        
        if(ptr == MAP_FAILED)
        {
            int err = ERRNO_ERROR;
            debug_osformatln(termerr, "logger_channel_alloc() shared memory allocation failed: %r", err);
            return NULL;
        }
        
        yassert(ptr != NULL);
                
        logger_channel_shared_memory = (logger_channel*)ptr;
        
        memset(logger_channel_shared_memory, 0U,  logger_channel_shared_memory_size());
        logger_channel_shared_memory_avail = logger_channel_shared_memory_size() / sizeof(logger_channel);

        memset(logger_channel_allocated, 0U,  sizeof(logger_channel_allocated));
    }
    
    logger_channel* chan;
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_channel_alloc()");
    flushout();
#endif
    
    if(logger_channel_shared_memory_avail == 0)
    {
        return NULL;
    }

    chan = NULL;

    for(int i = 0; i < LOGGER_CHANNEL_COUNT_MAX/8; ++i)
    {
        if(logger_channel_allocated[i] != MAX_U8)
        {
            for(int j = 0; j < 8; ++j)
            {
                if((logger_channel_allocated[i] & (1 << j)) == 0)
                {
                    logger_channel_allocated[i] |= 1 << j;
                    chan = &logger_channel_shared_memory[(i << 3) + j];

                    chan->data = NULL;
                    chan->vtbl = NULL;

#if !HAS_SHARED_QUEUE_SUPPORT
                    /* dummy to avoid a NULL test */
                    logger_message* last_message = logger_message_alloc();
                    last_message->pid = getpid_ex();
                    last_message->type = LOGGER_MESSAGE_TYPE_TEXT;
                    ZALLOC_ARRAY_OR_DIE(u8*, last_message->text.text, 1, LOGRTEXT_TAG);
                    *last_message->text.text = '\0';
                    last_message->text.text_length = 1;
                    last_message->text.text_buffer_length = 1;
                    last_message->text.flags = 0;
                    last_message->text.rc = 1;
                    last_message->text.thread_id = thread_self();

                    chan->last_message = last_message;
                    chan->last_message_count = 0;
#endif
                    chan->linked_handles = 0;
                    return chan;
                }
            }
        }
    }

    return NULL;
}

static void
logger_channel_free(logger_channel *channel)
{
    if((channel == NULL) || (channel < logger_channel_shared_memory))
    {
        return;
    }

#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_channel_free(%p), linked to %d", channel, channel->linked_handles);
    flushout();
#endif

    size_t slot = (channel - logger_channel_shared_memory);
    if(slot > (sizeof(logger_channel_allocated) * 8))
    {
        return;
    }

    if((logger_channel_allocated[slot >> 3] & (1 << (slot & 7))) == 0)
    {
        return;
    }

    assert(channel->linked_handles == 0); // don't yassert
    assert(logger_handle_owner_pid == getpid_ex());
    
#if !HAS_SHARED_QUEUE_SUPPORT
    logger_message* last_message = channel->last_message;
    
    if(--last_message->text.rc == 0)
    {
        ZFREE_ARRAY(last_message->text.text, last_message->text.text_buffer_length);
        logger_message_free(last_message);
    }
#endif
    if(channel->vtbl != NULL)
    {
        logger_channel_close(channel);
        channel->vtbl = NULL;
    }

    logger_channel_allocated[slot >> 3] &= ~(1 << (slot & 7));
    ++logger_channel_shared_memory_avail;
}

static logger_channel*
logger_service_channel_get(const char *channel_name)
{   
    logger_channel *channel = NULL;
    
    ptr_node *node = ptr_set_find(&logger_channels, channel_name);
    if(node != NULL)
    {
        channel = (logger_channel*)node->value;
    }
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_channel_get(%s) = %p", channel_name, channel);
    flushout();
#endif
    
    return channel;
}

static ya_result
logger_service_channel_register(const char *channel_name, logger_channel *channel)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_channel_register(%s,%p)", channel_name, channel);
    flushout();
#endif
    
    if(channel->linked_handles != 0)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_service_channel_register(%s,%p) ALREADY LINKED", channel_name, channel);
        flushout();
#endif
        return LOGGER_CHANNEL_HAS_LINKS;
    }
    
    if(logger_service_channel_get(channel_name) != NULL)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_service_channel_register(%s,%p) NAME ALREADY USED", channel_name, channel);
        flushout();
#endif
        logger_channel_free(channel);
        return LOGGER_CHANNEL_ALREADY_REGISTERED;
    }
    
    ptr_node *node = ptr_set_insert(&logger_channels, strdup(channel_name));
    node->value = channel;
    
    return SUCCESS;
}

static ya_result
logger_service_channel_unregister(const char *channel_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_channel_unregister(%s)", channel_name);
    flushout();
#endif
        
    logger_channel *channel;
    
    ptr_node *node = ptr_set_find(&logger_channels, channel_name);
    
    if(node == NULL)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_service_channel_unregister(%s) NAME NOT USED", channel_name);
        flushout();
#endif
        return LOGGER_CHANNEL_NOT_REGISTERED;
    }
    
    channel = (logger_channel*)node->value;

    if(channel->linked_handles != 0)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_service_channel_unregister(%s) STILL LINKED", channel_name);
        flushout();
#endif
        return LOGGER_CHANNEL_HAS_LINKS;
    }
    
    char *key = (char*)node->key;
    ptr_set_delete(&logger_channels, channel_name);
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
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_channel_unregister_all()");
    flushout();
#endif

    // for all channels

    ptr_vector logger_channel_list = PTR_VECTOR_EMPTY;
    ptr_vector logger_name_list = PTR_VECTOR_EMPTY;

    ptr_set_iterator iter;
    ptr_set_iterator_init(&logger_channels, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);

        logger_channel *channel = (logger_channel*)node->value;
        char *channel_name = (char*)node->key;

        ptr_vector_append(&logger_name_list, channel_name);
        ptr_vector_append(&logger_channel_list, channel);
    }

    for(int i = 0; i <= ptr_vector_last_index(&logger_name_list); ++i)
    {
        char *channel_name = (char*)ptr_vector_get(&logger_name_list, i);

#if DEBUG_LOG_HANDLER
        logger_channel *channel = (logger_channel*)ptr_vector_get(&logger_channel_list, i);
        debug_osformatln(termout, "logger_service_channel_unregister_all() : channel %s@%p", channel_name, channel);
        flushout();
#endif
        
        // for all handles
        
        for(s32 i = 0; i <= ptr_vector_last_index(&logger_handles); i++)
        {
            logger_handle *handle = (logger_handle*)ptr_vector_get(&logger_handles, i);
            
#if DEBUG_LOG_HANDLER
            debug_osformatln(termout, "logger_service_channel_unregister_all() : channel %s@%p : handle %s@%p", channel_name, channel, handle->name, handle);
            flushout();
#endif
            
            // remove channel from handle
            
            logger_service_handle_remove_channel(handle, channel_name);
        }

#if DEBUG_LOG_HANDLER
            assert(channel->linked_handles == 0);
#endif
    }

    for(int i = 0; i <= ptr_vector_last_index(&logger_name_list); ++i)
    {
        char *channel_name = (char*)ptr_vector_get(&logger_name_list, i);
        logger_channel *channel = (logger_channel*)ptr_vector_get(&logger_channel_list, i);

        logger_channel_free(channel);
        free(channel_name);
    }

    ptr_set_destroy(&logger_channels);

    ptr_vector_destroy(&logger_channel_list);
    ptr_vector_destroy(&logger_name_list);
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
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "[%i] logger_service_handle_create(%s)", getpid(), name);
    flushout();
#endif

    size_t name_len = strlen(name);

    if(name_len > LOGGER_HANDLE_NAME_SIZE_MAX)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "[%i] logger_service_handle_create(%s) : name is too big", getpid(), name);
        flushout();
#endif
        return NULL;
    }

    logger_handle* handle = (logger_handle*)ptr_vector_linear_search(&logger_handles, name, logger_handle_compare_match);

    if(handle == NULL)
    {
        s32 handle_index = ptr_vector_size(&logger_handles);

        assert(handle_index < LOGGER_HANDLE_COUNT_MAX);

        handle = &g_logger_handle_shared_table[handle_index];

        memcpy(handle->name, name, name_len + 1);
        memset(handle->formatted_name, ' ', LOGGER_HANDLE_FORMATTED_NAME_SIZE_MAX);
        memcpy(handle->formatted_name, name, MIN(name_len, LOGGER_HANDLE_FORMATTED_NAME_SIZE_MAX));
        handle->formatted_name[LOGGER_HANDLE_FORMATTED_NAME_SIZE_MAX] = '\0';

        handle->enabled = TRUE;

#if DEBUG
        handle->magic_check = LOGGER_HANDLE_MAGIC_CHECK;
#endif
        int i;

        for(i = 0; i < MSG_LEVEL_COUNT; i++)
        {
            handle->active[i] = 0;
            ptr_vector_init(&handle->channels[i]);
        }

        ptr_vector_append(&logger_handles, handle); // this is a collection to keep track of the handles, not their storage
    }
    else
    {
        if(handle->enabled)
        {
#if DEBUG_LOG_HANDLER
            debug_osformatln(termerr, "[%i] logger_service_handle_create(%s) : handle already created at %p", getpid(), name, handle);
            flusherr();
#endif
        }
        else
        {
            handle->enabled = TRUE;
        }
    }

#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "[%i] logger_service_handle_create(%s) = %p", getpid(), name, handle);
    flushout();
#endif

    return handle;
}

static void
logger_service_handle_close(const char *name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_handle_close(%s)", name);
    flushout();
#endif
    
    //logger_handle* handle = (logger_handle*)ptr_vector_search(&logger_handles, name, logger_handle_compare_match);
    logger_handle* handle = (logger_handle*)ptr_vector_linear_search(&logger_handles, name, logger_handle_compare_match);

    if(handle != NULL)
    {
        if(!handle->enabled)
        {
            return;
        }

        if(*handle->global_reference != LOGGER_HANDLE_SINK)
        {
            *handle->global_reference = LOGGER_HANDLE_SINK; // but the handle will still exist, only disabled
        }

        // decrement references for all channels used

        memset(handle->active, 0, sizeof(handle->active));
        
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

        handle->enabled = FALSE;
    }
    // else the handle never existed
}

#if 0
static void
logger_service_handle_close_all()
{
}
#endif

static inline logger_handle*
logger_service_handle_get(const char *name)
{
    logger_handle* handle = (logger_handle*)ptr_vector_linear_search(&logger_handles, name, logger_handle_compare_match);

    if((handle != NULL) && (!handle->enabled))
    {
        handle = NULL;
    }

    return handle;
}

/**
 * INTERNAL: used by the service
 */

static ya_result
logger_service_handle_add_channel(logger_handle *handle, int level, const char *channel_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_handle_add_channel(%s@%p, %x, %s)", handle->name, handle, level, channel_name);
    flushout();
#endif
        
    assert(level >= 0 && level <= MSG_ALL_MASK);

    int lvl;
    int level_mask;
    
    logger_channel *channel = logger_service_channel_get(channel_name);

    if(channel == NULL)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_service_handle_add_channel(%s@%p, %x, %s) UNKNOWN CHANNEL", handle->name, handle, level, channel_name);
        flushout();
#endif

        return LOGGER_CHANNEL_NOT_REGISTERED;
    }

    // add the channel in every level required by the level mask
    
    for(lvl = 0U,  level_mask = 1; level_mask <= MSG_ALL_MASK; lvl++, level_mask <<= 1)
    {
        if((level & level_mask) != 0)
        {
            if(ptr_vector_linear_search(&handle->channels[lvl], channel, logger_handle_channel_compare_match) == NULL)
            {
                ptr_vector_append(&handle->channels[lvl], channel);
                channel->linked_handles++;
                handle->active[lvl] = 1;
            }
        }
    }
    
    return SUCCESS;
}

static ya_result
logger_service_handle_remove_channel(logger_handle *handle, const char *channel_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_handle_remove_channel(%s@%p, %s)", handle->name, handle, channel_name);
    flushout();
#endif
        
    logger_channel *channel = logger_service_channel_get(channel_name);
    if(channel == NULL)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_service_handle_remove_channel(%s@%p, %s) UNKNOWN CHANNEL", handle->name, handle, channel_name);
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

            if(ptr_vector_isempty(&handle->channels[lvl]))
            {
                handle->active[lvl] = 0;
            }
        }
    }

    return SUCCESS;
}

static void
logger_service_handle_remove_all_channel(logger_handle *handle)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_handle_remove_all_channel(%s@%p)", handle->name, handle);
    flushout();
#endif
    memset(handle->active, 0, sizeof(handle->active));

    for(u8 lvl = 0; lvl < MSG_LEVEL_COUNT; lvl++)
    {
        for(s32 idx = 0; idx < ptr_vector_size(&handle->channels[lvl]); idx++)
        {
            logger_channel *channel = (logger_channel*)ptr_vector_get(&handle->channels[lvl], idx);
            channel->linked_handles--;
        }
        ptr_vector_clear(&handle->channels[lvl]);
    }
}

static ya_result
logger_service_handle_count_channels(logger_handle *handle)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_handle_count_channels(%s@%p)", handle->name, handle);
    flushout();
#endif
   
    s32 sum = 0;
    
    for(u8 lvl = 0; lvl <= MSG_ALL; lvl++)
    {
        sum += ptr_vector_size(&handle->channels[lvl]);
    }
    
    return sum;
}

/**
 * INTERNAL: used inside the service (2)
 */

static void
logger_service_flush_all_channels()
{
#if DEBUG_LOG_HANDLER > 1
    debug_osformatln(termout, "logger_service_flush_all_channels()");
    flushout();
#endif
    
    ptr_set_iterator iter;
    ptr_set_iterator_init(&logger_channels, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        logger_channel *channel = (logger_channel*)node->value;
        logger_channel_flush(channel);
    }
}

/**
 * INTERNAL: used inside the service (1)
 */

static void
logger_service_reopen_all_channels()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_reopen_all_channels()");
    flushout();
#endif
    ptr_set_iterator iter;
    ptr_set_iterator_init(&logger_channels, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        logger_channel *channel = (logger_channel*)node->value;
        ya_result return_code = logger_channel_reopen(channel);
        
        if(FAIL(return_code))
        {
            log_try_err("could not reopen logger channel '%s': %r", STRNULL((char*)node->key), return_code);
        }
    }
}

/**
 * INTERNAL: used inside the service (1)
 */

static void
logger_service_sink_all_channels()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_service_sink_all_channels()");
    flushout();
#endif
    ptr_set_iterator iter;
    ptr_set_iterator_init(&logger_channels, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        logger_channel *channel = (logger_channel*)node->value;
        logger_channel_sink(channel);
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
        debug_osformatln(termerr, "message level too low: %u < %u", level, MSG_CRIT);
        flusherr();
        return;
    }

    exit_level = level;
}

#if !HAS_SHARED_QUEUE_SUPPORT
static void*
logger_client_dispatcher_thread(void* context)
{
#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_set_thread_tag("loggercl");
#endif
    
    int sockfd;
    
    for(;;)
    {
        if((sockfd = ipc_client_connect("logger")) >= 0)
        {
            break;
        }        
    }
    
    output_stream los;
    input_stream lis;
    
    fd_output_stream_attach_noclose(&los, sockfd);
    //buffer_output_stream_init(&los, &los, 4096);
    fd_input_stream_attach_noclose(&lis, sockfd);
    
    bool must_run = TRUE; 
    
    while(must_run)
    {
        logger_message* message = (logger_message*)threaded_queue_try_dequeue(&logger_commit_queue);
        
        if(message == NULL)
        {
            output_stream_flush(&los);
            sleep(1);
            continue;
        }
        
        switch(message->type)
        {
            case LOGGER_MESSAGE_TYPE_TEXT:
            {
                struct logger_message_text_s *logger_message_text = (struct logger_message_text_s*)message;
                output_stream_write(&los, logger_message_text, offsetof(struct logger_message_text_s, text));
                output_stream_write(&los, &logger_message_text->tv, sizeof(struct logger_message_text_s) - offsetof(struct logger_message_text_s, tv));
                int len = strlen((const char*)logger_message_text->text);
                output_stream_write_u16(&los, len);
                output_stream_write(&los, logger_message_text->text, len);
                ZFREE_ARRAY(message->text.text, message->text.text_buffer_length);
                logger_message_free(message);
                break;
            }

            case LOGGER_MESSAGE_TYPE_STOP:
            {
                must_run = threaded_queue_size(&logger_commit_queue) > 0;
                if(must_run)
                {
                    // repost
                    logger_message_post(message);
                    break;
                }
                
                u8 tmp;
                output_stream_write_u8(&los, message->type);
                input_stream_read_u8(&lis, &tmp);
                // process the sync (flush + process)
                async_wait_s *awp = message->stop.aw;
                logger_message_free(message);
                async_wait_progress(awp, 1);
                
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_CHANNEL_FLUSH_ALL:
            case LOGGER_MESSAGE_TYPE_CHANNEL_REOPEN_ALL:                
            case LOGGER_MESSAGE_TYPE_CHANNEL_CLOSE_ALL:
            case LOGGER_MESSAGE_TYPE_CHANNEL_SINK_ALL:
            {
                u8 tmp;
                output_stream_write_u8(&los, message->type);
                input_stream_read_u8(&lis, &tmp);
                // process the sync (flush + process)
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

            default:
            {
                abort();
                break;
            }
        }
    }

    output_stream_close(&los);
    input_stream_close(&lis);

    ipc_client_close(sockfd);
    logger_started = FALSE;
    
    return NULL;
}

static void*
logger_server_dispatcher_client_thread(void* context)
{
    output_stream los;
    input_stream lis;
    int *sockfdp = (int*)context;
    int sockfd = *sockfdp;
    ZFREE_OBJECT(sockfdp);
    
    fd_input_stream_attach_noclose(&lis, sockfd);
    //buffer_input_stream_init(&lis, &lis, 4096);
    fd_output_stream_attach_noclose(&los, sockfd);
    
    bool must_run = TRUE; 
    
    logger_message* message = logger_message_alloc();
    
    while(must_run)
    {
        if(input_stream_read_u8(&lis, &message->type) == 0)
        {
            continue;
        }
        
        switch(message->type)
        {
            case LOGGER_MESSAGE_TYPE_TEXT:
            {
                struct logger_message_text_s *logger_message_text = (struct logger_message_text_s*)message;
                input_stream_read(&lis, &logger_message_text->level, offsetof(struct logger_message_text_s, text) - 1);
                input_stream_read(&lis, &logger_message_text->tv, sizeof(struct logger_message_text_s) - offsetof(struct logger_message_text_s, tv));
                u16 text_size = 0;
                input_stream_read_u16(&lis, &text_size);
                ZALLOC_ARRAY_OR_DIE(u8*, logger_message_text->text, logger_message_text->text_buffer_length, BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG);
                input_stream_read(&lis, logger_message_text->text, text_size);
                logger_message_post(message);
                message = logger_message_alloc();
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_STOP:
            {
                must_run = FALSE;
                /*
                must_run = threaded_queue_size(&logger_commit_queue) > 0;
                if(must_run)
                {
                    // repost
                    logger_message_post(message);
                    message = logger_message_alloc();
                }
                
                async_wait_progress(message->handle_close.aw, 1);
                */
                
                break;
            }
            case LOGGER_MESSAGE_TYPE_CHANNEL_FLUSH_ALL:
            case LOGGER_MESSAGE_TYPE_CHANNEL_REOPEN_ALL:                
            case LOGGER_MESSAGE_TYPE_CHANNEL_CLOSE_ALL:
            case LOGGER_MESSAGE_TYPE_CHANNEL_SINK_ALL:
            {
#if HAS_SHARED_QUEUE_SUPPORT
                async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
                message->channel_flush_all.aw = aw;
#else
                async_wait_s aw;
                async_wait_init(&aw, 1);
                message->channel_flush_all.aw = &aw;
#endif
                logger_message_post(message);
                
                while(logger_initialised_and_started())
                {
#if HAS_SHARED_QUEUE_SUPPORT
                    if(async_wait_timeout(aw, ONE_SECOND_US))
                    {
                        async_wait_destroy_shared(aw);
                        break;
                    }
#else
                    if(async_wait_timeout(&aw, ONE_SECOND_US))
                    {
                        async_wait_finalize(&aw);
                        break;
                    }
#endif
                }
                
                message = logger_message_alloc();
                
                output_stream_write_u8(&los, 1);
                                
                break;
            }
            default:
            {
                abort();
            }
        }
    }
    
    logger_message_free(message);
    ipc_client_close(sockfd);
    
    return NULL;
}

static void*
logger_server_dispatcher_thread(void* context)
{
#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_set_thread_tag("loggersr");
#endif
    int sockfd = ipc_server_listen("logger");
    int ret;
    
    for(;;)
    {
        int clientfd = ipc_server_accept(sockfd);
        if(clientfd >= 0)
        {
            int *clientfdp;
            ZALLOC_OBJECT_OR_DIE(clientfdp, int, GENERIC);
            *clientfdp = clientfd;
            if((ret = thread_create(&logger_thread_id, logger_server_dispatcher_client_thread, clientfdp)) != 0)
            {
            }
        }
    }
    ipc_server_close(sockfd);
    
    return NULL;
}
#endif

static void*
logger_dispatcher_thread(void* context)
{
    (void)context;

#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger: dispatcher starting");
    flushout();
#endif

    if(!smp_int_setifequal(&logger_thread_state, LOGGER_DISPATCHED_THREAD_STOPPED, LOGGER_DISPATCHED_THREAD_STARTED))
    {
        debug_osformatln(termout, "logger_dispatcher_thread(%p) state expected to be LOGGER_DISPATCHED_THREAD_STOPPED", context);
        return NULL;
    }

#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_dispatcher_thread(%p) started", context);
    flushout();
#endif

    thread_set_name("logger", 0U,  0);
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    thread_set_tag_with_pid_and_tid(getpid_ex(), thread_self(), "logger");
#endif

    output_stream baos;
    bytearray_output_stream_context baos_context;    
    bytearray_output_stream_init_ex_static(&baos, NULL, 1024, BYTEARRAY_DYNAMIC, &baos_context);

    /*
     * Since I'll use this virtual call a lot, it's best to cache it.
     * (Actually it would be even better to use the static method)
     */
    output_stream_write_method *baos_write = baos.vtbl->write;
    
#if !HAS_SHARED_QUEUE_SUPPORT    
    char repeat_text[128];
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    char thread_tag_buffer[12];
#endif
#endif

    if(!smp_int_setifequal(&logger_thread_state, LOGGER_DISPATCHED_THREAD_STARTED, LOGGER_DISPATCHED_THREAD_READY))
    {
        debug_osformatln(termout, "logger_dispatcher_thread(%p) state expected to be LOGGER_DISPATCHED_THREAD_STARTED", context);
        return NULL;
    }

    bool must_run = TRUE; 
    
    while(must_run)
    {
#if DEBUG_LOG_HANDLER > 1
        debug_osformatln(termout, "logger: waiting for message");
        flushout();
#endif

#if HAS_SHARED_QUEUE_SUPPORT
        struct shared_circular_buffer_slot* slot = shared_circular_buffer_prepare_dequeue(logger_shared_queue);
        logger_message* message = (logger_message*)slot;

#else
        logger_message* message = (logger_message*)threaded_queue_dequeue(&logger_commit_queue);
#endif

        assert(message != NULL);

#if DEBUG_LOG_HANDLER
#if DEBUG_LOG_HANDLER > 1
        debug_osformatln(termout, "logger: got message %p (%i) from %i:%p",
                        message,
                        message->type,
                        message->pid,
                        message->text.thread_id);
        flushout();
#else
        if(logger_thread_pid != getpid_ex())
        {
            debug_osformatln(termout, "logger: got message %p (%i) from %i:%p",
                            message,
                            message->type,
                            message->pid,
                            message->text.thread_id);
            flushout();
        }
#endif
        if(kill(message->pid, 0) < 0)
        {
            debug_osformatln(termerr, "logger: got message %p (%i) from %i:%p : PID doesn't exist",
                             message,
                             message->type,
                             message->pid,
                             message->text.thread_id);
            flusherr();
        }
#endif
        /*
         * Reopen is not a message per se.
         * It has to be done "now" (ie: the disk is full, files have to be moved)
         * But if it was handled as a message, it would need to clear the queue before having an effect.
         * So instead a flag is used0
         */

        {
            mutex_lock(&logger_mutex);
            logger_message *logger_sink_request_message = logger_shared_space->_logger_sink_request_message;
            if(logger_sink_request_message != NULL)
            {
                logger_shared_space->_logger_sink_request_message = NULL;
            }
            logger_message *logger_reopen_request_message = logger_shared_space->_logger_reopen_request_message;
            if(logger_reopen_request_message != NULL)
            {
                logger_shared_space->_logger_reopen_request_message = NULL;
            }
            mutex_unlock(&logger_mutex);

            if(((intptr)logger_sink_request_message | (intptr)logger_reopen_request_message) != 0)
            {
                if(logger_sink_request_message != NULL)
                {
                    logger_service_sink_all_channels();

                    if(logger_sink_request_message != LOGGER_MESSAGE_SINK_FAKE)
                    {
                        if(logger_sink_request_message->channel_sink_all.aw != NULL)
                        {

                            async_wait_progress(logger_sink_request_message->channel_sink_all.aw, 1);
                        }
                        logger_sink_request_message->channel_sink_all.aw = NULL;
                    }
                }

                if(logger_reopen_request_message != NULL)
                {
                    logger_service_reopen_all_channels();
                    if(logger_reopen_request_message->channel_sink_all.aw != NULL)
                    {
                        async_wait_progress(logger_reopen_request_message->channel_reopen_all.aw, 1);
                        logger_reopen_request_message->channel_reopen_all.aw = NULL;
                    }
                }
            }
        }

        switch(message->type)
        {
            case LOGGER_MESSAGE_TYPE_TEXT:
            {
#if DEBUG_LOG_MESSAGES
                {
                    time_t now = time(NULL);
                    if(now - allocated_messages_count_stats_time > 10)
                    {
                        allocated_messages_count_stats_time = now;
                        int val = smp_int_get(&allocated_messages_count);

                        //debug_osformatln(termerr, "messages allocated count = %d", val);
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
#if HAS_SHARED_QUEUE_SUPPORT
                    shared_heap_free(message->text.text);
                    shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                    ZFREE_ARRAY(message->text.text, message->text.text_buffer_length);
                    logger_message_free(message);
#endif
                    continue;
                }

                u32 date_header_len;

                if(message->text.flags == 0)
                {
                    struct tm t;
#if SIZEOF_TIMEVAL <= 8
                    localtime_r(&message->text.tv.tv_sec, &t);
                    osformat(&baos, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
                            t.tm_year + 1900U,  t.tm_mon + 1, t.tm_mday,
                            t.tm_hour, t.tm_min, t.tm_sec, message->text.tv.tv_usec);
#else
                    time_t tv_sec = message->text.timestamp / ONE_SECOND_US;
                    localtime_r(&tv_sec, &t);
                    osformat(&baos, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
                            t.tm_year + 1900U,  t.tm_mon + 1, t.tm_mday,
                            t.tm_hour, t.tm_min, t.tm_sec, message->text.timestamp % ONE_SECOND_US);
#endif
                    
                    
                    
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);

#if HAS_SHARED_QUEUE_SUPPORT
                    osprint_u16(&baos, message->pid);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);
#else
#if DEBUG || HAS_LOG_PID
                    osprint_u16(&baos, message->text.pid);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);
#endif
#endif
#if DEBUG || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
#if DNSCORE_HAS_LOG_THREAD_TAG
                    baos_write(&baos, (const u8*)thread_get_tag_with_pid_and_tid(message->pid, message->text.thread_id), 8);
#else
                    osprint_u32_hex(&baos, (u32)message->text.thread_id);
#endif
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);                    
#endif

                    baos_write(&baos, (u8*)handle->formatted_name, LOGGER_HANDLE_FORMATTED_NAME_SIZE_MAX);
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
#if SIZEOF_TIMEVAL <= 8
                    localtime_r(&message->text.tv.tv_sec, &t);
                    osformat(&baos, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                            t.tm_year + 1900U,  t.tm_mon + 1, t.tm_mday,
                            t.tm_hour, t.tm_min, t.tm_sec, message->text.tv.tv_usec / 1000);
                    baos_write(&baos, message->text.prefix, message->text.prefix_length);
#else
                    time_t tv_sec = message->text.timestamp / ONE_SECOND_US;
                    localtime_r(&tv_sec, &t);
                    osformat(&baos, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                            t.tm_year + 1900U,  t.tm_mon + 1, t.tm_mday,
                            t.tm_hour, t.tm_min, t.tm_sec, (message->text.timestamp % ONE_SECOND_US) / 1000ULL);
                    baos_write(&baos, message->text.prefix, message->text.prefix_length);
#endif


                    date_header_len = 24;
                }

                baos_write(&baos, message->text.text, message->text.text_length);
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_heap_free(message->text.text);
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#endif

                output_stream_write_u8(&baos, 0);                

                size_t size = bytearray_output_stream_size(&baos) - 1;
                char* buffer = (char*)bytearray_output_stream_buffer(&baos);

                logger_channel** channelp = (logger_channel**)handle->channels[level].data;
                
                do
                {
                    logger_channel* channel = *channelp;

                    ya_result return_code;

#if !HAS_SHARED_QUEUE_SUPPORT
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
#if SIZE_TIMEVAL <= 8
                            localtime_r(&message->text.tv.tv_sec, &t);
#else
                            localtime_r(&message->text.timestamp / 1000000ULL, &t);
#endif
                            
#if 1
#if DNSCORE_HAS_LOG_THREAD_TAG
                            thread_copy_tag(channel->last_message->text.thread_id, thread_tag_buffer);
#endif
                            
                            return_code = snformat(repeat_text, sizeof(repeat_text), 
                                    
#if (DEBUG || HAS_LOG_PID) && DNSCORE_HAS_LOG_THREAD_TAG
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %s | -------- | N | last message repeated %d times",
#elif DEBUG || (HAS_LOG_PID && HAS_LOG_THREAD_ID)
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | %08x | -------- | N | last message repeated %d times",
#elif DNSCORE_HAS_LOG_THREAD_TAG
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %s | -------- | N | last message repeated %d times",
#elif HAS_LOG_THREAD_ID
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %08x | -------- | N | last message repeated %d times",
#elif HAS_LOG_PID
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | %-5i | -------- | N | last message repeated %d times",
#else
                            "%04d-%02d-%02d %02d:%02d:%02d.%06d | -------- | N | last message repeated %d times",
#endif
                            t.tm_year + 1900U,  t.tm_mon + 1, t.tm_mday,
                                    t.tm_hour, t.tm_min, t.tm_sec,
#if SIZE_TIMEVAL <= 8
                                    message->text.tv.tv_usec
#else
                                    message->text.timestamp % ONE_SECOND_US
#endif
                                    ,
#if DEBUG || HAS_LOG_PID
                            getpid_ex(),
#endif
#if DNSCORE_HAS_LOG_THREAD_TAG
                            thread_tag_buffer,
#else
    #if DEBUG || HAS_LOG_THREAD_ID
                            channel->last_message->text.thread_id,
    #endif
#endif
                            channel->last_message_count);
#else
                            
                            return_code = snformat(repeat_text, sizeof(repeat_text), "%04d-%02d-%02d %02d:%02d:%02d.%06d" COLUMN_SEPARATOR 
#if DEBUG
                                    "%-5d" COLUMN_SEPARATOR
                                    "%08x" COLUMN_SEPARATOR
#endif
                                    "--------" COLUMN_SEPARATOR
                                    "N" COLUMN_SEPARATOR
                                    "last message repeated %d times",
                                    t.tm_year + 1900U,  t.tm_mon + 1, t.tm_mday,
                                    t.tm_hour, t.tm_min, t.tm_sec,
#if SIZE_TIMEVAL <= 8
                                    message->text.tv.tv_usec
#else
                                    message->text.timestamp % ONE_SECOND_US
#endif
                                    ,
#if DEBUG || HAS_LOG_PID
                                    channel->last_message->text.pid,
#endif
#if DEBUG || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
                                    channel->last_message->text.thread_id,
#endif
                                    channel->last_message_count);
#endif
                            

                            if(ISOK(return_code))
                            {
                                while(FAIL(return_code = logger_channel_msg(channel, level, repeat_text, return_code, 29)))
                                {
                                    if(stdstream_is_tty(termerr))
                                    {
                                        debug_osformatln(termerr, "message write failed on channel: %r", return_code);
                                        flusherr();
                                    }
                                    
                                    if(return_code == MAKE_ERRNO_ERROR(EBADF) || return_code == MAKE_ERRNO_ERROR(ENOSPC))
                                    {
                                        logger_sink_requested = TRUE;
                                    }
                                    
                                    if(logger_sink_requested || logger_reopen_requested)
                                    {
                                        if(logger_sink_requested)
                                        {
                                            logger_service_sink_all_channels();
                                            logger_sink_requested = FALSE;
                                        }
                                        if(logger_reopen_requested)
                                        {
                                            logger_service_reopen_all_channels();
                                            logger_reopen_requested = FALSE;
                                        }
                                    }
                                    
                                    if(dnscore_shuttingdown())
                                    {
                                        // message will be lost
                                        break;
                                    }
                                    
                                    sleep(1);
                                }
                            }
                            else
                            {
                                if(stdstream_is_tty(termerr))
                                {
                                    debug_osformatln(termerr, "message formatting failed on channel: %r", return_code);
                                    flusherr();
                                }
                            }
                        }

                        /* cleanup */
                        if(--channel->last_message->text.rc == 0)
                        {
                            /* free the message */

#if DEBUG_LOG_MESSAGES
                            debug_osformatln(termout, "message rc is 0 (%s)", channel->last_message->text.text);
                            flushout();
#endif
                            ZFREE_ARRAY(channel->last_message->text.text, channel->last_message->text.text_buffer_length);
                            logger_message_free(channel->last_message);
                        }
#if DEBUG_LOG_MESSAGES
                        else
                        {
                            debug_osformatln(termout, "message rc decreased to %d (%s)", channel->last_message->text.rc, channel->last_message->text.text);
                            flushout();
                        }

                        channel->last_message = message;
                        channel->last_message_count = 0;
                        message->text.rc++;
#endif
                        
                        
#if DEBUG_LOG_MESSAGES
                        debug_osformatln(termout, "message rc is %d (%s)", channel->last_message->text.rc, channel->last_message->text.text);
                        flushout();
#endif
                        
#endif // !HAS_SHARED_QUEUE_SUPPORT (no repeat compression)

                        while(FAIL(return_code = logger_channel_msg(channel, level, buffer, size, date_header_len)))
                        {
                            if(stdstream_is_tty(termerr))
                            {
                                debug_osformatln(termerr, "message write failed on channel: %r", return_code);
                                flusherr();
                            }

                            bool logger_sink_requested = FALSE;

                            if((return_code == MAKE_ERRNO_ERROR(EBADF)) || (return_code == MAKE_ERRNO_ERROR(ENOSPC)))
                            {
                                logger_sink_requested = TRUE;
                            }

                            mutex_lock(&logger_mutex);
                            logger_message *logger_sink_request_message = logger_shared_space->_logger_sink_request_message;
                            if(logger_sink_request_message != NULL)
                            {
                                logger_shared_space->_logger_sink_request_message = NULL;
                            }
                            logger_message *logger_reopen_request_message = logger_shared_space->_logger_reopen_request_message;
                            if(logger_reopen_request_message != NULL)
                            {
                                logger_shared_space->_logger_reopen_request_message = NULL;
                            }
                            mutex_unlock(&logger_mutex);

                            if(logger_sink_request_message != NULL)
                            {
                                logger_service_sink_all_channels();
                                //logger_sink_requested = FALSE;
                                if(logger_sink_request_message != LOGGER_MESSAGE_SINK_FAKE)
                                {
                                    if(logger_sink_request_message->channel_sink_all.aw != NULL)
                                    {

                                        async_wait_progress(logger_sink_request_message->channel_sink_all.aw, 1);
                                    }
                                    logger_sink_request_message->channel_sink_all.aw = NULL;
                                }
                            }
                            else if(logger_sink_requested)
                            {
                                logger_service_sink_all_channels();
                                //logger_sink_requested = FALSE;
                            }

                            if(logger_reopen_request_message != NULL)
                            {
                                logger_service_reopen_all_channels();
                                if(logger_reopen_request_message->channel_sink_all.aw != NULL)
                                {
                                    async_wait_progress(logger_reopen_request_message->channel_reopen_all.aw, 1);
                                    logger_reopen_request_message->channel_reopen_all.aw = NULL;
                                }
                            }

                            if(dnscore_shuttingdown())
                            {
                                // message will be lost
                                break;
                            }

                            sleep(1);
                        }
#if !HAS_SHARED_QUEUE_SUPPORT
                    }
#endif

                    channelp++;
                }
                while(--channel_count >= 0);

#if !HAS_SHARED_QUEUE_SUPPORT
                if(message->text.rc == 0)
                {
#if DEBUG_LOG_HANDLER
                    debug_osformatln(termout, "message has not been used (full dup): '%s'", message->text.text);
                    flushout();
#endif
                    ZFREE_ARRAY(message->text.text, message->text.text_buffer_length);
                    logger_message_free(message);
                }
#endif
                bytearray_output_stream_reset(&baos);

                break;
            }

            case LOGGER_MESSAGE_TYPE_CHANNEL_CLOSE_ALL:
            {
                async_wait_s *awp = message->channel_flush_all.aw;
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           

                logger_service_flush_all_channels();
                //logger_service_close_all_channels();
                logger_service_channel_unregister_all();

                async_wait_progress(awp, 1);

                break;
            }
            
            case LOGGER_MESSAGE_TYPE_STOP:
            {
#if HAS_SHARED_QUEUE_SUPPORT
                must_run = shared_circular_buffer_size(logger_shared_queue) > 1;
                if(must_run)
                {
                    // repost
                    logger_message* new_message = (logger_message*)shared_circular_buffer_prepare_enqueue(logger_shared_queue);
#if HAS_SHARED_QUEUE_SUPPORT
                    new_message->pid = getpid_ex();
#endif
                    new_message->type = LOGGER_MESSAGE_TYPE_STOP;
                    new_message->stop.aw = message->stop.aw;
                    shared_circular_buffer_commit_dequeue(logger_shared_queue);
                    shared_circular_buffer_commit_enqueue(logger_shared_queue, (struct shared_circular_buffer_slot*)new_message);
                }
                else
                {                
                    async_wait_s *awp = message->handle_close.aw;
                    shared_circular_buffer_commit_dequeue(logger_shared_queue); // destroys the message but not the synchronisation structure.
                    async_wait_progress(awp, 1);
                }
#else
                must_run = threaded_queue_size(&logger_commit_queue) > 0;
                if(must_run)
                {
                    // repost
                    logger_message_post(message);
                }
                else
                {
                    async_wait_s *awp = message->handle_close.aw;
                    async_wait_progress(awp, 1);
                }
#endif
                break;
            }
                
                /// @note fall through by design
                
            case LOGGER_MESSAGE_TYPE_CHANNEL_FLUSH_ALL:
            {
                async_wait_s *awp = message->channel_flush_all.aw;
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           

                logger_service_flush_all_channels();

                async_wait_progress(awp, 1);

                break;
            }

            case LOGGER_MESSAGE_TYPE_CHANNEL_REOPEN_ALL:
            {
                // reopen is activated by a flag
                // this structure is just a way to fire the event
                
                async_wait_s *awp = message->channel_reopen_all.aw;
                if(awp != NULL)
                {
                    if(stdstream_is_tty(termerr))
                    {
                        debug_osformatln(termerr, "logger: unexpected synchronization point in reopen");
                        flusherr();
                    }

                    async_wait_progress(awp, 1);
                }
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_CHANNEL_SINK_ALL:
            {
                // sink is activated by a flag
                // this structure is just a way to fire the event
                
                async_wait_s *awp = message->channel_sink_all.aw;
                if(awp != NULL)
                {
                    if(stdstream_is_tty(termerr))
                    {
                        debug_osformatln(termerr, "logger: unexpected synchronization point in sink");
                        flusherr();
                    }

                    async_wait_progress(awp, 1);
                }

#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_IGNORE:
            {
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_CHANNEL_GET_USAGE_COUNT:
            {
                async_wait_s *awp = message->get_usage_count.aw;
                const char *channel_name = message->get_usage_count.channel_name;
                                
                s32 *countp = message->get_usage_count.countp;
                
                assert(countp != NULL);
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           

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
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           

                logger_service_channel_register(channel_name, channel);
                
                async_wait_progress(awp, 1);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_CHANNEL_UNREGISTER:
            {
                async_wait_s *awp = message->channel_unregister.aw;
                const char *channel_name = message->channel_unregister.channel_name;
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           

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
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif
                async_wait_progress(awp, 1);                
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_HANDLE_CLOSE:
            {
                async_wait_s *awp = message->handle_close.aw;
                const char *name = message->handle_close.logger_name;
                //u32 name_len = message->text_length;              
                logger_service_handle_close(name);
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           
                
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
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           
                
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
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           
                
                async_wait_progress(awp, 1);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_HANDLE_NAME_COUNT_CHANNELS:
            {
                logger_handle *handle;
                async_wait_s *awp = message->handle_count_channels.aw;
                const char *name = message->handle_count_channels.logger_name;
                
                handle = logger_service_handle_get(name);
                
                *message->handle_count_channels.countp = 0;
                
                if(handle != NULL)
                {
                    *message->handle_count_channels.countp = logger_service_handle_count_channels(handle);
                }
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif           
                
                async_wait_progress(awp, 1);
                break;
            }
#if DNSCORE_HAS_LOG_THREAD_TAG
            case LOGGER_MESSAGE_TYPE_THREAD_SET_TAG:
            {
                async_wait_s *awp = message->thread_set_tag.aw;
#if DEBUG
                printf("logger: registering: pid=%i thread=%p tag=%c%c%c%c%c%c%c%c (printf)\n",
                              message->pid, (void*)(intptr_t)message->thread_set_tag.tid,
                              message->thread_set_tag.tag[0],message->thread_set_tag.tag[1],message->thread_set_tag.tag[2],message->thread_set_tag.tag[3],
                              message->thread_set_tag.tag[4],message->thread_set_tag.tag[5],message->thread_set_tag.tag[6],message->thread_set_tag.tag[7]);
                debug_osformatln(termout, "logger: registering: pid=%i thread=%p tag=%c%c%c%c%c%c%c%c (printf)",
                       message->pid, (void*)(intptr_t)message->thread_set_tag.tid,
                       message->thread_set_tag.tag[0],message->thread_set_tag.tag[1],message->thread_set_tag.tag[2],message->thread_set_tag.tag[3],
                       message->thread_set_tag.tag[4],message->thread_set_tag.tag[5],message->thread_set_tag.tag[6],message->thread_set_tag.tag[7]);
#endif
#if DEBUG
                log_try_debug("logger: registering: pid=%i thread=%p tag=%c%c%c%c%c%c%c%c (log_try_debug)",
                              message->pid, message->thread_set_tag.tid,
                              message->thread_set_tag.tag[0],message->thread_set_tag.tag[1],message->thread_set_tag.tag[2],message->thread_set_tag.tag[3],
                              message->thread_set_tag.tag[4],message->thread_set_tag.tag[5],message->thread_set_tag.tag[6],message->thread_set_tag.tag[7]);
#endif
                thread_set_tag_with_pid_and_tid(message->pid, message->thread_set_tag.tid, message->thread_set_tag.tag);
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif
                async_wait_progress(awp, 1);
                break;
            }
            
            case LOGGER_MESSAGE_TYPE_THREAD_CLEAR_TAG:
            {
                async_wait_s *awp = message->thread_clear_tag.aw;
                
                thread_clear_tag_with_pid_and_tid(message->pid, message->thread_clear_tag.tid);
                
#if HAS_SHARED_QUEUE_SUPPORT
                shared_circular_buffer_commit_dequeue(logger_shared_queue);
#else
                logger_message_free(message);
#endif
                async_wait_progress(awp, 1);
                break;
            }
#endif
            default:
            {
                if(stdstream_is_tty(termerr))
                {
                    debug_osformatln(termerr, "unexpected message type %u in log queue", message->type);
                    flusherr();
                }
                
                break;
            }
        }
    } // while must run

    if(!smp_int_setifequal(&logger_thread_state, LOGGER_DISPATCHED_THREAD_READY, LOGGER_DISPATCHED_THREAD_STOPPING))
    {
        debug_osformatln(termout, "logger_dispatcher_thread(%p) state expected to be LOGGER_DISPATCHED_THREAD_READY", context);
        return NULL;
    }

    // flush everything

    logger_service_flush_all_channels();

    // close everything
    
    output_stream_close(&baos);
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_dispatcher_thread(%p) END", context);
    flushout();
#endif
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    thread_clear_tag_with_pid_and_tid(getpid_ex(), thread_self());
#endif

    if(!smp_int_setifequal(&logger_thread_state, LOGGER_DISPATCHED_THREAD_STOPPING, LOGGER_DISPATCHED_THREAD_STOPPED))
    {
        debug_osformatln(termout, "logger_dispatcher_thread(%p) state expected to be LOGGER_DISPATCHED_THREAD_STOPPING", context);
        //return NULL;
    }

    return NULL;
}

s32
logger_channel_get_usage_count(const char* channel_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_channel_get_usage_count(%s) ", channel_name);
    flushout();
#endif
    
    s32 count = -2;
    
    if(logger_is_running())
    {
        logger_message *message = logger_message_alloc();

        // ZEROMEMORY(message, sizeof(logger_message));

#if HAS_SHARED_QUEUE_SUPPORT
        async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
        async_wait_s aw;
        async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
        message->pid = getpid_ex();
#endif
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_GET_USAGE_COUNT;
#if HAS_SHARED_QUEUE_SUPPORT
        message->get_usage_count.aw = aw;
#else
        message->get_usage_count.aw = &aw;
#endif
        message->get_usage_count.channel_name = channel_name;
        message->get_usage_count.countp = &count;

        logger_message_post(message);

#if HAS_SHARED_QUEUE_SUPPORT
        async_wait(aw);
        async_wait_destroy_shared(aw);
#else
        async_wait(&aw);
        async_wait_finalize(&aw);
#endif
    }
    else
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_lock(logger_shared_queue);
#else
        mutex_lock(&logger_commit_queue.mutex);
#endif

        logger_channel *channel = logger_service_channel_get(channel_name);

        if(channel != NULL)
        {
            count = channel->linked_handles;
        }
        else
        {
            count = -1;
        }
        
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_unlock(logger_shared_queue);
#else
        mutex_unlock(&logger_commit_queue.mutex);
#endif
    }
    
    return count;
}

void
logger_channel_register(const char* channel_name, struct logger_channel *channel)
{
    if((channel == NULL) || (channel->vtbl == NULL))
    {
        debug_osformatln(termerr, "tried to register channel on uninitialised channel");
        return;
    }
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_channel_register(%s,%p) ", channel_name, channel);
    flushout();
#endif
    if(logger_is_running())
    {
        logger_message *message = logger_message_alloc();

#if HAS_SHARED_QUEUE_SUPPORT
        async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
        async_wait_s aw;
        async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
        message->pid = getpid_ex();
#endif
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_REGISTER;
#if HAS_SHARED_QUEUE_SUPPORT
        message->channel_register.aw = aw;
#else
        message->channel_register.aw = &aw;
#endif
        message->channel_register.channel_name = channel_name;
        message->channel_register.channel = channel;

        logger_message_post(message);

#if HAS_SHARED_QUEUE_SUPPORT
        async_wait(aw);
        async_wait_destroy_shared(aw);
#else
        async_wait(&aw);
        async_wait_finalize(&aw);
#endif
    }
    else
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_lock(logger_shared_queue);
#else
        mutex_lock(&logger_commit_queue.mutex);
#endif
        logger_service_channel_register(channel_name, channel);
        
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_unlock(logger_shared_queue);
#else
        mutex_unlock(&logger_commit_queue.mutex);
#endif
    }
}

void
logger_channel_unregister(const char* channel_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_channel_unregister(%s) ", channel_name);
    flushout();
#endif
    
    logger_message *message = logger_message_alloc();

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
    async_wait_s aw;
    async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_CHANNEL_UNREGISTER;
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->channel_unregister.aw = aw;
#else
    message->channel_unregister.aw = &aw;
#endif
    message->channel_unregister.channel_name = channel_name;
    
    logger_message_post(message);
    
#if HAS_SHARED_QUEUE_SUPPORT
    async_wait(aw);
    async_wait_destroy_shared(aw);
#else
    async_wait(&aw);
    async_wait_finalize(&aw);
#endif
}

void
logger_handle_create(const char *logger_name, logger_handle **handle_holder)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_create(%s,%p) ", logger_name, handle_holder);
    flushout();
#endif
    
    if(logger_is_running())
    {
        logger_message *message = logger_message_alloc();

#if HAS_SHARED_QUEUE_SUPPORT
        async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
        async_wait_s aw;
        async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
        message->pid = getpid_ex();
#endif
        message->type = LOGGER_MESSAGE_TYPE_HANDLE_CREATE;
#if HAS_SHARED_QUEUE_SUPPORT
        message->handle_create.aw = aw;
#else
        message->handle_create.aw = &aw;
#endif
        message->handle_create.logger_name = logger_name;
        message->handle_create.handle_holder = handle_holder;

        logger_message_post(message);

#if HAS_SHARED_QUEUE_SUPPORT
        async_wait(aw);
        async_wait_destroy_shared(aw);
#else
        async_wait(&aw);
        async_wait_finalize(&aw);
#endif
    }
    else
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_lock(logger_shared_queue);
#else
        mutex_lock(&logger_commit_queue.mutex);
#endif
        logger_handle* handle = logger_service_handle_create(logger_name);
        handle->global_reference = handle_holder;
        *handle_holder = handle;
        
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_unlock(logger_shared_queue);
#else
        mutex_unlock(&logger_commit_queue.mutex);
#endif
    }
}

void
logger_handle_close(const char *logger_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_close(%s) ", logger_name);
    flushout();
#endif
    
    logger_message *message = logger_message_alloc();

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
    async_wait_s aw;
    async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_HANDLE_CLOSE;
#if HAS_SHARED_QUEUE_SUPPORT
    message->handle_close.aw = aw;
#else
    message->handle_close.aw = &aw;
#endif
    message->handle_close.logger_name = logger_name;
    
    logger_message_post(message);

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait(aw);
    async_wait_destroy_shared(aw);
#else
    async_wait(&aw);
    async_wait_finalize(&aw);
#endif
}

void
logger_handle_add_channel(const char *logger_name, int level, const char *channel_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_add_channel(%s,%x,%s) ", logger_name, level, channel_name);
    flushout();
#endif
    
    if(logger_is_running())
    {
        logger_message *message = logger_message_alloc();
        ZEROMEMORY(message, sizeof(logger_message));
#if HAS_SHARED_QUEUE_SUPPORT
        async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
        async_wait_s aw;
        async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
        message->pid = getpid_ex();
#endif
        message->type = LOGGER_MESSAGE_TYPE_HANDLE_NAME_ADD_CHANNEL;
#if HAS_SHARED_QUEUE_SUPPORT
        message->handle_add_channel.aw = aw;
#else
        message->handle_add_channel.aw = &aw;
#endif
        message->handle_add_channel.logger_name = logger_name;
        message->handle_add_channel.level = level;
        message->handle_add_channel.channel_name = channel_name;

        logger_message_post(message);

#if HAS_SHARED_QUEUE_SUPPORT
        async_wait(aw);
        async_wait_destroy_shared(aw);
#else
        async_wait(&aw);
        async_wait_finalize(&aw);
#endif
    }
    else
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_lock(logger_shared_queue);
#else
        mutex_lock(&logger_commit_queue.mutex);
#endif
        logger_handle *handle = logger_service_handle_get(logger_name);
        if(handle != NULL)
        {
            logger_service_handle_add_channel(handle, level, channel_name);
        }
        
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_unlock(logger_shared_queue);
#else
        mutex_unlock(&logger_commit_queue.mutex);
#endif
    }
}

void
logger_handle_remove_channel(const char *logger_name, const char *channel_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_remove_channel(%s,%s) ", logger_name, channel_name);
    flushout();
#endif
    
    logger_message *message = logger_message_alloc();

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
    async_wait_s aw;
    async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_HANDLE_NAME_REMOVE_CHANNEL;

#if HAS_SHARED_QUEUE_SUPPORT
    message->handle_remove_channel.aw = aw;
#else
    message->handle_remove_channel.aw = &aw;
#endif
    
    message->handle_remove_channel.logger_name = logger_name;
    message->handle_remove_channel.channel_name = channel_name;
    
    logger_message_post(message);

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait(aw);
    async_wait_destroy_shared(aw);
#else
    async_wait(&aw);
    async_wait_finalize(&aw);
#endif
}

/**
 * 
 * Helper function.
 * Creates a logger for the given file descriptor (typically 1/stdout or 2/stderr)
 * 
 * @param logger_name name of the logger
 * @param mask the mask to use (ie: MSG_ALL_MASK)
 * @param fd the file descriptor
 */

void
logger_handle_create_to_fd(const char *logger_name, int mask, int fd)
{
    logger_channel* channel = logger_channel_alloc();
    output_stream stdout_os;
    fd_output_stream_attach(&stdout_os, dup(fd));
    logger_channel_stream_open(&stdout_os, FALSE, channel);
    logger_channel_register("stdout", channel);
    logger_handle_create(logger_name, &g_system_logger);
    logger_handle_add_channel(logger_name, mask, "stdout");
}

s32
logger_handle_count_channels(const char *logger_name)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_count_channels(%s)", logger_name);
    flushout();
#endif
    
    logger_message *message = logger_message_alloc();
    s32 ret = -2;

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
    async_wait_s aw;
    async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_HANDLE_NAME_COUNT_CHANNELS;
#if HAS_SHARED_QUEUE_SUPPORT
    message->handle_count_channels.aw = aw;
#else
    message->handle_count_channels.aw = &aw;
#endif
    message->handle_count_channels.logger_name = logger_name;
    message->handle_count_channels.countp = &ret;
    
    logger_message_post(message);

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait(aw);
    async_wait_destroy_shared(aw);
#else
    async_wait(&aw);
    async_wait_finalize(&aw);
#endif
    
    return ret;
}

#if DNSCORE_HAS_LOG_THREAD_TAG

void
logger_handle_set_thread_tag_with_pid_and_tid(pid_t pid, thread_t tid, const char tag[THREAD_TAG_SIZE])
{
    (void)pid;
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_set_thread_tag_with_pid_and_tid(%i,%p) ", pid, tid,
            tag[0],tag[1],tag[2],tag[3],
            tag[4],tag[5],tag[6],tag[7]);
    flushout();
#endif

    logger_message *message = logger_message_alloc();
#if HAS_SHARED_QUEUE_SUPPORT
    async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
    async_wait_s aw;
    async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_THREAD_SET_TAG;
#if HAS_SHARED_QUEUE_SUPPORT
    message->thread_set_tag.aw = aw;
#else
    message->thread_set_tag.aw = &aw;
#endif
    memcpy(message->thread_set_tag.tag, tag, THREAD_TAG_SIZE);
    message->thread_set_tag.tid = tid;
    
    logger_message_post(message);

#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_set_thread_tag_with_pid_and_tid(%i,%p) (posted)", pid, tid,
            tag[0],tag[1],tag[2],tag[3],
            tag[4],tag[5],tag[6],tag[7]);
    flushout();
#endif

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait(aw);
    async_wait_destroy_shared(aw); // does the finalize call
#else
    async_wait(&aw);
    async_wait_finalize(&aw);
#endif
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_set_thread_tag_with_pid_and_tid(%i,%p) (synced, done)", pid, tid,
            tag[0],tag[1],tag[2],tag[3],
            tag[4],tag[5],tag[6],tag[7]);
    flushout();
#endif
}

void
logger_handle_clear_thread_tag_with_pid_and_tid(pid_t pid, thread_t tid)
{
    (void)pid;
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_handle_clear_thread_tag_with_pid_and_tid(%i,%p) ", pid, tid);
    flushout();
#endif
    
    logger_message *message = logger_message_alloc();

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
    async_wait_s aw;
    async_wait_init(&aw, 1);
#endif
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_THREAD_CLEAR_TAG;
#if HAS_SHARED_QUEUE_SUPPORT
    message->thread_clear_tag.aw = aw;
#else
    message->thread_clear_tag.aw = &aw;
#endif
    message->thread_clear_tag.tid = tid;
    
    logger_message_post(message);

#if HAS_SHARED_QUEUE_SUPPORT
    async_wait(aw);
    async_wait_destroy_shared(aw);
#else
    async_wait(&aw);
    async_wait_finalize(&aw);
#endif
}

void
logger_handle_set_thread_tag(const char tag[THREAD_TAG_SIZE])
{
    char clean_tag[THREAD_TAG_SIZE + 1];
    memset(clean_tag, 0U,  sizeof(clean_tag));
    strcpy_ex(clean_tag, tag, sizeof(clean_tag));

    if(logger_is_running())
    {
        logger_handle_set_thread_tag_with_pid_and_tid(getpid_ex(), thread_self(), clean_tag);
    }
    else
    {
        thread_set_tag_with_pid_and_tid(getpid_ex(), thread_self(), clean_tag);
    }
}

void
logger_handle_clear_thread_tag()
{
    if(logger_is_running())
    {
        logger_handle_clear_thread_tag_with_pid_and_tid(getpid_ex(), thread_self());
    }
    else
    {
        thread_clear_tag_with_pid_and_tid(getpid_ex(), thread_self());
    }
}

#endif

static u32 logger_queue_size = LOG_QUEUE_DEFAULT_SIZE;

#if !HAS_SHARED_QUEUE_SUPPORT
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
#endif

void
logger_init_ex(u32 queue_size, size_t shared_heap_size)
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_init_ex(%u)", queue_size);
    flushout();
#endif
    
    if(!logger_initialised())
    {
        logger_thread_pid = getpid_ex();
        
#if HAS_SHARED_QUEUE_SUPPORT
        shared_heap_init();
        
        if(shared_heap_size == 0)
        {
            shared_heap_size = 0x4000000 + LOGGER_HANDLE_SHARED_TABLE_SIZE; // 64MB
        }

        for(;;)
        {
            ya_result ret;
            if(ISOK(ret = shared_heap_create(shared_heap_size)))
            {
                logger_shared_heap_id = (u8)ret;
                break;
            }
            
            if(shared_heap_size < 0x10000)
            {
                debug_osformatln(termerr, "logger: unable to allocate enough shared memory: %r", ret);
                flusherr();
                exit(1);
            }
            
            shared_heap_size <<= 1;
        }

        g_logger_handle_shared_table = shared_heap_alloc(logger_shared_heap_id, LOGGER_HANDLE_SHARED_TABLE_SIZE);
        if(g_logger_handle_shared_table == NULL)
        {
            debug_osformatln(termerr, "logger: unable to allocate handle table");
            flusherr();
            exit(1);
        }

        memset(g_logger_handle_shared_table, 0U,  LOGGER_HANDLE_SHARED_TABLE_SIZE);

        for(int i = 0; i < LOGGER_HANDLE_COUNT_MAX; ++i)
        {
            for(int j = 0; j < MSG_LEVEL_COUNT; ++j)
            {
                ptr_vector_init(&g_logger_handle_shared_table[i].channels[j]);
            }
        }
#endif
        
        if(!logger_queue_initialised)
        {
#if HAS_SHARED_QUEUE_SUPPORT
            if(queue_size == 0)
            {
                logger_queue_size = 1024 * 1024;
            }
            
            logger_shared_queue = shared_circular_buffer_create_ex(20U,  sizeof(logger_shared_space_t));

            if(logger_shared_queue == NULL)
            {
                debug_osformatln(termerr, "logger: unable to allocate shared buffer: %r", ERRNO_ERROR);
                flusherr();
                exit(1);
            }

            logger_shared_space = (logger_shared_space_t*)shared_circular_buffer_additional_space_ptr(logger_shared_queue);
#else
            if(queue_size != 0)
            {
                logger_queue_size = queue_size;
            }            
            threaded_queue_init(&logger_commit_queue, logger_queue_size); // not used anymore (replaced by a shared queue)
#endif
            logger_queue_initialised = TRUE;
        }

        if(!logger_handle_init_done)
        {
            logger_handle_init_done = TRUE;

            ptr_vector_init(&logger_handles);

            format_class_init();
        }

#ifndef WIN32
        logger_set_uid(getuid());
        logger_set_gid(getgid());
#endif

        logger_handle_create("system", &g_system_logger);

        mutex_lock(&logger_mutex);
        _logger_initialised = TRUE;
        mutex_unlock(&logger_mutex);
    }
    else
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_init_ex(%u) : already initialised", logger_queue_size);
        flushout();
#endif
    }
}

void
logger_init()
{
    logger_init_ex(logger_queue_size, 0 );
}

void
logger_start()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_start() ");
    flushout();
#endif
    
    ya_result return_code;
    
    if(!logger_initialised())
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_start() : not initialised yet : calling");
        flushout();
#endif     

        logger_init();
    }
    
    if(logger_thread_pid != getpid_ex())
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_start() : not initialised by the same process");
        flushout();
#endif

#if DNSCORE_HAS_LOG_THREAD_TAG
        // push all tags to the logger process

        thread_tag_push_tags();
#endif
        return;
    }

    mutex_lock(&logger_mutex);
    if(!_logger_started)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_start() : starting");
        flushout();
#endif
        if((return_code = thread_create(&logger_thread_id, logger_dispatcher_thread, NULL)) != 0)
        {
            mutex_unlock(&logger_mutex);
            debug_osformatln(termerr, "logger_start: pthread_create: %r", return_code);
            DIE(LOGGER_INITIALISATION_ERROR);
        }

        _logger_started = TRUE;

        mutex_unlock(&logger_mutex);
    }
    else
    {
        mutex_unlock(&logger_mutex);
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_start() : already started");
        flushout();
#endif     
    }
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_start() : started");
    flushout();
#endif     
}

#if !HAS_SHARED_QUEUE_SUPPORT
static thread_t logger_server_id = 0;

void
logger_start_server()
{
    if(logger_initialised_and_started())
    {
        int ret;
        if((ret = thread_create(&logger_server_id, logger_server_dispatcher_thread, NULL)) != 0)
        {
            debug_osformatln(termerr, "logger_start_server: pthread_create: %r", ret);
            DIE(LOGGER_INITIALISATION_ERROR);
        }
    }
}

void
logger_stop_server()
{
    pthread_cancel(logger_server_id);
}

void
logger_start_client()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_start_client() ");
    flushout();
#endif
    
    ya_result ret;
    
    if(!logger_initialised())
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_start_client() : not initialised yet : calling");
        flushout();
#endif     

        logger_init();
    }
    
    if(!logger_started())
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_start_client() : starting");
        flushout();
#endif
        
        if((ret = thread_create(&logger_thread_id, logger_client_dispatcher_thread, NULL)) != 0)
        {
            debug_osformatln(termerr, "logger_start: pthread_create: %r", ret);
            DIE(LOGGER_INITIALISATION_ERROR);
        }

        logger_is_client = TRUE;
        logger_started = TRUE;
    }
    else
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_start_client() : already started");
        flushout();
#endif     
    }
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_start_client() : started");
    flushout();
#endif     
}

void
logger_stop_client()
{
    logger_stop();
    //pthread_cancel(logger_thread_id);
}

#endif

static void
logger_send_message_stop_wait()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_send_message_stop_wait()");
    flushout();
#endif
            
#if HAS_SHARED_QUEUE_SUPPORT
    async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
    async_wait_s aw;
    async_wait_init(&aw, 1);
#endif
    
    logger_message* message = logger_message_alloc();
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_STOP;
#if HAS_SHARED_QUEUE_SUPPORT
    message->stop.aw = aw;
#else
    message->stop.aw = &aw;
#endif

    logger_message_post(message);

#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_send_message_stop_wait() : waiting");
    flushout();
#endif
    
#if HAS_SHARED_QUEUE_SUPPORT
    async_wait(aw);
    async_wait_destroy_shared(aw);
#else
    async_wait(&aw);
    async_wait_finalize(&aw);
#endif
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_send_message_stop_wait() : should be stopped");
    flushout();
#endif
}

u8
logger_set_shared_heap(u8 id)
{
    u8 ret = logger_shared_heap_id;
    logger_shared_heap_id = id;
    return ret;
}

void
logger_stop()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_stop()");
    flushout();
#endif     

    if(logger_initialised_and_started())
    {
        // send the stop order

        if(logger_thread_pid == getpid_ex())
        {
            logger_send_message_stop_wait();

#if DEBUG_LOG_HANDLER
            debug_osformatln(termout, "logger_stop() : joining");
            flushout();
#endif     

            // wait for the end

            ya_result return_code;

            if((return_code = thread_join(logger_thread_id, NULL)) != 0)
            {
                flushout();
                flusherr();
                debug_osformatln(termerr, "logger_stop: thread_join: %r", return_code);
                flusherr();
            }

            logger_thread_id = 0;
            mutex_lock(&logger_mutex);
            _logger_started = FALSE;
            mutex_unlock(&logger_mutex);
        }
        else
        {
            // not the owner
        }
    }
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_stop() : stopped");
    flushout();
#endif 
}

void
logger_finalize()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_finalize()");
    flushout();
#endif 
    
    if(logger_thread_pid != getpid_ex())
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_finalize() : not owner");
        flushout();
#endif 
        return;
    }
            
    if(!logger_initialised())
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_finalize() : not initialised");
        flushout();
#endif 
        return;
    }
        
#if HAS_SHARED_QUEUE_SUPPORT
    if(!shared_circular_buffer_empty(logger_shared_queue))
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_finalize() : queue is not empty : starting & flushing");
        flushout();
#endif
        logger_start();
        if(logger_wait_started())
        {
            logger_flush();
        }
    }
#else
    if(threaded_queue_size(&logger_commit_queue) > 0)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_finalize() : queue is not empty : starting & flushing");
        flushout();
#endif
        logger_start();   
        logger_flush();
    }
#endif
    
    if(logger_started())
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_finalize() : still running : stopping");
        flushout();
#endif
        logger_stop();
    }

    /*
     * Ensure there is nothing left at all in the queue
     */

#if HAS_SHARED_QUEUE_SUPPORT
    while(!shared_circular_buffer_empty(logger_shared_queue))
    {
        logger_message* message = (logger_message*)shared_circular_buffer_prepare_dequeue(logger_shared_queue);
        if(message->type == LOGGER_MESSAGE_TYPE_TEXT)
        {
            shared_heap_free(message->text.text);
        }
        shared_circular_buffer_commit_dequeue(logger_shared_queue);
    }
#else
    while(threaded_queue_size(&logger_commit_queue) > 0)
    {
        logger_message* message = threaded_queue_dequeue(&logger_commit_queue);
        
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_finalize() : freeing message of type %u", message->type);
        flushout();
#endif
     
        if(message->type == LOGGER_MESSAGE_TYPE_TEXT)
        {
            ZFREE_ARRAY(message->text.text, message->text.text_buffer_length);
        }
        logger_message_free(message);
    }
#endif

    if(logger_handle_init_done)
    {
#if DEBUG_LOG_HANDLER
        debug_osformatln(termout, "logger_finalize() : flushing all channels");
        flushout();
#endif
        logger_service_flush_all_channels();
        
        // closes all handles
        
        if(logger_thread_pid == getpid_ex()) // logger_handle_owner_pid
        {
#if DEBUG_LOG_HANDLER
            debug_osformatln(termout, "logger_finalize() : closing all handles");
            flushout();
#endif
            ptr_vector_callback_and_clear(&logger_handles, logger_handle_free);
            ptr_vector_destroy(&logger_handles);
        
            // closes all channels

#if DEBUG_LOG_HANDLER
            debug_osformatln(termout, "logger_finalize() : closing all channels");
            flushout();
#endif
        
            logger_service_channel_unregister_all();
        }
        
        logger_handle_init_done = FALSE;
    }
    
    if(logger_queue_initialised)
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_circular_buffer_destroy(logger_shared_queue);
#else
        threaded_queue_finalize(&logger_commit_queue);
#endif
        logger_queue_initialised = FALSE;
    }
    
    logger_set_path(NULL);

    mutex_lock(&logger_mutex);
    _logger_initialised = FALSE;
    mutex_unlock(&logger_mutex);
    
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_finalize() : finalised");
    flushout();
#endif
}

void
logger_flush()
{
#if DEBUG_LOG_HANDLER > 1
    debug_osformatln(termout, "logger_flush()");
    flushout();
#endif
    
    if(logger_initialised_and_started())
    {
        if(logger_thread_id != thread_self())
        {
#if HAS_SHARED_QUEUE_SUPPORT
            async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
            async_wait_s aw;
            async_wait_init(&aw, 1);
#endif
            logger_message* message = logger_message_alloc();
#if DEBUG
            message->align0 = 0xde;
            message->align1 = 0xf00d;
#endif
#if HAS_SHARED_QUEUE_SUPPORT
            message->pid = getpid_ex();
#endif
            message->channel_flush_all.tid = thread_self();
            message->type = LOGGER_MESSAGE_TYPE_CHANNEL_FLUSH_ALL;
            
#if HAS_SHARED_QUEUE_SUPPORT
            message->channel_flush_all.aw = aw;
#else
            message->channel_flush_all.aw = &aw;
#endif
            logger_message_post(message);

            // avoid being stuck forever if the service is down

            while(logger_initialised_and_started())
            {
#if HAS_SHARED_QUEUE_SUPPORT
                if(async_wait_timeout(aw, ONE_SECOND_US))
                {
                    //async_wait_destroy_shared(aw);
                    break;
                }
#else
                if(async_wait_timeout(&aw, ONE_SECOND_US))
                {
                    async_wait_finalize(&aw);
                    break;
                }
#endif
            }

            async_wait_destroy_shared(aw);
        }
        else
        {
            logger_service_flush_all_channels();
        }
    }
#if DEBUG_LOG_HANDLER
    else
    {
        debug_osformatln(termout, "logger_flush() : i=%i s=%i", logger_initialised, logger_started());
        flushout();
    }
#endif
}

void
logger_channel_close_all()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_close_all_channels()");
    flushout();
#endif
    
    if(logger_initialised_and_started())
    {
#if HAS_SHARED_QUEUE_SUPPORT
        async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
        async_wait_s aw;
        async_wait_init(&aw, 1);
#endif
        
        logger_message* message = logger_message_alloc();

#if DEBUG        
        ZEROMEMORY(message, sizeof(logger_message));
#endif
#if HAS_SHARED_QUEUE_SUPPORT
        message->pid = getpid_ex();
#endif
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_CLOSE_ALL;
#if HAS_SHARED_QUEUE_SUPPORT
        message->channel_flush_all.aw = aw;
#else
        message->channel_flush_all.aw = &aw;
#endif
        
        logger_message_post(message);
        
        // avoid being stuck forever if the service is down
        
        while(logger_initialised_and_started())
        {
#if HAS_SHARED_QUEUE_SUPPORT
            formatln("logger_channel_close_all");
            if(async_wait_timeout(aw, ONE_SECOND_US))
            {
                //async_wait_destroy_shared(aw);
                break;
            }
#else
            if(async_wait_timeout(&aw, ONE_SECOND_US))
            {
                async_wait_finalize(&aw);
                break;
            }
#endif
        }

        async_wait_destroy_shared(aw);
    }
#if DEBUG_LOG_HANDLER
    else
    {
        debug_osformatln(termout, "logger_close_all_channels() : i=%i s=%i", logger_initialised, logger_started());
        flushout();
    }
#endif
}

void
logger_reopen()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_reopen()");
    flushout();
#endif
    
    if(logger_initialised_and_started())
    {
        // even for a lflag, the message NEEDS to be enqueued because
        // 1) it activates the service
        // 2) synchronises the memory between the threads (memory wall)
        
#if HAS_SHARED_QUEUE_SUPPORT
        async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
        async_wait_s aw;
        async_wait_init(&aw, 1);
#endif
        
        logger_message* message = logger_message_alloc();
        
#if DEBUG
        ZEROMEMORY(message, sizeof(logger_message));
#endif
#if HAS_SHARED_QUEUE_SUPPORT
        message->pid = getpid_ex();
#endif
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_REOPEN_ALL;
#if HAS_SHARED_QUEUE_SUPPORT
        message->channel_reopen_all.aw = aw;
#else
        message->channel_reopen_all.aw = &aw;
#endif
        mutex_lock(&logger_mutex);
        logger_shared_space->_logger_reopen_request_message = message;
        mutex_unlock(&logger_mutex);

        logger_message_post(message);
        
        while(logger_initialised_and_started())
        {
#if HAS_SHARED_QUEUE_SUPPORT
#if DEBUG_LOG_HANDLER
            formatln("logger_reopen");
#endif
            if(async_wait_timeout(aw, ONE_SECOND_US))
            {
                //async_wait_destroy_shared(aw);
                break;
            }
#else
            if(async_wait_timeout(&aw, ONE_SECOND_US))
            {
                async_wait_finalize(&aw);
                break;
            }
#endif
        }

        async_wait_destroy_shared(aw);
    }
#if DEBUG_LOG_HANDLER
    else
    {
        debug_osformatln(termout, "logger_reopen() : i=%i s=%i", logger_initialised, logger_started());
        flushout();
    }
#endif
}

void
logger_sink_noblock()
{
    mutex_lock(&logger_mutex);
    logger_shared_space->_logger_sink_request_message = LOGGER_MESSAGE_SINK_FAKE;
    mutex_unlock(&logger_mutex);
}

void
logger_sink()
{
#if DEBUG_LOG_HANDLER
    debug_osformatln(termout, "logger_reopen()");
    flushout();
#endif
    
    if(logger_initialised_and_started())
    {
        // even for a lflag, the message NEEDS to be enqueued because
        // 1) it activates the service
        // 2) synchronises the memory between the threads (memory wall)
        
#if HAS_SHARED_QUEUE_SUPPORT
        async_wait_s *aw = async_wait_create_shared(logger_shared_heap_id, 1);
#else
        async_wait_s aw;
        async_wait_init(&aw, 1);
#endif
        logger_message* message = logger_message_alloc();
#if DEBUG
        ZEROMEMORY(message, sizeof(logger_message));
#endif
#if HAS_SHARED_QUEUE_SUPPORT
        message->pid = getpid_ex();
#endif
        message->type = LOGGER_MESSAGE_TYPE_CHANNEL_SINK_ALL;
#if HAS_SHARED_QUEUE_SUPPORT
        message->channel_sink_all.aw = aw;
#else
        message->channel_sink_all.aw = &aw;
#endif
        mutex_lock(&logger_mutex);
        logger_shared_space->_logger_sink_request_message = message;
        mutex_unlock(&logger_mutex);

        logger_message_post(message);

        while(logger_initialised_and_started())
        {
#if HAS_SHARED_QUEUE_SUPPORT
#if DEBUG
            formatln("logger_sink");
#endif
            if(async_wait_timeout(aw, ONE_SECOND_US))
            {
                //async_wait_destroy_shared(aw);
                break;
            }
#else
            if(async_wait_timeout(&aw, ONE_SECOND_US))
            {
                async_wait_finalize(&aw);
                break;
            }
#endif
#if DEBUG
            mutex_lock(&logger_mutex);
            bool stop_looping = logger_shared_space->_logger_sink_request_message != NULL;
            mutex_unlock(&logger_mutex);
            if(stop_looping)
            {
                formatln("_logger_sink_requested is FALSE but the synchronization hasn't been released yet");
            }
#endif
        }

        async_wait_destroy_shared(aw);
    }
#if DEBUG_LOG_HANDLER
    else
    {
        debug_osformatln(termout, "logger_reopen() : i=%i s=%i", logger_initialised, logger_started());
        flushout();
    }
#endif
}

bool
logger_is_running()
{
    return logger_started();
}

void
logger_handle_vmsg(logger_handle* handle, u32 level, const char* fmt, va_list args)
{
    /*
     * check that the handle has got a channel for the level
     */

#if DEBUG
    if((handle == NULL) || (handle->magic_check != LOGGER_HANDLE_MAGIC_CHECK))
    {
#if DEBUG_LOG_HANDLER
        debug_stacktrace_print(termout, debug_stacktrace_get());
        debug_stacktrace_print(termerr, debug_stacktrace_get());
        flushout();
        flusherr();
#endif
        abort();
    }

    if(level >= MSG_LEVEL_COUNT)
    {
        debug_osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_emergency_shutdown();
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
            logger_handle_trigger_emergency_shutdown();
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
#if HAS_SHARED_QUEUE_SUPPORT
    shared_heap_output_stream_context shos_context;
#else
    bytezarray_output_stream_context baos_context;
#endif

    /*
     * DEFAULT_MAX_LINE_SIZE is the base size.
     *
     * The output stream has the BYTEARRAY_DYNAMIC flag set in order to allow
     * bigger sentences.
     *
     */

    /* Will use the tmp buffer, but alloc a bigger one if required. */
#if HAS_SHARED_QUEUE_SUPPORT
    shared_heap_output_stream_init_ex_static(&baos, logger_shared_heap_id, NULL, 48, SHARED_HEAP_DYNAMIC, &shos_context);
#else
    bytezarray_output_stream_init_ex_static(&baos, NULL, DEFAULT_MAX_LINE_SIZE, BYTEARRAY_DYNAMIC, &baos_context);
#endif

    if(FAIL(vosformat(&baos, fmt, args)))
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_heap_output_stream_reset(&baos);
#else
        bytezarray_output_stream_reset(&baos);
#endif
        osprint(&baos, "*** ERROR : MESSAGE FORMATTING FAILED ***");
    }

    output_stream_write_u8(&baos, 0);

    logger_message* message = logger_message_alloc();
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->text.text_length = shared_heap_output_stream_size(&baos) - 1;
    message->text.text_buffer_length = shared_heap_output_stream_buffer_size(&baos);
#else
    message->text.text_length = bytezarray_output_stream_size(&baos) - 1;
    message->text.text_buffer_length = bytezarray_output_stream_buffer_size(&baos);
#endif
    
    message->text.handle = handle;
    
#if HAS_SHARED_QUEUE_SUPPORT    
    message->text.text = shared_heap_output_stream_detach(&baos);
#else
    message->text.text = bytezarray_output_stream_detach(&baos);
#endif
    
#if SIZEOF_TIMEVAL <= 8
    gettimeofday(&message->text.tv, NULL);
#else
    message->text.timestamp = timeus();
#endif
    
#if !HAS_SHARED_QUEUE_SUPPORT
    // prefix
    // prefix_len
    
    message->text.rc = 0;
   
#if DEBUG || HAS_LOG_PID
    message->text.pid = getpid_ex();
#endif
#endif
    
#if DEBUG || HAS_SHARED_QUEUE_SUPPORT || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
    message->text.thread_id = thread_self();
#endif
    
    logger_message_post(message);

    output_stream_close(&baos); /* Frees the memory */
    
    if(level <= exit_level)
    {
        logger_handle_trigger_emergency_shutdown();
    }
}

void
logger_handle_msg_nocull(logger_handle* handle, u32 level, const char* fmt, ...)
{
    /**
     * @note At this point we KNOW we have to print something.
     */
    
#if DEBUG

    if((handle == NULL) || (handle->magic_check != LOGGER_HANDLE_MAGIC_CHECK))
    {
#if DEBUG_LOG_HANDLER
        debug_stacktrace_print(termout, debug_stacktrace_get());
        debug_stacktrace_print(termerr, debug_stacktrace_get());
        flushout();
        flusherr();
#endif
        abort();
    }

#ifdef NDEBUG
    size_t sizeof_logger_message = sizeof(logger_message);
    size_t sizeof_logger_message_text_s = sizeof(struct logger_message_text_s);
    assert(sizeof_logger_message_text_s <= 64);
    assert(sizeof_logger_message <= 64);
    (void)sizeof_logger_message;
    (void)sizeof_logger_message_text_s;
#endif

#endif

    output_stream baos;
#if HAS_SHARED_QUEUE_SUPPORT
    shared_heap_output_stream_context shos_context;
#else
    bytezarray_output_stream_context baos_context;
#endif
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
#if HAS_SHARED_QUEUE_SUPPORT
    shared_heap_output_stream_init_ex_static(&baos, logger_shared_heap_id, NULL, 48, SHARED_HEAP_DYNAMIC, &shos_context);
#else
    bytezarray_output_stream_init_ex_static(&baos, NULL, DEFAULT_MAX_LINE_SIZE, BYTEARRAY_DYNAMIC, &baos_context);
#endif

    if(FAIL(vosformat(&baos, fmt, args)))
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_heap_output_stream_reset(&baos);
#else
        bytezarray_output_stream_reset(&baos);
#endif
        osprint(&baos, "*** ERROR : MESSAGE FORMATTING FAILED ***");
    }

    output_stream_write_u8(&baos, 0);

    logger_message* message = logger_message_alloc();
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;

#if HAS_SHARED_QUEUE_SUPPORT
    message->text.text_length = shared_heap_output_stream_size(&baos) - 1;
    message->text.text_buffer_length = shared_heap_output_stream_buffer_size(&baos);
#else
    message->text.text_length = bytezarray_output_stream_size(&baos) - 1;
    message->text.text_buffer_length = bytezarray_output_stream_buffer_size(&baos);
#endif
    
    message->text.handle = handle;

#if HAS_SHARED_QUEUE_SUPPORT    
    message->text.text = shared_heap_output_stream_detach(&baos);
#else
    message->text.text = bytezarray_output_stream_detach(&baos);
#endif
    
    assert(message->text.text != NULL);
    
#if SIZEOF_TIMEVAL <= 8
    gettimeofday(&message->text.tv, NULL);
#else
    message->text.timestamp = timeus();
#endif
    
    // prefix
    // prefix_len
   
#if !HAS_SHARED_QUEUE_SUPPORT
    message->text.rc = 0;
   
#if DEBUG || HAS_LOG_PID
    message->text.pid = getpid_ex();
#endif
#endif

#if DEBUG || HAS_SHARED_QUEUE_SUPPORT || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
    message->text.thread_id = thread_self();
#endif
    
    logger_message_post(message);

    va_end(args);

    output_stream_close(&baos); /* Frees the memory */
}


void
logger_handle_msg(logger_handle* handle, u32 level, const char* fmt, ...)
{
    /*
     * check that the handle has got a channel for the level
     */

#if DEBUG
    if((handle == NULL) || (handle->magic_check != LOGGER_HANDLE_MAGIC_CHECK))
    {
#if DEBUG_LOG_HANDLER
        debug_stacktrace_print(termout, debug_stacktrace_get());
        debug_stacktrace_print(termerr, debug_stacktrace_get());
        flushout();
        flusherr();
#endif
        abort();
    }

    if(level >= MSG_LEVEL_COUNT)
    {
        debug_osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_emergency_shutdown();
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
            logger_handle_trigger_emergency_shutdown();
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
#if HAS_SHARED_QUEUE_SUPPORT
    shared_heap_output_stream_context baos_context;
#else
    bytezarray_output_stream_context baos_context;
#endif

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
#if HAS_SHARED_QUEUE_SUPPORT
    shared_heap_output_stream_init_ex_static(&baos, logger_shared_heap_id, NULL, DEFAULT_MAX_LINE_SIZE, SHARED_HEAP_DYNAMIC, &baos_context);
#else
    bytezarray_output_stream_init_ex_static(&baos, NULL, DEFAULT_MAX_LINE_SIZE, BYTEARRAY_DYNAMIC, &baos_context);
#endif

    if(FAIL(vosformat(&baos, fmt, args)))
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_heap_output_stream_reset(&baos);
#else
        bytezarray_output_stream_reset(&baos);
#endif
        osprint(&baos, "*** ERROR : MESSAGE FORMATTING FAILED ***");
    }

    output_stream_write_u8(&baos, 0);

    logger_message* message = logger_message_alloc();
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;

#if HAS_SHARED_QUEUE_SUPPORT
    message->text.text_length = shared_heap_output_stream_size(&baos) - 1;
    message->text.text_buffer_length = shared_heap_output_stream_buffer_size(&baos);
#else
    message->text.text_length = bytezarray_output_stream_size(&baos) - 1;
    message->text.text_buffer_length = bytezarray_output_stream_buffer_size(&baos);
#endif
    
    message->text.handle = handle;
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->text.text = shared_heap_output_stream_detach(&baos);
#else
    message->text.text = bytezarray_output_stream_detach(&baos);
#endif
    
    assert(message->text.text != NULL);
    
#if SIZEOF_TIMEVAL <= 8
    gettimeofday(&message->text.tv, NULL);
#else
    message->text.timestamp = timeus();
#endif
    
    // prefix
    // prefix_len
   
#if !HAS_SHARED_QUEUE_SUPPORT
    message->text.rc = 0;
   
#if DEBUG || HAS_LOG_PID
    message->text.pid = getpid_ex();
#endif
#endif
    
#if DEBUG || HAS_SHARED_QUEUE_SUPPORT || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
    message->text.thread_id = thread_self();
#endif
    
    logger_message_post(message);

    va_end(args);

    output_stream_close(&baos); /* Frees the memory */

    if(level <= exit_level)
    {
        exit_level = 0;
        if(!dnscore_shuttingdown())
        {
            logger_handle_trigger_emergency_shutdown();
        }
    }
}

void
logger_handle_msg_text(logger_handle* handle, u32 level, const char* text, u32 text_len)
{
    /*
     * check that the handle has got a channel for the level
     */

#if DEBUG
    if((handle == NULL) || (handle->magic_check != LOGGER_HANDLE_MAGIC_CHECK))
    {
#if DEBUG_LOG_HANDLER
        debug_stacktrace_print(termout, debug_stacktrace_get());
        debug_stacktrace_print(termerr, debug_stacktrace_get());
        flushout();
        flusherr();
#endif
        abort();
    }

    if(level >= MSG_LEVEL_COUNT)
    {
        debug_osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_emergency_shutdown();
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
            logger_handle_trigger_emergency_shutdown();
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
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;
    
    message->text.text_length = text_len;
    message->text.text_buffer_length = text_len;
    message->text.handle = handle;
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->text.text = (u8*)shared_heap_wait_alloc(logger_shared_heap_id, text_len);
#else
    ZALLOC_ARRAY_OR_DIE(u8*, message->text. text, text_len, LOGRTEXT_TAG);
#endif
    assert(message->text.text != NULL);
    
    memcpy(message->text.text, text, text_len);
    
#if SIZEOF_TIMEVAL <= 8
    gettimeofday(&message->text.tv, NULL);
#else
    message->text.timestamp = timeus();
#endif
    
    // prefix
    // prefix_len
    
#if !HAS_SHARED_QUEUE_SUPPORT
    message->text.rc = 0;

#if DEBUG || HAS_LOG_PID
    message->text.pid = getpid_ex();
#endif
#endif
    
#if DEBUG || HAS_SHARED_QUEUE_SUPPORT || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
    message->text.thread_id = thread_self();
#endif
    
    logger_message_post(message);

    if(level <= exit_level)
    {
        logger_handle_trigger_emergency_shutdown();
    }
}

void
logger_handle_msg_text_ext(logger_handle* handle, u32 level, const char* text, u32 text_len, const char* prefix, u32 prefix_len, u16 flags)
{
        /*
     * check that the handle has got a channel for the level
     */

#if DEBUG
    if((handle == NULL) || (handle->magic_check != LOGGER_HANDLE_MAGIC_CHECK))
    {
#if DEBUG_LOG_HANDLER
        debug_stacktrace_print(termout, debug_stacktrace_get());
        debug_stacktrace_print(termerr, debug_stacktrace_get());
        flushout();
        flusherr();
#endif
        abort();
    }

    if(level >= MSG_LEVEL_COUNT)
    {
        debug_osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_emergency_shutdown();
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
            logger_handle_trigger_emergency_shutdown();
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
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = flags;
    
    message->text.text_length = text_len;
    message->text.text_buffer_length = text_len;
    
    message->text.handle = handle;
    
    ZALLOC_ARRAY_OR_DIE(u8*, message->text.text, text_len, LOGRTEXT_TAG);
    memcpy(message->text.text, text, text_len);
    
#if SIZEOF_TIMEVAL <= 8
    gettimeofday(&message->text.tv, NULL);
#else
    message->text.timestamp = timeus();
#endif
        
    message->text.prefix = (const u8*)prefix;
    message->text.prefix_length = prefix_len;
    
#if !HAS_SHARED_QUEUE_SUPPORT
    message->text.rc = 0;
    
#if DEBUG || HAS_LOG_PID
    message->text.pid = getpid_ex();
#endif
#endif
    
#if DEBUG || HAS_SHARED_QUEUE_SUPPORT || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
    message->text.thread_id = thread_self();
#endif
    
    logger_message_post(message);

    if(level <= exit_level)
    {
        logger_handle_trigger_emergency_shutdown();
    }
}

void
logger_handle_try_msg(logger_handle* handle, u32 level, const char* fmt, ...)
{
    /*
     * check that the handle has got a channel for the level
     */

#if DEBUG
    if((handle == NULL) || (handle->magic_check != LOGGER_HANDLE_MAGIC_CHECK))
    {
#if DEBUG_LOG_HANDLER
        debug_stacktrace_print(termout, debug_stacktrace_get());
        debug_stacktrace_print(termerr, debug_stacktrace_get());
        flushout();
        flusherr();
#endif
        abort();
    }

    if(level >= MSG_LEVEL_COUNT)
    {
        debug_osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_emergency_shutdown();
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
            logger_handle_trigger_emergency_shutdown();
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
    
    logger_message* message = logger_message_try_alloc();

    if(message == NULL)
    {
        return;
    }

    /**
     * @note At this point we KNOW we have to print something.
     */

    output_stream baos;
#if HAS_SHARED_QUEUE_SUPPORT
    shared_heap_output_stream_context baos_context;
#else
    bytezarray_output_stream_context baos_context;
#endif

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
#if HAS_SHARED_QUEUE_SUPPORT
    shared_heap_output_stream_init_ex_static(&baos, logger_shared_heap_id, NULL, DEFAULT_MAX_LINE_SIZE, SHARED_HEAP_DYNAMIC, &baos_context);
#else
    bytezarray_output_stream_init_ex_static(&baos, NULL, DEFAULT_MAX_LINE_SIZE, BYTEARRAY_DYNAMIC, &baos_context);
#endif

    if(FAIL(vosformat(&baos, fmt, args)))
    {
#if HAS_SHARED_QUEUE_SUPPORT
        shared_heap_output_stream_reset(&baos);
#else
        bytezarray_output_stream_reset(&baos);
#endif
        osprint(&baos, "*** ERROR : MESSAGE FORMATTING FAILED ***");
    }

    output_stream_write_u8(&baos, 0);
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->text.text_length = shared_heap_output_stream_size(&baos) - 1;
    message->text.text_buffer_length = shared_heap_output_stream_buffer_size(&baos);
#else
    message->text.text_length = bytezarray_output_stream_size(&baos) - 1;
    message->text.text_buffer_length = bytezarray_output_stream_buffer_size(&baos);
#endif
    
    message->text.handle = handle;
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->text.text = shared_heap_output_stream_detach(&baos);
#else
    message->text.text = bytezarray_output_stream_detach(&baos);
#endif
    
    assert(message->text.text != NULL);
    
#if SIZEOF_TIMEVAL <= 8
    gettimeofday(&message->text.tv, NULL);
#else
    message->text.timestamp = timeus();
#endif
    
    // prefix
    // prefix_len
   
#if !HAS_SHARED_QUEUE_SUPPORT
    message->text.rc = 0;
   
#if DEBUG || HAS_LOG_PID
    message->text.pid = getpid_ex();
#endif
#endif
    
#if DEBUG || HAS_SHARED_QUEUE_SUPPORT || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
    message->text.thread_id = thread_self();
#endif
    
#if HAS_SHARED_QUEUE_SUPPORT
    logger_message_post(message);
#else
    if(!threaded_queue_try_enqueue(&logger_commit_queue, message))
    {
        // could not enqueue
        ZFREE_ARRAY(message->text.text, message->text.text_buffer_length);
        logger_message_free(message);
    }
#endif
    
    va_end(args);

    output_stream_close(&baos); /* Frees the memory */

    if(level <= exit_level)
    {
        exit_level = 0;
        if(!dnscore_shuttingdown())
        {
            logger_handle_trigger_emergency_shutdown();
        }
    }
}

void
logger_handle_try_msg_text(logger_handle* handle, u32 level, const char* text, u32 text_len)
{
    /*
     * check that the handle has got a channel for the level
     */

#if DEBUG
    if((handle == NULL) || (handle->magic_check != LOGGER_HANDLE_MAGIC_CHECK))
    {
#if DEBUG_LOG_HANDLER
        debug_stacktrace_print(termout, debug_stacktrace_get());
        debug_stacktrace_print(termerr, debug_stacktrace_get());
        flushout();
        flusherr();
#endif
        abort();
    }

    if(level >= MSG_LEVEL_COUNT)
    {
        debug_osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_emergency_shutdown();
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
            logger_handle_trigger_emergency_shutdown();
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
 
#if HAS_SHARED_QUEUE_SUPPORT
    logger_message* message = logger_message_try_alloc();
#else
    logger_message* message = logger_message_alloc();
#endif
    
#if HAS_SHARED_QUEUE_SUPPORT
    message->pid = getpid_ex();
#endif
    message->type = LOGGER_MESSAGE_TYPE_TEXT;
    message->text.level = level;
    message->text.flags = 0;
    
    message->text.text_length = text_len;
    message->text.text_buffer_length = text_len;
    message->text.handle = handle;

#if HAS_SHARED_QUEUE_SUPPORT
    message->text.text = (u8*)shared_heap_wait_alloc(logger_shared_heap_id, text_len);
#else
    ZALLOC_ARRAY_OR_DIE(u8*, message->text.text, text_len, LOGRTEXT_TAG);
#endif
    
    assert(message->text.text != NULL);
    
    memcpy(message->text.text, text, text_len);
    
#if SIZEOF_TIMEVAL <= 8
    gettimeofday(&message->text.tv, NULL);
#else
    message->text.timestamp = timeus();
#endif
    
    // prefix
    // prefix_len
    
#if !HAS_SHARED_QUEUE_SUPPORT
    message->text.rc = 0;

#if DEBUG || HAS_LOG_PID
    message->text.pid = getpid_ex();
#endif
#endif
    
#if DEBUG || HAS_SHARED_QUEUE_SUPPORT || HAS_LOG_THREAD_ID || DNSCORE_HAS_LOG_THREAD_TAG
    message->text.thread_id = thread_self();
#endif
    
#if HAS_SHARED_QUEUE_SUPPORT
    logger_message_post(message);
#else
    if(!threaded_queue_try_enqueue(&logger_commit_queue, message))
    {
        // could not enqueue
        ZFREE_ARRAY(message->text.text, message->text.text_buffer_length);
        logger_message_free(message);
    }
#endif
    
    if(level <= exit_level)
    {
        logger_handle_trigger_emergency_shutdown();
    }
}

bool
logger_queue_fill_critical()
{
#if HAS_SHARED_QUEUE_SUPPORT
    int size = shared_circular_buffer_size(logger_shared_queue);
    int room = shared_circular_buffer_avail(logger_shared_queue);
#else
    int size = threaded_ringbuffer_cw_size(&logger_commit_queue);
    int room = threaded_ringbuffer_cw_room(&logger_commit_queue);
#endif
    int maxsize = size + room;
    if(maxsize > 0)
    {
        float ratio = ((float)size) / ((float)maxsize);
        
        return (ratio > 0.5f);
    }
    else
    {
        return TRUE;
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

void
logger_release_ownership()
{
    if(logger_thread_pid != -1)
    {
        logger_thread_pid = -1;
    }

    if(logger_handle_owner_pid != -1)
    {
        logger_handle_owner_pid = -1;
    }
}

void
logger_take_ownership(pid_t new_owner)
{
    if(logger_thread_pid == -1)
    {
        logger_thread_pid = new_owner;
    }

    if(logger_handle_owner_pid == -1)
    {
        logger_handle_owner_pid = new_owner;
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

bool
logger_wait_started()
{
    for(int countdown = 50; countdown > 0; --countdown)
    {
        int value = smp_int_get(&logger_thread_state);
        if(value == LOGGER_DISPATCHED_THREAD_STARTED)
        {
            return TRUE;
        }
        usleep_ex(100000);
    }

    return FALSE;
}

/** @} */
