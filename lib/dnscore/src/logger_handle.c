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
/** @defgroup logger Logging functions
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>

#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include <pthread.h>

#include "dnscore/logger_channel_stream.h"
#include "dnscore/logger_channel.h"

#include "dnscore/mutex.h"
#include "dnscore/ptr_vector.h"

#include "dnscore/file_output_stream.h"
#include "dnscore/bytearray_output_stream.h"

#include "dnscore/format.h"
#include "dnscore/dnscore.h"


#include "dnscore/threaded_queue.h"


#define LOGGER_HANDLE_TAG 0x4c444e48474f4c /* LOGHNDL */
#define LOGRMSG_TAG 0x47534d52474f4c
#define LOGRTEXT_TAG 0x5458455452474f4c

#define USE_DEFAULT_HANDLER 0

#define DEBUG_LOG_HANDLER 0
#define DEBUG_LOG_MESSAGES 0

#define COLUMN_SEPARATOR " | "
#define COLUMN_SEPARATOR_SIZE 3

#define LOGGER_HANDLE_FORMATTED_LENGTH 8

#define MODULE_MSG_HANDLE g_system_logger
extern logger_handle *g_system_logger;

static ptr_vector logger_channels = EMPTY_PTR_VECTOR;
static ptr_vector logger_handles = EMPTY_PTR_VECTOR;
static pthread_mutex_t logger_mutex;

#if USE_DEFAULT_HANDLER != 0
static struct logger_handle default_handle;
#endif

static threaded_queue logger_commit_queue = THREADED_QUEUE_NULL;
static pthread_t logger_thread_id = 0;
static u32 exit_level = MSG_CRIT;
static volatile bool logger_started = FALSE;
static volatile bool logger_initialised = FALSE;
static volatile bool logger_queue_initialised = FALSE;

#if DEBUG_LOG_MESSAGES == 1
static smp_int allocated_messages_count = SMP_INT_INITIALIZER;
static time_t allocated_messages_count_stats_time = 0;
#endif

//static logger_message* last_message;        /** @todo by channels */
//static u32 last_message_text_repeat = 0;

static void logger_handle_trigger_shutdown()
{
    flusherr();
    logger_flush();
    // dnscore_shutdown();
    kill(getpid(), SIGINT);
}

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

static int
logger_handle_channel_compare_match(const void* a, const void* b)
{
    const logger_channel* channel_a = (const logger_channel*)a;
    const logger_channel* channel_b = (const logger_channel*)b;

    if(channel_a == channel_b)
    {
        return 0;
    }

    return 1;
}

static void
logger_handle_free_channel(void* ptr)
{
    logger_channel* channel = (logger_channel*)ptr;
    
    logger_channel_close(channel);
    if(--channel->last_message->rc == 0)
    {
        free(channel->last_message);
    }
    free(channel);
}

static void
logger_handle_free(void* ptr)
{
    logger_handle* handle = (logger_handle*)ptr;

    int i;

    for(i = 0; i < MSG_LEVEL_COUNT; i++)
    {
        ptr_vector_destroy(&handle->channels[i]);
    }

    free((char*)handle->formatted_name);
    free((char*)handle->name);
    free(handle);
}

logger_handle*
logger_handle_add(const char* name)
{
    pthread_mutex_lock(&logger_mutex);

    logger_handle* handle = (logger_handle*)ptr_vector_search(&logger_handles, name, logger_handle_compare_match);

    if(handle == NULL)
    {
        MALLOC_OR_DIE(logger_handle*, handle, sizeof (logger_handle), LOGGER_HANDLE_TAG);

        handle->name = strdup(name);
        
        int len = strlen(name);
        handle->formatted_name_len = LOGGER_HANDLE_FORMATTED_LENGTH;
                
        MALLOC_OR_DIE(char*, handle->formatted_name, handle->formatted_name_len, LOGGER_HANDLE_TAG);
        memset((char*)handle->formatted_name, ' ', LOGGER_HANDLE_FORMATTED_LENGTH);
        memcpy((char*)handle->formatted_name, name,  MIN(len , LOGGER_HANDLE_FORMATTED_LENGTH));

        int i;

        for(i = 0; i < MSG_LEVEL_COUNT; i++)
        {
            ptr_vector_init(&handle->channels[i]);
        }

        ptr_vector_append(&logger_handles, handle);
        ptr_vector_qsort(&logger_handles, logger_handle_compare);
    }

    pthread_mutex_unlock(&logger_mutex);

    return handle;
}

logger_handle*
logger_handle_get(const char* name)
{
    pthread_mutex_lock(&logger_mutex);

    logger_handle* handle = (logger_handle*)ptr_vector_search(&logger_handles, name, logger_handle_compare_match);

    pthread_mutex_unlock(&logger_mutex);

    return handle;
}

void
logger_handle_add_channel(logger_handle* handle, int level, logger_channel* chan)
{
    assert(level >= 0 && level <= MSG_ALL_MASK);

    int lvl;
    int level_mask;

    pthread_mutex_lock(&logger_mutex);

    if(ptr_vector_linear_search(&logger_channels, chan, logger_handle_channel_compare_match) == NULL)
    {
        ptr_vector_append(&logger_channels, chan);
    }

    for(lvl = 0, level_mask = 1; level_mask <= MSG_ALL_MASK; lvl++, level_mask <<= 1)
    {
        if((level & level_mask) != 0)
        {
            if(ptr_vector_linear_search(&handle->channels[lvl], chan, logger_handle_channel_compare_match) == NULL)
            {
                ptr_vector_append(&handle->channels[lvl], chan);
            }
        }
    }

    pthread_mutex_unlock(&logger_mutex);
}

static void
logger_handle_flush(logger_handle* handle)
{
    int i;
    for(i = 0; i < MSG_LEVEL_COUNT; i++)
    {
        logger_channel_array *channel_array = &handle->channels[i];

        s32 j;
        for(j = 0; j <= channel_array->offset; j++)
        {
            logger_channel *channel = (logger_channel*)channel_array->data[j];
            logger_channel_flush(channel);
        }
    }
}

static void
logger_handle_flush_all()
{
    int i;

    pthread_mutex_lock(&logger_mutex);

    for(i = 0; i <= logger_channels.offset; i++)
    {
        logger_channel *channel = (logger_channel*)logger_channels.data[i];
        logger_channel_flush(channel);
    }

    pthread_mutex_unlock(&logger_mutex);
}

static void
logger_handle_reopen_all()
{
    int i;

    pthread_mutex_lock(&logger_mutex);

    for(i = 0; i <= logger_channels.offset; i++)
    {
        logger_channel *channel = (logger_channel*)logger_channels.data[i];
        logger_channel_reopen(channel);
    }

    pthread_mutex_unlock(&logger_mutex);
}

/*
 *
 */

static void
logger_handle_init()
{
    ptr_vector_init(&logger_handles);
    ptr_vector_init(&logger_channels);

    pthread_mutex_init(&logger_mutex, NULL);

    format_class_init();

#if USE_DEFAULT_HANDLER != 0
    ZEROMEMORY(&default_handle, sizeof (default_handle));

    /*
     * Creates a "fake" handle (the name does not matters)
     * Writes on STDERR
     *
     */

    u32 u;

    default_handle.name = "---";

    for(u = 0; u < MSG_LEVEL_COUNT; u++)
    {
        output_stream os;

        file_output_stream_attach(2, &os);

        logger_channel* chan;

        MALLOC_OR_DIE(logger_channel*, chan, sizeof (logger_channel), 0x4c454e4e414843);

        logger_channel_stream_open(&os, FALSE, chan);

        ptr_vector_init(&default_handle.channels[u]);
        ptr_vector_append(&default_handle.channels[u], chan);
    }

#endif

}

void
logger_handle_finalize()
{
    int i;

    pthread_mutex_lock(&logger_mutex);

    for(i = 0; i <= logger_handles.offset; i++)
    {
        logger_handle_flush((logger_handle*)logger_handles.data[i]);
    }

    ptr_vector_free_empties(&logger_handles, logger_handle_free);
    ptr_vector_destroy(&logger_handles);

    ptr_vector_free_empties(&logger_channels, logger_handle_free_channel);
    ptr_vector_destroy(&logger_channels);

    pthread_mutex_unlock(&logger_mutex);
}

void
logger_handle_exit_level(u32 level)
{
    if(level >= MSG_LEVEL_COUNT)
    {
        OSDEBUG(termerr, "message level too high: %u > %u", level, MSG_LEVEL_COUNT - 1);
        return;
    }

    if(level <= MSG_CRIT)
    {
        OSDEBUG(termerr, "message level too low: %u < %u", level, MSG_CRIT);
        return;
    }

    exit_level = level;
}

static const char acewnid[16 + 1] = "!ACEWNID1234567";

static inline void
logger_message_free(logger_message *msg)
{
    free(msg->text);
    free(msg);
    
#if DEBUG_LOG_MESSAGES == 1
    smp_int_dec(&allocated_messages_count);
#endif
}

void*
logger_dispatcher_thread(void* context)
{
    output_stream baos;
    
    bytearray_output_stream_init_ex(NULL, 1024, &baos, BYTEARRAY_DYNAMIC);

    /*
     * Since I'll use this virtual call a lot, it's best to cache it.
     * (Actually it would be even better to use the static method)
     */
    output_stream_write_method *baos_write = baos.vtbl->write;
    
    char repeat_text[128];

    for(;;)
    {
        logger_message* message = (logger_message*)threaded_queue_dequeue(&logger_commit_queue);

        if(message != NULL)
        {
#if DEBUG_LOG_MESSAGES == 1
            {
                time_t now = time(NULL);
                if(now - allocated_messages_count_stats_time > 10)
                {
                    allocated_messages_count_stats_time = now;
                    int val = smp_int_get(&allocated_messages_count);
                    
                    osformatln(termerr, "messages allocated count = %d", val);
                    flusherr();
                }
            }
#endif
            
            if(message->pid != 0)
            {
                logger_handle *handle = message->handle;
                u32 level = message->level;

                s32 channel_count = handle->channels[level].offset;

                if(channel_count < 0)
                {
                    logger_message_free(message);
                    continue;
                }

                u32 date_header_len;
                
                if(message->flags == 0)
                {
                    struct tm t;
                    localtime_r(&message->tv.tv_sec, &t);
                    osformat(&baos, "%04d-%02d-%02d %02d:%02d:%02d.%06d", t.tm_year+1900,t.tm_mon+1,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec,message->tv.tv_usec);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);

#ifndef NDEBUG
                    osprint_u16(&baos, message->pid);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);

                    osprint_u32_hex(&baos, (u32)message->thread_id);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);
#endif

                    baos_write(&baos, (u8*)handle->formatted_name, handle->formatted_name_len);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);

                    osprint_char(&baos, acewnid[message->level & 15]);
                    baos_write(&baos, (const u8*)COLUMN_SEPARATOR, COLUMN_SEPARATOR_SIZE);
                    
                    date_header_len = 29;
                }
                else
                {
                    /* shortcut : assume both ones on since that's the only used case */
                    
                    zassert( (message->flags & (LOGGER_MESSAGE_TIMEMS | LOGGER_MESSAGE_PREFIX)) == (LOGGER_MESSAGE_TIMEMS | LOGGER_MESSAGE_PREFIX));
                    
                    struct tm t;
                    localtime_r(&message->tv.tv_sec, &t);
                    osformat(&baos, "%04d-%02d-%02d %02d:%02d:%02d.%03d", t.tm_year+1900,t.tm_mon+1,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec,message->tv.tv_usec/1000);
                    
                    baos_write(&baos, message->prefix, message->prefix_length);
                    
                    date_header_len = 24;
                }
                
                baos_write(&baos, message->text, message->text_length);

                output_stream_write_u8(&baos, 0);                

                size_t size = bytearray_output_stream_size(&baos) - 1;
                char* buffer = (char*)bytearray_output_stream_buffer(&baos);

                logger_channel** channelp = (logger_channel**)handle->channels[level].data;

                do
                {
                    logger_channel* channel = *channelp;
                    
                    ya_result return_code;
                                        
                    if((channel->last_message->text_length == message->text_length) && (memcmp(channel->last_message->text, message->text, message->text_length) == 0))
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
                            
                            return_code = snformat(repeat_text, sizeof(repeat_text), "----/--/-- --:--:--.------" COLUMN_SEPARATOR 
                                                        
#ifndef NDEBUG
                                    "%5d" COLUMN_SEPARATOR
                                    "%08x" COLUMN_SEPARATOR
#endif
                                    "--------" COLUMN_SEPARATOR
                                    "-" COLUMN_SEPARATOR
                                    "last message repeated %d times",
#ifndef NDEBUG
                                    channel->last_message->pid,
                                    channel->last_message->thread_id,
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
                        if(--channel->last_message->rc == 0)
                        {
                            /* free the message */
                            
#if DEBUG_LOG_HANDLER != 0
                            osformatln(termout, "message rc is 0 (%s)", channel->last_message->text);
                            flushout();
#endif
                            
                            logger_message_free(channel->last_message);
                        }
#if DEBUG_LOG_HANDLER != 0
                        else
                        {
                            osformatln(termout, "message rc decreased to %d (%s)", channel->last_message->rc, channel->last_message->text);
                            flushout();
                        }
#endif

                        channel->last_message = message;
                        channel->last_message_count = 0;
                        message->rc++;
                        
#if DEBUG_LOG_HANDLER != 0
                        osformatln(termout, "message rc is %d (%s)", channel->last_message->rc, channel->last_message->text);
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
                
                if(message->rc == 0)
                {
#if DEBUG_LOG_HANDLER != 0
                    osformatln(termout, "message has not been used (full dup): '%s'", message->text);
                    flushout();
#endif
                    logger_message_free(message);
                }

                bytearray_output_stream_reset(&baos);
            }
            else
            {
                u16 level = message->level;
                free(message);
                
#if DEBUG_LOG_MESSAGES == 1
                smp_int_dec(&allocated_messages_count);
#endif
                
                switch(level)
                {
                    case 0:
                    {
                        logger_handle_flush_all();
                        break;
                    }
                    case 1:
                    {
                        logger_handle_reopen_all();
                        break;
                    }
                }
            }
        }
        else
        {
            logger_handle_flush_all();
            
            while(threaded_queue_size(&logger_commit_queue) > 0)
            {
                message = (logger_message*)threaded_queue_dequeue(&logger_commit_queue);

                if(message != NULL)
                {
                    if(message->pid != 0)
                    {
#if defined(DEBUG)
                        assert(message->text != NULL);
#endif
                        osformatln(termerr, "logger: warning: message sent after shutdown order '%s'", message->text);
                        
                        free(message->text);
                        message->text = NULL;
                    }
                    
                    assert(message->text == NULL);

                    free(message);
                        
#if DEBUG_LOG_MESSAGES == 1
                    smp_int_dec(&allocated_messages_count);
#endif
                }
                else
                {
                    osformatln(termerr, "logger: warning: shutdown order sent after shutdown order");
                }

                flusherr();
            }

            break;
        }
    }

    output_stream_close(&baos);

    return NULL;
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
    if(!logger_initialised)
    {
        if(!logger_queue_initialised)
        {
            threaded_queue_init(&logger_commit_queue, logger_queue_size);
            logger_queue_initialised = TRUE;
        }

        logger_handle_init();

        logger_initialised = TRUE;
    }
}

void
logger_start()
{
    ya_result return_code;
    
#ifndef NDEBUG
    puts("logger_start()");fflush(NULL);
#endif

    if(!logger_initialised)
    {
#ifndef NDEBUG
        puts("logger_start(): init");fflush(NULL);
#endif
        logger_init();
    }
    
    if(!logger_started)
    {
#ifndef NDEBUG
        puts("logger_start(): start");fflush(NULL);
#endif

        if((return_code = pthread_create(&logger_thread_id, NULL, logger_dispatcher_thread, NULL)) != 0)
        {
            osformatln(termerr, "logger_start: pthread_create: %r", return_code);
            DIE(LOGGER_INITIALISATION_ERROR);
        }

        logger_started = TRUE;
    }
    
#ifndef NDEBUG
    puts("logger_start(): done");fflush(NULL);
#endif

}

void
logger_stop()
{
#ifndef NDEBUG
    puts("logger_stop(): init");fflush(NULL);
#endif

    if(logger_initialised)
    {
        if(logger_started)
        {
            ya_result return_code;

            threaded_queue_enqueue(&logger_commit_queue, NULL); // FLUSH
            //threaded_queue_wait_empty(&logger_commit_queue);
            
#ifndef NDEBUG
            puts("logger_stop(): wait");fflush(NULL);
#endif

            if((return_code = pthread_join(logger_thread_id, NULL)) != 0)
            {
                osformatln(termerr, "logger_stop: pthread_join: %r", return_code);
            }

            logger_thread_id = 0;
            logger_started = FALSE;
        }
    }
    
#ifndef NDEBUG
    puts("logger_stop(): done");fflush(NULL);
#endif
}

void
logger_finalize()
{
    if(logger_started)
    {
        logger_stop();
    }
    else
    {
        /*
         * Maybe the logger has NEVER been started
         *
         * If the queue is not empty, empty it by calling the dispatcher
         *
         */

        if(logger_initialised)
        {
            if(threaded_queue_size(&logger_commit_queue) > 0)
            {
                threaded_queue_enqueue(&logger_commit_queue, NULL);
                logger_dispatcher_thread(NULL);
            }
        }
    }

    if(logger_initialised)
    {
        /*
         * Ensure there is nothing left at all in the queue
         */
        
        while(threaded_queue_size(&logger_commit_queue) > 0)
        {
            void* data = threaded_queue_dequeue(&logger_commit_queue);
            free(data);
        }
        logger_handle_finalize();

        logger_initialised = FALSE;
    }
}

void
logger_flush()
{
    if(logger_initialised)
    {
        logger_message* message;
        MALLOC_OR_DIE(logger_message*, message, sizeof (logger_message), LOGRMSG_TAG);
        ZEROMEMORY(message, sizeof (logger_message));

#if DEBUG_LOG_MESSAGES == 1
        smp_int_inc(&allocated_messages_count);
#endif
        
        /*
         * pid   = 0 => special
         * level = 0 => flush all
         */

        threaded_queue_enqueue(&logger_commit_queue, message);
    }
}

void
logger_reopen()
{
    if(logger_initialised)
    {
        logger_message* message;
        MALLOC_OR_DIE(logger_message*, message, sizeof (logger_message), LOGRMSG_TAG);
        ZEROMEMORY(message, sizeof (logger_message));

#if DEBUG_LOG_MESSAGES == 1
        smp_int_inc(&allocated_messages_count);
#endif
        
        /*
         * pid   = 0 => special
         * level = 1 => reopen all
         */
        
        message->level = 1;

        threaded_queue_enqueue(&logger_commit_queue, message);
    }
}

void
logger_handle_msg(logger_handle* handle, u32 level, const char* fmt, ...)
{
    /*
     * check that the handle has got a channel for the level
     */

#ifndef NDEBUG
    if(level >= MSG_LEVEL_COUNT)
    {
        osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_shutdown();
    }
#endif

    if(handle == NULL)
    {
#if USE_DEFAULT_HANDLER != 0
        handle = &default_handle;
#else
        if(level <= exit_level)
        {
            logger_handle_trigger_shutdown();
        }
        return;
#endif
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
    bytearray_output_stream_init_ex(NULL, DEFAULT_MAX_LINE_SIZE, &baos, BYTEARRAY_DYNAMIC);

    if(FAIL(vosformat(&baos, fmt, args)))
    {
        output_stream_close(&baos);
        OSDEBUG(termerr, "message formatting failed");
        return;
    }

    output_stream_write_u8(&baos, 0);

    /**
     * 
     * @todo Instead of a malloc, I should use the nb mm (stack) allocator.
     * 
     */

    logger_message* message;
    MALLOC_OR_DIE(logger_message*, message, sizeof (logger_message), LOGRMSG_TAG);
    message->handle = handle;
    message->text = bytearray_output_stream_detach(&baos);
    message->text_length = bytearray_output_stream_size(&baos) - 1;
    message->level = level;
    message->thread_id = pthread_self();
    message->flags = 0;    
    gettimeofday(&message->tv, NULL);
    
    message->pid = getpid();
    message->rc = 0;
    
#if DEBUG_LOG_MESSAGES == 1
    smp_int_inc(&allocated_messages_count);
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

#ifndef NDEBUG
    if(level >= MSG_LEVEL_COUNT)
    {
        osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_shutdown();
    }
#endif

    if(handle == NULL)
    {
#if USE_DEFAULT_HANDLER != 0
        handle = &default_handle;
#else
        if(level <= exit_level)
        {
            logger_handle_trigger_shutdown();
        }
        return;
#endif
    }

    s32 channel_count = handle->channels[level].offset;

    if(channel_count < 0) /* it's count-1 actually */
    {
        return;
    }
 
    logger_message* message;
    MALLOC_OR_DIE(logger_message*, message, sizeof (logger_message), LOGRMSG_TAG);
    message->handle = handle;
    
    message->text_length = text_len ++;
    MALLOC_OR_DIE(u8*, message->text, text_len, LOGRTEXT_TAG);
    memcpy(message->text, text, text_len);
    
    message->level = level;
    message->thread_id = pthread_self();
    gettimeofday(&message->tv, NULL);
    
    message->pid = getpid();
    
    message->flags = 0;
    message->rc = 0;
    
#if DEBUG_LOG_MESSAGES == 1
    smp_int_inc(&allocated_messages_count);
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

#ifndef NDEBUG
    if(level >= MSG_LEVEL_COUNT)
    {
        osformatln(termerr, "bad message level %u", level);
        logger_handle_trigger_shutdown();
    }
#endif

    if(handle == NULL)
    {
#if USE_DEFAULT_HANDLER != 0
        handle = &default_handle;
#else
        if(level <= exit_level)
        {
            logger_handle_trigger_shutdown();
        }
        return;
#endif
    }

    s32 channel_count = handle->channels[level].offset;

    if(channel_count < 0) /* it's count-1 actually */
    {
        return;
    }
 
    logger_message* message;
    MALLOC_OR_DIE(logger_message*, message, sizeof (logger_message), LOGRMSG_TAG);
    message->handle = handle;
    
    message->text_length = text_len ++;
    MALLOC_OR_DIE(u8*, message->text, text_len, LOGRTEXT_TAG);
    memcpy(message->text, text, text_len);
    
    message->level = level;
    message->thread_id = pthread_self();
    gettimeofday(&message->tv, NULL);
    
    message->pid = getpid();
    
    message->flags = flags;
    
    message->prefix = (const u8*)prefix;
    message->prefix_length = prefix_len;
    
    message->rc = 0;
    
#if DEBUG_LOG_MESSAGES == 1
    smp_int_inc(&allocated_messages_count);
#endif
    
    threaded_queue_enqueue(&logger_commit_queue, message);

    if(level <= exit_level)
    {
        logger_handle_trigger_shutdown();
    }
}

/** @} */

/*----------------------------------------------------------------------------*/

