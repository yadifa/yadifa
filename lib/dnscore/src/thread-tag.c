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

/** @defgroup threading Threading, pools, queues, ...
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

#include <sys/types.h>
#include <unistd.h>

#include <dnscore/thread.h>
#include <sys/wait.h>

#include "dnscore/threaded_queue.h"
#include "dnscore/thread_pool.h"
#include "dnscore/logger.h"
#include "dnscore/format.h"
#include "dnscore/u32_set.h"
#include "dnscore/zalloc.h"
#include "dnscore/process.h"
#include "dnscore/mutex.h"
#include "dnscore/thread-tag.h"

/* 0 = nothing, 1 = warns and worse, 2 = info and worse, 3 = debug and worse */
#define VERBOSE_THREAD_LOG      0

/* Disable when in release mode */

#if !DEBUG
#undef VERBOSE_THREAD_LOG
#define VERBOSE_THREAD_LOG      0
#endif

#define MODULE_MSG_HANDLE		g_system_logger

#if DNSCORE_HAS_LOG_THREAD_TAG

#define THREAD_TAG_HASH_PRIME 8191
#define THREAD_TAG_HASH_SIZE (THREAD_TAG_HASH_PRIME + 1)

#if __SIZEOF_POINTER__ == 8
struct thread_tag_entry_s
{
    thread_t id;
    char tag[8];
    thread_t thread_id;
    intptr reserved;

};
#else
struct thread_tag_entry_s
{
    thread_t id;
    char tag[8];
    thread_t thread_id;
};
#endif

typedef struct thread_tag_entry_s thread_tag_entry_s;

static const char thread_tag_unknown[THREAD_TAG_SIZE] = {'-','-','-','-','-','-','-',' '};
#if __SIZEOF_POINTER__ == 8
static thread_tag_entry_s thread_tag_entry[THREAD_TAG_HASH_SIZE] = {{0,{0,0,0,0,0,0,0,0},0,0}};
#else
static thread_tag_entry_s thread_tag_entry[THREAD_TAG_HASH_SIZE] = {{0,{0,0,0,0,0,0,0,0},0}};
#endif
static mutex_t thread_tag_mtx = MUTEX_INITIALIZER;

static int
thread_id_key(thread_t id_)
{
    intptr id = (intptr)id_;
    unsigned int key = (u32)id;
    if(sizeof(id) == 8)
    {
        key ^= (u32)(id >> 32);
    }
    return key % THREAD_TAG_HASH_PRIME;
}

const char *
thread_get_tag_with_pid_and_tid(pid_t pid_, thread_t tid_)
{
    intptr pid = (intptr)pid_;
    intptr tid = (intptr)tid_;

    thread_t id = (thread_t)(tid ^ pid);
    int key = thread_id_key(id);
    
    for(int c = THREAD_TAG_HASH_SIZE;;) // no need to mtx this
    {
        if(thread_tag_entry[key].id == id)
        {
#if VERBOSE_THREAD_LOG
            const char *tag = thread_tag_entry[key].tag;
            osformatln(termout, "[%i] thread_get_tag_with_pid_and_tid(%i,%p) => %p = %c%c%c%c%c%c%c%c (%i)", getpid(), pid, tid, id,
                    tag[0],tag[1],tag[2],tag[3],
                    tag[4],tag[5],tag[6],tag[7], key);
#endif
            return thread_tag_entry[key].tag;
        }
        
        if(--c == 0)
        {
#if VERBOSE_THREAD_LOG
            osformatln(termout, "[%i] thread_get_tag_with_pid_and_tid(%i,%p) => %p = unknown (%i)", getpid(), pid, tid, id, thread_id_key(id));
#endif      
            return thread_tag_unknown;
        }
        
        key = (key + 1) & THREAD_TAG_HASH_PRIME;
    }
    
    // should never be reached
    
    // return thread_tag_unknown;
}

char *
thread_copy_tag_with_pid_and_tid(pid_t pid, thread_t tid, char *out_9_bytes)
{
    memcpy(out_9_bytes, thread_get_tag_with_pid_and_tid(pid, tid), 9);
    out_9_bytes[8] = '\0';
    return out_9_bytes;
}

#if DEBUG
static int thread_set_tag_with_pid_and_tid_collisions = 0;
#endif

void
thread_set_tag_with_pid_and_tid(pid_t pid_, thread_t tid_, const char *tag8chars)
{
    intptr pid = (intptr)pid_;
    intptr tid = (intptr)tid_;

    thread_t id = (thread_t)(tid ^ pid);
    int key = thread_id_key(id);
    
#if VERBOSE_THREAD_LOG
    const char *tag = tag8chars;
    osformatln(termout, "[%i] thread_set_tag_with_pid_and_tid(%i,%p, %c%c%c%c%c%c%c%c) => %p (%i)", getpid(), pid, tid,
            tag[0],tag[1],tag[2],tag[3],
            tag[4],tag[5],tag[6],tag[7],
            id, key);
    flushout();
#endif
        
#if VERBOSE_THREAD_LOG >= 3
    log_info("thread-tag: %i::%p: base key is %i '%c%c%c%c%c%c%c%c'", pid, tid, key,
            tag8chars[0],tag8chars[1],tag8chars[2],tag8chars[3],tag8chars[4],tag8chars[5],tag8chars[6],tag8chars[7]);
#endif
    
    mutex_lock(&thread_tag_mtx);
    for(int c = THREAD_TAG_HASH_SIZE;;)
    {
        if((thread_tag_entry[key].id == 0) || (thread_tag_entry[key].id == id))
        {
            thread_tag_entry[key].id = id;
            
            int i;
            for(i = 0; i < THREAD_TAG_SIZE; ++i)
            {
                if(tag8chars[i] == '\0')
                {
                    break;
                }
                thread_tag_entry[key].tag[i] = tag8chars[i];
            }

            for(; i < THREAD_TAG_SIZE; ++i)
            {
                thread_tag_entry[key].tag[i] = ' ';
            }

            thread_tag_entry[key].thread_id = (thread_t)tid;
            
            mutex_unlock(&thread_tag_mtx);
            
#if VERBOSE_THREAD_LOG >= 3
            log_warn("[%i] thread-tag: %i::%p: last key is %i, %i collisions", getpid(), pid, tid, key, THREAD_TAG_HASH_SIZE - c);
#endif
            return;
        }
        
        if(--c == 0)
        {
            mutex_unlock(&thread_tag_mtx);
            return; // ignore
        }
        
        key = (key + 1) & THREAD_TAG_HASH_PRIME;

#if DEBUG
        ++thread_set_tag_with_pid_and_tid_collisions;
        formatln("thread_set_tag_with_pid_and_tid_collisions = %i", thread_set_tag_with_pid_and_tid_collisions);
#endif
    }
}

void
thread_clear_tag_with_pid_and_tid(pid_t pid_, thread_t tid_)
{
    intptr pid = (intptr)pid_;
    intptr tid = (intptr)tid_;

    thread_t id = (thread_t)(tid ^ pid);
    int key = thread_id_key(id);
    
#if VERBOSE_THREAD_LOG
    osformatln(termout, "[%i] thread_clear_tag_with_pid_and_tid(%i,%p) => %p (%i)", getpid(), pid, tid, id, key);
    flushout();
#endif
       
    mutex_lock(&thread_tag_mtx);
    for(int c = THREAD_TAG_HASH_SIZE;;)
    {
        if(thread_tag_entry[key].id == id)
        {
            thread_tag_entry[key].id = 0;
            thread_tag_entry[key].tag[0] = 0;
            mutex_unlock(&thread_tag_mtx);
            return;
        }
        
        if(--c == 0)
        {
            mutex_unlock(&thread_tag_mtx);
            return; // ignore
        }
        
        key = (key + 1) & THREAD_TAG_HASH_PRIME;
    }
}

void
thread_tag_log_tags()
{
    for(int key = 0; key < THREAD_TAG_HASH_SIZE; ++key)
    {
        if(thread_tag_entry[key].id != 0)
        {
            log_info("thread-tag: id=%08i tag=%c%c%c%c%c%c%c%c",
                     thread_tag_entry[key].id,
                     thread_tag_entry[key].tag[0],thread_tag_entry[key].tag[1],thread_tag_entry[key].tag[2],thread_tag_entry[key].tag[3],
                     thread_tag_entry[key].tag[4],thread_tag_entry[key].tag[5],thread_tag_entry[key].tag[6],thread_tag_entry[key].tag[7]);
        }
    }
}

void
thread_tag_push_tags()
{
    for(int key = 0; key < THREAD_TAG_HASH_SIZE; ++key)
    {
        if(thread_tag_entry[key].id != 0)
        {
#if DEBUG
            debug_osformatln(termout, "thread-tag: pushing id=%p tag=%c%c%c%c%c%c%c%c",
                             thread_tag_entry[key].thread_id,
                             thread_tag_entry[key].tag[0],thread_tag_entry[key].tag[1],thread_tag_entry[key].tag[2],thread_tag_entry[key].tag[3],
                             thread_tag_entry[key].tag[4],thread_tag_entry[key].tag[5],thread_tag_entry[key].tag[6],thread_tag_entry[key].tag[7]);
            /*
            log_debug("thread-tag: pushing id=%p tag=%c%c%c%c%c%c%c%c",
                     thread_tag_entry[key].thread_id,
                     thread_tag_entry[key].tag[0],thread_tag_entry[key].tag[1],thread_tag_entry[key].tag[2],thread_tag_entry[key].tag[3],
                     thread_tag_entry[key].tag[4],thread_tag_entry[key].tag[5],thread_tag_entry[key].tag[6],thread_tag_entry[key].tag[7]);
            */
#endif
            logger_handle_set_thread_tag_with_pid_and_tid(getpid(), thread_tag_entry[key].thread_id, thread_tag_entry[key].tag);
        }
    }
}



void thread_make_tag(const char *prefix, u32 index, u32 count, char *out_service_tag)
{
    char service_tag[THREAD_TAG_SIZE + 1];
    
    if(prefix == NULL)
    {
        prefix = "X";
    }
    
    memset(out_service_tag, '-', THREAD_TAG_SIZE);
    
    size_t prefix_len = strlen(prefix);
    
    if(prefix_len > THREAD_TAG_SIZE)
    {
        prefix_len = THREAD_TAG_SIZE;
    }
    memcpy(service_tag, prefix, prefix_len);
    for(size_t i = prefix_len; i < THREAD_TAG_SIZE; ++i)
    {
        service_tag[i] = ' ';
    }
    service_tag[THREAD_TAG_SIZE] = '\0';
    
    if(count <= 1)
    {
        // good as it is
    }
    else if(count <= 0x10) // [ 0 ; 0x10 [ => 1 byte
    {
        snformat(&service_tag[7], 2, "%x", index);
    }
    else if(count <= 0x100)
    {
        snformat(&service_tag[6], 3, "%02x", index);
    }
    else if(count <= 0x1000)
    {
        snformat(&service_tag[5], 4, "%03x", index);
    }
    else if(count <= 0x10000)
    {
        snformat(&service_tag[4], 5, "%04x", index);
    }
    else if(count <= 0x100000)
    {
        snformat(&service_tag[3], 6, "%05x", index);
    }
    else
    {
        snformat(&service_tag[1], THREAD_TAG_SIZE, "%x", index);
    }
    
    memcpy(out_service_tag, service_tag, THREAD_TAG_SIZE);

#if VERBOSE_THREAD_LOG > 1
    osformatln(termout, "[%i] thread_make_tag(%s,%i,%i,&): %i (%i) %p) = %c%c%c%c%c%c%c%c",
               getpid(),
               prefix, index, count, getpid_ex(), getpid(), thread_self(),
               service_tag[0], service_tag[1], service_tag[2], service_tag[3],
               service_tag[4], service_tag[5], service_tag[6], service_tag[7]);
#endif

}

#endif

/** @} */
