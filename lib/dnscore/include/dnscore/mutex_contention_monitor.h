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
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/ptr_treemap.h>

#include <dnscore/debug.h>

#include <dnscore/mutex_defines.h>

#if DNSCORE_MUTEX_CONTENTION_MONITOR
#if DNSCORE_MUTEX_CONTENTION_MONITOR_NOTIFY
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#pragma message("DNSCORE_MUTEX_CONTENTION_MONITOR 1")
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#endif
#endif

struct mutex_contention_point_s
{
    stacktrace st;         // stack trace to that point
    int64_t    lock_wait;  // time spent waiting for the lock (but successfully acquired)
    int64_t    lock_loops; // loops made before acquiring the lock
    int64_t    owner_time; // time spent owning that mutex on that stack trace
    int64_t    use_count;
    int64_t    lock_fail; // try-locks that failed
};

typedef struct mutex_contention_point_s mutex_contention_point_t;

struct mutex_contention_object_s
{
    void         *mutex;
    ptr_treemap_t threads; // set of mutex_contention_monitor
    bool          recursive;
};

typedef struct mutex_contention_object_s mutex_contention_object_t;

typedef ptr_treemap_t                    mutex_contention_thread_t;

struct mutex_contention_monitor_s
{
    thread_t                  owning_thread;
    mutex_contention_point_t *contention_point;
    //
    mutex_contention_object_t *mutex_object;
    mutex_contention_thread_t *mutex_thread;
    const char                *type_name;
    int64_t                    lock_begin_timestamp;
    int64_t                    lock_wait_loops;
    int64_t                    lock_end_timestamp; // 0 until the mutex is acquired
    int32_t                    multi_lock_count;
    pid_t                      pid;
    bool                       used_by_condition; // true means not really locked
};

typedef struct mutex_contention_monitor_s mutex_contention_monitor_t;

void                                      mutex_contention_monitor_lock_count_inc(mutex_contention_monitor_t *mcm);
bool                                      mutex_contention_monitor_lock_count_dec(mutex_contention_monitor_t *mcm);
void                                      mutex_contention_object_create(void *mutex_ptr, bool recursive);
void                                      mutex_contention_object_destroy(void *mutex_ptr);
mutex_contention_monitor_t               *mutex_contention_lock_begin(thread_t thread, void *mutex_ptr, stacktrace st, const char *type_name);
void                                      mutex_contention_lock_wait(mutex_contention_monitor_t *mcm);
void                                      mutex_contention_lock_wait_with_mutex(thread_t thread, void *mutex_ptr);
void                                      mutex_contention_lock_resume(mutex_contention_monitor_t *mcm);
void                                      mutex_contention_lock_resume_with_mutex(thread_t thread, void *mutex_ptr);
void                                      mutex_contention_lock_end(mutex_contention_monitor_t *mcm);
void                                      mutex_contention_lock_fail(mutex_contention_monitor_t *mcm);
void                                      mutex_contention_unlock(thread_t thread, void *mutex_ptr);
void                                      mutex_contention_unlock_with_monitor(mutex_contention_monitor_t *mcm);
void                                      mutex_contention_monitor_start();
void                                      mutex_contention_monitor_stop();

/** @} */
