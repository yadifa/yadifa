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
/** @defgroup dnscore System core functions
 *  @brief System core functions
 *
 * @{ */

#define __DNSCORE_C__

#include "dnscore/dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <signal.h>

#include <pthread.h>

#include "dnscore/zalloc.h"

#include "dnscore/message.h"

#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/mt_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/dnsformat.h"
#include "dnscore/logger.h"
#include "dnscore/random.h"

#include "dnscore/sys_error.h"
#include "dnscore/thread_pool.h"
#include "dnscore/tsig.h"
#include "dnscore/mutex.h"
#include "dnscore/alarm.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/config_settings.h"
#include "dnscore/async.h"

#include <sys/time.h>

#if DNSCORE_HAS_TSIG_SUPPORT
#include <openssl/ssl.h>
#include <openssl/engine.h>
#endif

#define TERM_BUFFER_SIZE 4096
#define DNSCORE_TIDY_UP_MEMORY 1

#define MODULE_MSG_HANDLE g_system_logger

/*****************************************************************************/

#if DNSCORE_HAS_TSIG_SUPPORT
#if !DNSCORE_HAS_ACL_SUPPORT
#error "TSIG support is irrelevant without ACL support"
#endif
#endif

#ifndef __DATE__
#define __DATE__ "date?"
#endif

#ifndef __TIME__
#define __TIME__ "time?"
#endif

#ifdef DEBUG
const char *dnscore_lib = "dnscore " __DATE__ " " __TIME__ " debug";
#else
const char *dnscore_lib = "dnscore " __DATE__ " " __TIME__ " release";
#endif

static const char* ARCH_RECOMPILE_WARNING = "Please recompile with the correct settings.";
static const char* ARCH_CHECK_SIZE_WARNING = "PANIC: %s does not match the size requirements (%i instead of %i).\n";
static const char* ARCH_CHECK_SIGN_WARNING = "PANIC: %s does not match the sign requirements.\n";
#define ARCH_CHECK_SIZE(a,b) if(a!=b) { printf(ARCH_CHECK_SIZE_WARNING,#a,a,b);puts(ARCH_RECOMPILE_WARNING);DIE(ERROR); }
#define ARCH_CHECK_SIGNED(a) {a val=~0;if(val>0) { printf(ARCH_CHECK_SIGN_WARNING,#a);puts(ARCH_RECOMPILE_WARNING);DIE(ERROR); }}
#define ARCH_CHECK_UNSIGNED(a) {a val=~0;if(val<0) { printf(ARCH_CHECK_SIGN_WARNING,#a);puts(ARCH_RECOMPILE_WARNING);DIE(ERROR); }}

logger_handle *g_system_logger = NULL;



static smp_int g_shutdown = SMP_INT_INITIALIZER;

static void
dnscore_arch_checkup()
{
    /* Test the archi=tecture */
#pragma message("Don't worry about the possible warnings below")
    ARCH_CHECK_SIZE(__SIZEOF_POINTER__, sizeof (void*));
    ARCH_CHECK_SIZE(sizeof (u8), 1);
    ARCH_CHECK_SIZE(sizeof (s8), 1);
    ARCH_CHECK_SIZE(sizeof (u16), 2);
    ARCH_CHECK_SIZE(sizeof (s16), 2);
    ARCH_CHECK_SIZE(sizeof (u32), 4);
    ARCH_CHECK_SIZE(sizeof (s32), 4);
    ARCH_CHECK_SIZE(sizeof (u64), 8);
    ARCH_CHECK_SIZE(sizeof (s64), 8);
    ARCH_CHECK_SIZE(sizeof (intptr), sizeof (void*));
    ARCH_CHECK_SIGNED(s8);
    ARCH_CHECK_SIGNED(s16);
    ARCH_CHECK_SIGNED(s32);
    ARCH_CHECK_SIGNED(s64);
    ARCH_CHECK_UNSIGNED(u8);
    ARCH_CHECK_UNSIGNED(u16);
    ARCH_CHECK_UNSIGNED(u32);
    ARCH_CHECK_UNSIGNED(u64);
    ARCH_CHECK_UNSIGNED(intptr);

    message_data* msg = NULL;
    intptr msg_diffs = (intptr)(msg->buffer - msg->buffer_tcp_len); // cppcheck : false positive: of course it's a null pointer
    if((msg->buffer - msg->buffer_tcp_len) != 2)
    {
        printf("Structure aligment is wrong.  Expected 2 but got %i. (see message_data)\n", (int)msg_diffs);
        DIE(ERROR);
    }

#pragma message("You can resume worrying about warnings ...")
    
#if WORDS_BIGENDIAN==1
    u8 endian[4] = {1, 2, 3, 4}; /* BIG    */
    char* endian_name = "BIG";
#else
    u8 endian[4] = {4, 3, 2, 1}; /* LITTLE */
    char* endian_name = "LITTLE";
#endif

    u32 endian_match = GET_U32_AT(endian[0]);
    if(endian_match != 0x01020304)
    {
        fprintf(stderr, "Endianness is wrong. Compiled for %s\n", endian_name);
        puts(ARCH_RECOMPILE_WARNING);
        fflush(NULL);
        DIE(ERROR);
    }
}

/*****************************************************************************/

dnslib_fingerprint dnscore_getfingerprint()
{
    dnslib_fingerprint ret = (dnslib_fingerprint)(0
    
#if DNSCORE_HAS_TSIG_SUPPORT
    | DNSLIB_TSIG
#endif
    )
    ;
    
    return ret;
}

u32 dnscore_fingerprint_mask()
{
    return DNSLIB_TSIG;
}

/*****************************************************************************/

output_stream __termout__ = {NULL, NULL};
output_stream __termerr__ = {NULL, NULL};

static void
stdstream_init()
{
    output_stream tmp;
    output_stream tmp2;

    fd_output_stream_attach(&tmp, 1);
    buffer_output_stream_init(&tmp, &tmp2, TERM_BUFFER_SIZE);
    mt_output_stream_init(&tmp2, &__termout__);

    fd_output_stream_attach(&tmp, 2);
    buffer_output_stream_init(&tmp, &tmp2, TERM_BUFFER_SIZE);
    mt_output_stream_init(&tmp2, &__termerr__);
}

static void
stdtream_detach_fd(output_stream *os)
{
    /*
     * Ensure that the stream that will be detached is one of the valid ones
     */
    output_stream_flush(os);
    if(!is_fd_output_stream(os))
    {
        if(!is_mt_output_stream(os))
        {
            log_err("unexpected stream in term");
            exit(EXIT_FAILURE);
        }
        os = mt_output_stream_get_filtered(os);
        if(!is_buffer_output_stream(os))
        {
            log_err("unexpected stream in term");
            exit(EXIT_FAILURE);
        }
        os = buffer_output_stream_get_filtered(os);
        if(!is_fd_output_stream(os))
        {
            log_err("unexpected stream in term");
            exit(EXIT_FAILURE);
        }
        output_stream_flush(os);
    }
    fd_output_stream_detach(os);
}

static void
stdstream_flush_both_terms()
{
    output_stream_flush(&__termout__);
    output_stream_flush(&__termerr__);
}

/**
 * Detaches the fd at the bottom of the mt(buffer(file(fd))) stream ... if it can.
 * Closes the stream.
 * 
 * @param os
 * @return 1 if an seemingly valid fd has been found and detached.  0 otherwise.
 */

ya_result
stdtream_detach_fd_and_close_output_stream(output_stream *os)
{
    output_stream *wos = os;
    ya_result ret = 0;
    
    output_stream_flush(wos);
    
    if(is_mt_output_stream(wos))
    {
        wos = mt_output_stream_get_filtered(wos);
    }
    if(is_buffer_output_stream(wos))
    {
        wos = buffer_output_stream_get_filtered(wos);
    }
    if(is_fd_output_stream(wos))
    {
        stdtream_detach_fd(wos);
        ret = 1;
    }
    output_stream_close(os);
    return ret;
}

void
stdtream_detach_fd_and_close()
{
    stdtream_detach_fd_and_close_output_stream(&__termout__);
    stdtream_detach_fd_and_close_output_stream(&__termerr__);
}

bool
stdstream_is_tty(output_stream *os)
{
    if(is_mt_output_stream(os))
    {
        os = mt_output_stream_get_filtered(os);
    }
    
    if(is_buffer_output_stream(os))
    {
        os = buffer_output_stream_get_filtered(os);
    }
    
    bool ret = is_fd_output_stream(os);
    
    return ret;
}

void rfc_init();
void rfc_finalize();
void format_class_finalize();

static bool dnscore_init_done = FALSE;

//static smp_int dnscore_time_thread_must_run = SMP_INT_INITIALIZER;
static async_wait_s timer_thread_sync;
static pthread_t dnscore_timer_thread_id = 0;
static volatile int dnscore_timer_creator_pid = 0;
static int dnscore_timer_period = 5;
static volatile u32 dnscore_timer_tick = 0;

static void*
dnscore_timer_thread(void * unused0)
{
    thread_pool_setup_random_ctx();

    dnscore_timer_tick = time(NULL);

#ifdef HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
    pthread_setname_np(pthread_self(), "timer");
#endif
#endif
    
    log_debug5("dnscore_timer_thread started");

    // if the counter reaches 0 then we have to stop
    
    u64 loop_period = dnscore_timer_period;
    loop_period *= 1000000LL;
    
    u64 loop_next_timeout_epoch = timeus();
    
    while(!async_wait_timeout_absolute(&timer_thread_sync, loop_next_timeout_epoch))
    {
        /* log & term output flush handling */
        stdstream_flush_both_terms();

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        mutex_locked_set_monitor();
        group_mutex_locked_set_monitor();
        shared_group_mutex_locked_set_monitor();
#endif
        
        logger_flush();

        dnscore_timer_tick = time(NULL);
        
        alarm_run_tick(dnscore_timer_tick);

        loop_next_timeout_epoch += loop_period;
    }
    
    log_debug5("dnscore_timer_thread stopping");

    thread_pool_destroy_random_ctx();
    
    log_debug5("dnscore_timer_thread stopped");
    
    pthread_exit(NULL); /* not from the pool, so it's the way */

    return NULL;
}

void
dnscore_reset_timer()
{
    int mypid = getpid();

    if(mypid != dnscore_timer_creator_pid)
    {
        dnscore_timer_tick = 0;
        dnscore_timer_creator_pid = mypid;
        
        async_wait_init(&timer_thread_sync, 1);
        
        log_debug("starting timer");

        if(pthread_create(&dnscore_timer_thread_id, NULL, dnscore_timer_thread, NULL) != 0)
        {
            dnscore_timer_thread_id = 0;
            dnscore_timer_creator_pid = 0;
            log_err("failed to create timer thread: %r", ERRNO_ERROR);
            exit(EXIT_CODE_THREADCREATE_ERROR);
        }
    }
}

u32
dnscore_timer_get_tick()
{
    return dnscore_timer_tick;
}

void
dnscore_init()
{
    if(dnscore_init_done)
    {
        return;
    }
    
#if DNSCORE_HAS_ZALLOC_SUPPORT
    zalloc_init();
#endif
    
    output_stream_set_void(&__termout__);
    output_stream_set_void(&__termerr__);
    
    stdstream_init();
    
    dnscore_init_done = TRUE;
    dnscore_arch_checkup();
    
    thread_pool_setup_random_ctx();
    random_ctx rnd = thread_pool_get_random_ctx();
    
    // random NEEDS to work.
    {
        u32 r0 = random_next(rnd);
        u32 r1 = random_next(rnd);
        u32 r2 = random_next(rnd);
        u32 r3 = random_next(rnd);
        
        if( ((r0 == 0) && (r1 == 0) && (r2 == 0) && (r3 == 0)) || ((r0 == r1) && (r1 == r2) && (r2 == r3)) )
        {
            // this IS possible, but has one chance in the order of 2^128 to happen
            
            printf("panic: random generation fails. (%08x,%08x,%08x,%08x)\n", r0, r1, r2, r3);
            exit(-1);
        }
    }

    rfc_init();
    
    format_class_init();
    dnsformat_class_init();
    logger_init();

    dnscore_register_errors();
    
#if DNSCORE_HAS_TSIG_SUPPORT
    ENGINE_load_openssl();
    ENGINE_load_builtin_engines();
    SSL_library_init();
    SSL_load_error_strings();
    tsig_register_algorithms();
#endif
    
    atexit(dnscore_finalize);
    
    alarm_init();
    
    dnscore_reset_timer();
    
    tcp_init_with_env();
}

void
dnscore_stop_timer()
{
    /*
     * Timer thread stop
     */

    int mypid = getpid();

    if(mypid == dnscore_timer_creator_pid)
    {
        dnscore_timer_creator_pid = 0;
        
        if(dnscore_timer_thread_id != 0)
        {
            log_debug("stopping timer");
            
            async_wait_progress(&timer_thread_sync, 1);
            
            // pthread_kill(dnscore_timer_thread_id, SIGUSR1);
            pthread_join(dnscore_timer_thread_id, NULL);
            
            dnscore_timer_thread_id = 0;
            
            async_wait_finalize(&timer_thread_sync);
        }
    }
    else
    {
#ifdef DEBUG
        if(dnscore_timer_creator_pid != 0)
        {
            log_debug("timer owned by %d, not touching it (I'm %d)", dnscore_timer_creator_pid, mypid);
        }
        else
        {
            log_debug("timer stopped already (I'm %d)", mypid);
        }
#endif
    }
    
    logger_flush();
}

void
dnscore_wait_timer_stopped()
{
    pthread_t id = dnscore_timer_thread_id;
    
    if(id != 0)
    {
        pthread_join(id, NULL);
    }
}

void
dnscore_shutdown()
{
    smp_int_set(&g_shutdown, 1);
}

bool
dnscore_shuttingdown()
{
    return smp_int_get(&g_shutdown) != 0;
}

static volatile bool dnscore_finalizing = FALSE;

void log_assert__(bool b, const char *txt, const char *file, int line)
{
    if(!b)
    {
        if(logger_is_running() && (g_system_logger != NULL))
        {
            //logger_handle_exit_level(MAX_U32);
            log_crit("assert: at %s:%d: %s", file, line, txt); /* this is in zassert */
            logger_flush();
        }
        else
        {
            osformatln(&__termerr__,"assert: at %s:%d: %s", file, line, txt);            
        }
        stdstream_flush_both_terms();
        abort();
    }
}

void
dnscore_finalize()
{
    /*
     * No need to "finalize" format, dnsformat and rfc
     */

    if(dnscore_finalizing)
    {
        /* OOPS : ALREADY BUSY SHUTTING DOWN */

        /* DO NOT USE LOGGER HERE ! */
        
        return;
    }

    dnscore_finalizing = TRUE;
    
    dnscore_shutdown();
    
#ifdef DEBUG
    debug_bench_logdump_all();
#endif
    
#ifdef DEBUG
    log_debug("exit: destroying the thread pool");
#endif
    
    logger_flush();
    
#ifdef DEBUG
    log_debug("exit: bye (pid=%hd)", getpid());
    
    logger_flush();
#endif
    
    logger_flush();
    
    dnscore_stop_timer();               // timer uses logger
    dnscore_wait_timer_stopped();
    
    alarm_finalise();
    
    config_finalise();
        
    async_message_pool_finalize();

    stdstream_flush_both_terms();
    
    logger_finalize();  /** @note does a logger_stop */

#if defined(DEBUG) || defined(DNSCORE_TIDY_UP_MEMORY)
    /*
     *  It may not be required right now, but in case the stdstream are filtered/buffered
     *  this will flush them.
     */

    thread_pool_destroy_random_ctx();
    
    stdstream_flush_both_terms();
        
#if DNSCORE_HAS_TSIG_SUPPORT
    tsig_finalize();
#endif
    
    error_unregister_all();
    rfc_finalize();
    format_class_finalize();
    
#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
    debug_stat(TRUE);
    zalloc_print_stats(&__termout__);
#endif
    
    stdstream_flush_both_terms();
    
#endif // DNSCORE_TIDY_UP_MEMORY
    
    output_stream_close(&__termerr__);
    output_stream_close(&__termout__);
    
    debug_stacktrace_clear();
}

static void
dnscore_signature_check_one(const char* name, int should, int is)
{
    if(is != should)
    {
        printf("critical: dnscore: '%s' should be of size %i but is of size %i\n", name, is, should);
        fflush(stdout);
        abort();
    }
}

void dnscore_signature_check(int so_mutex_t, int so_group_mutex_t)
{
    dnscore_signature_check_one("mutex_t", sizeof(mutex_t), so_mutex_t);
    dnscore_signature_check_one("group_mutex_t", sizeof(group_mutex_t), so_group_mutex_t);
}

/** @} */

/*----------------------------------------------------------------------------*/

