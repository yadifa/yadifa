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

/** @defgroup dnscore System core functions
 *  @brief System core functions
 *
 * @{ */

#define __DNSCORE_C__

#include "dnscore/dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#if DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <signal.h>

#include "dnscore/zalloc.h"
#include "dnscore/message.h"

#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/mt_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/dnsformat.h"
#include "dnscore/logger.h"
#include "dnscore/random.h"
#include "dnscore/process.h"

#include "dnscore/sys_error.h"
#include "dnscore/thread.h"
#include "dnscore/thread_pool.h"
#include "dnscore/tsig.h"
#include "dnscore/mutex.h"
#include "dnscore/alarm.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/config_settings.h"
#include "dnscore/async.h"
#include "dnscore/hash.h"
#include "dnscore/socket-server.h"
#include "dnscore/shared-heap.h"
#if DNSCORE_HAS_TCP_MANAGER
#include "dnscore/tcp_manager.h"
#endif
#include <sys/time.h>

#if DNSCORE_HAS_TSIG_SUPPORT
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
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

#if HAS_BUILD_TIMESTAMP
#if DEBUG
const char *dnscore_lib = "dnscore " __DATE__ " " __TIME__ " debug";
#else
const char *dnscore_lib = "dnscore " __DATE__ " " __TIME__ " release";
#endif
#else
#if DEBUG
const char *dnscore_lib = "dnscore debug";
#else
const char *dnscore_lib = "dnscore release";
#endif
#endif

void rfc_init();
void rfc_finalize();
void format_class_finalize();
#ifndef WIN32
void chroot_unmanage_all();
#endif
void signal_handler_finalize();
void dnskey_init();
void dnskey_finalize();
void xfr_input_stream_finalize();

static const char* ARCH_RECOMPILE_WARNING = "Please recompile with the correct settings.";
static const char* ARCH_CHECK_SIZE_WARNING = "PANIC: %s does not match the size requirements (%i instead of %i).\n";
static const char* ARCH_CHECK_SIGN_WARNING = "PANIC: %s does not match the sign requirements.\n";
#define ARCH_CHECK_SIZE(a,b) if(a!=b) { printf(ARCH_CHECK_SIZE_WARNING,#a,a,b);puts(ARCH_RECOMPILE_WARNING);DIE(ERROR); }
#define ARCH_CHECK_SIGNED(a) {a val=~0;if(val>0) { printf(ARCH_CHECK_SIGN_WARNING,#a);puts(ARCH_RECOMPILE_WARNING);DIE(ERROR); }}
#define ARCH_CHECK_UNSIGNED(a) {a val=~0;if(val<0) { printf(ARCH_CHECK_SIGN_WARNING,#a);puts(ARCH_RECOMPILE_WARNING);DIE(ERROR); }}

logger_handle *g_system_logger = LOGGER_HANDLE_SINK;

static smp_int g_shutdown = SMP_INT_INITIALIZER;

/**
 * Tests the architecture:
 * 
 * Ensures that types sizes are exactly what they are expected to be.
 * Ensures that signed types are signed and unsigned types are unsigned.
 * Ensures that endianness is as expected.
 * Ensures that structure alignment is as expected.
 * 
 * Will kill the program if an inconsistency is detected.
 */

typedef void (*function_pointer_t)(const u8 *fqdn);

static void
dnscore_arch_checkup()
{
/// @note 20170413 edf -- older compilers (gcc 4.6 and such) used to complain a lot about this
///
# pragma message("Don't worry about the possible warnings below")
    ARCH_CHECK_SIZE(__SIZEOF_POINTER__, sizeof(void*));
    ARCH_CHECK_SIZE(sizeof(u8), 1);
    ARCH_CHECK_SIZE(sizeof(s8), 1);
    ARCH_CHECK_SIZE(sizeof(u16), 2);
    ARCH_CHECK_SIZE(sizeof(s16), 2);
    ARCH_CHECK_SIZE(sizeof(u32), 4);
    ARCH_CHECK_SIZE(sizeof(s32), 4);
    ARCH_CHECK_SIZE(sizeof(u64), 8);
    ARCH_CHECK_SIZE(sizeof(s64), 8);
    ARCH_CHECK_SIZE(sizeof(intptr), sizeof(void*));
    ARCH_CHECK_SIZE(sizeof(function_pointer_t), sizeof(void*)); // to safely ignore the function pointer/data pointer conversion
    ARCH_CHECK_SIGNED(s8);
    ARCH_CHECK_SIGNED(s16);
    ARCH_CHECK_SIGNED(s32);
    ARCH_CHECK_SIGNED(s64);
    ARCH_CHECK_UNSIGNED(u8);
    ARCH_CHECK_UNSIGNED(u16);
    ARCH_CHECK_UNSIGNED(u32);
    ARCH_CHECK_UNSIGNED(u64);
    ARCH_CHECK_UNSIGNED(intptr);

#if !MESSAGE_PAYLOAD_IS_POINTER
    message_data* msg = NULL;
    intptr msg_diffs = (intptr)(msg->_buffer - msg->_buffer_tcp_len); // cppcheck : false positive: of course it's a null pointer
    if(msg_diffs != 2)
    {
        printf("Structure aligment is wrong.  Expected 2 but got %i. (see message_data)\n", (int)msg_diffs);
        DIE(ERROR);
    }
#endif

# pragma message("You can resume worrying about warnings ...")
    
#if WORDS_BIGENDIAN == 1
    static const u8 endian[4] = {1, 2, 3, 4}; /* BIG    */
    static const char* endian_name = "BIG";
#else
    static const u8 endian[4] = {4, 3, 2, 1}; /* LITTLE */
    static const char* endian_name = "LITTLE";
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

struct dnscore_ipc_prefix_t
{
    char zero;
    char pid[8];
    char uid[8];
    char gid[8];
    char timestamp[16];
    char rnd[7];
};

#ifndef WIN32
static struct dnscore_ipc_prefix_t dnscore_ipc_prefix;

static void
dnscore_init_ipc_prefix()
{
    int pid = getpid();
    int uid = getpid();
    int gid = getgid();
    u64 timestamp = timeus();
    snformat(dnscore_ipc_prefix.pid, sizeof(dnscore_ipc_prefix) - 1, "%08x%08x%08x%016x", pid, uid, gid, timestamp);
    dnscore_ipc_prefix.zero = '\0';
    random_ctx rnd = thread_pool_get_random_ctx();
    
    for(size_t i = 0; i < sizeof(dnscore_ipc_prefix.rnd); ++i)
    {
        char c = random_next(rnd)&0x7f7f7f7f;
        c %= 62;
        if(c < 10)
        {
            c += '0' - 0;
        }
        else if(c < 36)
        {
            c += 'A' - 10;
        }
        else // if(c < 62)
        {
            c += 'a' - 36;
        }
        dnscore_ipc_prefix.rnd[i] = c;
    }
}

static size_t
dnscore_ipc_prefix_copy(char *out_buffer, size_t out_buffer_size)
{
    if(out_buffer != NULL)
    {
        if(out_buffer_size >= sizeof(struct dnscore_ipc_prefix_t))
        {
            memcpy(out_buffer, &dnscore_ipc_prefix, sizeof(struct dnscore_ipc_prefix_t));
        }
        else
        {
            return 0;
        }
    }

    return sizeof(struct dnscore_ipc_prefix_t);
}

size_t
dnscore_ipc_make_name(const char *suffix, char *out_buffer, size_t out_buffer_size)
{
    size_t offset = dnscore_ipc_prefix_copy(out_buffer, out_buffer_size);
    
    if(offset > 0)
    {
        size_t suffix_len = strlen(suffix) + 1;
        
        if(out_buffer != NULL)
        {
            if(offset + suffix_len <= out_buffer_size)
            {
                memcpy(&out_buffer[offset], suffix, suffix_len);
            }
            else
            {
                return 0;
            }
        }
        
        return offset + suffix_len;
    }
    
    return 0;
}

#endif

/*****************************************************************************/

dnscore_fingerprint dnscore_getfingerprint()
{
    dnscore_fingerprint ret = dnscore_getmyfingerprint();
    return ret;
}

u32 dnscore_fingerprint_mask()
{
    return DNSCORE_TSIG;
}

/*****************************************************************************/

output_stream __termout__ = {NULL, NULL};
output_stream __termerr__ = {NULL, NULL};

static void
stdstream_init(bool bufferise)
{
    output_stream tmp;
    output_stream tmp2;

    if(bufferise)
    {
        fd_output_stream_attach(&tmp, 1);
        buffer_output_stream_init(&tmp2, &tmp, TERM_BUFFER_SIZE);
        mt_output_stream_init(&__termout__, &tmp2);
    }
    else
    {
        fd_output_stream_attach(&__termout__, 1);
    }
    
    if(bufferise)
    {
        fd_output_stream_attach(&tmp, 2);
        buffer_output_stream_init(&tmp2, &tmp, TERM_BUFFER_SIZE);
        mt_output_stream_init(&__termerr__, &tmp2);
    }
    else
    {
        fd_output_stream_attach(&__termerr__, 2);
    }
}

static void
stdstream_flush_both_terms()
{
    output_stream_flush(&__termout__);
    output_stream_flush(&__termerr__);
}

/**
 * Detaches the fd at the bottom of the mt(buffer(file(fd))) stream ... if it can.
 *
 * @param os
 * @return 1 if an seemingly valid fd has been found and detached.  0 otherwise.
 */

ya_result
stdstream_detach_fd(output_stream *os)
{
    output_stream *wos = NULL;
    ya_result ret = 0;

    output_stream_flush(os);

    if(is_mt_output_stream(wos))
    {
        output_stream filtered;
        wos = &filtered;
        mt_output_stream_detach_filtered(os, &filtered);
        if(is_buffer_output_stream(&filtered))
        {
            wos = buffer_output_stream_get_filtered(wos);
            if(is_fd_output_stream(wos))
            {
                fd_output_stream_detach(wos);
                ret = 1;
            }
        }
        else if(is_fd_output_stream(&filtered))
        {
            fd_output_stream_detach(&filtered);
            ret = 1;
        }
        else
        {
            // no clues
        }
    }
    else
    {
        if(is_buffer_output_stream(os))
        {
            wos = buffer_output_stream_get_filtered(wos);
            if(is_fd_output_stream(wos))
            {
                fd_output_stream_detach(wos);
                ret = 1;
            }
        }
        else if(is_fd_output_stream(os))
        {
            fd_output_stream_detach(os);
            ret = 1;
        }
        else
        {
            // no clues
        }
    }

    return ret;
}



ya_result
stdstream_detach_fd_and_close_filtered(output_stream *os)
{
    output_stream *wos = NULL;
    ya_result ret = 0;

    output_stream_flush(os);

    if(is_mt_output_stream(wos))
    {
        output_stream filtered;
        wos = &filtered;
        mt_output_stream_detach_filtered(os, &filtered);
        if(is_buffer_output_stream(&filtered))
        {
            wos = buffer_output_stream_get_filtered(wos);
            if(is_fd_output_stream(wos))
            {
                fd_output_stream_detach(wos);
                ret = 1;
            }
        }
        else if(is_fd_output_stream(&filtered))
        {
            fd_output_stream_detach(&filtered);
            ret = 1;
        }
        else
        {
            // no clues
        }

        // closes the whole output_stream stack but not the file descriptor at the bottom
        output_stream_close(&filtered);

        ret |= 2;
    }
    else
    {
        if(is_buffer_output_stream(os))
        {
            wos = buffer_output_stream_get_filtered(wos);
            if(is_fd_output_stream(wos))
            {
                fd_output_stream_detach(wos);
                ret = 1;
            }
        }
        else if(is_fd_output_stream(os))
        {
            fd_output_stream_detach(os);
            ret = 1;
        }
        else
        {
            // no clues
        }
    }

    return ret;
}

void
stdstream_detach_fds_and_close()
{
    stdstream_detach_fd_and_close_filtered(&__termout__);
    stdstream_detach_fd_and_close_filtered(&__termerr__);
}

void
stdstream_detach_fds()
{
    stdstream_detach_fd(&__termout__);
    stdstream_detach_fd(&__termerr__);
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

//static smp_int dnscore_time_thread_must_run = SMP_INT_INITIALIZER;
static async_wait_s* timer_thread_sync = NULL;
static thread_t dnscore_timer_thread_id = 0;
static volatile int dnscore_timer_creator_pid = 0;
static int dnscore_timer_period = 5;
static volatile u32 dnscore_timer_tick = 0;
static mutex_t dnscore_timer_mtx = MUTEX_INITIALIZER;

static noreturn void*
dnscore_timer_thread(void * unused0)
{
    (void)unused0;

    thread_pool_setup_random_ctx();

    mutex_lock(&dnscore_timer_mtx);
    dnscore_timer_tick = time(NULL);
    mutex_unlock(&dnscore_timer_mtx);

    thread_set_name("timer", 0, 0);

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_set_thread_tag("timer");
#endif
    
    log_debug5("dnscore_timer_thread started");

    // if the counter reaches 0 then we have to stop
    
    u64 loop_period = dnscore_timer_period;
    loop_period *= ONE_SECOND_US;
    
    u64 loop_next_timeout_epoch = timeus();

    // every timeout (1s) loops as the async_ call returned FALSE.
    while(!async_wait_timeout_absolute(timer_thread_sync, loop_next_timeout_epoch))
    {
        /* log & term output flush handling */
        stdstream_flush_both_terms();

        logger_flush();

        mutex_lock(&dnscore_timer_mtx);
        dnscore_timer_tick = time(NULL);
        u32 local_dnscore_timer_tick = dnscore_timer_tick;
        mutex_unlock(&dnscore_timer_mtx);
        
        if(!dnscore_shuttingdown())
        {
            alarm_run_tick(local_dnscore_timer_tick);
        }
        else
        {
            loop_period = 1000000LL;
        }

        loop_next_timeout_epoch += loop_period;
    }

    log_debug5("dnscore_timer_thread stopping");

    thread_pool_destroy_random_ctx();
    
    log_debug5("dnscore_timer_thread stopped");

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_clear_thread_tag();
#endif

    thread_exit(NULL); /* not from the pool, so it's the way */

    // unreachable
    // return NULL;

#ifndef _STDNORETURN_H
    return NULL; // just so the compiler shuts-up
#endif
}

void
dnscore_reset_timer()
{
    assert(getpid_ex() == getpid());
    
    int mypid = getpid_ex();

    mutex_lock(&dnscore_timer_mtx);

    if(mypid != dnscore_timer_creator_pid)
    {
        dnscore_timer_tick = 0;
        dnscore_timer_creator_pid = mypid;
        mutex_unlock(&dnscore_timer_mtx);

        if(timer_thread_sync != NULL)
        {
            log_err("timer_thread_sync isn't NULL");
            abort();
        }

        timer_thread_sync = async_wait_new_instance(1);
        
        log_debug("starting timer");

        if(thread_create(&dnscore_timer_thread_id, dnscore_timer_thread, NULL) != 0)
        {
            mutex_lock(&dnscore_timer_mtx);
            dnscore_timer_thread_id = 0;
            dnscore_timer_creator_pid = 0;
            mutex_unlock(&dnscore_timer_mtx);
            log_err("failed to create timer thread: %r", ERRNO_ERROR);
            exit(EXIT_CODE_THREADCREATE_ERROR);
        }
    }
    else
    {
        mutex_unlock(&dnscore_timer_mtx);
    }
}

u32
dnscore_timer_get_tick()
{
    mutex_lock(&dnscore_timer_mtx);
    u32 ret = dnscore_timer_tick;
    mutex_unlock(&dnscore_timer_mtx);
    return ret;
}

static volatile u32 dnscore_features = 0;
static volatile bool dnscore_arch_checked = FALSE;
static volatile bool dnscore_tty_init = FALSE;
static volatile bool dnscore_tty_set = FALSE;
static volatile bool dnscore_random_set = FALSE;
static volatile bool dnscore_atexit_registered = FALSE;

void
dnscore_init_ex(u32 features, int argc, char **argv)
{
    if(!dnscore_arch_checked)
    {
        dnscore_arch_checkup();
        dnscore_arch_checked = TRUE;
    }

    g_pid = getpid();
    
    debug_bench_init();
    
    debug_malloc_hooks_init();

    /* Init the hash tables */

    hash_init();
    
    if(!dnscore_tty_init)
    {
        output_stream_set_sink(&__termout__);
        output_stream_set_sink(&__termerr__);

        dnscore_tty_init = TRUE;
    }
    
#if DNSCORE_HAS_ZALLOC_SUPPORT
    if((features & DNSCORE_ZALLOC) && !(dnscore_features & DNSCORE_ZALLOC))
    {
        zalloc_init();
        dnscore_features |= DNSCORE_ZALLOC;
    }
#endif
          
    if(((features & DNSCORE_TTY_BUFFERED) && !(dnscore_features & DNSCORE_TTY_BUFFERED)) || !dnscore_tty_set)
    {
        if(dnscore_tty_set)
        {
            stdstream_detach_fds_and_close();
            dnscore_tty_set = FALSE;
        }
        if(features & DNSCORE_TTY_BUFFERED)
        {
            features |= DNSCORE_TIMER_THREAD;
        }
        stdstream_init(features & DNSCORE_TTY_BUFFERED);
        dnscore_features |= DNSCORE_TTY_BUFFERED;
        dnscore_tty_set = TRUE;
    }

#if MUTEX_CONTENTION_MONITOR
    //mutex_contention_monitor_start();
#endif

    if(!dnscore_random_set)
    {
        thread_pool_setup_random_ctx();
        random_ctx rnd = thread_pool_get_random_ctx();

        // random NEEDS to work.
        for(int impossible_collisions_countdown = 16; impossible_collisions_countdown >= 0; --impossible_collisions_countdown)
        {
            u32 r0 = random_next(rnd);
            u32 r1 = random_next(rnd);
            u32 r2 = random_next(rnd);
            u32 r3 = random_next(rnd);

            if( ((r0 == 0) && (r1 == 0) && (r2 == 0) && (r3 == 0)) || ((r0 == r1) && (r1 == r2) && (r2 == r3)) )
            {
                // this IS possible, but has one chance in the order of 2^128 to happen

                if(impossible_collisions_countdown == 0)
                {
                    printf("panic: random generation fails. (%08x,%08x,%08x,%08x)\n", r0, r1, r2, r3);
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                break;
            }
        }
                
        dnscore_random_set = TRUE;
#ifndef WIN32
        dnscore_init_ipc_prefix();
#endif
    }

    netformat_class_init();
    
    if((features & DNSCORE_DNS) && !(dnscore_features & DNSCORE_DNS))
    {
        rfc_init();
        dnsformat_class_init();
        dnscore_features |= DNSCORE_DNS;
    }
    
    if((features & DNSCORE_LOGGER) && !(dnscore_features & DNSCORE_LOGGER))
    {
        features |= DNSCORE_TIMER_THREAD;
        logger_init();
        dnscore_features |= DNSCORE_LOGGER;
    }
    
    if((features & DNSCORE_SHARED_HEAP) && !(dnscore_features & DNSCORE_SHARED_HEAP))
    {
        shared_heap_init();
        /*
        int ret = shared_heap_create(20);
        if(ret < 0)
        {
            osformatln(&__termerr__, "[%i] failed to allocate shared memory: %r", getpid(), ret);
            exit(1);
        }
        if(ret != 0)
        {
            osformatln(&__termerr__, "[%i] expected shared memory id to be 0, instead it is %i", getpid(), ret);
            exit(2);
        }
        */
        dnscore_features |= DNSCORE_SHARED_HEAP;
    }
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_set_thread_tag("main");
#endif

    dnscore_register_errors();
    
    if((features & DNSCORE_CRYPTO) && !(dnscore_features & DNSCORE_CRYPTO))
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        ENGINE_load_openssl();
        ENGINE_load_builtin_engines();
        SSL_library_init();
        SSL_load_error_strings();
        tsig_register_algorithms();
#endif
        dnskey_init();
        dnscore_features |= DNSCORE_CRYPTO;
    }
    /*
    if(features & DNSCORE_SHARED_HEAP)
    {
        shared_heap_init();
    }
    */
    if(!dnscore_atexit_registered)
    {
        atexit(dnscore_finalize);
        dnscore_atexit_registered = TRUE;
    }
    
    if((features & DNSCORE_ALARM) && !(dnscore_features & DNSCORE_ALARM))
    {
        features |= DNSCORE_TIMER_THREAD;
        alarm_init();
        dnscore_features |= DNSCORE_ALARM;
    }
    
    int timer_period = (features >> (32 - 6)) & 0x3f;
    if(timer_period == 0)
    {
        timer_period = 5;
    }
    dnscore_timer_period = timer_period;
    
    if((features & DNSCORE_TIMER_THREAD) && !(dnscore_features & DNSCORE_TIMER_THREAD))
    {
        dnscore_reset_timer();
        dnscore_features |= DNSCORE_TIMER_THREAD;
    }
    
    tcp_init_with_env();
    
    if((features & DNSCORE_SOCKET_SERVER) && !(dnscore_features & DNSCORE_SOCKET_SERVER))
    {
        if(FAIL(socket_server_init(argc, argv))) // yes, even before the core
        {
            puts("no server socket available ...");
            fflush(NULL);
            exit(EXIT_FAILURE);
        }
        dnscore_features |= DNSCORE_SOCKET_SERVER;
    }

#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_init();
#endif
}

void
dnscore_init()
{
    dnscore_init_ex(DNSCORE_MOST, 0, NULL);
}

u32 dnscore_get_active_features()
{
    return dnscore_features;
}

void
dnscore_stop_timer()
{
    /*
     * Timer thread stop
     */

    //yassert(getpid_ex() == getpid());
    
    int mypid = getpid_ex();

    if(mypid == dnscore_timer_creator_pid)
    {
        dnscore_timer_creator_pid = 0;
        
        if(dnscore_timer_thread_id != 0)
        {
            log_debug("stopping timer");
            
            async_wait_progress(timer_thread_sync, 1);
            
            // pthread_kill(dnscore_timer_thread_id, SIGUSR1);
            thread_join(dnscore_timer_thread_id, NULL);
            
            dnscore_timer_thread_id = 0;

            async_wait_destroy(timer_thread_sync);
            timer_thread_sync = NULL;
        }
    }
    else
    {
#if DEBUG
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
    thread_t id = dnscore_timer_thread_id;
    
    if(id != 0)
    {
        thread_join(id, NULL);
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
#if !HAS_SHARED_QUEUE_SUPPORT
        if(logger_is_running() && (g_system_logger != NULL) && (g_system_logger != LOGGER_HANDLE_SINK))
        {
            //logger_handle_exit_level(MAX_U32);
            log_crit("assert: at %s:%d: %s", file, line, txt); /* this is in yassert */
            logger_flush();
        }
#endif
        osformatln(&__termerr__,"assert: [pid=%i, thread=%p] at %s:%d: %s", getpid(), thread_self(), file, line, txt);
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
    
#if DEBUG
    debug_bench_logdump_all();
#endif
    
#if DEBUG
    log_debug("exit: destroying the thread pool");
#endif
    
    logger_flush();
    
#if DEBUG
    log_debug("exit: bye (pid=%hd)", getpid());
    logger_flush();
#endif

#if DNSCORE_HAS_TCP_MANAGER
#if DEBUG
    log_debug("exit: destroying the TCP manager");
    logger_flush();
#endif
    tcp_manager_finalise();
#endif
    
    dnscore_stop_timer();               // timer uses logger
    dnscore_wait_timer_stopped();
    if(dnscore_features & DNSCORE_ALARM)
    {
        alarm_finalize();
    }
    
    config_finalize();
        
    async_message_pool_finalize();

    stdstream_flush_both_terms();
    
    signal_handler_finalize();
    
    xfr_input_stream_finalize();
    
    logger_finalize();  /** @note does a logger_stop */
    
    config_set_log_base_path(NULL);

#if DEBUG || defined(DNSCORE_TIDY_UP_MEMORY)
    /*
     *  It may not be required right now, but in case the stdstream are filtered/buffered
     *  this will flush them.
     */

    thread_pool_destroy_random_ctx();
    
    stdstream_flush_both_terms();
        
#if DNSCORE_HAS_TSIG_SUPPORT
    tsig_finalize();
#if SSL_API_LT_110
    CONF_modules_free();
#endif
    ENGINE_cleanup();
#if SSL_API_LT_110
    CONF_modules_unload(1);
#endif
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    //sk_free(SSL_COMP_get_compression_methods());
    
#endif
    
#ifndef WIN32
    chroot_unmanage_all();
#endif
    error_unregister_all();
    rfc_finalize();
    format_class_finalize();
    
#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
    debug_stat(DEBUG_STAT_SIZES|DEBUG_STAT_TAGS|DEBUG_STAT_DUMP);
    zalloc_print_stats(&__termout__);
#endif
    
    stdstream_flush_both_terms();
    
    dnskey_finalize();
    
#endif // DNSCORE_TIDY_UP_MEMORY

    if(__termerr__.vtbl != NULL)
    {
        output_stream_close(&__termerr__);
    }
    if(__termout__.vtbl != NULL)
    {
        output_stream_close(&__termout__);
    }

    debug_bench_unregister_all();
    
    debug_stacktrace_clear();
    
    debug_malloc_hooks_finalize();

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_stop();
#endif
    
#if DEBUG
    FILE* dnscore_finalize_file = fopen("/tmp/dnscore_finalize_file.txt", "a+");
    if(dnscore_finalize_file != NULL)
    {
        fprintf(dnscore_finalize_file, "dnscore_finalize() of pid %i properly terminated\n", getpid());
        fclose(dnscore_finalize_file);
    }
#endif
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

/**
 * Helper function, used for tracking generic error codes.
 */

bool dnscore_monitored_isok(ya_result ret)
{
    if(ret == -1 /* ERROR */)
    {
        log_warn("error-code-monitor: a function returned the generic ERROR code");
        debug_log_stacktrace(g_system_logger, MSG_WARNING, "error-code-monitor: ");
    }

    return ((((u32)(ret)) & ((u32)ERRNO_ERROR_BASE)) == 0);
}

/**
 * Helper function, used for tracking generic error codes.
 */

bool dnscore_monitored_fail(ya_result ret)
{
    if(ret == -1 /* ERROR */)
    {
        log_warn("error-code-monitor: a function returned the generic ERROR code");
        debug_log_stacktrace(g_system_logger, MSG_WARNING, "error-code-monitor: ");
    }

    return ((((u32)(ret)) & ((u32)ERRNO_ERROR_BASE)) != 0);
}

void dnscore_hookme()
{
    puts("BREAKPOINT HOLDER");
}

#ifdef LIBRESSL_VERSION_NUMBER
void ENGINE_load_openssl(void) {}
void ENGINE_cleanup(void) {}
int SSL_library_init(void) {return 1;}
void SSL_load_error_strings(void) {}
void ERR_free_strings(void) {}
void EVP_cleanup(void) {}
void CRYPTO_cleanup_all_ex_data(void) {}
#endif

/** @} */
