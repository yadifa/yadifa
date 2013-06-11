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
/** @defgroup dnscore System core functions
 *  @brief System core functions
 *
 * @{ */
#define __DNSCORE_C__

#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include "dnscore/message.h"

#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/mt_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/dnsformat.h"
#include "dnscore/logger.h"
#include "dnscore/random.h"
#include "dnscore/rdtsc.h"
#include "dnscore/sys_error.h"
#include "dnscore/thread_pool.h"
#include "dnscore/tsig.h"
#include "dnscore/scheduler.h"
#include "dnscore/mutex.h"
#include "dnscore/alarm.h"

#include <sys/time.h>

#define TERM_BUFFER_SIZE 4096

#define MODULE_MSG_HANDLE g_system_logger

/*****************************************************************************/

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
#pragma message("Don't worry about the possible warnings here")
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
    intptr msg_diffs = (intptr)(msg->buffer - msg->buffer_tcp_len);
    if((msg->buffer - msg->buffer_tcp_len) != 2)
    {
        printf("Structure aligment is wrong.  Expected 2 but got %i. (see message_data)\n", (int)msg_diffs);
        DIE(ERROR);
    }

#pragma message("You can resume worrying now ...")

    
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
    
#if HAS_TSIG_SUPPORT
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

    fd_output_stream_attach(1, &tmp);
    buffer_output_stream_init(&tmp, &tmp2, TERM_BUFFER_SIZE);
    mt_output_stream_init(&tmp2, &__termout__);

    fd_output_stream_attach(2, &tmp);
    buffer_output_stream_init(&tmp, &tmp2, TERM_BUFFER_SIZE);
    mt_output_stream_init(&tmp2, &__termerr__);
}

static void
stdstream_flush_both_terms()
{
    output_stream_flush(&__termout__);
    output_stream_flush(&__termerr__);
}

void rfc_init();
void rfc_finalize();
void format_class_finalize();

static bool dnscore_init_done = FALSE;

static smp_int dnscore_running = SMP_INT_INITIALIZER;
static pthread_t dnscore_timer_thread_id = 0;
static int dnscore_timer_creator_pid = 0;
static int dnscore_timer_period = 5;
static volatile u32 dnscore_timer_tick = 0;

static void*
dnscore_timer_thread(void * unused0)
{
    thread_pool_setup_random_ctx();

    int last_call = time(NULL);
    dnscore_timer_tick = last_call;

    while(smp_int_get(&dnscore_running) != 0)
    {
        /* log & term output flush handling */
        stdstream_flush_both_terms();

        logger_flush();

        /* alarm callback handling */        
        int period = dnscore_timer_period;

        do
        {
            sleep(period);

            dnscore_timer_tick = time(NULL);

            period = dnscore_timer_tick - last_call;
        }
        while((period < dnscore_timer_period) && (smp_int_get(&dnscore_running) != 0));

        alarm_run_tick(dnscore_timer_tick);
        
        last_call = dnscore_timer_tick;
    }

    pthread_exit(NULL);

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

        smp_int_set(&dnscore_running, 1);

        if(pthread_create(&dnscore_timer_thread_id, NULL, dnscore_timer_thread, NULL) != 0)
        {
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

    dnscore_init_done = TRUE;
    dnscore_arch_checkup();

    //random_init(time(NULL));
    
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
            printf("panic: random generation fails. (%08x,%08x,%08x,%08x)\n", r0, r1, r2, r3);
            exit(-1);
        }
    }

    rfc_init();

    format_class_init();
    dnsformat_class_init();
    stdstream_init();
    logger_init();

    dnscore_register_errors();

#if HAS_TSIG_SUPPORT
    tsig_register_algorithms();
#endif

    atexit(dnscore_finalize);

    dnscore_reset_timer();
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
        smp_int_set(&dnscore_running, 0);

        if(dnscore_timer_thread_id != 0)
        {
            log_debug("stopping timer");

            pthread_join(dnscore_timer_thread_id, NULL);
            pthread_detach(dnscore_timer_thread_id);
            
            dnscore_timer_creator_pid = 0;
            dnscore_timer_thread_id = 0;
        }
    }
    else
    {
#ifndef NDEBUG
        log_debug("timer owned by %d (0 meaning stopped already), not touching it (I'm %d)", dnscore_timer_creator_pid, mypid);
#endif
    }
    
    logger_flush();
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
        log_err("assert: at %s:%d: %s", file, line, txt); /* this is in zassert */
        logger_flush();
        sleep(10);                  /* be nice */
        exit(-1);
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

#ifndef NDEBUG
    log_debug("exit: destroying the thread pool");
#endif
    
    logger_flush();

    thread_pool_destroy();
    
#ifdef DEBUG
    log_debug("exit: bye (pid=%hd)", getpid());
    
    logger_flush();
#endif
    
    scheduler_finalize();

    logger_flush();

    logger_finalize();  /** @note does a logger_stop */

    logger_handle_finalize();

#ifndef NDEBUG
    /*
     *  It may not be required right now, but in case the stdstream are filtered/buffered
     *  this will flush them.
     */

#if HAS_TSIG_SUPPORT
    tsig_finalize();
#endif

    stdstream_flush_both_terms();

    error_unregister_all();

    rfc_finalize();

    format_class_finalize();

#endif
    
#ifndef NDEBUG
#if ZDB_DEBUG_MALLOC != 0
    debug_stat(TRUE);
#endif
#endif

    stdstream_flush_both_terms();
    
    output_stream_close(&__termerr__);
    output_stream_close(&__termout__);
}

/*
#if HAS_STRDUP == 0

char *
strdup(const char* txt)
{
    char *r;
    size_t n = strlen(txt) + 1;
    MALLOC_OR_DIE(char *, r, n, GENERIC_TAG);
    memcpy(r, txt, n);
    return r;
}

#endif
*/

/** @} */

/*----------------------------------------------------------------------------*/

