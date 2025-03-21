/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @defgroup dnscore System core functions
 * @brief System core functions
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _DNSCORE_H
#define _DNSCORE_H

#include <dnscore/output_stream.h>

#ifndef __DNSCORE_C__
#ifdef __cplusplus
extern "C" output_stream_t __termout__;
extern "C" output_stream_t __termerr__;
extern "C" logger_handle  *g_system_logger;
#else
extern output_stream_t __termout__;
extern output_stream_t __termerr__;
struct logger_handle;
extern struct logger_handle_s *g_system_logger;
#endif

static inline void flushout() { output_stream_flush(&__termout__); }

static inline void flusherr() { output_stream_flush(&__termerr__); }

#define termout &__termout__
#define termerr &__termerr__

#endif

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * This fingerprint feature has been added so libraries could check they are compatible
 */

typedef enum
{
    DNSCORE_TSIG = 1,
    DNSCORE_ACL = 2,
    DNSCORE_NSEC = 4,
    DNSCORE_NSEC3 = 8,
    DNSCORE_ZALLOC = 16,
    DNSCORE_DEBUG = 32
} dnscore_fingerprint;

uint32_t                          dnscore_fingerprint_mask();

static inline dnscore_fingerprint dnscore_getmyfingerprint()
{
    dnscore_fingerprint ret = (dnscore_fingerprint)(0

#if DNSCORE_HAS_TSIG_SUPPORT
                                                    | DNSCORE_TSIG
#endif
#if DNSCORE_HAS_ACL_SUPPORT
                                                    | DNSCORE_ACL
#endif
#if DNSCORE_HAS_NSEC_SUPPORT
                                                    | DNSCORE_NSEC
#endif
#if DNSCORE_HAS_NSEC3_SUPPORT
                                                    | DNSCORE_NSEC3
#endif
#if DNSCORE_HAS_ZALLOC_SUPPORT
                                                    | DNSCORE_ZALLOC
#endif
#if DEBUG
                                                    | DNSCORE_DEBUG
#endif
    );

    return ret;
}

dnscore_fingerprint dnscore_getfingerprint();

// Required by DNSCORE_TTY_BUFFERED and DNSCORE_LOGGER: a thread will periodically
// do some tasks.  Required by the alarm mechanism.
#define DNSCORE_TIMER_THREAD            0x02000000

// default: 5 seconds
#define DNSCORE_TIMER_PERIOD(seconds__) (((uint32_t)((seconds__) & 0x3f)) << (32 - 6))

// The logging system will be initialised.  Default points to the TTY.
#define DNSCORE_LOGGER                  0x00000001 // logging mechanism

// Enables initialisation of SSL, dns keys, digests, ...
#define DNSCORE_CRYPTO                  0x00000002

// Enables initialisation of DNS-related structures (RFC, dns format class for the *format*() calls, ...)
#define DNSCORE_DNS                     0x00000004 // DNS specific initialisation (specific formats, keyrings, ...)

// Enables the use of ZALLOC calls.  Without this calling a ZALLOC call will give undefined results (a.k.a: crash)
#define DNSCORE_ZALLOC                  0x00000008

#define DNSCORE_ALARM                   0x00000010

// The TTY output will be flushed every timer tick
// else the TTY output will be buffered by line ('\r' or '\n')
// default: on
#define DNSCORE_TTY_BUFFERED            0x00000020

#define DNSCORE_SOCKET_SERVER           0x00000040
#define DNSCORE_SHARED_HEAP             0x00000080
#define DNSCORE_TCP_MANAGER             0x00000100

#define DNSCORE_SERVICE                 0x20000000 // for Windows, to handle the program as a service
#define DNSCORE_WSA                     0x40000000 // for Windows, automatic

#define DNSCORE_MOST                    (DNSCORE_TIMER_THREAD | DNSCORE_TIMER_PERIOD(5) | DNSCORE_LOGGER | DNSCORE_CRYPTO | DNSCORE_DNS | DNSCORE_ZALLOC | DNSCORE_ALARM | DNSCORE_TTY_BUFFERED | DNSCORE_SHARED_HEAP)
#define DNSCORE_TINYRUN                 (DNSCORE_DNS | DNSCORE_ZALLOC)
#define DNSCORE_ALL                     (DNSCORE_MOST | DNSCORE_SOCKET_SERVER | DNSCORE_TCP_MANAGER)

/**
 * Initialises DNSCORE partially and keeps a reference to the program arguments table.
 *
 * argc can be 0 and argv can be NULL
 *
 * @param features the features to enable
 * @param argc the size of the argv table, can be 0
 * @param argv the argv table
 *
 */

void     dnscore_init_ex(uint32_t features, int argc, char **argv);

void     dnscore_init();

int64_t  dnscore_init_timestamp();

uint32_t dnscore_get_active_features();

uint32_t dnscore_timer_get_tick();

void     dnscore_reset_timer();

void     dnscore_stop_timer();

void     dnscore_finalize(void);

void     dnscore_shutdown();

bool     dnscore_shuttingdown();

/**
 * Tool function to check binary integrity (build features, matching structures sizes, ...)
 */

void      dnscore_signature_check(int so_mutex_t, int so_group_mutex_t);

size_t    dnscore_ipc_make_name(const char *suffix, char *out_buffer, size_t out_buffer_size);

ya_result stdstream_detach_fd(output_stream_t *os);
ya_result stdstream_detach_fd_and_close_filtered(output_stream_t *os);
void      stdstream_detach_fds_and_close();
void      stdstream_detach_fds();

/**
 * Will try to find a FD in MT(BUFFER(FILE(fd)))
 * Returns true if it has been found (valid or invalid)
 *
 * @param os
 * @return true iff there is an fd at the bottom.
 */

bool stdstream_is_tty(output_stream_t *os);

#define DNSCORE_API_CHECK() dnscore_signature_check(sizeof(mutex_t), sizeof(group_mutex_t))

void dnscore_hookme(); // debugging tool : this function can be used as a single breakpoint

struct dnscore_meminfo_s
{
    int64_t page_size;
    int64_t page_count;
    int64_t total_memory;
    int64_t rss_current;
    int64_t rss_max;
    int64_t program_memory_limit;
};

typedef struct dnscore_meminfo_s dnscore_meminfo_t;

const dnscore_meminfo_t         *dnscore_meminfo_get(dnscore_meminfo_t *mi);

/**
 * Return the number of args
 *
 * @return argc
 */

int dnscore_args_count();

/**
 * Return args at that index
 *
 * @param index the index of the arg
 *
 * @return argv the argument at index or NULL if index is out of range
 */

char *dnscore_args_get(int index);

/**
 * Helper function, used for tracking generic error codes.
 *
 * Return ISOK(ret), logs an error and stacktrace if ret == -1
 *
 * @param ret
 *
 * @return ISOK(ret)
 */

bool dnscore_monitored_isok(ya_result ret);

/**
 * Helper function, used for tracking generic error codes.
 *
 * Return FAIL(ret), logs an error and stacktrace if ret == -1
 *
 * @param ret
 *
 * @return FAIL(ret)
 */

bool dnscore_monitored_fail(ya_result ret);

void log_assert__(bool b, const char *txt, const char *file, int line);

#ifdef __cplusplus
}
#endif

#endif /* _DNSCORE_H */

/** @} */
