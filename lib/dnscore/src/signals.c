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
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

#if __unix__
#if HAS_GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <dnscore/thread.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ucontext.h>

#if defined(__linux__) || defined(__gnu_hurd__)

#if defined(__GLIBC__) || defined(__gnu_hurd__)
#include <execinfo.h>
#endif

#include <sys/mman.h>
#endif

#include "dnscore/logger.h"
#include "dnscore/format.h"
#include "dnscore/fdtools.h"
#include "dnscore/timems.h"
#include "dnscore/thread.h"
#include "dnscore/thread_pool.h"
#include "dnscore/process.h"
#include "dnscore/signals.h"

#define SIGNAL_MAX              32
#define SIGNAL_HANDLER_CHAIN    0
#define SIGNAL_DONT_QUEUE_TWICE 1 // avoids hammering the signal handling thread

#if SIGNAL_DONT_QUEUE_TWICE

#if HAVE_STDATOMIC_H
#include <stdatomic.h>
#else
#include "dnscore/thirdparty/stdatomic.h"
#endif // HAS_STDATOMIC_H

#endif // SIGNAL_DONT_QUEUE_TWICE

#if DEBUG
#if defined(__linux__)
#include <sys/types.h>

// testing for !((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 30))) is irrelevant as there is no name
// collision.

// #include <asm/unistd.h>
#include <sys/syscall.h>

static inline long int signal_gettid() { return (long int)syscall(__NR_gettid); }
#else
static inline long int signal_gettid() { return (long int)~0; }
#endif
#endif

#define MODULE_MSG_HANDLE    g_system_logger
#define MAXTRACE             128

// Let this to 0
// This prevents the coredump from occurring.
// Let's configure this using runtime flags.
#define SIGNAL_HOOK_COREDUMP 1

static const char  *signal_dump_path = "/tmp";

static thread_t     signal_thread = 0;
static mutex_t      signal_mutex = MUTEX_INITIALIZER;

static volatile int signal_handler_read_fd = -1;
static volatile int signal_handler_write_fd = -1;

static bool         sigsegv_trytrace = true;
static bool         sigsegv_tryloggerflush = true;

#if DEBUG
static void signal_handler_cb_debug(uint8_t signum) { log_info("signal: %i received", (int)signum); }

#define SIGNAL_HANDLER_NULL signal_handler_cb_debug

#else

#define SIGNAL_HANDLER_NULL NULL

#endif

// signal can be lost, a full pipe will not block and lose even more.
// shutdown is thus given an override so that it cannot be lost after
// the signal handler gets it.

static volatile bool signal_shutdown_received = false;

struct signal_handler_entry
{
    signal_handler_function_t handler;
#if SIGNAL_HANDLER_CHAIN
    struct signal_handler_entry *next;
#endif
#if SIGNAL_DONT_QUEUE_TWICE
    atomic_flag queued;
#endif
};

typedef struct signal_handler_entry signal_handler_entry;

#if SIGNAL_HANDLER_CHAIN
#if SIGNAL_DONT_QUEUE_TWICE
#define SIGNAL_HANDLER_ENTRY {SIGNAL_HANDLER_NULL, NULL, ATOMIC_FLAG_INIT}
#else
#define SIGNAL_HANDLER_ENTRY {SIGNAL_HANDLER_NULL, NULL}
#endif
#else
#if SIGNAL_DONT_QUEUE_TWICE
#define SIGNAL_HANDLER_ENTRY {SIGNAL_HANDLER_NULL, ATOMIC_FLAG_INIT}
#else
#define SIGNAL_HANDLER_ENTRY {SIGNAL_HANDLER_NULL}
#endif
#endif

static signal_handler_entry signal_handlers[SIGNAL_MAX] = {SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY,
                                                           SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY,
                                                           SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY,
                                                           SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY, SIGNAL_HANDLER_ENTRY};

static uint8_t              signal_ignored_at_shutdown[SIGNAL_MAX] = {
    SIGHUP, SIGUSR1, SIGINT, SIGTERM, SIGPIPE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static void signal_ignore_for_shutdown()
{
    int errno_value = errno;
    for(int_fast32_t i = 0; i < SIGNAL_MAX; ++i)
    {
        int s;
        if((s = signal_ignored_at_shutdown[i]) == 0)
        {
            break;
        }
        signal(s, SIG_IGN);
    }
    errno = errno_value;
}

static void signal_send_to_thread(int signo)
{
#if SIGNAL_DONT_QUEUE_TWICE
    assert(((signo >= 0) && (signo < SIGNAL_MAX)) || (signo == U8_MAX));

#if !defined(GCC_VERSION) || (GCC_VERSION > 40700)
    bool old_flag = (signo < SIGNAL_MAX) ? atomic_flag_test_and_set(&signal_handlers[signo].queued) : false;
#else
    bool old_flag;
    if(signo < SIGNAL_MAX)
    {
        atomic_flag *flag = &signal_handlers[signo].queued;
        old_flag = atomic_flag_test_and_set(flag);
    }
    else
    {
        old_flag = false;
    }
#endif

    if(!old_flag)
    {
#endif
        int     errno_value = errno;
        int     ret;
        uint8_t signum = (uint8_t)signo; // MUST be one byte long
        while((ret = write(signal_handler_write_fd, &signum, sizeof(signum))) != sizeof(signum))
        {
            if(ret < 0)
            {
                ret = errno;
#if EAGAIN != EWOULDBLOCK
                if((ret == EINTR) || (ret == EAGAIN) || (ret == EWOULDBLOCK))
                {
                    continue;
                }
#else
            if((ret == EINTR) || (ret == EAGAIN))
            {
                continue;
            }
#endif
            }
            else if(ret == 0)
            {
                continue;
            }

            // failed unexpectedly

            if(signo < SIGNAL_MAX)
            {
                atomic_flag_clear(&signal_handlers[signo].queued);
            }

            break;
        }

        errno = errno_value;
#if SIGNAL_DONT_QUEUE_TWICE
    }
#endif
}

/*
 * signals are not supposed to be interrupted by other signals
 * still, it happened once, the pthread_create of another signal : deadlock
 * so, here is another check (mutexes are of course forbidden)
 */

// tool to avoid external function calls during the signal

static int signal_strcat(char *dest, const char *src)
{
    char *p = dest;

    while(*p != '\0')
    {
        p++;
    }

    while(*src != '\0')
    {
        *p++ = *src++;
    }

    *p = '\0';

    return p - dest;
}

// tool to avoid external function calls during the signal

static int signal_int2str(char *dest, int src)
{
    char *p = dest;
    int   tmp = src;
    do
    {
        p++;
        tmp /= 10;
    } while(tmp > 0);

    *p = '\0';

    do
    {
        char c = '0' + (char)(src % 10);
        src /= 10;

        --p;

        *p = c;
    } while(src > 0);

    while(p > dest)
    {
        --p;

        *p = ' ';
    }

    return p - dest;
}

#if defined(__GLIBC__) || defined(__gnu_hurd__)

static const char __HEXA__[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static int        signal_longlong2hexstr(char *dest, uint64_t src)
{
    int shift = 60;
    do
    {
        *dest++ = __HEXA__[(src >> shift) & 15];
        shift -= 4;
    } while(shift >= 0);
    *dest = '\0';
    return 16;
}

static int signal_int2hexstr(char *dest, uint32_t src)
{
    int shift = 28;
    do
    {
        *dest++ = __HEXA__[(src >> shift) & 15];
        shift -= 4;
    } while(shift >= 0);
    *dest = '\0';
    return 8;
}

static int signal_char2hexstr(char *dest, uint8_t src)
{
    int shift = 4;
    do
    {
        *dest++ = __HEXA__[(src >> shift) & 15];
        shift -= 4;
    } while(shift >= 0);
    *dest = '\0';
    return 2;
}

// tool to avoid external function calls during the signal

static int signal_ptr2str(char *dest, const void *srcp)
{
#if __SIZEOF_POINTER__ == 8
    return signal_longlong2hexstr(dest, (uint64_t)srcp);
#elif __SIZEOF_POINTER__ == 4
    return signal_int2hexstr(dest, (uint32_t)srcp);
#else
#error "unsupported pointer size"
#endif
}

#endif

//

static void signal_handler_thread_stop()
{
    log_info("signal: thread stopping");

    mutex_lock(&signal_mutex);
    if(signal_handler_read_fd >= 0)
    {
        signal_send_to_thread(U8_MAX);
    }
    mutex_unlock(&signal_mutex);
}

static _Noreturn void *signal_handler_thread(void *parms)
{
    (void)parms;

#if DEBUG
    log_debug7("thread started: self=%p, tid=%i", thread_self(), signal_gettid());
#endif

    thread_set_name("signal", 0, 0);

#if DNSCORE_HAS_LOG_THREAD_TAG
    static char signal_thread_tag[9] = "signal";
    logger_handle_set_thread_tag(signal_thread_tag);
#endif

    log_info("signal: thread started");

    while(signal_handler_read_fd >= 0)
    {
        uint8_t   signum;
        ya_result return_code;

#if DEBUG
        log_debug7("signal: waiting for next signal");
#endif

        if(FAIL(return_code = readfully(signal_handler_read_fd, &signum, sizeof(signum))))
        {
            log_err("signal: error reading the next signal: %r", return_code);
            break;
        }

#if DEBUG
        log_debug7("signal: handling signal %i", signum);
#endif

        if(signum < SIGNAL_MAX)
        {
#if SIGNAL_DONT_QUEUE_TWICE
            atomic_flag_clear(&signal_handlers[signum].queued);
#endif
            if(signal_shutdown_received)
            {
#if DEBUG
                if(signum != SIGINT && signum != SIGTERM)
                {
                    log_debug7("signal: check that, handling a SIGINT instead");
                }
#endif
                signum = SIGINT;
            }
#if SIGNAL_HANDLER_CHAIN
            signal_handler_entry * = &signal_handlers[signum];
            if(signal_handler_entry->handler != NULL)
            {
                do
                {
                    signal_handler_entry->handler(signum);
                    signal_handler_entry = signal_handler_entry->next;
                } while(signal_handler_entry != NULL);
            }
#else
            switch(signum)
            {
                case SIGABRT:
                case SIGBUS:
                case SIGFPE:
                case SIGILL:
                case SIGSEGV:
                    break;
                case SIGINT:
                case SIGTERM:
                    logger_sink_noblock();
                    break;
                default:
                    logger_sink_noblock();
                    break;
            }

            if(signal_handlers[signum].handler != NULL) // NULL is right
            {
                signal_handlers[signum].handler(signum);
            }
#endif
        }
        else if(signum == U8_MAX)
        {
            // signal_handler_thread_stop();
            break;
        }
    }

    log_info("signal: thread stopping");

    /*
    mutex_lock(&signal_mutex);
    signal_thread = 0;
    mutex_unlock(&signal_mutex);
    */
#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_flush();
    logger_handle_clear_thread_tag();
#endif

    log_info("signal: thread stopped");

    logger_flush();

    thread_exit(NULL);

    // unreachable
#if !__clang__ && (GCC_VERSION < 40600)
    return NULL;
#endif
}

void signal_handler_stop()
{
    signal_handler_thread_stop();

    /**
     * The signal thread CANNOT be joined here,
     * as if a signal handler callback calls it then it will ovbiously be a deadlock.
     */
}

/** \brief handle the signals received
 *
 *  @param[in] signo
 *
 *  @note The signal handler CANNOT use the loggers or it has to use its own channels + handle. (ie: not the ones of the
 * logger) The reason being mutexes are not reentrant.  So if a signal occurs while the log mutex is on the signal will
 * deadlock as soon as it tries to log.
 *
 *  return NONE
 */

static void signal_handler(int signo, siginfo_t *info, void *context)
{
    // formatln("signal_handler, pid=%i, tid=%p, signal=%i", getpid(), thread_self(), signo);

    switch(signo)
    {
        case SIGINT: // special cases
        case SIGTERM:
        {
            /*
             * We are shutting down : ignore other "command" signals
             * Also, in order to avoid handling an hammering of signals,
             * (and risking missing the shutdown if the pipe is already full)
             * we set a volatile that will be sync "soon" (no mutexes here please)
             */

            signal_ignore_for_shutdown();
            signal_shutdown_received = true;

            signal_send_to_thread(signo);
            break;
        }

#if SIGNAL_HOOK_COREDUMP
        case SIGABRT:
        case SIGBUS:
        case SIGFPE:
        case SIGILL:
        case SIGSEGV:
        {
            // reactivate the default handler

            int errno_value = errno;

            signal(signo, SIG_DFL);

            if(sigsegv_trytrace)
            {
                char filepath[PATH_MAX];
                char number[32];

                sigsegv_trytrace = false;

                for(int_fast32_t source = 0; source <= 1; source++)
                {
                    char *eol = (source == 0) ? "\n" : "";
                    int   fd = -1; /// @note edf: set to -1 to shut-up false positive "uninitialised"
                    int   len;

                    filepath[0] = '\0';
                    signal_strcat(filepath, signal_dump_path);
                    signal_strcat(filepath, "/");
                    signal_strcat(filepath, "sig-");
                    signal_int2str(number, signo);
                    signal_strcat(filepath, number);
                    signal_strcat(filepath, "-");
                    signal_int2str(number, getpid_ex());
                    signal_strcat(filepath, number);

                    if(source == 0)
                    {
                        fd = open_create_ex(filepath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);

                        if(fd < 0)
                        {
                            continue;
                        }
                    }
                    else
                    {
                        if(!logger_is_running())
                        {
                            continue;
                        }
                    }

                    len = signal_strcat(filepath, eol);

                    if(source == 0)
                    {
                        writefully(fd, filepath, len);
                        fsync(fd);
                    }
                    else
                    {
                        log_err(filepath);
                    }

#if defined(__GLIBC__) || defined(__gnu_hurd__)
                    void  *buffer[MAXTRACE];
                    char **strings;
                    int    n = backtrace(buffer, MAXTRACE);
                    int    i;
                    time_t now = time(NULL);

                    filepath[0] = '\0';
                    signal_strcat(filepath, "got signal ");
                    signal_int2str(number, signo);
                    signal_strcat(filepath, number);
                    signal_strcat(filepath, " at time=");
                    signal_int2str(number, now);
                    signal_strcat(filepath, number);
                    signal_strcat(filepath, " for address ");

                    signal_ptr2str(number, info->si_addr);
                    signal_strcat(filepath, number);
                    len = signal_strcat(filepath, eol);

                    if(source == 0)
                    {
                        writefully(fd, filepath, len);
                        fsync(fd);
                    }
                    else
                    {
                        log_err(filepath);
                    }

#if __linux__
                    ucontext_t *ucontext = (ucontext_t *)context;

                    /*
                     * cpu registers dump, if supported
                     * this helps a lot if there is no core dump available
                     */

#ifdef __x86_64__
                    // specific x86_64 information

                    struct text_idx
                    {
                        const char *name;
                        int         index;
                    };

                    static struct text_idx text_idx[18] = {{"rax", REG_RAX},
                                                           {"rcx", REG_RCX},
                                                           {"rdx", REG_RDX},
                                                           {"rbx", REG_RBX},
                                                           {"rsi", REG_RSI},
                                                           {"rdi", REG_RDI},
                                                           {"rsp", REG_RSP},
                                                           {"rbp", REG_RBP},
                                                           {"r8 ", REG_R8},
                                                           {"r9 ", REG_R9},
                                                           {"r10", REG_R10},
                                                           {"r11", REG_R11},
                                                           {"r12", REG_R12},
                                                           {"r13", REG_R13},
                                                           {"r14", REG_R14},
                                                           {"r15", REG_R15},
                                                           {"rip", REG_RIP},
                                                           {"efl", REG_EFL}};

                    for(int_fast32_t i = 0; i < 18; ++i)
                    {
                        filepath[0] = '\0';
                        signal_strcat(filepath, text_idx[i].name);
                        signal_strcat(filepath, "=");
                        signal_longlong2hexstr(number, ucontext->uc_mcontext.gregs[text_idx[i].index]);
                        signal_strcat(filepath, number);
                        len = signal_strcat(filepath, eol);

                        if(source == 0)
                        {
                            writefully(fd, filepath, len);
                            fsync(fd);
                        }
                        else
                        {
                            log_err(filepath);
                        }
                    }
#elif defined(__i386__)
                    struct text_idx
                    {
                        const char *name;
                        int         index;
                    };

                    static struct text_idx text_idx[10] = {{"eax", REG_EAX}, {"ecx", REG_ECX}, {"edx", REG_EDX}, {"ebx", REG_EBX}, {"esi", REG_ESI}, {"edi", REG_EDI}, {"esp", REG_ESP}, {"ebp", REG_EBP}, {"rip", REG_EIP}, {"efl", REG_EFL}};

                    for(int_fast32_t i = 0; i < 10; ++i)
                    {
                        filepath[0] = '\0';
                        signal_strcat(filepath, text_idx[i].name);
                        signal_strcat(filepath, "=");
                        signal_int2hexstr(number, ucontext->uc_mcontext.gregs[text_idx[i].index]);
                        signal_strcat(filepath, number);
                        len = signal_strcat(filepath, eol);

                        if(source == 0)
                        {
                            writefully(fd, filepath, len);
                            fsync(fd);
                        }
                        else
                        {
                            log_err(filepath);
                        }
                    }
#else // not x86_64 nor i386
      // cpu registers dump not supported
#endif

#endif // linux
                    strings = backtrace_symbols(buffer, n);

                    if(strings != NULL)
                    {
                        for(i = 0; i < n; i++)
                        {
                            filepath[0] = '\0';
                            signal_strcat(filepath, "\t[");
                            signal_int2str(number, i);
                            signal_strcat(filepath, number);
                            signal_strcat(filepath, "]: ");
                            signal_strcat(filepath, strings[i]);
                            len = signal_strcat(filepath, eol);

                            if(source == 0)
                            {
                                writefully(fd, filepath, len);
                                fsync(fd);
                            }
                            else
                            {
                                log_err(filepath);
                            }
                        }
                    }
                    else
                    {
                        filepath[0] = '\0';
                        signal_strcat(filepath, "no backtrace available: ");
                        signal_int2str(number, errno);
                        signal_strcat(filepath, number);
                        len = signal_strcat(filepath, eol);

                        if(source == 0)
                        {
                            writefully(fd, filepath, len);
                            fsync(fd);
                        }
                        else
                        {
                            log_err(filepath);
                        }
                    }

                    filepath[0] = '\0';
                    signal_strcat(filepath, "pid: ");
                    signal_int2str(number, getpid_ex());
                    signal_strcat(filepath, number);
                    signal_strcat(filepath, " ");
                    signal_strcat(filepath, "thread id: ");

                    thread_t self = thread_self();

                    if(sizeof(self) >= sizeof(uint64_t))
                    {
                        signal_longlong2hexstr(number, (uint64_t)self);
                    }
                    else
                    {
                        signal_int2hexstr(number, (uint32_t)self);
                    }

                    signal_strcat(filepath, number);
                    len = signal_strcat(filepath, eol);

                    if(source == 0)
                    {
                        writefully(fd, filepath, len);
                        fsync(fd); // fd IS initialised : (source == 0) => fd set
                    }
                    else
                    {
                        log_err(filepath);
                    }

#if __linux__ && (defined(__x86_64__) || defined(__i386__)) && (_BSD_SOURCE || _SVID_SOURCE || _DEFAULT_SOURCE)
                    // dump more information about the memory address of the error
#define PAGESIZE 4096
#define LINESIZE 32
                    const uint8_t *addr = (uint8_t *)info->si_addr;
                    for(;;)
                    {
                        uint8_t      *page_addr = (uint8_t *)(((intptr_t)addr) & ~(PAGESIZE - 1));
                        unsigned char vec[1];

                        if(mincore(page_addr, PAGESIZE, vec) == 0)
                        {
                            // memory is resident

                            for(const uint8_t *p = page_addr; p < &page_addr[PAGESIZE]; p += 32)
                            {
                                filepath[0] = '\0';
                                signal_ptr2str(number, p);
                                signal_strcat(filepath, number);
                                signal_strcat(filepath, " | ");
                                for(int_fast32_t i = 0; i < LINESIZE; ++i)
                                {
                                    signal_char2hexstr(number, p[i]);
                                    signal_strcat(filepath, number);
                                    signal_strcat(filepath, " ");
                                }
                                len = signal_strcat(filepath, "| ");
                                for(int_fast32_t i = 0; i < LINESIZE; ++i)
                                {
                                    uint8_t c = p[i];
                                    if(c < 32 || c >= 127)
                                    {
                                        c = '.';
                                    }
                                    filepath[len + i] = c;
                                }
                                len += LINESIZE;

                                if(source == 0)
                                {
                                    writefully(fd, filepath, len);
                                    fsync(fd); // fd IS initialised : (source == 0) => fd set
                                }
                                else
                                {
                                    log_err(filepath);
                                }
                            }

                            // dump enough memory to make sense

                            if(&page_addr[PAGESIZE] >= &addr[32])
                            {
                                break;
                            }
                        }
                        else
                        {
                            int err = errno;

                            if(err == ENOMEM)
                            {
                                // memory is not mapped
                                filepath[0] = '\0';
                                signal_strcat(filepath, "page at ");
                                signal_ptr2str(number, page_addr);
                                signal_strcat(filepath, number);
                                len = signal_strcat(filepath, " is not mapped.");
                            }
                            else
                            {
                                //
                                filepath[0] = '\0';
                                signal_strcat(filepath, "could not get information for page at ");
                                signal_ptr2str(number, page_addr);
                                signal_strcat(filepath, number);
                                signal_strcat(filepath, " : errno = ");
                                signal_int2str(number, err);
                                len = signal_strcat(filepath, number);
                            }

                            if(source == 0)
                            {
                                writefully(fd, filepath, len);
                                fsync(fd); // fd IS initialised : (source == 0) => fd set
                            }
                            else
                            {
                                log_err(filepath);
                            }

                            break;
                        }
                    }

#endif // linux && mincore supported

#elif defined(__sun)
                    filepath[0] = '\0';
                    signal_strcat(filepath, "got signal ");
                    signal_int2str(number, signo);
                    signal_strcat(filepath, number);

                    signal_strcat(filepath, eol);
                    if(source == 0) // 0 -> output to file, else to the logger if it's on
                    {
                        writefully(fd, filepath, len);
                        printstack(fd);
                        fsync(fd);
                    }
                    else
                    {
                        signal_strcat(filepath, "stack trace dumped in ");
                        signal_strcat(filepath, signal_dump_path);
                        signal_strcat(filepath, "/");
                        signal_strcat(filepath, "sig-");
                        signal_int2str(number, signo);
                        signal_strcat(filepath, number);
                        signal_strcat(filepath, "-");
                        signal_int2str(number, getpid_ex());
                        signal_strcat(filepath, number);

                        log_err(filepath);
                    }
#else
                    (void)info;
                    (void)context;
                    filepath[0] = '\0';
                    signal_strcat(filepath, "got signal ");
                    signal_int2str(number, signo);
                    signal_strcat(filepath, number);
                    len = signal_strcat(filepath, "\nno backtrace available\n");

                    if(source == 0)
                    {
                        writefully(fd, filepath, len);
                        fsync(fd);
                    }
                    else
                    {
                        log_err(filepath);
                    }
#endif
                    if(source == 0)
                    {
                        close_ex(fd);
                    }

                } // for both sources

                /**
                 * Do NOT free(strings) :
                 * If the memory is corrupted, this is one more chance to crash
                 *
                 */
            } // if sigsegv_trytrace

            /* There COULD be some relevant information in the logger */
            /* try to flush it */

            if(sigsegv_tryloggerflush)
            {
                sigsegv_tryloggerflush = false;
                logger_flush();
                log_err("CRITICAL ERROR");
                logger_flush();
            }

            debug_malloc_hook_tracked_dump();
            flushout();

            errno = errno_value;

            break;
        }
#endif

        default:
        {
            if(signal_handlers[signo].handler != NULL) // NULL is right, don't use SIGNAL_HANDLER_NULL
            {
                signal_send_to_thread(signo);
            }
            break;
        }
    }
}

/** \brief initialize the signals
 *
 *  @param NONE
 *
 *  @return NONE
 *
 */
int signal_handler_init()
{
    int fds[2];

    log_debug("signal_handler_init()");

    if((signal_handler_read_fd >= 0) || (signal_handler_write_fd >= 0))
    {
        log_debug("signal_handler_init() : already initialised");

        return INVALID_STATE_ERROR; // invalid status
    }

    if(pipe(fds) < 0)
    {
        int pipe_err = ERRNO_ERROR;

        log_debug("signal_handler_init(): %r", pipe_err);

        return pipe_err;
    }

    signal_handler_read_fd = fds[0];
    signal_handler_write_fd = fds[1];

    int write_fd_flags = fcntl(signal_handler_write_fd, F_GETFL, 0);
    write_fd_flags |= O_NONBLOCK;
    if(fcntl(signal_handler_write_fd, F_SETFL, write_fd_flags) < 0)
    {
        int fcntl_err = ERRNO_ERROR;

        log_debug("signal_handler_init(): %r", fcntl_err);

        return fcntl_err;
    }

    int thread_errcode;

    if((thread_errcode = thread_create(&signal_thread, signal_handler_thread, NULL)) != 0)
    {
        close_ex(signal_handler_read_fd);
        close_ex(signal_handler_write_fd);

        signal_handler_read_fd = -1;
        signal_handler_write_fd = -1;

        log_debug("signal_handler_init(): %r", thread_errcode);

        return thread_errcode;
    }

    static const uint8_t handled_signals[] = {SIGHUP,  /* Hangup (POSIX).  */
                                              SIGINT,  /* Interrupt (ANSI).  */
                                              SIGQUIT, /* Quit (POSIX).  */
                                              SIGIOT,  /* IOT trap (4.2 BSD).  */
                                              SIGUSR1, /* User-defined signal 1 (POSIX).  */
#if SIGNAL_HOOK_COREDUMP
                                              SIGABRT, /* Abort (ANSI).  */
                                              SIGILL,
                                              /* Illegal instruction (ANSI).  */ /* ERROR/EXIT */
                                              SIGBUS,                            /* BUS error (4.2 BSD).  */
                                              SIGFPE,
                                              /* Floating-point exception (ANSI).  */ /* ERROR/EXIT */
                                              SIGSEGV,
    /* Segmentation violation (ANSI).  */ /* ERROR/EXIT */
#endif
                                              SIGUSR2,               /* User-defined signal 2 (POSIX).  */
                                              SIGALRM,               /* Alarm clock (POSIX).  */
                                              SIGTERM,               /* Termination (ANSI).  */
                                              /*	SIGSTKFLT,*/ /* Stack fault.  */
                                              SIGCHLD,               /* Child status has changed (POSIX).  */
                                              SIGCONT,               /* Continue (POSIX).  */
                                              SIGTSTP,               /* Keyboard stop (POSIX).  */
                                              SIGTTIN,               /* Background read from tty (POSIX).  */
                                              SIGTTOU,               /* Background write to tty (POSIX).  */
                                              SIGURG,                /* Urgent condition on socket (4.2 BSD).  */
                                              SIGXCPU,               /* CPU limit exceeded (4.2 BSD).  */
                                              SIGXFSZ,               /* File size limit exceeded (4.2 BSD).  */
                                              0};

    static const uint8_t ignored_signals[] = {SIGPIPE, /* Broken pipe (POSIX).  */
                                              0};

    struct sigaction     action;
    struct sigaction     error_action;
    int                  signal_idx;

    ZEROMEMORY(&action, sizeof(action));
    action.sa_sigaction = signal_handler;
#ifdef SA_NOCLDWAIT
    action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT;
#else /// @note 20151119 edf -- quick fix for Debian Hurd i386, and any other system missing SA_NOCLDWAIT
    action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP;
#endif

    ZEROMEMORY(&error_action, sizeof(error_action));
    error_action.sa_sigaction = signal_handler;
#ifdef SA_NOCLDWAIT
    error_action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESETHAND;
#else /// @note 20151119 edf -- quick fix for Debian Hurd i386, and any other system missing SA_NOCLDWAIT
    error_action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_RESETHAND;
#endif

    for(signal_idx = 0; handled_signals[signal_idx] != 0; signal_idx++)
    {
        switch(signal_idx)
        {
            case SIGBUS:
            case SIGFPE:
            case SIGILL:
            case SIGSEGV:
            case SIGABRT:
            {
                sigemptyset(&error_action.sa_mask); /* can interrupt the interrupt */
                break;
            }
            default:
            {
                sigfillset(&action.sa_mask); /* don't interrupt the interrupt */
                break;
            }
        }
        sigaction(handled_signals[signal_idx], &action, NULL);
    }

    action.sa_handler = SIG_IGN;

    for(signal_idx = 0; ignored_signals[signal_idx] != 0; ++signal_idx)
    {
        sigaction(ignored_signals[signal_idx], &action, NULL);
    }

    log_debug("signal_handler_init() done");

    return SUCCESS;
}

signal_handler_function_t signal_handler_get(uint8_t signum)
{
    if(signum < SIGNAL_MAX)
    {
        return signal_handlers[signum].handler;
    }
    else
    {
        return NULL;
    }
}

void signal_handler_set(uint8_t signum, signal_handler_function_t handler)
{
    if(handler != NULL)
    {
        struct sigaction action;
        struct sigaction error_action;

        ZEROMEMORY(&action, sizeof(action));
        action.sa_sigaction = signal_handler;
#ifdef SA_NOCLDWAIT
        action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT;
#else /// @note 20151119 edf -- quick fix for Debian Hurd i386, and any other system missing SA_NOCLDWAIT
        action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP;
#endif

        ZEROMEMORY(&error_action, sizeof(error_action));
        error_action.sa_sigaction = signal_handler;
#ifdef SA_NOCLDWAIT
        error_action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESETHAND;
#else /// @note 20151119 edf -- quick fix for Debian Hurd i386, and any other system missing SA_NOCLDWAIT
        error_action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_RESETHAND;
#endif
        sigfillset(&action.sa_mask); /* don't interrupt the interrupt */

        signal_handlers[signum].handler = handler;

        sigaction(signum, &action, NULL);
    }
    else
    {
        signal(signum, SIG_DFL);

        signal_handlers[signum].handler = NULL;
    }
}

void signal_handler_finalize()
{
    log_debug("signal_handler_finalize()");

    if(signal_handler_write_fd >= 0)
    {
        for(int_fast32_t signum = 0; signum < SIGNAL_MAX; ++signum)
        {
            if(signal_handlers[signum].handler != NULL) // NULL is right
            {
                signal_handler_set(signum, NULL);
            }
        }

        log_debug1("signal: pipe not closed yet");

        mutex_lock(&signal_mutex);
        thread_t signal_thread_local = signal_thread;
        mutex_unlock(&signal_mutex);

        if(signal_handler_read_fd >= 0)
        {
            uint8_t stop_value = U8_MAX;

            if(signal_thread_local != 0)
            {
                log_debug1("signal: handler is still running");

                writefully(signal_handler_write_fd, &stop_value, sizeof(stop_value));
                thread_join(signal_thread_local, NULL);
                mutex_lock(&signal_mutex);
                signal_thread = 0;
                mutex_unlock(&signal_mutex);

                log_debug1("signal: handler has stopped");
            }
            else
            {
                log_debug1("signal: handler is not running anymore");
            }

            int signal_handler_read_fd_local = signal_handler_read_fd;

            if(signal_handler_read_fd_local >= 0)
            {
                close_ex(signal_handler_read_fd_local);
                mutex_lock(&signal_mutex);
                signal_handler_read_fd = -1;
                mutex_unlock(&signal_mutex);
            }
        }
        else
        {
            if(signal_thread_local != 0)
            {
                log_debug1("signal: waiting for the handler to stop");

                thread_join(signal_thread_local, NULL);
                mutex_lock(&signal_mutex);
                signal_thread = 0;
                mutex_unlock(&signal_mutex);
            }

            log_debug1("signal: handler has stopped");
        }

        close_ex(signal_handler_write_fd);
        signal_handler_write_fd = -1;
    }
    else
    {
        if(signal_handler_read_fd >= 0)
        {
            log_err("signal: invalid pipe status r:%i>=0 && w:%i>=0", signal_handler_read_fd, signal_handler_write_fd);
        }

        if(signal_thread != 0)
        {
            log_err("signal: handler is unexpectedly still running");
        }
    }

    log_debug("signal_handler_finalize() done");
}

#else // windows

#include "dnscore/signals.h"

int                       signal_handler_init() { return 0; }

signal_handler_function_t signal_handler_get(uint8_t signum) { return NULL; }

void                      signal_handler_set(uint8_t signum, signal_handler_function_t handler) {}

void                      signal_handler_stop() {}

void                      signal_handler_finalize() {}

#endif

/** @} */
