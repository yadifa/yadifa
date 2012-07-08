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
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <unistd.h>

#if defined(__linux__)
#include <execinfo.h>
#endif

#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/scheduler.h>

#include "signals.h"
#include "server_context.h"
#include "server.h"

#define MODULE_MSG_HANDLE g_server_logger
#define MAXTRACE 128

// Let this to 0
#define SIGNAL_HOOK_COREDUMP 0

ya_result database_save_all_zones_to_disk();

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */
//extern server_context_t *server_context;

static config_data *config = NULL;
static bool sigsegv_trytrace = TRUE;
static bool sigsegv_tryloggerflush = TRUE;

#define LOGGER_REOPEN_MIN_PERIOD 10

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/*
 * signals are not supposed to be interrupted by other signals
 * still, it happened once, the pthread_create of another signal : deadlock
 * so, here is another check (mutexes are of course forbidden)
 */
static volatile bool calling_pthread_create = FALSE;

//

static volatile time_t signal_task_logger_handle_reopen_last_active = 0;


void *
signal_logger_handle_reopen_all_thread(void* ignored)
{
    if(!dnscore_shuttingdown())
    {
        log_debug("signal_logger_handle_reopen_all_thread: begin");

        logger_reopen();

        log_info("loggers reopened");

        log_debug("signal_logger_handle_reopen_all_thread: end");
    }
    
    pthread_exit(NULL);
    
    return NULL;
}


static void
signal_task_logger_handle_reopen_all()
{  
    time_t now = time(NULL);
    
    if(now - signal_task_logger_handle_reopen_last_active > LOGGER_REOPEN_MIN_PERIOD)
    {        
        signal_task_logger_handle_reopen_last_active = now;
        
        if(!calling_pthread_create)
        {
            calling_pthread_create = TRUE;
            
            pthread_t t;

            if(pthread_create(&t, NULL, signal_logger_handle_reopen_all_thread, NULL) == 0)
            {
            }
            else
            {
                pthread_detach(t);
            }
            
            calling_pthread_create = FALSE;
        }
    }
}

/***/

static volatile bool signal_task_database_save_all_zones_to_disk_active = FALSE;

void *
signal_task_database_save_all_zones_to_disk_thread(void* ignored)
{
    if(!dnscore_shuttingdown())
    {
        log_debug("signal_task_database_save_all_zones_to_disk_thread: begin");

        database_save_all_zones_to_disk();

        signal_task_database_save_all_zones_to_disk_active = FALSE;    

        log_debug("signal_task_database_save_all_zones_to_disk_thread: end");
    }
    
    pthread_exit(NULL);
    
    return NULL;
}

static void
signal_task_database_save_all_zones_to_disk()
{
    if(!signal_task_database_save_all_zones_to_disk_active)
    {
        signal_task_database_save_all_zones_to_disk_active = TRUE;
        
        if(!calling_pthread_create)
        {
            pthread_t t;
        
            calling_pthread_create = TRUE;
            
            if(pthread_create(&t, NULL, signal_task_database_save_all_zones_to_disk_thread, NULL) == 0)
            {
                pthread_detach(t);
            }
            else
            {
                signal_task_database_save_all_zones_to_disk_active = FALSE;
            }
            
            calling_pthread_create = FALSE;
        }
    }
    else
    {
        /*
#ifndef NDEBUG
        printf("\n[%5i] already saving zones\n",getpid());
        fflush(stdout);
#endif
         */
    }
}

/**/

static volatile bool signal_task_shutdown_thread_active = FALSE;

void *
signal_task_shutdown_thread(void* ignored)
{
    if(!dnscore_shuttingdown())
    {
        log_debug("signal_task_shutdown_thread: begin");
        
        program_mode = SA_SHUTDOWN;
        
        dnscore_shutdown();

        log_debug("signal_task_shutdown_thread: end");
    }
    
    pthread_exit(NULL);
    
    return NULL;
}

static void
signal_task_shutdown()
{
    program_mode = SA_SHUTDOWN;
    
    if(!signal_task_shutdown_thread_active)
    {
        signal_task_shutdown_thread_active = TRUE;
        
        if(!calling_pthread_create)
        {
            pthread_t t;
            
            calling_pthread_create = TRUE;
            
            if(pthread_create(&t, NULL, signal_task_shutdown_thread, NULL) == 0)
            {
                signal_task_shutdown_thread_active = FALSE;
            }
            else
            {
                pthread_detach(t);
            }
            
            calling_pthread_create = FALSE;
        }
    }
    else
    {/*
#ifndef NDEBUG
        printf("\n[%5i] already shutting down\n",getpid());
        fflush(stdout);
#endif
        */
    }
}

/** \brief handle the signals received
 *
 *  @param[in] signo
 *
 *  @note The signal handler CANNOT use the loggers or it has to use its own channels + handle.
 *        The reason being mutexes are not reentrant.  So if a signal occurs while the log mutex is on
 *        the signal will deadlock as soon as it tries to log.
 *
 *  return NONE
 */

static void
signal_handler(int signo, siginfo_t* info, void* context)
{
    /*
    int status;
    int i;
    */
    
    /*    ------------------------------------------------------------    */

    switch(signo)
    {
        case SIGHUP:
        {
            signal_task_logger_handle_reopen_all();
            break;
        }
        case SIGUSR1:
        {
            /* write all (dirty) zones to disk */
            
            signal_task_database_save_all_zones_to_disk();
            
            break;
        }
        case SIGUSR2:
        {
            // Used to break a syscall (sync)
            break;
        }
        case SIGINT:
        case SIGTERM:
        {
            /*
             * We are shutting down : ignore other "command" signals
             */
            
            signal(SIGHUP, SIG_IGN);
            signal(SIGUSR1, SIG_IGN);
            signal(SIGINT, SIG_IGN);
            signal(SIGTERM, SIG_IGN);
            
            signal_task_shutdown();
            
            break;
        }
#if SIGNAL_HOOK_COREDUMP == 0
        case SIGBUS:
        case SIGFPE:
        case SIGILL:
        case SIGSEGV:
        {
            signal(signo, SIG_DFL);
            
            if(sigsegv_trytrace)
            {
                char filepath[1024];
                FILE *f;

                /* So if we crashed while trying to dump, we will not do it anymore */
                sigsegv_trytrace = FALSE;

                snprintf(filepath, sizeof(filepath), "%ssig%i.%i", config->log_path, signo, getpid());

                f = fopen(filepath, "a+");

                if(f == NULL)
                {
                    snprintf(filepath, sizeof(filepath), "/tmp/yadifa.sig%i.%i", signo, getpid());

                    f = fopen(filepath, "a+");
                }

                if(f != NULL)
                {

        #if defined(__linux__)
                    void* buffer[MAXTRACE];
                    char** strings;
                    int n = backtrace(buffer, MAXTRACE);
                    int i;
                    time_t now = time(NULL);

                    fprintf(f, "Signal %i at time=%li for address %p\n", signo, now, info->si_addr);

                    fflush(f);

                    strings = backtrace_symbols(buffer, n);

                    if(strings != NULL)
                    {
                        for(i = 0; i < n; i++)
                        {
                            fprintf(f, "\t[%3i]: %s\n", i, strings[i]);
                        }
                    }
                    else
                    {
                        fprintf(f, "No backtrace available (%s)\n", strerror(errno));
                    }
                    fflush(f);
                    fprintf(f, "pid: %i\n", getpid());
                    fprintf(f, "thread id: %d",  (u32)pthread_self());
        #else
                    fprintf(f, "Got signal %i.  No backtrace available\n", signo);
        #endif
                    fclose(f);
                }

                /**
                 * Do NOT free(strings) :
                 * If the memory is corrupted, this is one more chance to crash
                 *
                 */
            }

            /* There COULD be some relevant information in the logger */
            /* try to flush it */

            if(sigsegv_tryloggerflush)
            {
                sigsegv_tryloggerflush = FALSE;
                logger_flush();
                log_err("CRITICAL ERROR");
                logger_flush();
            }

            /* trigger the original signal (to dump a core if possible ) */

            raise(signo);

            /* should never be reached : Exit without disabling stuff (no atexit registered function called) */

            _exit(EXIT_CODE_SELFCHECK_ERROR);

            break;
        }
#endif

        /*
        case SIGUSR2:
        case SIGCHLD:
        */
        default:
        {
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
void
init_signals()
{
    u8 handlded_signals[] =
    {
        SIGHUP,		/* Hangup (POSIX).  */
        SIGINT,		/* Interrupt (ANSI).  */
        SIGQUIT,	/* Quit (POSIX).  */
        SIGILL,		/* Illegal instruction (ANSI).  */	    /* ERROR/EXIT */
        SIGABRT,	/* Abort (ANSI).  */
        SIGIOT,		/* IOT trap (4.2 BSD).  */
        SIGBUS,		/* BUS error (4.2 BSD).  */
        SIGFPE,		/* Floating-point exception (ANSI).  */	    /* ERROR/EXIT */
        SIGUSR1,	/* User-defined signal 1 (POSIX).  */
        //SIGSEGV,	/* Segmentation violation (ANSI).  */	    /* ERROR/EXIT */
        SIGUSR2,	/* User-defined signal 2 (POSIX).  */
        SIGALRM,	/* Alarm clock (POSIX).  */
        SIGTERM,	/* Termination (ANSI).  */
    /*	SIGSTKFLT,*/	/* Stack fault.  */
        SIGCHLD,	/* Child status has changed (POSIX).  */
        SIGCONT,	/* Continue (POSIX).  */
        SIGTSTP,	/* Keyboard stop (POSIX).  */
        SIGTTIN,	/* Background read from tty (POSIX).  */
        SIGTTOU,	/* Background write to tty (POSIX).  */
        SIGURG,		/* Urgent condition on socket (4.2 BSD).  */
        SIGXCPU,	/* CPU limit exceeded (4.2 BSD).  */
        SIGXFSZ,	/* File size limit exceeded (4.2 BSD).  */
        0
    };

    u8 ignored_signals[] =
    {
        SIGPIPE,	/* Broken pipe (POSIX).  */
        0
    };

    struct sigaction action;
    int signal_idx;

    ZEROMEMORY(&action,sizeof(action));

    action.sa_sigaction = signal_handler;
    
    for(signal_idx = 0; handlded_signals[signal_idx] != 0; signal_idx++)
    {
        action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT;
        
        switch(signal_idx)
        {
            case SIGBUS:
            case SIGFPE:
            case SIGILL:
            case SIGSEGV:
            {
                sigemptyset(&action.sa_mask);    /* can interrupt the interrupt */
                
                /*
                sigaddset(&action.sa_mask, SIGBUS);
                sigaddset(&action.sa_mask, SIGFPE);
                sigaddset(&action.sa_mask, SIGILL);
                sigaddset(&action.sa_mask, SIGSEGV);
                */
                break;
            }
            default:
            {
                sigfillset(&action.sa_mask);    /* don't interrupt the interrupt */
                break;
            }
        }
        sigaction(handlded_signals[signal_idx], &action, NULL);
    }
    
    action.sa_handler = SIG_IGN;

    for(signal_idx = 0; ignored_signals[signal_idx] != 0; signal_idx++)
    {
        sigaction(ignored_signals[signal_idx], &action, NULL);
    }
}

/** @} */
