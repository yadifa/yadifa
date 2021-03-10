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

#include <sys/time.h>

#include <dnscore/dnscore-config.h>

//#define THREADED_QUEUE_MODE THREADED_QUEUE_DLL_CW
//#define THREADED_QUEUE_MODE THREADED_THREAD_CW

#define N 8000000
#define W 1
#define D 0
#define S 32

#include <dnscore/dnscore.h>
#include <dnscore/threaded_dll_cw.h>
#include <dnscore/threaded-qsl-cw.h>
#include <dnscore/threaded_ringbuffer_cw.h>
#if EXPERIMENTAL_LOCKFREE
#include <dnscore/threaded_dynamic_fifo.h>
#endif
#include <dnscore/threaded_queue_slg.h>
#include <dnscore/thread_pool.h>

static int n = N;                   // 8M messages by default
static int w = W;                   // 8 threads by default
static int mask = 8;                // dll_cw by default
static int msg_buffer_size = S;     // no significant effect so far
static int use_zalloc = 1;          // +50% performance

#ifndef ITEM_FILL
#define ITEM_FILL 1
#endif

struct msg
{
    char buffer[1];
};

typedef struct msg msg;

static void *msg_alloc()
{
    msg *m;
    
    if(msg_buffer_size > 0)
    {   
        if(use_zalloc)
        {
            ZALLOC_ARRAY_OR_DIE(msg*,m, msg_buffer_size,0);
        }
        else
        {
            MALLOC_OR_DIE(msg*,m, msg_buffer_size,0);
        }

#if ITEM_FILL
        for(int i = 0; i < msg_buffer_size; i++)
        {
            m->buffer[i] = (char)i;
        }
#endif
    }
    else
    {
        m = (msg*)1;
    }
    
    return m;
}

static void msg_free(msg *m)
{
    if(msg_buffer_size > 0)
    {
        if(use_zalloc)
        {
            ZFREE_ARRAY(m, msg_buffer_size);
        }
        else
        {
            free(m);
        }
    }
    else
    {
        // nothing to do
    }
}

static mutex_t rwstat_mtx = MUTEX_INITIALIZER;

struct rwstat
{
    volatile u64 rbegin;
    volatile u64 rend;
    volatile u64 wbegin;
    volatile u64 wend;
    volatile int rcount;
    volatile int wcount;
    volatile const char *name;
};

typedef struct rwstat rwstat;

static void rwstat_print(rwstat *s)
{
    formatln("%s: ", (s->name != NULL)?s->name:"???");
    u64 rd = s->rend - s->rbegin;
    if(rd == 0)
    {
        rd = 1;
    }
    double rdf = (ONE_SECOND_US_F * n * w) / rd;
    formatln("R: %llu->%llu: %i in %9lluus or %10.6f/s", s->rbegin, s->rend, n * w, rd, rdf);

    u64 wd = s->wend - s->wbegin;
    if(wd == 0)
    {
        wd = 1;
    }
    double wdf = (ONE_SECOND_US_F * n) / wd;
    formatln("W: %llu->%llu: %i in %9lluus or %10.6f/s", s->wbegin, s->wend, n, wd, wdf);
}

// DLL_CW
//////////////////////////////////////////////////////////////

threaded_dll_cw dll_cw_queue;// = THREADED_SLL_CW_EMPTY;

static void *reader_call_dll_cw(void *parm)
{
#if D
    formatln("reader_call_dll_cw begin");
#endif

    rwstat *s = (rwstat*)parm;
    u64 rbegin = timeus();
    int i;
    int c = 0;
    int wc = w;
    for(i = 0;; i++)
    {
        msg *m = threaded_dll_cw_dequeue(&dll_cw_queue);
        if(m == NULL)
        {
            if(--wc == 0)
            {
                break;
            }
        }
        msg_free(m);
        c++;
    }
    u64 rend = timeus();
    if(c != (n * w) + w - 1)
    {
        formatln("oops: %i != %i", c, n);
    }

#if D
    formatln("reader_call_dll_cw end");
#endif

    mutex_lock(&rwstat_mtx);
    s->rbegin = rbegin;
    s->rend = rend;
    s->rcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

static void *writer_call_dll_cw(void *parm)
{
#if D
    formatln("writer_call_dll_cw begin");
#endif
    rwstat *s = (rwstat*)parm;
    u64 wbegin = timeus();
    for(int i = 0; i < n; i++)
    {
        threaded_dll_cw_enqueue(&dll_cw_queue, msg_alloc());
    }

    threaded_dll_cw_enqueue(&dll_cw_queue, NULL);
    u64 wend = timeus();

#if D
    formatln("writer_call_dll_cw end");
#endif

    mutex_lock(&rwstat_mtx);
    s->wbegin = wbegin;
    s->wend = wend;
    s->wcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

// QSL_CW
//////////////////////////////////////////////////////////////

threaded_qsl_cw qsl_cw_queue;// = THREADED_SLL_CW_EMPTY;

static void *reader_call_qsl_cw(void *parm)
{
#if D
    formatln("reader_call_qsl_cw begin");
#endif

    rwstat *s = (rwstat*)parm;
    u64 rbegin = timeus();
    int i;
    int c = 0;
    int wc = w;
    for(i = 0;; i++)
    {
        msg *m = threaded_qsl_cw_dequeue(&qsl_cw_queue);
        if(m == NULL)
        {
            if(--wc == 0)
            {
                break;
            }
        }
        msg_free(m);
        c++;
    }
    u64 rend = timeus();
    if(c != (n * w) + w - 1)
    {
        formatln("oops: %i != %i", c, n);
    }

#if D
    formatln("reader_call_qsl_cw end");
#endif

    mutex_lock(&rwstat_mtx);
    s->rbegin = rbegin;
    s->rend = rend;
    s->rcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

static void *writer_call_qsl_cw(void *parm)
{
#if D
    formatln("writer_call_qsl_cw begin");
#endif
    rwstat *s = (rwstat*)parm;
    u64 wbegin = timeus();
    for(int i = 0; i < n; i++)
    {
        threaded_qsl_cw_enqueue(&qsl_cw_queue, msg_alloc());
    }

    threaded_qsl_cw_enqueue(&qsl_cw_queue, NULL);
    u64 wend = timeus();

#if D
    formatln("writer_call_qsl_cw end");
#endif

    mutex_lock(&rwstat_mtx);
    s->wbegin = wbegin;
    s->wend = wend;
    s->wcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

// RINGBUFFER_CW
//////////////////////////////////////////////////////////////

threaded_ringbuffer_cw ringbuffer_cw_queue;// = THREADED_SLL_CW_EMPTY;

static void *reader_call_ringbuffer_cw(void *parm)
{
#if D
    formatln("reader_call_ringbuffer_cw begin");
#endif

    rwstat *s = (rwstat*)parm;
    u64 rbegin = timeus();
    int i;
    int c = 0;
    int wc = w;
    for(i = 0;; i++)
    {
        msg *m = threaded_ringbuffer_cw_dequeue(&ringbuffer_cw_queue);
        if(m == NULL)
        {
            if(--wc == 0)
            {
                break;
            }
        }        
        msg_free(m);
        c++;
    }
    u64 rend = timeus();
    if(c != (n * w) + w - 1)
    {
        formatln("oops: %i != %i", c, n);
    }

#if D
    formatln("reader_call_ringbuffer_cw end");
#endif

    mutex_lock(&rwstat_mtx);
    s->rbegin = rbegin;
    s->rend = rend;
    s->rcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

static void *writer_call_ringbuffer_cw(void *parm)
{
#if D
    formatln("writer_call_ringbuffer_cw begin");
#endif
    rwstat *s = (rwstat*)parm;
    u64 wbegin = timeus();
    for(int i = 0; i < n; i++)
    {
        threaded_ringbuffer_cw_enqueue(&ringbuffer_cw_queue, msg_alloc());
    }

    threaded_ringbuffer_cw_enqueue(&ringbuffer_cw_queue, NULL);
    u64 wend = timeus();

#if D
    formatln("writer_call_ringbuffer_cw end");
#endif

    mutex_lock(&rwstat_mtx);
    s->wbegin = wbegin;
    s->wend = wend;
    s->wcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

// RINGBUFFER_CW
//////////////////////////////////////////////////////////////

threaded_queue_slg_t queue_slg_queue = THREADED_QUEUE_SLG_EMPTY;

static void *reader_call_queue_slg(void *parm)
{
#if D
    formatln("reader_call_queue_slg begin");
#endif

    rwstat *s = (rwstat*)parm;
    u64 rbegin = timeus();
    int i;
    int c = 0;
    int wc = w;
    for(i = 0;; i++)
    {
        msg *m = threaded_queue_slg_dequeue(&queue_slg_queue);
        if(m == NULL)
        {
            if(--wc == 0)
            {
                break;
            }
        }

        msg_free(m);
        c++;
    }
    u64 rend = timeus();
    if(c != (n * w) + w - 1)
    {
        formatln("oops: %i != %i", c, n);
    }

#if D
    formatln("reader_call_queue_slg end");
#endif

    mutex_lock(&rwstat_mtx);
    s->rbegin = rbegin;
    s->rend = rend;
    s->rcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

static void *writer_call_queue_slg(void *parm)
{
#if D
    formatln("writer_call_queue_slg begin");
#endif
    rwstat *s = (rwstat*)parm;
    u64 wbegin = timeus();
    for(int i = 0; i < n; i++)
    {
        threaded_queue_slg_enqueue(&queue_slg_queue, msg_alloc());
    }

    threaded_queue_slg_enqueue(&queue_slg_queue, NULL);
    u64 wend = timeus();

#if D
    formatln("writer_call_queue_slg end");
#endif

    mutex_lock(&rwstat_mtx);
    s->wbegin = wbegin;
    s->wend = wend;
    s->wcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

#if EXPERIMENTAL_LOCKFREE

// DYNAMIC_FIFO
//////////////////////////////////////////////////////////////

threaded_dynamic_fifo dynamic_fifo_queue;// = THREADED_SLL_CW_EMPTY;

static void *reader_call_dynamic_fifo(void *parm)
{
#if D
    formatln("reader_call_dynamic_fifo begin");
#endif

    rwstat *s = (rwstat*)parm;
    u64 rbegin = timeus();
    int i;
    int c = 0;
    int wc = w;
    for(i = 0;; i++)
    {
        msg *m = threaded_dynamic_fifo_dequeue(&dynamic_fifo_queue);
        if(m == NULL)
        {
            if(--wc == 0)
            {
                break;
            }
        }
        msg_free(m);
        c++;
    }
    u64 rend = timeus();
    if(c != (n * w) + w - 1)
    {
        formatln("oops: %i != %i", c, n);
    }

#if D
    formatln("reader_call_dynamic_fifo end");
#endif

    mutex_lock(&rwstat_mtx);
    s->rbegin = rbegin;
    s->rend = rend;
    s->rcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

static void *writer_call_dynamic_fifo(void *parm)
{
#if D
    formatln("writer_call_dynamic_fifo begin");
#endif
    rwstat *s = (rwstat*)parm;
    u64 wbegin = timeus();
    for(int i = 0; i < n; i++)
    {
        threaded_dynamic_fifo_enqueue(&dynamic_fifo_queue, msg_alloc());
    }

    threaded_dynamic_fifo_enqueue(&dynamic_fifo_queue, NULL);
    u64 wend = timeus();

#if D
    formatln("writer_call_dynamic_fifo end");
#endif

    mutex_lock(&rwstat_mtx);
    s->wbegin = wbegin;
    s->wend = wend;
    s->wcount--;
    mutex_unlock(&rwstat_mtx);
    return NULL;
}

#endif

// ALLOC
//////////////////////////////////////////////////////////////

static void alloc_bench()
{
    u64 _4g_fill = 0x100000000 / msg_buffer_size;
    u64 an = MIN(0x400000, _4g_fill);
    formatln("measuring %llu alloc/free", an);
    msg **set = (msg**)malloc(an * sizeof(msg*));
    memset(set, 0, an * sizeof(msg*));
    
    for(int i = 0; i < 4; i++)
    {
        u64 alloc_start = timeus();
        u64 free_start;
        u64 end;
        if(set == NULL)
        {
            formatln("unable to allocated %llu messages", an);
            return;
        }
        for(u64 i = 0; i < an; i++)
        {
            set[i] = msg_alloc();
        }
        free_start = timeus();
        for(u64 i = 0; i < an; i++)
        {
            msg_free(set[i]);
        }
        end = timeus();
        double aps = (ONE_SECOND_US_F * an) / ((double)(free_start - alloc_start));
        double fps = (ONE_SECOND_US_F * an) / ((double)(end - free_start));

        formatln("alloc=%12.6f/s free=%12.6f/s", aps, fps);
    }
    
    free(set);
}

int main(int argc, char *argv[])
{
    puts("[workers [messages [mask [buffer-size [use-zalloc]]]]]");

    if(argc > 1)
    {
        w = atoi(argv[1]);
        if(w <= 0)
        {
            w = W;
        }
        if(argc > 2)
        {
            n = atoi(argv[2]);
            if(n <= 0)
            {
                n = N;
            }
            if( argc > 3)
            {
                mask = atoi(argv[3]);

                if(argc > 4)
                {
                    msg_buffer_size = atoi(argv[4]);

                    if(argc > 5)
                    {
                        use_zalloc = atoi(argv[5]);
                    }
                }
            }
        }
    }
    
    dnscore_init();    
    println("usage: %s [writer-count [insert-count-per-writer [thread-type-mask [message-size] ] ] ]");
    formatln("running with %i %i %i %i", w, n, mask, msg_buffer_size);

    formatln("benching with %i items", n);
    
    if(msg_buffer_size > 0)
    {
        formatln("the queues will be filled by items of %i bytes allocated and deallocated using %s", msg_buffer_size, (use_zalloc)?"z-alloc":"malloc");
    }
    else
    {
        println("the queues will be filled by a constant pointer (void*)1");
    }

    u32 tp_max = thread_pool_get_max_thread_per_pool_limit();
    if(tp_max > 0x80000000)
    {
        formatln("thread_pool_get_max_thread_per_pool_limit() returned something too big for the test (%u)", tp_max);
        exit(EXIT_FAILURE);
    }

    for(u32 i = 0; i <= tp_max * 2; i += 7)
    {
        formatln("testing thread_pool of %u workers", i);

        struct thread_pool_s *tp = thread_pool_init(i, i);

        if(tp != NULL)
        {
            if((i < THREAD_POOL_SIZE_LIMIT_MIN) || (i > tp_max))
            {
                formatln("thread_pool size set to %u and shouldn't have been instanciated", i);
                exit(EXIT_FAILURE);
            }

            u32 real_size = thread_pool_get_size(tp);

            if(real_size != i)
            {
                formatln("thread_pool size set to %u but silently got %u instead", i, real_size);
                exit(EXIT_FAILURE);
            }
/*
            ya_result ret = thread_pool_wait_all_running(tp);

            if(FAIL(ret))
            {
                formatln("thread_pool failed waiting for all %u workers to be running: %r", i, ret);
                exit(EXIT_FAILURE);
            }
*/
            thread_pool_destroy(tp);
            tp = NULL;
        }
        else
        {
            if((i >= THREAD_POOL_SIZE_LIMIT_MIN) && (i <= tp_max))
            {
                formatln("thread_pool size set to %u and should have been instantiated", i);
                exit(EXIT_FAILURE);
            }
        }
    }

    struct thread_pool_s *tp = thread_pool_init(128, 128);

    if(tp == NULL)
    {
        println("tp");
    }
    
    formatln("waiting for all threads to be running");
        
#if 0
    ya_result ret = thread_pool_wait_all_running(tp);

    if(FAIL(ret))
    {
        formatln("oops: %r", ret);
        abort();
    }

    formatln("all %i threads are up and running", ret);
    flushout();
#else
    sleep(1);
    formatln("hopefully all threads are up and running");
    flushout();
#endif
    alloc_bench();
    flushout();
    
    rwstat dll_cw_rwstat;
    ZEROMEMORY(&dll_cw_rwstat, sizeof(rwstat));
    dll_cw_rwstat.name = "dll_cw";
    threaded_dll_cw_init(&dll_cw_queue, MAX_U32);

    rwstat qsl_cw_rwstat;
    ZEROMEMORY(&qsl_cw_rwstat, sizeof(rwstat));
    qsl_cw_rwstat.name = "qsl_cw";
    threaded_qsl_cw_init(&qsl_cw_queue, MAX_U32);

    rwstat ringbuffer_cw_rwstat;
    ZEROMEMORY(&ringbuffer_cw_rwstat, sizeof(rwstat));
    ringbuffer_cw_rwstat.name = "ringbuffer_cw";
    threaded_ringbuffer_cw_init(&ringbuffer_cw_queue, n * w * 2);

    rwstat queue_slg_rwstat;
    ZEROMEMORY(&queue_slg_rwstat, sizeof(rwstat));
    queue_slg_rwstat.name = "queue_slg";
    threaded_queue_slg_init(&queue_slg_queue, 0);

#if EXPERIMENTAL_LOCKFREE
    rwstat dynamic_fifo_rwstat;
    ZEROMEMORY(&dynamic_fifo_rwstat, sizeof(rwstat));
    dynamic_fifo_rwstat.name = "dynamic_fifo_rwstat";
    threaded_dynamic_fifo_init(&dynamic_fifo_queue, n * w * 2);
#endif

    thread_pool_task_counter counter;
    thread_pool_counter_init(&counter, 0);

    if(mask & 1)
    {
        formatln("ringbuffer_cw %T", time(NULL));
        flushout();

        ringbuffer_cw_rwstat.rcount = 1;
        ringbuffer_cw_rwstat.wcount = w;
        thread_pool_enqueue_call(tp, reader_call_ringbuffer_cw, &ringbuffer_cw_rwstat, &counter, "reader");
        for(int i = 0; i < w; i++)
        {
            thread_pool_enqueue_call(tp, writer_call_ringbuffer_cw, &ringbuffer_cw_rwstat, &counter, "writer");
        }

        thread_pool_wait_queue_empty(tp);
        thread_pool_counter_wait_below_or_equal(&counter, 0);
        flushout();
    }

    if(mask & 2)
    {
        formatln("dll_cw %T", time(NULL));
        flushout();

        dll_cw_rwstat.rcount = 1;
        dll_cw_rwstat.wcount = w;
        thread_pool_enqueue_call(tp, reader_call_dll_cw, &dll_cw_rwstat, &counter, "reader");
        for(int i = 0; i < w; i++)
        {
            thread_pool_enqueue_call(tp, writer_call_dll_cw, &dll_cw_rwstat, &counter, "writer");
        }

        thread_pool_wait_queue_empty(tp);
        thread_pool_counter_wait_below_or_equal(&counter, 0);
        flushout();
    }

    if(mask & 4)
    {
        formatln("qsl_cw %T", time(NULL));
        flushout();

        qsl_cw_rwstat.rcount = 1;
        qsl_cw_rwstat.wcount = w;
        thread_pool_enqueue_call(tp, reader_call_qsl_cw, &qsl_cw_rwstat, &counter, "reader");
        for(int i = 0; i < w; i++)
        {
            thread_pool_enqueue_call(tp, writer_call_qsl_cw, &qsl_cw_rwstat, &counter, "writer");
        }

        thread_pool_wait_queue_empty(tp);
        thread_pool_counter_wait_below_or_equal(&counter, 0);
        flushout();
    }

    if(mask & 8)
    {
        formatln("queue_slg %T", time(NULL));
        flushout();

        queue_slg_rwstat.rcount = 1;
        queue_slg_rwstat.wcount = w;
        thread_pool_enqueue_call(tp, reader_call_queue_slg, &queue_slg_rwstat, &counter, "reader");
        for(int i = 0; i < w; i++)
        {
            thread_pool_enqueue_call(tp, writer_call_queue_slg, &queue_slg_rwstat, &counter, "writer");
        }

        thread_pool_wait_queue_empty(tp);
        thread_pool_counter_wait_below_or_equal(&counter, 0);
        flushout();
    }

#if EXPERIMENTAL_LOCKFREE

    if(mask & 16)
    {
        formatln("dynamic_fifo %T", time(NULL));
        flushout();

        dynamic_fifo_rwstat.rcount = 1;
        dynamic_fifo_rwstat.wcount = w;
        thread_pool_enqueue_call(tp, reader_call_dynamic_fifo, &dynamic_fifo_rwstat, &counter, "reader");
        for(int i = 0; i < w; i++)
        {
            thread_pool_enqueue_call(tp, writer_call_dynamic_fifo, &dynamic_fifo_rwstat, &counter, "writer");
        }

        thread_pool_wait_queue_empty(tp);
        thread_pool_counter_wait_below_or_equal(&counter, 0);
        flushout();
    }
#endif

    for(;;)
    {
        mutex_lock(&rwstat_mtx);
        int r = 0;
        r += dll_cw_rwstat.rcount + dll_cw_rwstat.wcount;
        r += ringbuffer_cw_rwstat.rcount + ringbuffer_cw_rwstat.wcount;
        mutex_unlock(&rwstat_mtx);
        if(r <= 0)
        {
            break;
        }
        sleep(1);
    }

    thread_pool_destroy(tp);
    tp = NULL;
    threaded_ringbuffer_cw_finalize(&ringbuffer_cw_queue);
    threaded_dll_cw_finalize(&dll_cw_queue);
    threaded_qsl_cw_finalize(&qsl_cw_queue);
#if EXPERIMENTAL_LOCKFREE
    threaded_dynamic_fifo_finalize(&dynamic_fifo_queue);
#endif
    rwstat_print(&ringbuffer_cw_rwstat);
    rwstat_print(&dll_cw_rwstat);
    rwstat_print(&qsl_cw_rwstat);
    rwstat_print(&queue_slg_rwstat);
#if EXPERIMENTAL_LOCKFREE
    rwstat_print(&dynamic_fifo_rwstat);
#endif

    flushout();
    flusherr();

    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
