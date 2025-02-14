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

#include "yatest.h"
#include "dnscore/format.h"
#include <dnscore/dnscore.h>
#include <dnscore/alarm.h>
#include <inttypes.h>
#include <time.h>

#define ALARM_TEST_ARBIRARTY_KEY 0
#define ALARM_TEST_COUNT         10
#define ALARM_HANDLE_COUNT       10
#define ALARM_REARM_LIMIT        3

struct alarm_test_s
{
    time_t             now;
    time_t             delay;
    volatile uint64_t *counterp;
    volatile uint64_t *maskp;
    int64_t            position;
    int64_t            replace_mode;
};

typedef struct alarm_test_s alarm_test_t;

struct alarm_rearm_s
{
    time_t             now;
    time_t             delay;
    volatile uint64_t *counterp;
    volatile uint64_t *maskp;
    int64_t            count;
    int64_t            limit;
};

typedef struct alarm_rearm_s alarm_rearm_t;

static int                   alarm_callback_return_code = 0;

static ya_result             alarm_test_callback(void *myargs_, bool cancel)
{
    alarm_test_t *myargs = (alarm_test_t *)myargs_;
    time_t        now = time(NULL);
    time_t        real_delay = now - myargs->now;
    yatest_log("alarm: now=%" PRIi64 ", delay=%" PRIi64 ", real=%" PRIi64 ", *counterp=%" PRIi64 ", *maskp=%08" PRIx64 ", position=%" PRIi64 ", cancel=%i",
               myargs->now,
               myargs->delay,
               real_delay,
               *myargs->counterp,
               *myargs->maskp,
               myargs->position,
               cancel);

    if(myargs->replace_mode >= 0)
    {
        switch(myargs->replace_mode)
        {
            case ALARM_DUP_NOP:
            {
                if(cancel)
                {
                    yatest_log("alarm replaced in ALARM_DUP_NOP");
                    alarm_callback_return_code |= 1;
                }
                break;
            }
            case ALARM_DUP_REMOVE_EARLIER:
            {
                if(!cancel) // we will run this alarm
                {
                    if(myargs->position != ALARM_TEST_COUNT - 1)
                    {
                        yatest_log("wrong alarm kept in ALARM_DUP_REMOVE_EARLIER (%" PRIi64 " instead of %" PRIi64 ")", myargs->position, ALARM_TEST_COUNT - 1);
                        alarm_callback_return_code |= 1;
                    }
                }
                else // we are cancelling this alarm
                {
                    if(myargs->position == ALARM_TEST_COUNT - 1)
                    {
                        yatest_log("wrong alarm replaced in ALARM_DUP_REMOVE_EARLIER (%" PRIi64 " instead of anything but %" PRIi64 ")", myargs->position, 0);
                        alarm_callback_return_code |= 1;
                    }
                }
                break;
            }
            case ALARM_DUP_REMOVE_LATEST:
            {
                if(!cancel) // we will run this alarm
                {
                    if(myargs->position != 0)
                    {
                        yatest_log("wrong alarm kept in ALARM_DUP_REMOVE_LATEST (%" PRIi64 " instead of %" PRIi64 ")", myargs->position, 0);
                        alarm_callback_return_code |= 1;
                    }
                }
                else // we are cancelling this alarm
                {
                    if(myargs->position == 0)
                    {
                        yatest_log("wrong alarm replaced in ALARM_DUP_REMOVE_LATEST (%" PRIi64 " instead of anything but %" PRIi64 ")", myargs->position, 0);
                        alarm_callback_return_code |= 1;
                    }
                }
                break;
            }
            default:
            {
                yatest_log("bug in the test, wrong replace_mode value");
                alarm_callback_return_code |= 1;
            }
        }
    }

    if(!cancel)
    {
        (*myargs->counterp)++;
        (*myargs->maskp) |= 1 << myargs->delay;
    }
    free(myargs);
    return SUCCESS;
}

static ya_result alarm_rearm_callback(void *myargs_, bool cancel)
{
    alarm_rearm_t *myargs = (alarm_rearm_t *)myargs_;
    time_t         now = time(NULL);
    time_t         real_delay = now - myargs->now;
    yatest_log("alarm: now=%" PRIi64 ", delay=%" PRIi64 ", real=%" PRIi64 ", *counterp=%" PRIi64 ", *maskp=%08" PRIx64 ", count=%" PRIi64 ", limit=%" PRIi64 ", cancel=%i",
               (int64_t)myargs->now,
               (int64_t)myargs->delay,
               (int64_t)real_delay,
               *myargs->counterp,
               *myargs->maskp,
               myargs->count,
               myargs->limit,
               cancel);

    if(!cancel)
    {
        myargs->count++;

        (*myargs->counterp)++;
        (*myargs->maskp) |= 1 << myargs->delay;
        if(myargs->count < myargs->limit)
        {
            return ALARM_REARM;
        }
        else
        {
            free(myargs);
            return SUCCESS;
        }
    }
    else
    {
        free(myargs);
        return SUCCESS;
    }
}

static ya_result alarm_shutdown_callback(void *myargs_, bool cancel)
{
    (void)myargs_;
    (void)cancel;
    yatest_log("shutdown in an event");
    dnscore_shutdown();
    return SUCCESS;
}

static uint64_t isqrt(uint64_t i)
{
    if(i >= 2)
    {
        uint64_t hi = i / 2;
        uint64_t lo = (hi + i / hi) / 2;

        while(lo < hi)
        {
            hi = lo;
            lo = (hi + i / hi) / 2;
        }
        return hi;
    }
    else
    {
        return i;
    }
}

static bool isprime_naive(uint64_t i)
{
    if(i >= 4)
    {
        if((i & 1) != 0)
        {
            uint64_t limit = isqrt(i);

            for(uint64_t j = 3; j <= limit; j += 2)
            {
                uint64_t a = i / j;
                uint64_t b = a * j;
                if(b == i)
                {
                    return false;
                }
            }

            return true;
        }
        return false;
    }
    else
    {
        return i > 1;
    }
}

static ya_result alarm_slow_callback(void *myargs_, bool cancel)
{
    alarm_test_t *myargs = (alarm_test_t *)myargs_;
    time_t        now = time(NULL);
    time_t        real_delay = now - myargs->now;
    yatest_log("alarm: now=%" PRIi64 ", delay=%" PRIi64 ", real=%" PRIi64 ", *counterp=%" PRIi64 ", *maskp=%08" PRIx64 ", position=%" PRIi64 ", cancel=%i",
               (int64_t)myargs->now,
               (int64_t)myargs->delay,
               (int64_t)real_delay,
               *myargs->counterp,
               *myargs->maskp,
               myargs->position,
               cancel);

    if(!cancel)
    {
        (*myargs->counterp)++;
        (*myargs->maskp) |= 1 << myargs->delay;
        // some slow computation
        isprime_naive(0xff00000000001);
    }
    free(myargs);
    return SUCCESS;
}

static int alarm_simple_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_init(); // to hit the already-initialised else test
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
    {
        alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
        myargs->now = now;
        myargs->delay = delay;
        myargs->counterp = &counter;
        myargs->maskp = &mask;
        myargs->position = 0;
        myargs->replace_mode = -1;
        alarm_event_node_t *event = alarm_event_new( // zone refresh
            now + delay,
            ALARM_TEST_ARBIRARTY_KEY + delay,
            alarm_test_callback,
            myargs,
            ALARM_DUP_REMOVE_LATEST, // in case of key collision
            "batch of alarms");
        alarm_set(ah, event);
    }

    while(time(NULL) < now + 15)
    {
        if(counter == ALARM_TEST_COUNT)
        {
            break;
        }
        sleep(1);
    }

    if(counter != ALARM_TEST_COUNT)
    {
        yatest_err("failed to call every alarm event: %" PRIu64 "/%" PRIu64, counter, ALARM_TEST_COUNT);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_endfirst_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
    {
        alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
        myargs->now = now;
        myargs->delay = delay + 86400;
        myargs->counterp = &counter;
        myargs->maskp = &mask;
        myargs->position = 0;
        myargs->replace_mode = -1;
        alarm_event_node_t *event = alarm_event_new( // zone refresh
            now + delay + 86400,
            ALARM_TEST_ARBIRARTY_KEY + delay,
            alarm_test_callback,
            myargs,
            ALARM_DUP_REMOVE_LATEST, // in case of key collision
            "batch of alarms");
        alarm_set(ah, event);
    }

    while(time(NULL) < now + 2)
    {
        sleep(1);
    }

    if(counter > 0)
    {
        yatest_err("unexpected call of alarm event: %" PRIu64 "/%" PRIu64, counter, ALARM_TEST_COUNT);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_lock_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
    {
        alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
        myargs->now = now;
        myargs->delay = delay;
        myargs->counterp = &counter;
        myargs->maskp = &mask;
        myargs->position = 0;
        myargs->replace_mode = -1;
        alarm_event_node_t *event = alarm_event_new( // zone refresh
            now + delay,
            ALARM_TEST_ARBIRARTY_KEY + delay,
            alarm_test_callback,
            myargs,
            ALARM_DUP_REMOVE_LATEST, // in case of key collision
            "batch of alarms");
        alarm_set(ah, event);
    }

    while(time(NULL) < now + 15)
    {
        if(counter == ALARM_TEST_COUNT)
        {
            break;
        }
        sleep(1);
        alarm_lock();
        alarm_event_node_t *event = alarm_get_first(ah);
        while(event != NULL)
        {
            yatest_log("has event at %" PRIi64 ": %s", event->epoch, event->text);
            event = event->time_next;
        }
        alarm_unlock();
    }

    if(counter != ALARM_TEST_COUNT)
    {
        yatest_err("failed to call every alarm event: %" PRIu64 "/%" PRIu64, counter, ALARM_TEST_COUNT);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_replace_latest_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    int     delay = 10;
    {
        for(int position = 0; position < ALARM_TEST_COUNT; ++position)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now + delay + position;
            myargs->delay = delay + position;
            myargs->counterp = &counter;
            myargs->maskp = &mask;
            myargs->position = position;
            myargs->replace_mode = ALARM_DUP_REMOVE_LATEST;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay + position,
                ALARM_TEST_ARBIRARTY_KEY + delay,
                alarm_test_callback,
                myargs,
                ALARM_DUP_REMOVE_LATEST, // in case of key collision
                "batch of alarms");
            alarm_set(ah, event);
        }
    }

    while(time(NULL) < now + delay + ALARM_TEST_COUNT + 1)
    {
        if(counter != 0)
        {
            break;
        }
        sleep(1);
    }

    yatest_log("counter: %" PRIu64 ", mask=%08x", counter, mask);

    if(counter != 1)
    {
        yatest_err("failed to call alarm event only once: %" PRIu64, counter);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_replace_latest_reverse_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    int     delay = 10;
    {
        for(int position = 0; position < ALARM_TEST_COUNT; ++position)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now + delay + ALARM_TEST_COUNT - 1 - position;
            myargs->delay = delay + ALARM_TEST_COUNT - 1 - position;
            myargs->counterp = &counter;
            myargs->maskp = &mask;
            myargs->position = ALARM_TEST_COUNT - 1 - position;
            myargs->replace_mode = ALARM_DUP_REMOVE_LATEST;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay + ALARM_TEST_COUNT - 1 - position,
                ALARM_TEST_ARBIRARTY_KEY + delay,
                alarm_test_callback,
                myargs,
                ALARM_DUP_REMOVE_LATEST, // in case of key collision
                "batch of alarms");
            alarm_set(ah, event);
        }
    }

    while(time(NULL) < now + delay + ALARM_TEST_COUNT + 1)
    {
        if(counter != 0)
        {
            break;
        }
        sleep(1);
    }

    yatest_log("counter: %" PRIu64 ", mask=%08x", counter, mask);

    if(counter != 1)
    {
        yatest_err("failed to call alarm event only once: %" PRIu64, counter);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_replace_earlier_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    int     delay = 10;
    {
        for(int position = 0; position < ALARM_TEST_COUNT; ++position)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now + delay + position;
            myargs->delay = delay + position;
            myargs->counterp = &counter;
            myargs->maskp = &mask;
            myargs->position = position;
            myargs->replace_mode = ALARM_DUP_REMOVE_EARLIER;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay + position,
                ALARM_TEST_ARBIRARTY_KEY + delay,
                alarm_test_callback,
                myargs,
                ALARM_DUP_REMOVE_EARLIER, // in case of key collision
                "batch of alarms");
            alarm_set(ah, event);
        }
    }

    while(time(NULL) < now + delay + ALARM_TEST_COUNT + 1)
    {
        if(counter != 0)
        {
            break;
        }
        sleep(1);
    }

    yatest_log("counter: %" PRIu64 ", mask=%08x", counter, mask);

    if(counter != 1)
    {
        yatest_err("failed to call alarm event only once: %" PRIu64, counter);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_replace_earlier_reverse_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    int     delay = 10;
    {
        for(int position = 0; position < ALARM_TEST_COUNT; ++position)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now + delay + ALARM_TEST_COUNT - 1 - position;
            myargs->delay = delay + ALARM_TEST_COUNT - 1 - position;
            myargs->counterp = &counter;
            myargs->maskp = &mask;
            myargs->position = ALARM_TEST_COUNT - 1 - position;
            myargs->replace_mode = ALARM_DUP_REMOVE_EARLIER;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay + ALARM_TEST_COUNT - 1 - position,
                ALARM_TEST_ARBIRARTY_KEY + delay,
                alarm_test_callback,
                myargs,
                ALARM_DUP_REMOVE_EARLIER, // in case of key collision
                "batch of alarms");
            alarm_set(ah, event);
        }
    }

    while(time(NULL) < now + delay + ALARM_TEST_COUNT + 1)
    {
        if(counter != 0)
        {
            break;
        }
        sleep(1);
    }

    yatest_log("counter: %" PRIu64 ", mask=%08x", counter, mask);

    if(counter != 1)
    {
        yatest_err("failed to call alarm event only once: %" PRIu64, counter);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_dup_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    int     delay = 10;
    {
        for(int position = 0; position < ALARM_TEST_COUNT; ++position)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now;
            myargs->delay = delay;
            myargs->counterp = &counter;
            myargs->maskp = &mask;
            myargs->position = position;
            myargs->replace_mode = ALARM_DUP_NOP;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay,
                ALARM_TEST_ARBIRARTY_KEY + delay,
                alarm_test_callback,
                myargs,
                ALARM_DUP_NOP, // in case of key collision
                "batch of alarms");
            alarm_set(ah, event);
        }
    }

    while(time(NULL) < now + delay + 5)
    {
        if(counter != 0)
        {
            break;
        }
        sleep(1);
    }

    yatest_log("counter: %" PRIu64 ", mask=%08x", counter, mask);

    if(counter != ALARM_TEST_COUNT)
    {
        yatest_err("failed to call every alarm event: %" PRIu64 "/%" PRIu64, counter, ALARM_TEST_COUNT);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

// because in the current implementation the alarm handle name has to be a constant in a fixed place in memory.
static uint8_t alarm_cleanup_test_name[ALARM_HANDLE_COUNT][32];

volatile uint64_t alarm_cleanup_test_counter = 0;
volatile uint64_t alarm_cleanup_test_mask = 0;

// alarm_cleanup_test

static int alarm_cleanup_test()
{
    dnscore_init();
    alarm_t aha[ALARM_HANDLE_COUNT];
    for(int alarm_handle_index = 0; alarm_handle_index < ALARM_HANDLE_COUNT; ++alarm_handle_index)
    {
        char name_buffer[32];
        snformat(name_buffer, sizeof(name_buffer), "alarm-test-%i", alarm_handle_index);
        cstr_to_dnsname(alarm_cleanup_test_name[alarm_handle_index], name_buffer);
        aha[alarm_handle_index] = alarm_open(alarm_cleanup_test_name[alarm_handle_index]);
    }

    time_t now = time(NULL);

    for(int alarm_handle_index = 0; alarm_handle_index < ALARM_HANDLE_COUNT; ++alarm_handle_index)
    {
        for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
        {
            alarm_rearm_t *myargs = (alarm_rearm_t*)malloc(sizeof(alarm_rearm_t));
            myargs->now = now;
            myargs->delay = delay;
            myargs->counterp = &alarm_cleanup_test_counter;
            myargs->maskp = &alarm_cleanup_test_mask;
            myargs->count = 0;
            myargs->limit = ALARM_REARM_LIMIT;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now,
                ALARM_TEST_ARBIRARTY_KEY + delay,
                alarm_rearm_callback,
                myargs,
                ALARM_DUP_REMOVE_LATEST, // in case of key collision
                "batch of alarms");
            alarm_set(aha[alarm_handle_index], event);
        }

        for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now + delay;
            myargs->delay = delay;
            myargs->counterp = &alarm_cleanup_test_counter;
            myargs->maskp = &alarm_cleanup_test_mask;
            myargs->position = 0;
            myargs->replace_mode = -1;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay,
                ALARM_TEST_ARBIRARTY_KEY + delay + alarm_handle_index * ALARM_HANDLE_COUNT,
                alarm_slow_callback,
                myargs,
                ALARM_DUP_REMOVE_LATEST, // in case of key collision
                "batch of alarms");
            alarm_set(aha[alarm_handle_index], event);
        }

        for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now + delay * 86400;
            myargs->delay = delay;
            myargs->counterp = &alarm_cleanup_test_counter;
            myargs->maskp = &alarm_cleanup_test_mask;
            myargs->position = 0;
            myargs->replace_mode = -1;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay * 86400,
                ALARM_TEST_ARBIRARTY_KEY + delay + alarm_handle_index * ALARM_HANDLE_COUNT,
                alarm_test_callback,
                myargs,
                ALARM_DUP_REMOVE_LATEST, // in case of key collision
                "batch of alarms");
            alarm_set(aha[alarm_handle_index], event);
        }
    }

    while(time(NULL) < now + 5)
    {
        if(alarm_cleanup_test_counter == ALARM_TEST_COUNT * ALARM_HANDLE_COUNT)
        {
            break;
        }
        sleep(1);
    }

    // do NOT close the alarms as it's part of the test

    return alarm_callback_return_code;
}

static int alarm_shutdown_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t aha[ALARM_HANDLE_COUNT];
    for(int alarm_handle_index = 0; alarm_handle_index < ALARM_HANDLE_COUNT; ++alarm_handle_index)
    {
        char name_buffer[32];
        snformat(name_buffer, sizeof(name_buffer), "alarm-test-%i", alarm_handle_index);
        cstr_to_dnsname(alarm_cleanup_test_name[alarm_handle_index], name_buffer);
        aha[alarm_handle_index] = alarm_open(alarm_cleanup_test_name[alarm_handle_index]);
    }

    time_t now = time(NULL);

    for(int alarm_handle_index = 0; alarm_handle_index < ALARM_HANDLE_COUNT; ++alarm_handle_index)
    {
        for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
        {
            alarm_rearm_t *myargs = (alarm_rearm_t *)malloc(sizeof(alarm_rearm_t));
            myargs->now = now;
            myargs->delay = delay;
            myargs->counterp = &counter;
            myargs->maskp = &mask;
            myargs->count = 0;
            myargs->limit = ALARM_REARM_LIMIT;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now,
                ALARM_TEST_ARBIRARTY_KEY + delay,
                alarm_rearm_callback,
                myargs,
                ALARM_DUP_REMOVE_LATEST, // in case of key collision
                "batch of alarms");
            alarm_set(aha[alarm_handle_index], event);
        }

        for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now + delay;
            myargs->delay = delay;
            myargs->counterp = &counter;
            myargs->maskp = &mask;
            myargs->position = 0;
            myargs->replace_mode = -1;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay,
                ALARM_TEST_ARBIRARTY_KEY + delay + alarm_handle_index * ALARM_HANDLE_COUNT,
                alarm_slow_callback,
                myargs,
                ALARM_DUP_REMOVE_LATEST, // in case of key collision
                "batch of alarms");
            alarm_set(aha[alarm_handle_index], event);
        }

        for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
        {
            alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
            myargs->now = now + delay * 86400;
            myargs->delay = delay;
            myargs->counterp = &counter;
            myargs->maskp = &mask;
            myargs->position = 0;
            myargs->replace_mode = -1;
            alarm_event_node_t *event = alarm_event_new( // zone refresh
                now + delay * 86400,
                ALARM_TEST_ARBIRARTY_KEY + delay + alarm_handle_index * ALARM_HANDLE_COUNT,
                alarm_test_callback,
                myargs,
                ALARM_DUP_REMOVE_LATEST, // in case of key collision
                "batch of alarms");
            alarm_set(aha[alarm_handle_index], event);
        }
    }

    // to start a shutdown during an alarm event

    {
        int                 delay = 5;
        alarm_event_node_t *event = alarm_event_new( // zone refresh
            now + delay,
            UINT16_MAX,
            alarm_shutdown_callback,
            NULL,
            ALARM_DUP_REMOVE_LATEST, // in case of key collision
            "shutdown alarm");
        alarm_set(aha[0], event);
    }

    yatest_log("waiting");

    while(time(NULL) < now + 15)
    {
        if(counter == ALARM_TEST_COUNT * ALARM_HANDLE_COUNT)
        {
            break;
        }
        sleep(1);
    }

    yatest_log("done waiting");

    // do NOT close the alarms as it's part of the test

    return alarm_callback_return_code;
}

static int alarm_epoch0_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
    {
        alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
        myargs->now = now;
        myargs->delay = delay;
        myargs->counterp = &counter;
        myargs->maskp = &mask;
        myargs->position = 0;
        myargs->replace_mode = -1;
        alarm_event_node_t *event = alarm_event_new( // zone refresh
            0,
            ALARM_TEST_ARBIRARTY_KEY + delay,
            alarm_test_callback,
            myargs,
            ALARM_DUP_REMOVE_LATEST, // in case of key collision
            "batch of alarms");
        alarm_set(ah, event);
    }

    while(time(NULL) < now + 5)
    {
        if(counter == ALARM_TEST_COUNT)
        {
            break;
        }
        sleep(1);
    }

    if(counter != ALARM_TEST_COUNT)
    {
        yatest_err("failed to call every alarm event: %" PRIu64 "/%" PRIu64, counter, ALARM_TEST_COUNT);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_doomsday_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
    {
        alarm_test_t *myargs = (alarm_test_t *)malloc(sizeof(alarm_test_t));
        myargs->now = now;
        myargs->delay = delay;
        myargs->counterp = &counter;
        myargs->maskp = &mask;
        myargs->position = 0;
        myargs->replace_mode = -1;
        alarm_event_node_t *event = alarm_event_new( // zone refresh
            UINT32_MAX,
            ALARM_TEST_ARBIRARTY_KEY + delay,
            alarm_test_callback,
            myargs,
            ALARM_DUP_REMOVE_LATEST, // in case of key collision
            "batch of alarms");
        alarm_set(ah, event);
    }

    while(time(NULL) < now + 5)
    {
        if(counter == ALARM_TEST_COUNT)
        {
            break;
        }
        sleep(1);
    }

    if(counter > 0)
    {
        yatest_err("unexpected call to at least one alarm event: %" PRIu64 "/%" PRIu64, counter, ALARM_TEST_COUNT);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_rearm_test()
{
    volatile uint64_t counter = 0;
    volatile uint64_t mask = 0;
    dnscore_init();
    alarm_t ah = alarm_open((const uint8_t *)"\012alarm-test");

    time_t  now = time(NULL);

    for(time_t delay = 0; delay < ALARM_TEST_COUNT; ++delay)
    {
        alarm_rearm_t *myargs = (alarm_rearm_t*)malloc(sizeof(alarm_rearm_t));
        myargs->now = now;
        myargs->delay = delay;
        myargs->counterp = &counter;
        myargs->maskp = &mask;
        myargs->count = 0;
        myargs->limit = ALARM_REARM_LIMIT;
        alarm_event_node_t *event = alarm_event_new( // zone refresh
            now,
            ALARM_TEST_ARBIRARTY_KEY + delay,
            alarm_rearm_callback,
            myargs,
            ALARM_DUP_REMOVE_LATEST, // in case of key collision
            "batch of alarms");
        alarm_set(ah, event);
    }

    while(time(NULL) < now + 5 * (ALARM_REARM_LIMIT + 2))
    {
        if(counter == ALARM_TEST_COUNT * ALARM_REARM_LIMIT)
        {
            break;
        }
        sleep(1);
    }

    if(counter != ALARM_TEST_COUNT * ALARM_REARM_LIMIT)
    {
        yatest_err("failed to call every alarm event: %" PRIu64 "/%" PRIu64, counter, ALARM_TEST_COUNT);
        return 1;
    }

    alarm_close(ah);
    return alarm_callback_return_code;
}

static int alarm_invalid_test()
{
    alarm_set(ALARM_HANDLE_INVALID, NULL);
    alarm_set((alarm_t)0, NULL);
    alarm_set((alarm_t)1, NULL);

    alarm_close(ALARM_HANDLE_INVALID);
    alarm_close((alarm_t)0);
    alarm_close((alarm_t)1);
    alarm_close((alarm_t)alarm_callback_return_code);
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(alarm_simple_test)
YATEST(alarm_endfirst_test)
YATEST(alarm_lock_test)
YATEST(alarm_replace_earlier_test)
YATEST(alarm_replace_earlier_reverse_test)
YATEST(alarm_replace_latest_test)
YATEST(alarm_replace_latest_reverse_test)
YATEST(alarm_dup_test)
YATEST(alarm_cleanup_test)
YATEST(alarm_shutdown_test)
YATEST(alarm_epoch0_test)
YATEST(alarm_doomsday_test)
YATEST(alarm_rearm_test)
YATEST(alarm_invalid_test)
YATEST_TABLE_END
