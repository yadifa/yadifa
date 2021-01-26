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

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/limiter.h>
#include <dnscore/format.h>
#include <dnscore/timems.h>

#define MAX_RATE 100000

static u64 give_bandwidth_double(u32 index)
{
    (void)index;
    return MAX_RATE * 2;
}

static u64 give_bandwidth_exact(u32 index)
{
    (void)index;
    return MAX_RATE;
}

static u64 give_bandwidth_half(u32 index)
{
    (void)index;
    return MAX_RATE / 2;
}

static u64 give_bandwidth_onoff(u32 index)
{
    return ((index & 255) == 0)?0:MAX_RATE;
}

static u64 give_bandwidth_random(u32 index)
{
    (void)index;
    return rand() % 200000;
}

static void test_bandwidth(u64 (*giver)(u32))
{
    limiter_t l;
    limiter_init(&l, MAX_RATE);
    
    u64 total = 0;
    u64 start = timeus();
    u64 reported = 0;
    u64 now = start;
    u64 previous = 0;
    u64 min_time = 1000000;
    double min_time_f = 1.0;
        
    for(u32 index = 0; ; ++index)
    {
        u64 amount = giver(index);
        limiter_wait(&l, amount);
        total += amount;
        now = timeus();
        u64 elapsed = now - start;

        min_time_f = (1.0 * min_time) / ONE_SECOND_US_F;
        if(elapsed - reported >= 1000000)
        {
            formatln("time: %9.0fms total: %16llu rate: %9.3llf/s, minimum time between operations: %fs",
                    (1.0 * (elapsed + ONE_SECOND_US_F)) / 1000.0,
                    total,
                    (1.0 * total) / ((1.0 * (elapsed + ONE_SECOND_US_F)) / ONE_SECOND_US_F),
                    min_time_f);
            reported = elapsed;
        }
        
        min_time = MIN(now - previous, min_time);
        previous = now;
        
        if(elapsed > 10000000)
        {
            println("=========================================================");
            formatln("time: %9.0fms total: %16llu rate: %9.3llf/s, minimum time between operations: %fs",
                    (1.0 * elapsed) / 1000.0,
                    total,
                    (1.0 * total) / ((1.0 * elapsed) / ONE_SECOND_US_F),
                    min_time_f);
            println("=========================================================");
            break;
        }
    }
        
    limiter_finalize(&l);
    
    flushout();
}

static void test_rate()
{
    limiter_t l;
    limiter_init(&l, 5);
    
    limiter_set_wait_time(&l, 10000);
    
    u64 total = 0;
    u64 start = timeus();
    u64 reported = 0;
    u64 now = start;
    u64 previous = 0;
    u64 min_time = 1000000;
    double min_time_f = 1.0;
    
    for(u32 index = 0; ; ++index)
    {
        u64 amount = 1;
        limiter_wait(&l, amount);
        total += amount;
        now = timeus();
        u64 elapsed = now - start;

        min_time_f = (1.0 * min_time) / ONE_SECOND_US_F;
        if(elapsed - reported >= 1000000)
        {
            formatln("time: %9.0fms total: %16llu rate: %9.3llf/s, minimum time between operations: %fs",
                    (1.0 * (elapsed + ONE_SECOND_US_F)) / 1000.0,
                    total,
                    (1.0 * total) / ((1.0 * (elapsed + ONE_SECOND_US_F)) / ONE_SECOND_US_F),
                    min_time_f);
            reported = elapsed;
        }
        
        min_time = MIN(now - previous, min_time);
        previous = now;
        
        if(elapsed > 10000000)
        {
            println("=========================================================");
            formatln("time: %9.0fms total: %16llu rate: %9.3llf/s, minimum time between operations: %fs",
                    (1.0 * elapsed) / 1000.0,
                    total,
                    (1.0 * total) / ((1.0 * elapsed) / ONE_SECOND_US_F),
                    min_time_f);
            println("=========================================================");
            break;
        }
        
        usleep(rand() % 50000);
    }
        
    limiter_finalize(&l);
    
    flushout();
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    dnscore_init();
    
    puts("rate test");
    test_rate();
    
    puts("bandwidth test: double maximum");
    test_bandwidth(give_bandwidth_double);
    
    puts("bandwidth test: maximum");
    test_bandwidth(give_bandwidth_exact);
    
    puts("bandwidth test: half maximum");
    test_bandwidth(give_bandwidth_half);
    
    puts("bandwidth test: 0 or maximum");
    test_bandwidth(give_bandwidth_onoff);
    
    puts("bandwidth test: random between 0 and double maximum");
    test_bandwidth(give_bandwidth_random);
    
    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
