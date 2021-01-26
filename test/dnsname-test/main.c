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
 * This is a speed test.
 *
 * Character case needs to be very fast but
 * _ the simple "or" formula doesn't work with the extended character set
 * _ the simple sub,or,add formula doesn't work with the full character set
 *
 * So it will probably be done using a lookup table.
 * Each test covers one method, the first one points to the current choosen method.
 *
 * One solution may be better on a different architecture so we may want to try on other CPUs. e.g.: ARM and RISC-V
 *
 */

#include <dnscore/dnscore.h>
#include <ctype.h>
#include <dnscore/format.h>

#define BENCH_LOOPS 100000
#define FQDN_COUNT 12
#define LONG_STRING_SIZE 0x1000000

static char *names[FQDN_COUNT] =
{
    "www.e.eu.",
    "www.eu.eu.",
    "www.ode.eu.",
    "www.code.eu.",
    "www.eurid.eu.",
    "www.yadifa.eu.",
    "www.zorglub.eu.",
    "www.mountain.eu.",
    "www.something.eu.",
    "www.somethingsomething.eu.",
    "www.somethingsomethingelse.eu.",
    "www._#!$*\\0123456789abcdefghijklmnopqrstuvwxyz.eu."
};

static u8 **fqdns = NULL;

static u8 *long_string = NULL;
static size_t long_string_size = 0;
static u8 *long_string_target = NULL;

static void test_cases_prepare()
{
    u8 tmp[MAX_DOMAIN_LENGTH];

    srand(0);

    fqdns = malloc(FQDN_COUNT * FQDN_COUNT * sizeof(u8*));

    if(fqdns == NULL)
    {
        exit(2);
    }

    for(int i = 0; i < FQDN_COUNT; ++i)
    {
        for(int j = 0; j < FQDN_COUNT; ++j)
        {
            cstr_to_dnsname(tmp, names[i]);

            if(j > 0)
            {
                u8 *p = &tmp[0];
                for(u8 n = *p++; n != 0; n = *p++)
                {
                    for(u8 k = 0; k < n; ++k)
                    {
                        if(rand() & 1)
                        {
                            p[k] = tolower(p[k]);
                        }
                        else
                        {
                            p[k] = toupper(p[k]);
                        }
                    }
                }
            }

            fqdns[i * FQDN_COUNT + j] = dnsname_zdup(tmp);
        }
    }

    long_string = malloc(LONG_STRING_SIZE * 2);

    if(long_string == NULL)
    {
        exit(2);
    }

    long_string_target = &long_string[LONG_STRING_SIZE];

    for(int i = 0; i < LONG_STRING_SIZE; ++i)
    {
        long_string[i] = (u8)rand();
    }
    long_string[LONG_STRING_SIZE - 1] = '\0';
    long_string_size = LONG_STRING_SIZE;
}

static void test_cases_equals()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                if(!dnsname_equals_ignorecase(a, b))
                {
                    formatln("failed to equate %{dnsname} and %{dnsname}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_cases_equals : time: %lli", stop - start);
}

static void test_cases_equals1()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                if(!dnsname_equals_ignorecase1(a, b))
                {
                    formatln("failed to equate %{dnsname} and %{dnsname}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_cases_equals1: time: %lli", stop - start);
}


static void test_cases_equals2()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                if(!dnsname_equals_ignorecase2(a, b))
                {
                    formatln("failed to equate %{dnsname} and %{dnsname}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_cases_equals2: time: %lli", stop - start);
}

static void test_cases_equals3()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                if(!dnsname_equals_ignorecase3(a, b))
                {
                    formatln("failed to equate %{dnsname} and %{dnsname}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_cases_equals3: time: %lli", stop - start);
}

static void test_label_cases_equals()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                a += *a + 1;
                b += *b + 1;
                if(!dnslabel_equals_ignorecase_left(a, b))
                {
                    formatln("failed to equate %{dnslabel} and %{dnslabel}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_label_cases_equal : time: %lli", stop - start);
}

static void test_label_cases_equals1()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                a += *a + 1;
                b += *b + 1;
                if(!dnslabel_equals_ignorecase_left1(a, b))
                {
                    formatln("failed to equate %{dnslabel} and %{dnslabel}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_label_cases_equal1: time: %lli", stop - start);
}

static void test_label_cases_equals2()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                a += *a + 1;
                b += *b + 1;
                if(!dnslabel_equals_ignorecase_left2(a, b))
                {
                    formatln("failed to equate %{dnslabel} and %{dnslabel}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_label_cases_equal2: time: %lli", stop - start);
}

static void test_label_cases_equals3()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                a += *a + 1;
                b += *b + 1;
                if(!dnslabel_equals_ignorecase_left3(a, b))
                {
                    formatln("failed to equate %{dnslabel} and %{dnslabel}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_label_cases_equal3: time: %lli", stop - start);
}

static void test_label_cases_equals4()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                a += *a + 1;
                b += *b + 1;
                if(!dnslabel_equals_ignorecase_left4(a, b))
                {
                    formatln("failed to equate %{dnslabel} and %{dnslabel}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_label_cases_equal4: time: %lli", stop - start);
}

static void test_label_cases_equals5()
{
    s64 start = timeus();

    for(int l = 0; l < BENCH_LOOPS; ++l)
    {
        for(int i = 0; i < FQDN_COUNT; ++i)
        {
            for(int j = 1; j < FQDN_COUNT; ++j)
            {
                u8 *a = fqdns[i * FQDN_COUNT + 0];
                u8 *b = fqdns[i * FQDN_COUNT + j + 0];
                a += *a + 1;
                b += *b + 1;
                if(!dnslabel_equals_ignorecase_left5(a, b))
                {
                    formatln("failed to equate %{dnslabel} and %{dnslabel}", a, b);
                    exit(1);
                }
            }
        }
    }

    s64 stop = timeus();

    formatln("test_label_cases_equal5: time: %lli", stop - start);
}

static void test_string_tolower()
{
    s64 start = timeus();

    for(size_t i = 0; i < long_string_size; ++i)
    {
        long_string_target[i] = LOCASE(long_string[i]);
    }

    s64 stop = timeus();

    formatln("test_string_tolower: time: %lli", stop - start);
}

static void test_string_tolower1()
{
    s64 start = timeus();

    for(size_t i = 0; i < long_string_size; ++i)
    {
        long_string_target[i] = tolower(long_string[i]);
    }

    s64 stop = timeus();

    formatln("test_string_tolower1: time: %lli", stop - start);
}

static void test_string_tolower2()
{
    s64 start = timeus();

    for(size_t i = 0; i < long_string_size; ++i)
    {
        long_string_target[i] = __LOCASE_TABLE__[long_string[i]];
    }

    s64 stop = timeus();

    formatln("test_string_tolower2: time: %lli", stop - start);
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    test_cases_prepare();

    test_cases_equals();
    test_cases_equals();
    test_cases_equals1();
    test_cases_equals1();
    test_cases_equals2();
    test_cases_equals2();
    test_cases_equals3();
    test_cases_equals3();

    test_label_cases_equals();
    test_label_cases_equals();
    test_label_cases_equals1();
    test_label_cases_equals1();
    test_label_cases_equals2();
    test_label_cases_equals2();
    test_label_cases_equals3();
    test_label_cases_equals3();
    test_label_cases_equals4();
    test_label_cases_equals4();
    test_label_cases_equals5();
    test_label_cases_equals5();

    test_string_tolower();
    test_string_tolower();
    test_string_tolower1();
    test_string_tolower1();
    test_string_tolower2();
    test_string_tolower2();

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
