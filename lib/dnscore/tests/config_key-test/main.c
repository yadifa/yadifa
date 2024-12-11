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
#include "yatest_stream.h"
#include "dnscore/format.h"
#include <dnscore/dnscore.h>
#include <dnscore/config_settings.h>
#include <dnscore/logger.h>

static const char key_conf[] =
    "<key>\n"
    "name        abroad-admin-key\n"
    "algorithm   hmac-md5\n"
    "secret      PleaseChangeThisKey=\n"
    "</key>\n"
    "\n";

static const char key_empty_conf[] =
    "<key>\n"
    "</key>\n"
    "\n";

static const char key_incomplete_conf[] =
    "<key>\n"
    "name        incomplete-key\n"
    "</key>\n"
    "\n";

static const char key_unknown_algorithm_conf[] =
    "<key>\n"
    "name        abroad-admin-key\n"
    "algorithm   not-an-algorithm\n"
    "secret      PleaseChangeThisKey=\n"
    "</key>\n"
    "\n";

static void init()
{
    int ret;
    dnscore_init();
    config_init();

    int priority = -1; // -1 forces the logger to assume 0 (coverage of 1 line)

    if(FAIL(ret = config_register_key(NULL, priority)))
    {
        yatest_err("config_register_key failed with %s", error_gettext(ret));
        exit(1);
    }
}

static int simple_test()
{
    int ret;
    init();
    // logger_conf
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, key_conf, sizeof(key_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        return 1;
    }

    config_print(termout);

    dnscore_finalize();

    return 0;
}

static int empty_test()
{
    int ret;
    init();
    // logger_conf
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, key_empty_conf, sizeof(key_empty_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        return 1;
    }

    dnscore_finalize();

    return 0;
}

static int incomplete_test()
{
    int ret;
    init();
    // logger_conf
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, key_incomplete_conf, sizeof(key_incomplete_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(ret != CONFIG_KEY_INCOMPLETE_KEY)
    {
        yatest_err("config_read_from_sources expected to fail with CONFIG_KEY_INCOMPLETE_KEY (%08x)", ret);
        return 1;
    }

    dnscore_finalize();

    return 0;
}

static int unknown_algorithm_test()
{
    int ret;
    init();
    // logger_conf
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, key_unknown_algorithm_conf, sizeof(key_unknown_algorithm_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(ret != CONFIG_KEY_UNSUPPORTED_ALGORITHM)
    {
        yatest_err("config_read_from_sources expected to fail with CONFIG_KEY_UNSUPPORTED_ALGORITHM (%08x)", ret);
        return 1;
    }

    dnscore_finalize();

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(simple_test)
YATEST(empty_test)
YATEST(incomplete_test)
YATEST(unknown_algorithm_test)
YATEST_TABLE_END
