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

#include "yatest.h"
#include "yatest_stream.h"
#include "dnscore/format.h"
#include <dnscore/dnscore.h>
#include <dnscore/config_settings.h>
#include <dnscore/logger.h>

logger_handle_t *g_test_logger = LOGGER_HANDLE_SINK;

#define TEST_DIR "/tmp/config_logger-test"

static const char logger_conf[] =
    "<channels>\n"
    "#       name        stream-name     arguments\n"
    "system      system.log      0644\n"
    "test        test.log        0644\n"
    "all         all.log         0644\n"
    "\n"
    "syslog      syslog          USER,CRON,PID\n"
    "\n"
    "# It is to be noted that the command will be run even if no logger is bound to it.\n"
    "# gzip-log    \"|/usr/bin/gzip - >> /var/log/yadifa/yadifa.log.gz\"\n"
    "\n"
    "# although possible, these two will end up writing to /dev/null if daemon is enabled\n"
    "    stderr      STDERR\n"
    "    stdout      STDOUT\n"
    "    </channels>\n"
    "\n"
    "# Logging input configurations\n"
    "#\n"
    "# name debug-level channels\n"
    "#\n"
    "# name          is predefined\n"
    "# debuglevel    uses the same names as syslog or * or all to filter the input\n"
    "# channels      is a comma-separated list of channels\n"
    "\n"
    "# In production, use EMERG,ALERT,CRIT,ERR,WARNING,NOTICE,INFO instead of *\n"
    "\n"
    "<loggers>\n"
    "#       bundle          debuglevel                          channels\n"
    "    system          prod                                system,all\n"
    "test prod test,all,stdout,stderr\n"
    "    </loggers>\n"
    "\n";

static const char logger_syslog_error_conf[] =
    "<channels>\n"
    "syslog syslog not-a-keyword\n"
    "</channels>\n"
    "<loggers>\n"
    "test prod syslog\n"
    "</loggers>\n"
    "\n";

static const char logger_pipe_conf[] =
    "<channels>\n"
    "pipe-log    \"|/usr/bin/gzip - >> " TEST_DIR
    "/pipe.log.gz\"\n"
    "</channels>\n"
    "<loggers>\n"
    "test prod pipe-log\n"
    "</loggers>\n"
    "\n";

static const char logger_pipe_error_conf[] =
    "<channels>\n"
    "pipe-log    \"|/usr/bin/does-not-exist - >> " TEST_DIR
    "/pipe.log.gz\"\n"
    "</channels>\n"
    "<loggers>\n"
    "test prod pipe-log\n"
    "</loggers>\n"
    "\n";

static void init()
{
    int ret;
    dnscore_init();
    config_init();
    yatest_mkdir(TEST_DIR);

    logger_init();
    logger_start();
    logger_handle_create("system", &g_system_logger);
    logger_handle_create("database", &g_test_logger);

    int priority = -1; // -1 forces the logger to assume 0 (coverage of 1 line)

    if(FAIL(ret = config_register_logger(NULL, NULL, priority))) // 5 & 6
    {
        yatest_err("config_register_logger failed with %s", error_gettext(ret));
        exit(1);
    }

    if(g_test_logger == &LOGGER_HANDLE_SINK_)
    {
        yatest_err("config_register_logger failed to setup the 'test' logger");
        exit(1);
    }

    if(g_system_logger == &LOGGER_HANDLE_SINK_)
    {
        yatest_err("config_register_logger failed to setup the 'system' logger");
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

    config_set_log_base_path(TEST_DIR);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, logger_conf, sizeof(logger_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        return 1;
    }

    if(!config_logger_isconfigured())
    {
        yatest_err("config_logger_isconfigured expected to return true");
        return 1;
    }
    config_logger_clearconfigured();
    if(config_logger_isconfigured())
    {
        yatest_err("config_logger_isconfigured expected to return false");
        return 1;
    }

    config_print(termout);

    dnscore_finalize();

    return 0;
}

static int already_configured_test()
{
    int ret;
    init();
    // logger_conf
    config_error_t cerr;
    config_error_init(&cerr);

    config_set_log_base_path(TEST_DIR);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, logger_conf, sizeof(logger_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        return 1;
    }

    ret = config_read_from_sources(sources, 1, &cerr);

    if(ret != CONFIG_LOGGER_HANDLE_ALREADY_DEFINED)
    {
        yatest_err("config_read_from_sources expected to fail with CONFIG_LOGGER_HANDLE_ALREADY_DEFINED, got %08x", ret);
        return 1;
    }

    dnscore_finalize();

    return 0;
}

static int syslog_error_test()
{
    int ret;
    init();
    // logger_conf
    config_error_t cerr;
    config_error_init(&cerr);

    config_set_log_base_path(TEST_DIR);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, logger_syslog_error_conf, sizeof(logger_syslog_error_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(ret != PARSE_INVALID_ARGUMENT)
    {
        yatest_err("config_read_from_sources expected to fail with PARSE_INVALID_ARGUMENT, got %08x", ret);
        return 1;
    }

    dnscore_finalize();

    return 0;
}

static int pipe_test()
{
    int ret;
    init();
    // logger_conf
    config_error_t cerr;
    config_error_init(&cerr);

    config_set_log_base_path(TEST_DIR);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, logger_pipe_conf, sizeof(logger_pipe_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        return 1;
    }

    dnscore_finalize();

    return 0;
}

static int pipe_error_test()
{
    int ret;
    init();
    // logger_conf
    config_error_t cerr;
    config_error_init(&cerr);

    config_set_log_base_path(TEST_DIR);

    struct config_source_s sources[1];
    config_source_set_buffer(&sources[0], "local", 3, logger_pipe_error_conf, sizeof(logger_pipe_error_conf) - 1);
    ret = config_read_from_sources(sources, 1, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        return 1;
    }

    dnscore_finalize();

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(simple_test)
YATEST(already_configured_test)
YATEST(syslog_error_test)
YATEST(pipe_test)
YATEST(pipe_error_test)
YATEST_TABLE_END
