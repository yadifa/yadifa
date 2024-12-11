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
#include <dnscore/dnscore.h>
#include <dnscore/error_state.h>

logger_handle_t     *g_test_logger = LOGGER_HANDLE_SINK;
static error_state_t es = ERROR_STATE_INITIALIZER;

static void          init()
{
    dnscore_init();
    logger_init();
    logger_start();
    logger_handle_create("system", &g_system_logger);
    logger_handle_create("database", &g_test_logger);
}

static void finalise() { dnscore_finalize(); }

static int  error_state_test()
{
    init();
    error_state_log(&es, PARSESTRING_ERROR);
    error_state_log(&es, PARSESTRING_ERROR);
    error_state_clear(&es, g_test_logger, 0, "error_state_clear");
    yatest_sleep((ERROR_STATE_FAILURE_LOG_PERIOD / ONE_SECOND_US) + 10);
    error_state_clear(&es, g_test_logger, 0, "error_state_clear");
    error_state_log(&es, PARSESTRING_ERROR);
    yatest_sleep((ERROR_STATE_FAILURE_LOG_PERIOD / ONE_SECOND_US) + 10);
    error_state_log(&es, PARSESTRING_ERROR);
    yatest_sleep((ERROR_STATE_FAILURE_LOG_PERIOD / ONE_SECOND_US) + 10);
    error_state_clear(&es, g_test_logger, 0, "error_state_clear");
    finalise();
    return 0;
}

static int error_state_locked_test()
{
    init();
    error_state_log_locked(&es, PARSESTRING_ERROR);
    error_state_log_locked(&es, PARSESTRING_ERROR);
    error_state_clear_locked(&es, g_test_logger, 0, "error_state_clear");
    error_state_clear_locked(&es, g_test_logger, 0, "error_state_clear");
    error_state_log_locked(&es, PARSESTRING_ERROR);
    error_state_log_locked(&es, PARSESTRING_ERROR);
    error_state_clear_locked(&es, g_test_logger, 0, "error_state_clear");
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(error_state_test)
YATEST(error_state_locked_test)
YATEST_TABLE_END
