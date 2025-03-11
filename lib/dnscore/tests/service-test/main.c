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
#include <dnscore/dnscore.h>
#include <dnscore/service.h>

static struct service_s service = UNINITIALIZED_SERVICE;

static int              sleep_exit(struct service_worker_s *w)
{
    yatest_log("service worker %i/%i started", w->worker_index + 1, w->service->worker_count);
    service_set_servicing(w);
    do
    {
        while(!service_should_reconfigure_or_stop(w))
        {
            yatest_sleep(1);
        }
        if(service_should_reconfigure(w))
        {
            yatest_log("service worker %i/%i reconfiguring", w->worker_index + 1, w->service->worker_count);
            service_clear_reconfigure(w);
            yatest_log("service worker %i/%i reconfigured", w->worker_index + 1, w->service->worker_count);
        }
    } while(service_should_run(w));
    service_set_stopping(w);
    yatest_log("service worker %i/%i stopping", w->worker_index + 1, w->service->worker_count);
    return 0;
}

static int sleep_then_exit(struct service_worker_s *w)
{
    yatest_log("service worker %i/%i started", w->worker_index + 1, w->service->worker_count);
    service_set_servicing(w);
    int countdown = 2;
    while(service_should_run(w))
    {
        yatest_sleep(1);
        if(--countdown <= 0)
        {
            for(int i = 0;; ++i)
            {
                service_worker_t *sibling = service_worker_get_sibling(w, i);
                if(sibling == NULL)
                {
                    break;
                }
                yatest_log("service worker %i/%i sibling %i at %p", w->worker_index + 1, w->service->worker_count, i, sibling);
            }
            break;
        }
    }
    service_set_stopping(w);
    yatest_log("service worker %i/%i stopping", w->worker_index + 1, w->service->worker_count);
    return 0;
}

static void init(int count, service_entry_point_t *ep, service_wakeup_t *w)
{
    dnscore_init();

    int ret;
    if(count < 1)
    {
        count = 1;
    }
    if(ep == NULL)
    {
        ep = sleep_exit;
    }
    if(w != NULL)
    {
        ret = service_init_ex2(&service, ep, w, "test-service", count);
    }
    else if(count > 1)
    {
        ret = service_init_ex(&service, ep, "test-service", count);
    }
    else
    {
        ret = service_init(&service, ep, "test-service");
    }
    if(ret < 0)
    {
        yatest_err("service initialisation failed with %08x = %s", ret, error_gettext(ret));
        exit(1);
    }
}

static void finalise()
{
    service_finalise(&service);
    dnscore_finalize();
}

static int init_finalise_test()
{
    int ret;
    init(0, NULL, NULL);
    ret = service_start(&service);
    if(ret < 0)
    {
        yatest_err("service_start failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ptr_vector_t services;
    ptr_vector_init_empty(&services);
    service_get_all(&services);
    if(ptr_vector_size(&services) != 1)
    {
        yatest_err("service_get_all didn't add one service in the array");
        return 1;
    }
    for(int i = 0; i <= ptr_vector_last_index(&services); ++i)
    {
        service_t *s = ptr_vector_get(&services, i);
        service_args_set(s, s);
        for(int j = 0;; j++)
        {
            service_worker_t *w = service_get_worker(s, j);
            if(w == NULL)
            {
                break;
            }

            yatest_log("service %s worker #%i at %p", service.name, j, w);
        }
        if(service_args_get(s) != s)
        {
            yatest_err("service_args_set/get failed");
            return 1;
        }
    }
    yatest_sleep(2);
    finalise();
    return 0;
}

static int service_start_and_wait_test()
{
    int ret;
    init(4, sleep_then_exit, NULL);
    ret = service_start_and_wait(&service);
    if(ret < 0)
    {
        yatest_err("service_start_and_wait failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int service_start_and_wait_single_test()
{
    int ret;
    init(1, sleep_then_exit, NULL);
    ret = service_start_and_wait(&service);
    if(ret < 0)
    {
        yatest_err("service_start_and_wait failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int service_stop_test()
{
    int ret;
    init(0, NULL, NULL);
    ret = service_start(&service);
    if(ret < 0)
    {
        yatest_err("service_start failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = service_wait_servicing(&service);
    if(ret < 0)
    {
        yatest_err("service_wait_servicing failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(service_check_all_alive(&service) != SUCCESS)
    {
        yatest_err("Unexpected service_check_all_alive result");
        return 1;
    }
    yatest_sleep(2);
    ret = service_stop(&service);
    if(ret < 0)
    {
        yatest_err("service_stop failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    while(!service_stopped(&service))
    {
        usleep(1000);
    }
    finalise();
    return 0;
}

static int service_wait_test()
{
    int ret;
    init(0, sleep_then_exit, NULL);
    ret = service_start(&service);
    if(ret < 0)
    {
        yatest_err("service_start failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    while(!service_servicing(&service))
    {
        usleep(1000);
    }
    ret = service_wait(&service);
    if(ret < 0)
    {
        yatest_err("service_wait failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int service_reconfigure_test()
{
    int ret;
    init(0, NULL, NULL);
    ret = service_start(&service);
    if(ret < 0)
    {
        yatest_err("service_start failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_sleep(2);
    yatest_log("reconfiguring");
    ret = service_reconfigure(&service);
    if(ret < 0)
    {
        yatest_err("service_reconfigure failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    yatest_log("reconfigured");
    yatest_sleep(2);
    ret = service_stop(&service);
    if(ret < 0)
    {
        yatest_err("service_stop failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int service_start_stop_all_test()
{
    int ret;
    init(8, NULL, NULL);
    ret = service_start(&service);
    if(ret < 0)
    {
        yatest_err("service_start failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    while(!service_servicing(&service))
    {
        usleep(1000);
    }
    yatest_log("service_stop_all");
    service_stop_all();
    yatest_log("service_stop_all done");
    yatest_sleep(1);
    yatest_log("service_start_all");
    service_start_all();
    yatest_log("service_start_all done");
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(init_finalise_test)
YATEST(service_start_and_wait_test)
YATEST(service_start_and_wait_single_test)
YATEST(service_stop_test)
YATEST(service_wait_test)
YATEST(service_reconfigure_test)
YATEST(service_start_stop_all_test)
YATEST_TABLE_END
