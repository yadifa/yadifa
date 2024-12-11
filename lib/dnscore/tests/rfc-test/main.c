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
#include <dnscore/rfc.h>

static uint8_t soa_rdata[] = {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 5, 'a', 'd', 'm', 'i', 'n', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 2, 0};

static int     rr_soa_serial_test()
{
    int ret;
    dnscore_init();
    uint32_t ser0;
    uint32_t ser1;
    uint32_t ser2;
    ret = rr_soa_get_serial(soa_rdata, sizeof(soa_rdata), &ser0);
    if(ret < 0)
    {
        yatest_err("rr_soa_get_serial failed (ser0)");
        return 1;
    }
    uint32_t increase = 123456;
    ret = rr_soa_increase_serial(soa_rdata, sizeof(soa_rdata), increase);
    if(ret < 0)
    {
        yatest_err("rr_soa_increase_serial failed");
        return 1;
    }
    ret = rr_soa_get_serial(soa_rdata, sizeof(soa_rdata), &ser1);
    if(ret < 0)
    {
        yatest_err("rr_soa_get_serial failed (ser1)");
        return 1;
    }
    if(ser1 - ser0 != increase)
    {
        yatest_err("unexpected incremented serial value");
        return 1;
    }
    ret = rr_soa_set_serial(soa_rdata, sizeof(soa_rdata), 0);
    if(ret < 0)
    {
        yatest_err("rr_soa_set_serial failed");
        return 1;
    }
    ret = rr_soa_get_serial(soa_rdata, sizeof(soa_rdata), &ser2);
    if(ret < 0)
    {
        yatest_err("rr_soa_get_serial failed (ser2)");
        return 1;
    }
    if(ser2 != 0)
    {
        yatest_err("unexpected serial value");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(rr_soa_serial_test)
YATEST_TABLE_END
