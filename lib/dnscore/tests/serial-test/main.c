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
#include <dnscore/serial.h>

static int serial_test()
{
    uint32_t a = 0x10000000;
    uint32_t b = 0x90000000;
    uint32_t c = 0x8fffffff;
    // b - a > 0x7fffffff
    bool gt = serial_gt(a, b);
    bool lt = serial_lt(a, b);
    bool ge = serial_ge(a, b);
    bool le = serial_le(a, b);

    if(!(!gt & !lt & !ge & !le))
    {
        yatest_err("a b comparison error (undefined case)");
        return 1;
    }

    gt = serial_gt(a, c);
    lt = serial_lt(a, c);
    ge = serial_ge(a, c);
    le = serial_le(a, c);

    if(!(!gt & lt & !ge & le))
    {
        yatest_err("a c comparison error");
        return 1;
    }

    gt = serial_gt(a, a);
    lt = serial_lt(a, a);
    ge = serial_ge(a, a);
    le = serial_le(a, a);

    if(!(!gt & !lt & ge & le))
    {
        yatest_err("a a comparison error");
        return 1;
    }

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(serial_test)
YATEST_TABLE_END
