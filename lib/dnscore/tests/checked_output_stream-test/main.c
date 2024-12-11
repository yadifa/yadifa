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

#include <dnscore/dnscore.h>
#include <dnscore/checked_output_stream.h>
#include <dnscore/file_output_stream.h>

static int error_test(int error_code)
{
    int                          ret;
    int32_t                      size = 4096;
    output_stream_t              eos;
    output_stream_t              os;
    checked_output_stream_data_t data;

    dnscore_init();

    yatest_error_output_stream_init(&eos, size / 2, error_code);
    checked_output_stream_init(&os, &eos, &data);

    for(int i = 0; i < size; ++i)
    {
        ret = output_stream_write_u8(&os, i);
        if(FAIL(ret))
        {
            if((i == (size / 2)) && (ret == error_code))
            {
                yatest_log("output_stream_write_u8 failed at position %i with %s (expected)", i, error_gettext(ret));

                ret = checked_output_stream_error(&os);
                if(ret == error_code)
                {
                    output_stream_close(&eos);
                    output_stream_close(&os);
                    return 0;
                }
                else
                {
                    yatest_log("checked_output_stream_error didn't return the right error code: %08x instead of %08x", ret, error_code);
                    return 1;
                }
            }
            else
            {
                yatest_err("output_stream_write_u8 failed at position %i with %s (bad)", i, error_gettext(ret));
                return 1;
            }
        }
    }

    yatest_err("output_stream_write_u8 suceeded (bad)");

    output_stream_close(&eos);
    output_stream_close(&os);

    return 1;
}

static int success_test()
{
    int                          ret;
    uint32_t                     size = 4096;
    output_stream_t              eos;
    output_stream_t              os;
    checked_output_stream_data_t data;

    dnscore_init();

    yatest_error_output_stream_init(&eos, size / 2, 0);
    checked_output_stream_init(&os, &eos, &data);

    if(!checked_output_stream_instance(&os))
    {
        return 1;
    }

    if(checked_output_stream_instance(&eos))
    {
        return 1;
    }

    ret = checked_output_stream_error(&os);
    if(ret != 0)
    {
        yatest_err("success_test failed with %i", ret);
    }
    output_stream_close(&eos);
    output_stream_close(&os);
    return 0;
}

static int enospc_test() { return error_test(MAKE_ERRNO_ERROR(ENOSPC)); }

static int eperm_test() { return error_test(MAKE_ERRNO_ERROR(EPERM)); }

static int eio_test() { return error_test(MAKE_ERRNO_ERROR(EIO)); }

static int efbig_test() { return error_test(MAKE_ERRNO_ERROR(EFBIG)); }

static int edquot_test() { return error_test(MAKE_ERRNO_ERROR(EDQUOT)); }

static int ebadf_test() { return error_test(MAKE_ERRNO_ERROR(EBADF)); }

YATEST_TABLE_BEGIN
YATEST(success_test)
YATEST(enospc_test)
YATEST(eperm_test)
YATEST(eio_test)
YATEST(efbig_test)
YATEST(edquot_test)
YATEST(ebadf_test)
YATEST_TABLE_END
