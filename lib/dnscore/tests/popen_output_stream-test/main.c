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
#include "dnscore/fdtools.h"

#include <dnscore/dnscore.h>
#include <dnscore/popen_output_stream.h>

static int write_test()
{
    int                            ret;
    output_stream_t                os;
    popen_output_stream_parameters params;
    dnscore_init();
    ZEROMEMORY(&params, sizeof(popen_output_stream_parameters));
    params.uid = getuid();
    params.gid = getgid();
    char *command = NULL;
    if(file_exists("/usr/bin/cat"))
    {
        command = "/usr/bin/cat > /dev/null";
    }
    else if(file_exists("/bin/cat"))
    {
        command = "/bin/cat > /dev/null";
    }
    else
    {
        yatest_err("could not find 'cat' command");
        exit(1);
    }

    ret = popen_output_stream_ex(&os, command, &params);
    if(FAIL(ret))
    {
        yatest_err("popen_output_stream_ex failed with %s", error_gettext(ret));
        return 1;
    }
    for(int i = 0; i < 65536; ++i)
    {
        output_stream_write_u8(&os, i);
    }
    output_stream_flush(&os);
    output_stream_close(&os);
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(write_test)
YATEST_TABLE_END
