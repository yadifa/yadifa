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
#include <dnscore/chroot.h>
#include <sys/stat.h>

#define CHROOT_TEST_DIR          "/tmp/chroot-test"
#define CHROOT_TEST_DIR_TRAILING "/tmp/chroot-test/"
#define CHROOT_TEST_FILE         CHROOT_TEST_DIR "/sample.bin"

static void init()
{
    dnscore_init();

    yatest_mkdir(CHROOT_TEST_DIR);

    FILE *f = fopen(CHROOT_TEST_FILE, "w+");
    fputs(yatest_lorem_ipsum, f);
    fclose(f);
}

static int simple_test()
{
    int ret;
    init();
    ret = chroot_set_path(CHROOT_TEST_DIR);
    if(FAIL(ret))
    {
        yatest_err("chroot_set_path failed with %s", error_gettext(ret));
        return 1;
    }
    char *managed_location = strdup(CHROOT_TEST_FILE);
    ret = chroot_manage_path(&managed_location, CHROOT_TEST_DIR, true);
    if(FAIL(ret))
    {
        yatest_err("chroot_manage_path failed with %s", error_gettext(ret));
        return 1;
    }
    ret = chroot_jail();
    if(FAIL(ret))
    {
        if(ret != MAKE_ERRNO_ERROR(EPERM))
        {
            yatest_err("chroot_jail failed with %s", error_gettext(ret));
            return 1;
        }
        else
        {
            yatest_log("chroot_jail insufficient privileges to proceed");
            chroot_unmanage_all();
            return 0;
        }
    }
    return 0;
}

static int trailing_test()
{
    int ret;
    init();
    ret = chroot_set_path(CHROOT_TEST_DIR_TRAILING);
    if(FAIL(ret))
    {
        yatest_err("chroot_set_path failed with %s", error_gettext(ret));
        return 1;
    }
    char *managed_location = strdup(CHROOT_TEST_FILE);
    ret = chroot_manage_path(&managed_location, CHROOT_TEST_DIR_TRAILING, true);
    if(FAIL(ret))
    {
        yatest_err("chroot_manage_path failed with %s", error_gettext(ret));
        return 1;
    }
    ret = chroot_jail();
    if(FAIL(ret))
    {
        if(ret != MAKE_ERRNO_ERROR(EPERM))
        {
            yatest_err("chroot_jail failed with %s", error_gettext(ret));
            return 1;
        }
        else
        {
            yatest_log("chroot_jail insufficient privileges to proceed");
            chroot_unmanage_path(&managed_location);
            return 0;
        }
    }
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(simple_test)
YATEST(trailing_test)
YATEST_TABLE_END
