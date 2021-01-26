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

/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "dnsdb/dnsdb-config.h"

#include <dnscore/packet_reader.h>
#include <dnscore/format.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/xfr_input_stream.h>
#include <dnscore/logger.h>

#include "dnsdb/zdb-zone-path-provider.h"
#include "dnsdb/xfr_copy.h"

#ifndef WIN32
/* it depends if host is DARWIN or LINUX */
#ifdef HAVE_SYS_SYSLIMITS_H
#include        <sys/syslimits.h>
#elif HAVE_LINUX_LIMITS_H
#include        <linux/limits.h>
#endif /* HAVE_SYS_SYSLIMITS_H */
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

static ya_result
xfr_copy_create_file(output_stream *xfrs, char *file_path, u32 file_path_len, const char* data_path, const u8 *origin, bool data_path_is_target) // should be temp
{
    ya_result ret;

    (void)data_path;

    yassert(xfrs != NULL);

    if(!data_path_is_target)
    {
        if(ISOK(ret = zdb_zone_path_get_provider()(
            origin,
            file_path, file_path_len,
            ZDB_ZONE_PATH_PROVIDER_AXFR_FILE|ZDB_ZONE_PATH_PROVIDER_RNDSUFFIX|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
        {
            if(ISOK(ret = file_output_stream_create(xfrs, file_path, 0644)))
            {
                return ret;
            }
        }

        ret = file_output_stream_create_excl(xfrs, file_path, 0644);
    }
    else
    {
        mkdir_ex(data_path, 0755, MKDIR_EX_PATH_TO_FILE);

        ret = file_output_stream_create_excl(xfrs, data_path, 0644);
    }


    /*
     * Do NOT use buffers yet.
     */

    return ret;
}

ya_result
xfr_delete_axfr(const u8 *origin)
{
    ya_result ret;
    char file_path[PATH_MAX];
    
    if(ISOK(ret = zdb_zone_path_get_provider()(
        origin, 
        file_path, sizeof(file_path),
        ZDB_ZONE_PATH_PROVIDER_AXFR_FILE)))
    {
        if(unlink(file_path) < 0) // VS false positive: reaching this point, file_path is initialized (by contract)
        {
            ret = ERRNO_ERROR;
            if(ret != MAKE_ERRNO_ERROR(ENOENT))
            {
                log_err("unlink '%s': %r", file_path, ret);
            }
            else
            {
                log_debug("unlink '%s': %r", file_path, ret);
            }
        }
    }

    return ret;
}

ya_result
xfr_copy(input_stream *xis, const char *base_data_path, bool base_data_path_is_target)
{
    output_stream xos;
    ya_result ret;
    char tmp_file_path[PATH_MAX];
    char file_path[PATH_MAX];
    u8 buffer[1024];
    
    if(ISOK(ret = xfr_copy_create_file(&xos, tmp_file_path, sizeof(tmp_file_path), base_data_path, xfr_input_stream_get_origin(xis), base_data_path_is_target)))
    {
        buffer_output_stream_init(&xos, &xos, 4096);
        
        for(;;)
        {
            if(dnscore_shuttingdown())
            {
                ret = STOPPED_BY_APPLICATION_SHUTDOWN;
                break;
            }
            
            ret = input_stream_read(xis, buffer, sizeof(buffer));

            if(ret <= 0)
            {
                break;
            }
            
            output_stream_write(&xos, buffer, ret);
        }
        
        output_stream_close(&xos);
        
        if(ISOK(ret))
        {
            u16 xfr_type = xfr_input_stream_get_type(xis);
            
            //u32 last_serial = xfr_input_stream_get_serial(xis);

            if(!base_data_path_is_target)
            {
                if(ISOK(ret = zdb_zone_path_get_provider()(
                    xfr_input_stream_get_origin(xis),
                    file_path, sizeof(file_path),
                    ZDB_ZONE_PATH_PROVIDER_AXFR_FILE|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
                {
                    unlink(file_path); // VS false positive: reaching this point, file_path is initialized to an ASCIIZ (by contract)

                    if(rename(tmp_file_path, file_path) < 0)
                    {
                        ret = ERRNO_ERROR;
                    }

                    if(ISOK(ret))
                    {
                        ret = xfr_type;
                    }
                }
                else
                {
                    log_err("xfr_copy: %r", ret);
                }
            }
        }
        else
        {
            unlink(tmp_file_path);
        }
    }
    
    return ret;
}


/** @} */
