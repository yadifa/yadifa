/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "dnscore-config.h"

#include "dnscore/packet_reader.h"
#include "dnscore/format.h"
#include "dnscore/xfr_copy.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/fdtools.h"

/* it depends if host is DARWIN or LINUX */
#ifdef HAVE_SYS_SYSLIMITS_H
#include        <sys/syslimits.h>
#elif HAVE_LINUX_LIMITS_H
#include        <linux/limits.h>
#endif /* HAVE_SYS_SYSLIMITS_H */

#define MODULE_MSG_HANDLE g_system_logger

/**
 * Fixes an issue with the dirent not always set as expected.
 *
 * The type can be set to DT_UNKNOWN instead of file or directory.
 * In that case the function will call stats to get the type.
 */

u8
dirent_get_file_type(const char* folder, struct dirent *entry)
{
    u8 d_type;

#ifdef _DIRENT_HAVE_D_TYPE
    d_type = entry->d_type;
#else
    d_type = DT_UNKNOWN;
#endif
    
    /*
     * If the FS OR the OS does not supports d_type :
     */

    if(d_type == DT_UNKNOWN)
    {
        struct stat file_stat;
        
        char d_name[PATH_MAX];
        snprintf(d_name, sizeof(d_name), "%s/%s", folder, entry->d_name);

        while(stat(d_name, &file_stat) < 0)
        {
            int e = errno;

            if(e != EINTR)
            {
                log_err("stat(%s): %r", d_name, ERRNO_ERROR);
                break;
            }
        }

        if(S_ISREG(file_stat.st_mode))
        {
            d_type = DT_REG;
        }
    }

    return d_type;
}

/**
 * The hash function that gives a number from an ASCIIZ string
 * 
 * @param p ASCIIZ string
 * 
 * @return the hash
 */

static u32
xfr_copy_hash(const u8 *p)
{
    u32 h = 0;
    u32 c;
    u8 s = 0;
    do
    {
        c = toupper(*p++);
        c &= 0x3f;
        h += c << (s & 15);
        h += 97;
        s += 13;
    }
    while(c != 0);
    
    return h;
}

/**
 * 
 * Returns the hashed folder path for a zone.
 * 
 * @param data_path             the target buffer for the data path
 * @param data_path_size        the target buffer size
 * @param base_data_path        the base folder
 * @param origin                the origin of the zone
 * 
 * @return 
 */

ya_result
xfr_copy_get_data_path(char *data_path, u32 data_path_size, const char *base_data_path, const u8 *origin)
{
    u32 h = xfr_copy_hash(origin);
    
    return snformat(data_path, data_path_size, "%s/%02x/%02x", base_data_path, h & 0xff, (h >> 8) & 0xff);
}

/**
 * 
 * Returns the hashed folder path for a zone.  Creates the path
 * 
 * @param data_path             the target buffer for the data path
 * @param data_path_size        the target buffer size
 * @param base_data_path        the base folder
 * @param origin                the origin of the zone
 * 
 * @return 
 */

ya_result
xfr_copy_mkdir_data_path(char *data_path, u32 data_path_size, const char *base_data_path, const u8 *origin)
{
    u32 h = xfr_copy_hash(origin);
    ya_result return_value;
    
    data_path[0] = '?';
    data_path[1] = '\0';
    
    if(ISOK(return_value = snformat(data_path, data_path_size, "%s/%02x", base_data_path, h & 0xff)))
    {
        errno = 0;
        mkdir(data_path, 0755);
        int err = errno;
        if((err == 0) || (err == EEXIST))
        {
            ya_result rv = return_value;

            if(ISOK(return_value = snformat(&data_path[return_value], data_path_size - return_value, "/%02x", (h >> 8) & 0xff)))
            {        
                return_value += rv; // to get the full size of the string as a return value if all goes well

                if(mkdir(data_path, 0755) < 0)
                {
                    err = errno;
                    if(err != EEXIST)
                    {
                        return_value = MAKE_ERRNO_ERROR(err);
                    }
                }
            }
        }
        else
        {
            return_value = MAKE_ERRNO_ERROR(err);
        }
    }
    
    return return_value;
}

/**
 * Builds the path for an AXFR wire dump.
 * 
 * @param file_path             target name
 * @param file_path_len         target name max len
 * @param data_path             base path
 * @param origin                the origin of the zone
 * @param serial                serial of the dump
 * @param tmp                   appends ".tmp" to the name
 * @return 
 */

static ya_result
xfr_copy_get_file_name(char *file_path, u32 file_path_len, const u8 *origin, u32 serial, bool tmp)
{
    char *tmptxt = (tmp)?".tmp":"";
    
    ya_result return_value;
        
    yassert(file_path != NULL);

    return_value = snformat(file_path, file_path_len, "%{dnsname}%08x.axfr%s", origin, serial, tmptxt);
    
    return return_value;
}

static ya_result
xfr_copy_create_file(output_stream *xfrs, char *file_path, u32 file_path_len, const char* data_path, const u8 *origin, u32 serial)
{
    ya_result return_value;

    yassert(xfrs != NULL);

    const u32 minimum_file_len =  1 + 1 + 8 + 1 + 4 + 1 + 3 + 1;
    
    if(FAIL(return_value = xfr_copy_mkdir_data_path(file_path, file_path_len - minimum_file_len, data_path, origin)))
    {
        return return_value;
    }
    
    // append the / after the directory name
    
    file_path[return_value++] = '/';
        
    if(FAIL(xfr_copy_get_file_name(&file_path[return_value], file_path_len - return_value, origin, serial, TRUE)))
    {
        return return_value;
    }
    
    /*
     * We finally can create the file
     */

    return_value = file_output_stream_create(file_path, 0644, xfrs);

    /*
     * Do NOT use buffers yet.
     */

    return return_value;
}

ya_result
xfr_delete_axfr(const u8 *origin, const char *folder)
{
    struct dirent entry;
    struct dirent *result;
    u32 serial;
    ya_result return_code = ERROR;

    char fqdn[MAX_DOMAIN_TEXT_LENGTH + 1];

    /* returns the number of bytes = strlen(x) + 1 */

    s32 fqdn_len = dnsname_to_cstr(fqdn, origin);

    DIR* dir = opendir(folder);
    
    if(dir != NULL)
    {
        for(;;)
        {
            readdir_r(dir, &entry, &result);

            if(result == NULL)
            {
                break;
            }

            u8 d_type = dirent_get_file_type(folder, result);

            if(d_type == DT_REG)
            {
                if(memcmp(result->d_name, fqdn, fqdn_len) == 0)
                {
                    const char* serials = &result->d_name[fqdn_len];

                    /*
                     * at serials [ 8+1+8 ] we MUST have a '.'
                     * followed by 'i' 'x' '\0'
                     */

                    if(strlen(serials) == 8 + XFR_FULL_EXT_STRLEN)
                    {
                        if(strcmp(&serials[8], XFR_FULL_EXT) == 0)
                        {
                            int converted = sscanf(serials, "%08x", &serial);

                            if(converted == 1)
                            {
                                /* got one */
                                
                                log_debug("deleting AXFR file: %s", result->d_name);
                                
                                if(unlink_ex(folder, result->d_name) < 0)
                                {
                                    log_err("unlink %s/%s: %r", folder, result->d_name, ERRNO_ERROR);
                                }
                            }
                        }
                    }
                }
            }
        }

        closedir(dir);
    }

    return return_code;
}

ya_result
xfr_copy(input_stream *xis, const char *base_data_path)
{
    output_stream xos;
    ya_result return_value;
    char tmp_file_path[PATH_MAX];
    char file_path[PATH_MAX];
    u8 buffer[1024];
    
    if(ISOK(return_value = xfr_copy_create_file(&xos, tmp_file_path, sizeof(tmp_file_path), base_data_path, xfr_input_stream_get_origin(xis), xfr_input_stream_get_serial(xis))))
    {
        buffer_output_stream_init(&xos, &xos, 4096);
        
        for(;;)
        {
            if(dnscore_shuttingdown())
            {
                return_value = STOPPED_BY_APPLICATION_SHUTDOWN;
                break;
            }
            
            return_value = input_stream_read(xis, buffer, sizeof(buffer));

            if(return_value <= 0)
            {
                break;
            }
            
            output_stream_write(&xos, buffer, return_value);
        }
        
        output_stream_close(&xos);
        
        if(ISOK(return_value))
        {
            u16 xfr_type = xfr_input_stream_get_type(xis);

            return_value = strlen(tmp_file_path);
            memcpy(file_path, tmp_file_path, return_value - 4);
            file_path[return_value - 4] = '\0';

            unlink(file_path);

            if(rename(tmp_file_path, file_path) < 0)
            {
                return_value = ERRNO_ERROR;
            }

            if(ISOK(return_value))
            {
                return_value = xfr_type;
            }
        }
        else
        {
            unlink(tmp_file_path);
        }
    }
    
    return return_value;
}


/** @} */
