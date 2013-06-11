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
* DOCUMENTATION */
/** @defgroup dnsdb
 *  @ingroup dnsdb
 *  @brief Internal functions for the database: storage of the db.
 *
 *  Storage of the DB.
 *  The axfr, ixfr, signature, ... will make use of this format.
 *
 * @{
 */


#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_store.h"
#include "dnsdb/zdb_zone.h"

#include <dnscore/ptr_vector.h>

#include "dnsdb/zdb_utils.h"

#include "dnsdb/dnsrdata.h"

ya_result
zdb_store_getfileprefix(const u8* origin, u16 zclass, char* buffer, size_t buffer_size)
{
    char name[MAX_DOMAIN_TEXT_LENGTH + 1];

    dnsname_to_cstr(name, origin);

    if(snprintf(buffer, buffer_size, "zone-%s-%02i-", name, zclass) > buffer_size)
    {
        return ERROR;
    }

    return SUCCESS;
}

ya_result
zdb_store_file_test_prefix_suffix(const char* filename, const char* prefix, u32 prefix_len, const char* suffix, u32 suffix_len)
{
    ya_result ret = ERROR;

    char tmp[8];

    FILE *f = fopen(filename, "rb");

    int err;

    if(f != NULL)
    {
        if(fread(tmp, prefix_len, 1, f) == 1)
        {
            if(memcmp(tmp, prefix, prefix_len) == 0)
            {
                /** @todo: > 2GB files will happen sooner or later */
                if((err = fseek(f, -((s32)prefix_len), SEEK_END)) >= 0)
                {
                    //long offs = ftell(f);

                    if(fread(tmp, suffix_len, 1, f) == 1)
                    {
                        if(memcmp(tmp, suffix, suffix_len) == 0)
                        {
                            ret = SUCCESS;
                        }
                    }
                }
            }
        }

        fclose(f);
    }

    err = errno;

    return ret;
}

static u32
zdb_store_search_best_incremental_path(ptr_vector* znc_names, u32 base_names_offset, u32 prefix_len,
                                       u32 serial_from,
                                       ptr_vector* current_serial_path,
                                       u32* serial_best_p,
                                       ptr_vector* serial_bestpath)
{
    s32 znc_i;

    bool bottom = TRUE;

    /* We only will do work in this loop if we still have work.
     */

    for(znc_i = base_names_offset; znc_i <= znc_names->offset; znc_i++)
    {
        char* znc_filename = znc_names->data[znc_i];

        u32 znc_serial_from;
        u32 znc_serial_to;

        if(sscanf(&znc_filename[prefix_len], "%08x-%08x.znc", &znc_serial_from, &znc_serial_to) == EOF)
        {
            /* match or conversion error */

            continue;
        }

        /* A typical bugger.  Let's avoid this potential infinite loop. */

        if(znc_serial_from == znc_serial_to)
        {
            continue;
        }

        /* NOTE: if(serial_gt(znc_serial_to,serial_best)) is ALWAYS true, because it's supposed to be incremental
         * So even a step of (2^31) is acceptable.
         */

        bottom = FALSE;

        ptr_vector_append(current_serial_path, znc_filename);

        if(znc_serial_from == serial_from)
        {
            zdb_store_search_best_incremental_path(znc_names, znc_i + 1, prefix_len, znc_serial_to, current_serial_path, serial_best_p, serial_bestpath);
        }

        ptr_vector_pop(current_serial_path);
    }

    if(bottom) /* We hit bottom */
    {
        u32 serial_best = *serial_best_p;

        if(serial_gt(serial_from, serial_best) || ((serial_from == serial_best) && (current_serial_path->offset < serial_bestpath->offset)))
        {
            /* The path found there is better or (equal and shorter) than the one we used previously */

            int n = current_serial_path->offset;
            ptr_vector_ensures(serial_bestpath, n + 1);

            int i;
            for(i = 0; i <= n; i++)
            {
                serial_bestpath->data[i] = current_serial_path->data[i];
            }

            serial_bestpath->offset = n;

            *serial_best_p = serial_from;
        }
    }

    return serial_from;
}

static int
zdb_store_file_alphasort(const void* a, const void* b)
{
    return strcmp((const char*)a, (const char*)b);
}

/* Checks if the zone has been found in the zdb+znc format
 *
 * Returns:
 *
 * "exists" if the zone file already exists with the same or newer serial
 * "old" if the zone file exists but has got an old serial
 * "not" if the zone file does not exists
 *
 */

ya_result
zdb_store_search(const u8* origin, u16 zclass, u32* bestserial_p, ptr_vector* serial_bestpath_p)
{
    DIR* dir = opendir(".");

    if(dir == NULL)
    {
        return ERROR;
    }

    char prefix[MAX_DOMAIN_TEXT_LENGTH + 1];

    if(FAIL(zdb_store_getfileprefix(origin, zclass, prefix, sizeof (prefix))))
    {
        return ERROR;
    }

    size_t prefix_len = strlen(prefix);

    ptr_vector zdb_names;
    ptr_vector_init(&zdb_names);

    ptr_vector znc_names;
    ptr_vector_init(&znc_names);

    struct dirent *name;

    for(;;)
    {
        name = readdir(dir);

        if(name == NULL)
        {
            break;
        }

#if defined(_DIRENT_HAVE_D_TYPE)
        if((name->d_type & DT_REG) == 0)
        {
            /* not a regular file */

            continue;
        }
#endif

        size_t name_len = strlen(name->d_name);

        if(name_len < prefix_len)
        {
            continue;
        }

        if(memcmp(prefix, name->d_name, prefix_len) != 0)
        {
            continue;
        }

        /* Found a good candidate */
        /* the file name->d_name is probably a base or incremental file for the zone */

        if(memcmp(&name->d_name[name_len - 4], ".zdb", 4) == 0)
        {
            /* supposedly a base */

            if(FAIL(zdb_store_file_test_prefix_suffix(name->d_name, ZDB_ZONE_STORE_BASE_START, sizeof (ZDB_ZONE_STORE_BASE_START), ZDB_ZONE_STORE_BASE_STOP, sizeof (ZDB_ZONE_STORE_BASE_STOP))))
            {
                continue;
            }

            ptr_vector_append(&zdb_names, strdup(name->d_name));

        }
        else if(memcmp(&name->d_name[name_len - 4], ".znc", 4) == 0)
        {
            /* supposedly a incremental */

            if(FAIL(zdb_store_file_test_prefix_suffix(name->d_name, ZDB_ZONE_STORE_INCREMENTAL_START, sizeof (ZDB_ZONE_STORE_INCREMENTAL_START), ZDB_ZONE_STORE_INCREMENTAL_STOP, sizeof (ZDB_ZONE_STORE_INCREMENTAL_STOP))))
            {
                continue;
            }

            ptr_vector_append(&znc_names, strdup(name->d_name));
        }
    }

    ptr_vector_qsort(&zdb_names, zdb_store_file_alphasort);

    /* We have the names */
    /* Now we have to find the best match */

    ptr_vector serial_currentpath;
    ptr_vector_init(&serial_currentpath);

    ptr_vector serial_bestpath;

    if(serial_bestpath_p == NULL)
    {
        serial_bestpath_p = &serial_bestpath;
        ptr_vector_init(serial_bestpath_p);
    }

    u32 serial;

    if(bestserial_p == NULL)
    {
        bestserial_p = &serial;
    }

    ya_result ret = ERROR;

    s32 zdb_i;

    for(zdb_i = 0; zdb_i <= zdb_names.offset; zdb_i++)
    {
        char* zdb_filename = zdb_names.data[zdb_i];
        u32 zdb_serial;

        if(sscanf(&zdb_filename[prefix_len], "%08x.zdb", &zdb_serial) == EOF)
        {
            /* match or conversion error */

            continue;
        }

        if(zdb_i == 0)
        {
            /* our first serial
             * Let's say the best one we got until here was not good enough.
             */

            *bestserial_p = zdb_serial - 1;
        }

        /* We have a base serial.  Let's see how far we can go. */

        ptr_vector_append(&serial_currentpath, zdb_filename);

        zdb_store_search_best_incremental_path(&znc_names, 0, prefix_len, zdb_serial, &serial_currentpath, bestserial_p, serial_bestpath_p);

        ptr_vector_pop(&serial_currentpath);

        ret = SUCCESS;
    }

    /* serial_bestpath contains the path for bestserial */

    /* Cleanup :
     *
     * I could delete only the names I don't need looking for them in the serial_bestpath_p BUT it is potentially much more expensive
     * than duping the serial_bestpath_p and destroying everything else.
     *
     */

    if(serial_bestpath_p != &serial_bestpath)
    {
        /* The caller wants to keep the path */

        int i;
        for(i = 0; i <= serial_bestpath_p->offset; i++)
        {
            serial_bestpath_p->data[i] = strdup(serial_bestpath_p->data[i]);
        }
    }

    ptr_vector_free_empties(&zdb_names, free);
    ptr_vector_free_empties(&znc_names, free);

    return ret;
}

/**
 * @}
 */
