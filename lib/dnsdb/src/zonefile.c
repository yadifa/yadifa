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
/** @defgroup zonefile Functions used to read the zone-file
 *  @ingroup dnsdb
 *  @brief Functions used to read the zone-file
 *
 *  Functions used to read the zone-file
 *  It is used internally by the database.
 *
 * @{
 */


#ifndef _ZONEFILE_C
#define	_ZONEFILE_C

#include <string.h>
#include <strings.h>
#include <arpa/inet.h>  /* or netinet/in.h */
#include "dnsdb/zdb_error.h"
#include "dnsdb/zonefile.h"
#include <dnscore/dnsname.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/file_input_stream.h>


#ifdef	__cplusplus
extern "C"
{
#endif

/** @brief Opens a zone file
 *
 *  Opens a zone file
 *
 *  @param[in]  filename the name of the file to open
 *  @param[out] zonefile a pointer to a structure that will be used by the function to hold the zone-file information
 *
 *  @return A result code
 *  @retval OK : the file has been opened successfully
 *  @retval else : an error occurred
 */

ya_result
zonefile_open(const char* filename, zone_file* output)
{
    zassert(output != NULL);

    ya_result err;

    input_stream fis;

    if(FAIL(file_input_stream_open(filename, &fis)))
    {
        perror(filename);
        return ZDB_ERROR_CANTOPEN;
    }

    buffer_input_stream_init(&fis, &output->bis, 4096);

    /* I'm doing nothing with this yet, except checking the magic */

    u32 magic;
    u16 version;
    u8 type;
    u8 reserved;

    if(FAIL(err = input_stream_read_nu32(&output->bis, &magic)))
    {
        return ZDB_ERROR_CORRUPTEDDATA;
    }
    if(magic != ZONE_MAGIC)
    {
        return ZDB_ERROR_BADMAGIC;
    }
    if(FAIL(err = input_stream_read_nu16(&output->bis, &version)))
    {
        return ZDB_ERROR_CORRUPTEDDATA;
    }
    if(FAIL(err = input_stream_read_u8(&output->bis, &type)))
    {
        return ZDB_ERROR_CORRUPTEDDATA;
    }
    if(FAIL(err = input_stream_read_u8(&output->bis, &reserved)))
    {
        return ZDB_ERROR_CORRUPTEDDATA;
    }

    output->version = version;
    output->type = type;
    output->reserved = reserved;

    return SUCCESS;
}

/** @brief Reads a zone file entry
 *
 *  Reads a zone file entry
 *
 *  @param[in] zonefile a pointer to a valid (zonefile_open'ed) zone-file structure
 *  @param[out] entry a pointer to a zonefile_entry structure that will hold the record
 *
 *  @return A result code
 *  @retval OK : a record has been read successfully
 *  @retval else : an error occurred
 */

ya_result
zonefile_read(zone_file* in_file, zonefile_entry* entry)
{
    zassert((in_file != NULL) && (entry != NULL));

    input_stream* is = &in_file->bis;

    ZEROMEMORY(entry, sizeof (zonefile_entry));

    if(FAIL(input_stream_read_dnsname(is, entry->name)))
    {
        zonefile_entry_freecontent(entry);
        return ZDB_ERROR_CORRUPTEDDATA;
    }

    if(entry->name[0] == 0)
    {
        return SUCCESS;
    }

    if(FAIL(input_stream_read_nu16(is, &entry->class)))
    {
        zonefile_entry_freecontent(entry);
        return ZDB_ERROR_CORRUPTEDDATA;
    }

    if(FAIL(input_stream_read_nu16(is, &entry->type)))
    {
        zonefile_entry_freecontent(entry);
        return ZDB_ERROR_CORRUPTEDDATA;
    }

    if(FAIL(input_stream_read_nu32(is, &entry->ttl)))
    {
        zonefile_entry_freecontent(entry);
        return ZDB_ERROR_CORRUPTEDDATA;
    }

    /* because the type is stored on 32 bits instead of 16 bits */
    if(FAIL(input_stream_read_nu16(is, &entry->rdata_size)))
    {
        zonefile_entry_freecontent(entry);
        return ZDB_ERROR_CORRUPTEDDATA;
    }

    if(FAIL(input_stream_read_nu16(is, &entry->rdata_size)))
    {
        zonefile_entry_freecontent(entry);
        return ZDB_ERROR_CORRUPTEDDATA;
    }

    MALLOC_OR_DIE(u8*, entry->rdata, entry->rdata_size, ZONEFILE_RDATA_TAG); /* ZALLOC IMPOSSIBLE */

    if(FAIL(input_stream_read_fully(is, entry->rdata, entry->rdata_size)))
    {
        zonefile_entry_freecontent(entry);
        return ZDB_ERROR_CORRUPTEDDATA;
    }

    return SUCCESS;
}

/** @brief Closes a zone file entry
 *
 *  Closes a zone file entry.  The function will do nothing if the zonefile has already been closed
 *
 *  @param[in] zonefile a pointer to a valid (zonefile_open'ed) zone-file structure
 *
 */

void
zonefile_close(zone_file* in_file)
{
    zassert(in_file != NULL);

    /* The filter closes the filtered */

    input_stream_close(&in_file->bis);
}

void
zonefile_entry_freecontent(zonefile_entry* entry)
{
    zassert(entry != NULL);

    entry->name[0] = '\0';
    free(entry->rdata);
    entry->rdata = NULL;

    entry->rdata_size = 0;
}

#ifdef	__cplusplus
}
#endif

#endif	/* _FILE_C */

/** @} */
