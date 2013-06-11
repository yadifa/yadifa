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
 *  _ open
 *  _ read record
 *  _ close
 *
 * @{
 */

#ifndef _ZONEFILE_H
#define	_ZONEFILE_H

#include <stdio.h>
#include <dnscore/sys_types.h>
#include <dnscore/dnsname.h>
#include <dnscore/input_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define ZONE_MAGIC 0x45444e53	/* "EDNS" EurID - DNS - Network order. */

#define ZONEFILE_NAME_TAG 0x454d414e465a        /* "ZFNAME" */
#define ZONEFILE_RDATA_TAG 0x4154414452465a     /* "ZFRDATA" */

#ifndef ZONE_H_

/* This zone file structure is used on my test loader
 * It is not compatible with Yadifa
 */

typedef struct zone_file zone_file;


struct zone_file
{
    //input_stream fis;
    input_stream bis;
    u16 version;
    u8 type;
    u8 reserved;
};

#endif

typedef struct zonefile_entry zonefile_entry;


struct zonefile_entry
{
    u16    class;
    u16    type;
    u32    ttl;
    u8* rdata;
    u16	   rdata_size;
    u8     name[MAX_DOMAIN_LENGTH + 1];
};

#define ZONEFILE_ENTRY_CLASS(zfe) ((zfe).class)
#define ZONEFILE_ENTRY_TYPE(zfe) ((zfe).type)
#define ZONEFILE_ENTRY_TTL(zfe) ((zfe).ttl)
#define ZONEFILE_ENTRY_RDATA(zfe) ((zfe).data)
#define ZONEFILE_ENTRY_NAME(zfe) ((zfe).name)

#define ZONEFILE_ENTRY_IS_EOF(ze) ((ze).name[0]==0)

/** @brief Opens a zone file
 *
 *  Opens a zone file
 *
 *  @param[in]  filename the name of the file to open
 *  @param[in]  dnsdomain the zone name associated to the file
 *  @param[out] zonefile a pointer to a structure that will be used by the function to hold the zone-file information
 *
 *  @return A result code
 *  @retval OK : the file has been opened successfully
 *  @retval else : an error occurred
 */

ya_result zonefile_open(const char* filename,zone_file* output);

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

ya_result zonefile_read(zone_file* zonefile,zonefile_entry* entry);

/** @brief Closes a zone file entry
 *
 *  Closes a zone file entry.  The function will do nothing if the zonefile has already been closed
 *
 *  @param[in] zonefile a pointer to a valid (zonefile_open'ed) zone-file structure
 *
 */

void zonefile_close(zone_file* zonefile);

void zonefile_entry_freecontent(zonefile_entry* entry);

#ifdef	__cplusplus
}
#endif

#endif	/* _FILE_H */

/** @} */
