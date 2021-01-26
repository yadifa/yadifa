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

/** @defgroup 
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
 /* It's a suggestion for a common interface for stored files.
 * I'd add an "add" and "remove" status on a record in order to
 * accommodate dynupdate features.
 *
 */

#ifndef _ZONEFILE_READER_H
#define	_ZONEFILE_READER_H

#error DONT USE YET

#include <dnscore/sys_types.h>

#define ZONEFILE_OPERATION_ADD          0x00   /* The next record is meant to be added */
#define ZONEFILE_OPERATION_REMOVE       0x01   /* The next record is meant to be removed */

#define ZONEFILE_OPERATION_LABELCHANGED 0x02   /* The caller should reload the label */
#define ZONEFILE_OPERATION_TYPECHANGED  0x04   /* The caller should reload the type */

#define ZONEFILE_OPERATION_EOF          0x80   /* End of file */

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct zonefile_reader zonefile_reader;
    

    /*
     * Opens a zone file using the filename (mostly used for TXT zone files)
     * The next dnsname is made ready
     */

    typedef ya_result zonefile_openfile_method(zonefile_reader* reader, const char* filename);

    /*
     * Opens a zone file using the origin (used for any internal file)
     * The next dnsname is made ready
     */

    typedef ya_result zonefile_openzone_method(zonefile_reader* reader,const u8* origin,u16 zclass);
    
    /*
     * Go to the next dnrecord if any
     *
     * return the operation
     */

    typedef ya_result zonefile_nextrecord_method(zonefile_reader* reader);

    /*
     * Closes the file(s)
     */

    typedef ya_result zonefile_close_method(zonefile_reader* reader);

    /*
     * Returns true if the format name is supported by the current implementation
     */

    typedef bool zonefile_supports_method(zonefile_reader* reader,const char* format);

    /*
     * Returns the current operation
     */

    typedef ya_result zonefile_getcurrenoperation_method(zonefile_reader* reader);

    /*
     * Returns the current class (should be constant for the whole zone
     */

    typedef u16 zonefile_getcurrentclass_method(zonefile_reader* reader);

    /*
     * Returns the current type
     */

    typedef u16 zonefile_getcurrenttype_method(zonefile_reader* reader);

    /*
     * Returns the current ttl
     */

    typedef u32 zonefile_getcurrentttl_method(zonefile_reader* reader);

    /*
     * Returns the current rdata_size
     */

    typedef u16 zonefile_getcurrentrdatasize_method(zonefile_reader* reader);

    /*
     * Returns the current rdata
     */
    
    typedef const u8* zonefile_getcurrentrdata_method(zonefile_reader* reader);

    struct zonefile_reader
    {
        void*   data;

        zonefile_openfile_method* openfile;
        zonefile_openzone_method* openzone;

        zonefile_nextrecord_method* nextrecord;
        
        zonefile_getcurrentclass_method* getcurrentclass;
        zonefile_getcurrenttype_method* getcurrenttype;
        zonefile_getcurrentttl_method* getcurrentttl;
        zonefile_getcurrentrdatasize_method* getcurrentrdatasize;
        zonefile_getcurrentrdata_method* getcurrentrdata;

        zonefile_close_method* close;
        zonefile_supports_method* supports;
    };

    #define zonefile_openfile(zf,filename)   (zf)->openfile_method(zf,filename)
    #define zonefile_openzone(zf,origin)     (zf)->openzone_method(zf,origin)
    #define zonefile_close(zf)               (zf)->close_method(zf)

    #define zonefile_supports(zf)            (zf)->zonefile_supports_method_method(zf)

    #define zonefile_nextrecord(zf)          (zf)->zonefile_nextrecord_method(zf)
    #define zonefile_getcurrentclass(zf)     (zf)->zonefile_getcurrentclass_method(zf)
    #define zonefile_getcurrenttype(zf)      (zf)->zonefile_getcurrenttype_method(zf)
    #define zonefile_getcurrentttl(zf)       (zf)->zonefile_getcurrentttl_method(zf)
    #define zonefile_getcurrentrdatasize(zf) (zf)->zonefile_getcurrentrdatasize_method(zf)
    #define zonefile_getcurrentrdata(zf)     (zf)->zonefile_getcurrentrdata_method(zf)

#ifdef	__cplusplus
}
#endif

#endif	/* _ZONEFILE_READER_H */
/** @} */

/*----------------------------------------------------------------------------*/

