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

#include "dnscore/dnscore-config.h"
#include <stdlib.h>
//#include <arpa/inet.h>
//#include <ctype.h>

//#include "dnscore/dnscore-config.h"

#define DNSCORE_NSID_C

#include "dnscore/nsid.h"
#include "dnscore/rfc.h"

static u8 edns0_rdatasize_nsid_option_wire_default[2] = {0,0};

u32 edns0_record_size = EDNS0_RECORD_SIZE;
u8 *edns0_rdatasize_nsid_option_wire = edns0_rdatasize_nsid_option_wire_default;
u32 edns0_rdatasize_nsid_option_wire_size = 2;

void
edns0_set_nsid(u8 *bytes, u16 size)
{
    if(bytes != NULL)
    {
        if(size > EDNS0_NSID_SIZE_MAX)
        {
            return;
        }
        
        u8 *tmp = malloc(2 + 2 + 2 + size);

        if(tmp == NULL)
        {
            return;
        }
        
        tmp[0] = (size + 4) >> 8; 
        tmp[1] = (size + 4) & 255; // VS false positive (nonsense) 
        tmp[2] = 0;
        tmp[3] = EDNS0_OPT_3;
        tmp[4] = size >> 8;
        tmp[5] = size & 255;
        memcpy(&tmp[6], bytes, size);
        
        if(edns0_rdatasize_nsid_option_wire != edns0_rdatasize_nsid_option_wire_default)
        {
            free(edns0_rdatasize_nsid_option_wire);
        }
        
        edns0_rdatasize_nsid_option_wire = tmp;
        edns0_rdatasize_nsid_option_wire_size = 6 + size;
        
        edns0_record_size = EDNS0_RECORD_SIZE - 2 + edns0_rdatasize_nsid_option_wire_size;
    }
    else
    {
        if(edns0_rdatasize_nsid_option_wire != edns0_rdatasize_nsid_option_wire_default)
        {
            free(edns0_rdatasize_nsid_option_wire);
            edns0_rdatasize_nsid_option_wire = edns0_rdatasize_nsid_option_wire_default;
            edns0_rdatasize_nsid_option_wire_size = 2;            
            edns0_record_size = EDNS0_RECORD_SIZE;
        }
    }
}

/** @} */
