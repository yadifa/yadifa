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
/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/sys_types.h"
#include "dnscore/logger.h"

#include <unistd.h>
#include <sys/types.h>


/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

#define MODULE_MSG_HANDLE g_system_logger
extern logger_handle *g_system_logger;


/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** \brief Change uid and gid of the program
 *
 *  @param[in] config is a config_data structure
 *
 *  @return an error code
 */
ya_result
identity_change(uid_t new_uid, gid_t new_gid)
{
    ya_result                                                   return_code;

    uid_t                                                    uid = getuid();
    gid_t                                                    gid = getgid();

    /*    ------------------------------------------------------------    */

    if( (uid == 0) && ((uid != new_uid) || (gid != new_gid)))
    {
        log_info("changing identity to %d:%d (current: %d:%d)", new_uid, new_gid, uid, gid);
    }

    if((gid != new_gid) && (uid == 0))
    {
        if(setgid(new_gid) < 0)
        {
            return_code = ERRNO_ERROR;
            log_err("error switching to gid %i: %r", new_gid, return_code);

            return return_code;;
        }
    }

    if((uid != new_uid) && (uid == 0))
    {
        if(setuid(new_uid) < 0)
        {
            return_code = ERRNO_ERROR;
            log_err("error switching to uid %i: %r", new_uid, return_code);

            return return_code;;
        }
    }

    return SUCCESS;
}



    /*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

