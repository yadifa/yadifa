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
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"
#include "dnscore/sys_types.h"
#include "dnscore/logger.h"
#include "dnscore/file_output_stream.h"

#include <unistd.h>
#include <sys/types.h>

#if HAVE_GRP_H
#include <grp.h>
#endif


/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

#define MODULE_MSG_HANDLE g_system_logger

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
#ifndef WIN32
    ya_result return_code;

    uid_t uid = getuid();
    uid_t euid = getuid();
    gid_t gid = getgid();
    gid_t egid = getegid();
    
    bool is_admin = (uid==0)||(euid==0)||(gid==0)||(egid==0);
    
    /*    ------------------------------------------------------------    */

    if( is_admin && ((uid != new_uid) || (gid != new_gid) || (euid != new_uid) || (egid != new_gid)))
    {
        log_info("changing identity to %d:%d (current: %d:%d)", new_uid, new_gid, uid, gid);
    }

    if(((0 != new_gid) || (0 != new_gid)) && is_admin) // if we need to change to something else than admin and we are admin ...
    {
#if HAVE_GRP_H && HAS_SETGROUPS
        if(setgroups(0, NULL) < 0)
        {
            log_warn("could not relinquish all groups : %r", ERRNO_ERROR);
        }
#endif
        if(setgid(new_gid) < 0)
        {
            return_code = ERRNO_ERROR;
            log_err("error switching to gid %i: %r", new_gid, return_code);

            return return_code;;
        }
        
        if(setegid(new_gid) < 0)
        {
            return_code = ERRNO_ERROR;
            log_err("error switching to egid %i: %r", new_gid, return_code);

            return return_code;;
        }
    }

    if(((0 != new_uid) || (0 != new_uid)) && is_admin) // if we need to change to something else than admin and we are admin ...
    {
#if HAVE_GRP_H && HAS_SETGROUPS
        if(setgroups(0, NULL) < 0)
        {
            log_warn("could not relinquish all groups : %r", ERRNO_ERROR);
        }
#endif
        if(setuid(new_uid) < 0)
        {
            return_code = ERRNO_ERROR;
            log_err("could not change uid to %i: %r", new_uid, return_code);

            return return_code;;
        }
        
        if(seteuid(new_uid) < 0)
        {
            return_code = ERRNO_ERROR;
            log_err("could not change euid to %i: %r", new_uid, return_code);

            return return_code;;
        }
    }
#if DEBUG
    output_stream os;
    if(ISOK(file_output_stream_create(&os, "/tmp/test-uid-gid", 0644)))
    {
        osformatln(&os, "uid=%u gid=%u euid=%u egid=%u\n", uid, gid, euid, egid);
        output_stream_close(&os);
    }
#endif
    return SUCCESS;
#else
    return FEATURE_NOT_IMPLEMENTED_ERROR;
#endif
}

/** @} */
