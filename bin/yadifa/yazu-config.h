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
#pragma once

/** @defgroup yadifa
*  @ingroup ###
*  @brief yadifa
*/

#include <dnscore/sys_error.h>
#include <dnscore/message.h>


typedef struct config_yazu_settings_s config_yazu_settings_s;

struct config_yazu_settings_s
{
    host_address                                                    *server;



    /*    ------------------------------------------------------------    */

    int16_t                                                          qclass;
    int16_t                                                           qtype;
    u32                                                                qttl;

    u8                                                               *qzone;
    u8                                                               *qname;
    u8                                                                *file;
    u8                                                              *update;

#if 1
    u16                                                            protocol;
    u16                                                       question_mode;
    u16                                                           view_mode;
    u16                                                      view_mode_with;

    u32                                                                edns;
    u32                                                            edns_max;

    host_address                                                    *qname2;
//    host_address                                                     *qzone;
#endif

    char                                                           *pre_nxr;
    char                                                           *pre_nxd;
    char                                                           *pre_nyd;
    char                                                           *pre_nyr;

    message_dnsupdate_data                                      *dns_update;

};

/*----------------------------------------------------------------------------*/

ya_result yazu_config_cmdline(int argc, char **argv);
ya_result yazu_config_finalise();
ya_result yazu_config_init();

