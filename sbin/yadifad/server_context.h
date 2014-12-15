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
/** @defgroup server Server
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#pragma once

#include "config.h"

#include <dnscore/message.h>
#include <database.h>

#include "confs.h"

#if HAS_MESSAGES_SUPPORT
#define UDP_USE_MESSAGES 1
#else
#define UDP_USE_MESSAGES 0
#endif

#ifdef	__cplusplus
extern "C"
{
#endif
    
/** \brief  Initialize sockets and copy the config parameters into server_context_t
 *
 *  @param[in] config
 *  @param[out] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */

int config_update_network(config_data *);

/**
 * Appends the name of the socket s to the buffer.
 * The buffer has to be big enough, no size test is performed.
 * 
 * @param buffer
 * @param s
 * 
 * @return the length of the name
 */
    
u32 server_context_append_socket_name(char *buffer, u16 s);

/** \brief Closes all sockets and remove pid file
 *
 *  @param[in] config
 *  @param[in] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */

void server_context_clear(config_data *);

#ifdef	__cplusplus
}
#endif

