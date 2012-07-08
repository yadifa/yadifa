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
/** @defgroup logger Logging functions
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/logger.h"
#include "dnscore/logger_channel.h"

logger_channel*
logger_channel_alloc()
{
    logger_channel* chan;

    MALLOC_OR_DIE(logger_channel*, chan, sizeof (logger_channel), 0x4e414843474f4c); /* LOGCHAN */

    chan->data = NULL;
    chan->vtbl = NULL;
    
    /* dummy to avoid a NULL test */
    logger_message* last_message;
    MALLOC_OR_DIE(logger_message*,last_message,sizeof(logger_message), LOGRMSG_TAG);
    MALLOC_OR_DIE(u8*, last_message->text, 1, LOGRTEXT_TAG);
    *last_message->text = '\0';
    last_message->text_length = 0;
    last_message->flags = 0;
    last_message->rc = 1;
    
    chan->last_message = last_message;
    chan->last_message_count = 0;

    return chan;
}

/** @} */

/*----------------------------------------------------------------------------*/

