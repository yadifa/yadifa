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
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */


#include <dnsdb/zdb_types.h>
#include "zone.h"

ya_result
scheduler_database_load_zone(zdb *db, zone_data *zone);

#define DATABASE_LOAD_STOP              0
#define DATABASE_LOAD_LOAD_ZONE         1
#define DATABASE_LOAD_UNLOAD_ZONE       2



struct database_message_stop
{
    u8 type;
};

struct database_message_load_zone
{
    u8 type;
};

struct database_message_unload_zone
{
    u8 type;
};


typedef struct database_message database_message;

struct database_message
{
    u8 *origin;

    union
    {
        u8 type;
        
        struct database_message_stop stop;
        
        struct database_message_load_zone load_zone;
        struct database_message_unload_zone unload_zone;
        
        
    } payload;
};

/**
 * Starts the database load service
 */

void database_load_startup();

/**
 * Stops the database load service
 */

void database_load_shutdown();

/**
 * Queue the load of a zone
 */

void database_load_zone_load(const u8 *origin);

/**
 * Queue the drop of a zone
 */

void database_load_zone_unload(const u8 *origin);


/** @} */
