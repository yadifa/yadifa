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
/*----------------------------------------------------------------------------*/

#ifndef DATABASE_H_
#define DATABASE_H_

#ifdef __cplusplus
extern "C" {
#endif

    /*----------------------------------------------------------------------------*/

#include    "config.h"

#include <dnscore/message.h>
#include <dnscore/fingerprint.h>
#include <dnscore/treeset.h>

#include    "zone.h"

    /* List of database type in string form */
#define     DB_STRING_NO            "no database"

    typedef void *database_t;

    void            database_init();
    void            database_finalize();

    ya_result       database_clear_zones(database_t *database, zone_data_set *dset);
    ya_result       database_load(database_t **, zone_data_set *dset);
    
    /** \brief Get dns answer from database
     *
     *  @param mesg
     *
     *  @retval OK
     *  @retval NOK
     *  @return status of message is written in mesg->status
     */
    void            database_query(database_t *database, message_data *mesg);
    
    /**
     * A task is a function called in the main thread loop
     * A delegate is a task we are waiting for
     */
    void            database_delegate_query(database_t *database, message_data *mesg);
    
    finger_print    database_update(database_t *database, message_data *mesg);
    
    finger_print    database_delegate_update(database_t *database, message_data *mesg);

    ya_result       database_print_zones(zone_data *, char *);
    ya_result       database_unload(database_t *);

    /**
     *  Master only :
     * 
     * For all (valid) master zones,
     *  if the zone has signatures (about to) expire(d), 
     *   queue the database_update_signatures_alarm for said zone.
     * 
     * This does not makes as much sense to call this at startup now that zones are async
     * 
     */
    ya_result       database_signature_maintenance(database_t *database);

    /* Slave only */
    ya_result       database_zone_refresh_maintenance(database_t *database, const u8 *origin);
    ya_result       database_refresh_maintenance(database_t *database);
    
    bool            database_are_all_zones_saved_to_disk();
    void            database_wait_all_zones_saved_to_disk();
    void            database_disable_all_zone_save_to_disk();

    /*    ------------------------------------------------------------    */

#ifdef __cplusplus
}
#endif

#endif /* DATABASE_H_ */

/*    ------------------------------------------------------------    */

/** @} */
