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
/** @defgroup dnsdbdnssec DNSSEC functions
 *  @ingroup dnsdb
 *  @brief 
 *
 *  
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#define	_DNSSEC_SCHEDULER_H

#ifndef _DNSSEC_SCHEDULER_H

#error "getting rid of this"

#define	_DNSSEC_SCHEDULER_H

#include <dnsdb/zdb_config.h>
#include <dnscore/message.h>

#include "nsec3_types.h"

#ifdef	__cplusplus
extern "C"
{
#endif

    /**
     * @note Schedule a time-consuming task
     *
     * @todo I think it should be zone-wise.  I have to think about this.
     *
     */

    /**
     * The typical use of the scheduler is:
     *
     * _ ST-Mark the zone as being ST-modified
     * _ ST-launch a thread Do a task about the DB in the background, without modifying it.
     * _ MT-Schedule (many) write(s) on the DB about (part of) the work done in the background.
     * _ MT-When the task is done, schedule the un-marking of the zone as ST-modified
     *
     * Why the mark ? Because a writer can then check if anybody else is working on the DB already
     * which would be a problem.
     *
     * @note The signature & nsec3 generation algorithm works in a way that prevent race-conditions between
     *       its MT-writes and his ST-read.
     *
     * @note A dynupdate has got a prerequisite that is launched ST, and could (MUST?) do a dry-run.
     *       The real write should be scheduled after the signature.
     *       The write CANNOT be put between to signature update because the signer is still working
     *       and could break if his area is modified.  It MUST be added in the "next" shedule queue, at the end.
     *       This also means that a pre-requisite could succeed, and a dry-run.  But after a signature the
     *       RRSIG & NSEC3 changes could be against the prerequisites and break the update.
     *
     *       I see a a few solutions but I don't like them:
     *
     *       _ reject dynupdates with sensible requisites (rrsig & nsec3 based ones) while the signer is running.
     *          could reject otherwise perfectly valid updates
     *       _ reject dynupdates that are removing sensignes records (rrsig & nsec3 again) while signer is running.
     *          could reject otherwise perfectly valid updates
     *       _ reject all dynupdates while the signer is running
     *          could reject otherwise perfectly valid updates
     *       _ stop the signer as soon as a dynupdate is required and do the 3 steps (pre, dry, run) ST
     *          could restart the signer every couple of seconds (HEAVY)
     *          could, maybe, never end the signature task
     *
     *       As a sidenode, please remember that a dynupdate should also trigger an IXFR recording for the slaves.
     *
     * @note IXFR write
     *       The IXFR stream is put on the disk.  On EOF it is sent to be written in the zone.
     *       The IXFR conflicts with the signer so, like the dynupdate, its changes are queued in the "next" schedule queue.
     *
     * @note AXFR write
     *       The AXFR stream is put on the disk.  On EOF it is sent to be written in the zone.
     *       The AXFR resets the zone.  It means that the writers can and MUST be stopped.
     *       When everything is still the zone is dropped and reloaded (and verified, signed, ...)
     *
     * @note The cache has nothing to do with the dynupdate & dnssec, they are never in conflict
     *       The cache entries have an absolute end TTL
     *       When a cache line is added, a timed event is set for removing it at its expiration.
     *       This event writes the removal in the scheduler so that it is ST-removed and no race occurs
     *
     *
     */

#if ZDB_HAS_DNSSEC_SUPPORT != 0

    /*
     *  Use this to create and add a key in background
     */

    void scheduler_queue_dnskey_create(zdb_zone* zone, u16 flags, u8 algorithm, u16 size);

    /*
     * Takes the result of an update and schedule to commits it to the label
     * Used by the signing threads.
     */

    void scheduler_task_rrsig_update_commit(zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, zdb_rr_label* label, zdb_zone* zone, dnsname_stack* name, void* context_to_destroy);

#endif

#if ZDB_HAS_NSEC3_SUPPORT != 0

    /*
     * Use this to verify/update the nsec3 records of the zone and all signatures
     */

    void scheduler_queue_nsec3_update(zdb_zone *zone);

    void scheduler_task_nsec3_rrsig_update_commit(zdb_packed_ttlrdata *removed_rrsig_sll, zdb_packed_ttlrdata *added_rrsig_sll, nsec3_zone_item *item, zdb_zone *zone, void *context_to_destroy);

#endif

    /*
     * Stores the zone in a template-formated-name file in the directory path.
     * If the file exists already, it will be renamed with a .bak suffix.
     *
     * ie: /usr/local/share/zone/eu-zone.txt
     * 
     */

    ya_result scheduler_queue_zone_write(zdb_zone* zone, const char* path, callback_function *cb, void *cb_args);

    void      scheduler_queue_zone_write_axfr(zdb_zone* zone, const char* dirpath, u32 packet_size_limit, u32 packet_records_limit, bool compress_dname_rdata);

    void      scheduler_queue_zone_send_axfr(zdb_zone *zone, const char *directory, u32 packet_size_limit, u32 packet_records_limit, bool compress_dname_rdata, message_data *mesg);

    void      scheduler_queue_zone_send_ixfr(zdb_zone* zone, const char* directory, u32 packet_size_limit, u32 packet_records_limit, bool compress_dname_rdata, message_data *mesg);

    ya_result scheduler_queue_zone_freeze(zdb_zone* zone, const char* path, const char* filename);

    ya_result scheduler_queue_zone_unfreeze(zdb_zone* zone);

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSSEC_SCHEDULER_H */

/** @} */

/*----------------------------------------------------------------------------*/

