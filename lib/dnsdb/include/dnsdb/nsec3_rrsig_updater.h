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
/** @defgroup rrsig RRSIG functions
 *  @ingroup dnsdbdnssec
 *  @brief 
 *
 *  
 *
 * @{
 *
 * lock for readers
 * 
 * label iterator -> Q -> sign -> Q
 *                   U -> sign -> U
 *                   E -> sign -> E
 *                   U -> sign -> U
 *                   E -> sign -> E -> get results -> set lock to writer -> store
 * 
 *----------------------------------------------------------------------------*/

#pragma once

struct nsec3_rrsig_updater_result_process_item_s
{
    struct nsec3_rrsig_updater_result_process_item_s *next;
    zdb_packed_ttlrdata *added_rrsig_sll;
    zdb_packed_ttlrdata *removed_rrsig_sll;
    nsec3_node *item;
};

typedef struct nsec3_rrsig_updater_result_process_item_s nsec3_rrsig_updater_result_process_item_s;

struct nsec3_rrsig_answer_context_s
{
    dnssec_task_s *task;
    struct nsec3_rrsig_updater_result_process_item_s *items;
};

typedef struct nsec3_rrsig_answer_context_s nsec3_rrsig_answer_context_s;

struct nsec3_rrsig_updater_parms
{
    dnssec_task_s task;
    smp_int remaining_quota;
    
    struct nsec3_rrsig_updater_result_process_item_s *to_commit;
    
    s32 quota;  /// maximum number of signatures allowed
    
    // output
    
    u32 good_signatures;
    u32 expired_signatures;
    u32 wrong_signatures;
    
    bool signatures_are_verified;
};

typedef struct nsec3_rrsig_updater_parms nsec3_rrsig_updater_parms;

void nsec3_rrsig_updater_init(nsec3_rrsig_updater_parms *parms, zdb_zone *zone);

ya_result nsec3_rrsig_updater_process_zone(nsec3_rrsig_updater_parms *parms);

void nsec3_rrsig_updater_commit(nsec3_rrsig_updater_parms *parms);

void nsec3_rrsig_updater_finalize(nsec3_rrsig_updater_parms *parms);

/** @} */
