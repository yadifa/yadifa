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
/** @defgroup dnsdbdnssec DNSSEC functions
 *  @ingroup dnsdb
 *  @brief 
 *
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef _DNSSEC_TASK_H
#define	_DNSSEC_TASK_H
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include <dnsdb/zdb_types.h>

#include <dnsdb/dnssec_keystore.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define DNSSEC_TASK_ZONE_KEY_NOP            0
#define DNSSEC_TASK_ZONE_KEY_ADD            1
#define DNSSEC_TASK_ZONE_KEY_LOAD           2
#define DNSSEC_TASK_ZONE_KEY_MASK        0x03

typedef struct dnssec_task dnssec_task;


typedef void* dnssec_thread_function(void*);
typedef ya_result dnssec_task_initializer(dnssec_task*);
typedef ya_result dnssec_task_finalizer(dnssec_task*);

struct dnssec_task
{
    threaded_queue* query;
    dnssec_thread_function* query_thread;
    dnssec_thread_function* answer_thread;
    
    u32 task_flags;
    
#if __SIZEOF_POINTER__ >= 8
    u32 reserved;
#endif

    const char* descriptor_name;

    /*
     * STACK !
     */
    
    dnsname_stack path;
};

typedef struct dnssec_task_descriptor dnssec_task_descriptor;


struct dnssec_task_descriptor
{
    dnssec_task_initializer* initialize_task;
    dnssec_task_finalizer* finalize_task;
    dnssec_thread_function* query_thread;
    dnssec_thread_function* answer_thread;
    const char* name;
};

ya_result   dnssec_process_initialize(dnssec_task* task,dnssec_task_descriptor* desc);

/**
 *
 * Processes all the labels of the zone using dnssec_process_task
 *
 * @param db
 * @param task
 * @return
 */

ya_result   dnssec_process_zone(zdb_zone* db, dnssec_task* task);

#if ZDB_NSEC3_SUPPORT != 0
ya_result dnssec_process_zone_nsec3(zdb_zone* zone, dnssec_task* task);
#endif

/**
 *
 * Processes all the labels of all the zones using dnssec_process_zone
 *
 * @param db
 * @param task
 */

void dnssec_process_database(zdb* db, dnssec_task* task);
void dnssec_process_finalize(dnssec_task* task);

typedef ya_result dnssec_process_task_callback(zdb_zone* zone, dnssec_task* task, void* whatyouwant);

/**
 *
 * @param zone
 * @param task
 * @param callback
 * @param whatyouwant
 * @return
 */

ya_result dnssec_process_task(zdb_zone* zone, dnssec_task* task, dnssec_process_task_callback *callback, void *whatyouwant);

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSSEC_KEY_H */


    /*    ------------------------------------------------------------    */

/** @} */
