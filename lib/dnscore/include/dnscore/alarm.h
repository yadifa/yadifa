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
/** @defgroup alarm
 *  @ingroup dnscore
 *  @brief Alarm functions
 *
 * @{
 */
#ifndef _ALARM_H
#define	_ALARM_H

#include <dnscore/sys_types.h>

typedef ya_result alarm_function_callback(void*);

/* 
 * Duplicates stays duplicated
 */
#define ALARM_DUP_NOP                   0
/*
 * If there is a earlier duplicate it is removed,
 * if there is a later duplate this one is dropped.
 */
#define ALARM_DUP_REMOVE_EARLIER        1
/*
 * If there is a later duplicate it is removed,
 * if there is a earlier duplate this one is dropped.
 */
#define ALARM_DUP_REMOVE_LATEST         2

/**
 * You know what a mask is.  It's not used yet because theer is no need (yet).
 */

#define ALARM_DUP_MASK                  3

/* alarm handle */

typedef s32 alarm_t;

#define ALARM_HANDLE_INVALID            ((alarm_t)(~0))

struct alarm_event_node
{
    struct alarm_event_node *hndl_next;
    struct alarm_event_node *hndl_prev;
    struct alarm_event_node *time_next;
    struct alarm_event_node *time_prev;

    u32 epoch;
    u32 key;                            /* typically a merge of a target ID and an operation flag
                                         *
                                         * ie: zone-alarm-id | signature-update-flag
                                         *
                                         * Id give 4 bits for the operations (I think there are actually 2 or 3)
                                         * assume 16 millions zones, 4 bits left ...
                                         */
    alarm_function_callback *function;
    void *args;
    const char *text;                   /* human readable for logging */
    alarm_t handle;                     /* reserved */
    u8 flags;                           /* how to handle DUPs */
};

typedef struct alarm_event_node alarm_event_node;

void alarm_init();

/**
 * Alarm events MUST be allocated through this.
 *
 * @return a pointer to the alarm event structure.
 */

alarm_event_node *alarm_event_alloc();

/**
 * Alarm events MUST be freed to this IF AND ONLY IF THEY HAVEN'T BEEN USED IN alarm_set
 *
 * @param node a pointer to the alarm event structure.
 */

void alarm_event_free(alarm_event_node *node);

/**
 * Opens an alarm handle.
 * 
 * @parm owner_dnsname a dnsname to show to the owner (typically a zone name or the database)
 *
 * @return the alarm handle.
 */

alarm_t alarm_open(const u8 *owner_dnsname);

/**
 * Closes an alarm handle.  Releases all its events.
 *
 * @parm hndl the alarm handle
 */

void alarm_close(alarm_t hndl);

/**
 * 
 * Sets an alarm event.  desc has to be properly setup (everything
 * 
 * @param hndl
 * @param desc
 */

void alarm_set(alarm_t hndl, alarm_event_node *desc);

/**
 *
 * Called to resolve all alarm events until a given epoch.
 *
 * DO NOT USE THIS.  ITS USAGE IS RESERVED FOR THE ALARM THREAD.
 */
void alarm_run_tick(u32 epoch);

/**
 * These three are harmful.  Use with care.
 * They are only meant to be used in an independent thread (tcp, remote controller) to send the status of a zone.
 *
 * The usage is: lock, get first, process the list, unlock
 * 
 * No other alarm_ function can be called between lock and unlock
 */

void alarm_lock();
void alarm_unlock();
alarm_event_node *alarm_get_first(alarm_t hndl);


#ifdef	__cplusplus
}
#endif

#endif	/* _DNSCORE_H */
/** @} */

/*----------------------------------------------------------------------------*/

