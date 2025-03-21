/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup alarm
 * @ingroup dnscore
 * @brief Alarm functions
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _ALARM_H
#define _ALARM_H

#include <dnscore/sys_types.h>

/**
 * Of the returned values, ALARM_REARM means to re-do the alarm on the next batch run
 * Any other value is mostly ignored (besides being printed in a log_debug)
 *
 * The cancel flag means that the callback should only cleanup its parameters
 */

typedef ya_result alarm_function_callback(void *, bool cancel);

/**
 * Duplicates stays duplicated
 */
#define ALARM_DUP_NOP            0
/**
 * If there is a earlier duplicate it is removed,
 * if there is a later duplicate this one is dropped.
 * Note that only the epoch is considered for earlier or later determination.
 * Events with the same key are expected to be identical.
 */
#define ALARM_DUP_REMOVE_EARLIER 1
/**
 * If there is a later duplicate it is removed,
 * if there is a earlier duplicate this one is dropped.
 * Note that only the epoch is considered for earlier or later determination.
 * Events with the same key are expected to be identical.
 */
#define ALARM_DUP_REMOVE_LATEST  2

/**
 * You know what a mask is.  It's not used yet because theer is no need (yet).
 */

#define ALARM_DUP_MASK           3

/* alarm handle */

typedef int32_t alarm_t;

#define ALARM_HANDLE_INVALID ((alarm_t)(~0))

struct alarm_event_node_s
{
    struct alarm_event_node_s *hndl_next;
    struct alarm_event_node_s *hndl_prev;
    struct alarm_event_node_s *time_next;
    struct alarm_event_node_s *time_prev;

    uint32_t                   epoch;
    uint32_t                   key;    /* typically a merge of a target ID and an operation flag
                                        *
                                        * ie: zone-alarm-id | signature-update-flag
                                        *
                                        * Id give 8 bits for the operations
                                        * assume 2 millions zones, 4 bits left ...
                                        *
                                        * key has to be unique per handle as its how duplicates are identified
                                        */
    alarm_function_callback *function; /* the function can return an error code or ALARM_REARM to replace the alarm automatically */
    void                    *args;
    const char              *text;   /* human readable for logging */
    alarm_t                  handle; /* reserved */
    uint8_t                  flags;  /* how to handle DUPs with the same key */
};

typedef struct alarm_event_node_s alarm_event_node_t;

void                              alarm_init();
void                              alarm_finalize();

/**
 * Allocates and initialises an event for the alarm.
 *
 * Function must be able to handled the cancel flag.
 *
 * key is used for collision per handle, so an event with collision handling flag has to be carefully setup with this.
 *
 * @param epoch
 * @param key
 * @param function
 * @param args
 * @param flags
 * @param text
 * @return
 */

alarm_event_node_t *alarm_event_new(uint32_t epoch, uint32_t key, alarm_function_callback *function, void *args, uint8_t flags, const char *text);

/**
 * Alarm events MUST be freed with this IF AND ONLY IF THEY HAVEN'T BEEN USED IN alarm_set
 *
 * @param node a pointer to the alarm event structure.
 */

void alarm_event_free(alarm_event_node_t *node);

/**
 * Opens an alarm handle.
 *
 * @parm owner_dnsname a dnsname to show to the owner (typically a zone name or the database)
 *
 * @return the alarm handle.
 */

alarm_t alarm_open(const uint8_t *owner_dnsname);

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

void alarm_set(alarm_t hndl, alarm_event_node_t *desc);

/**
 *
 * Called to resolve all alarm events until a given epoch.
 *
 * DO NOT USE THIS.  ITS USAGE IS RESERVED FOR THE ALARM THREAD.
 */
void alarm_run_tick(uint32_t epoch);

/**
 *
 * Locks the alarm queue.
 *
 * Use with care.
 *
 * Only meant to be used in an independent thread (tcp, remote controller) to send the status of a zone.
 *
 * The usage is: lock, get first, process the list, unlock
 *
 * No other alarm_ function can be called between lock and unlock
 */

void alarm_lock();

/**
 *
 * Unlocks the alarm queue.
 *
 * Use with care.
 *
 * Only meant to be used in an independent thread (tcp, remote controller) to send the status of a zone.
 *
 * The usage is: lock, get first, process the list, unlock
 *
 * No other alarm_ function can be called between lock and unlock
 */

void alarm_unlock();

/**
 *
 * Gets the first element the alarm queue.
 *
 * Only valid between alarm_lock() and alarm_unlock() calls.
 *
 * Use with care.
 *
 * Only meant to be used in an independent thread (tcp, remote controller) to send the status of a zone.
 *
 * The usage is: lock, get first, process the list, unlock
 *
 * No other alarm_ function can be called between lock and unlock
 */

alarm_event_node_t *alarm_get_first(alarm_t hndl);

#endif /* _DNSCORE_H */
/** @} */
