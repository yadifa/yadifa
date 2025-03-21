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
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
// YYYY MM DD hh mm
//    7  4  5  5  6 : 27 bits : one bit is not worth it, shifts it is
//        134217728 :
//         68567040 : 26.031 bits => 27 bits
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/sys_types.h>
#include <dnscore/ptr_vector.h>

#include <time.h>

#include "zone_desc.h"

#define ZONE_POLICY_DATE_YEAR_BASE                              2000

#define DNSSEC_POLICY_KEY_ROLL_COUNT_MAXIMUM                    4

#define DNSSEC_POLICY_MINIMUM_ACTIVATED_TIME_SUGGESTION_SECONDS (7 * 86400)

#define ZONE_POLICY_ABSOLUTE                                    1
#define ZONE_POLICY_RELATIVE                                    2
#define ZONE_POLICY_RULE                                        3 // index to a rule

typedef struct zone_policy_rule_definition_s zone_policy_rule_definition_s;

#define ZONE_POLICY_RULE_ANYMINUTE            0x0fffffffffffffffLL
#define ZONE_POLICY_RULE_ANYWEEK              0x0000000f
#define ZONE_POLICY_RULE_ANYHOUR              0x00ffffff
#define ZONE_POLICY_RULE_ANYDAY               0x7fffffff
#define ZONE_POLICY_RULE_ANYWEEKDAY           0x0000007f
#define ZONE_POLICY_RULE_ANYMONTH             0x00000fff

#define ZONE_POLICY_RELATIVE_TO_GENERATE      0
#define ZONE_POLICY_RELATIVE_TO_PUBLISH       1
#define ZONE_POLICY_RELATIVE_TO_ACTIVATE      2
#define ZONE_POLICY_RELATIVE_TO_INACTIVE      3
#define ZONE_POLICY_RELATIVE_TO_REMOVE        4
#define ZONE_POLICY_RELATIVE_TO_DS_PUBLISH    5
#define ZONE_POLICY_RELATIVE_TO_DS_REMOVE     6

#define DNSSEC_POLICY_FLAGS_REMOVE_OTHER_KEYS 0x01 // remove keys not matching a policy

struct zone_policy_rule_definition_s // rule-like match
{
    uint64_t minute : 60, week : 4;            // 64 / 0 minutes, nth dayname of month
    uint64_t hour : 24, day : 31, weekday : 7; // 62 / 2 hours, day of month, day of week
    uint16_t month : 12;                       // 12 / 4 month of year
};

struct zone_policy_time_type_s
{
    uint32_t reserved : 30, type : 2;
};

struct zone_policy_absolute_s // all zero-based except year 2000-based
{
    uint32_t minute : 6, hour : 5, day : 5, month : 4, year : 7, zeroes : 3, type : 2;
};

// 60 + 24 + 31 + 12 + 7 + 4 = 138

typedef struct zone_policy_rule_s zone_policy_rule_s;

struct zone_policy_rule_s // points to a rule-like match
{
    uint32_t index : 30, type : 2;
};

typedef struct zone_policy_relative_s zone_policy_relative_s;

struct zone_policy_relative_s
{ // 25 bits ~ 1 year, 26 2, 27 ~ 4

    uint32_t seconds : 27, relativeto : 3, type : 2;
};

typedef union zone_policy_date zone_policy_date;

union zone_policy_date
{
    struct zone_policy_time_type_s type;
    struct zone_policy_absolute_s  absolute;
    struct zone_policy_rule_s      rule;
    struct zone_policy_relative_s  relative;
};

typedef struct zone_policy_table_s zone_policy_table_s;

struct zone_policy_table_s
{
    zone_policy_date created;  // from previous created ?
    zone_policy_date publish;  // from created
    zone_policy_date activate; // from publish
    zone_policy_date inactive; // from activate
    zone_policy_date delete;   // from inactive
#if HAS_DS_PUBLICATION_SUPPORT
    zone_policy_date ds_add; // from publish
    zone_policy_date ds_del; // from delete
#endif
};

typedef struct dnssec_denial dnssec_denial;

struct dnssec_denial
{
    char      *name;
    uint8_t   *salt;
    uint32_t   resalting;
    uint16_t   iterations;
    uint8_t    algorithm; // hash algorithm: 1
    uint8_t    salt_length;
    bool       optout; //
    atomic_int rc;
};

typedef struct dnssec_policy_key dnssec_policy_key;

struct dnssec_policy_key
{
    char        *name;      // default
    uint16_t     size;      // 1024
    uint16_t     flags;     // 0
    uint8_t      algorithm; // RSA-SHA256
    volatile int rc;
};

typedef struct dnssec_policy_roll dnssec_policy_roll;

struct dnssec_policy_roll
{
    char                      *name; // default
    struct zone_policy_table_s time_table;
    atomic_int                 rc;
};

typedef struct dnssec_policy_key_suite dnssec_policy_key_suite;

struct dnssec_policy_key_suite
{
    char               *name;
    dnssec_policy_key  *key;
    dnssec_policy_roll *roll;
    atomic_int          rc;
};

struct dnssec_policy
{
    char                 *name; // default
    struct dnssec_denial *denial;
    ptr_vector_t          key_suite;
    uint8_t               flags;
    uint8_t               dnskey_count_max;
    atomic_int            rc;
};

typedef struct dnssec_policy dnssec_policy;

#define DNSSEC_POLICY_COMMAND_INIT         0
#define DNSSEC_POLICY_COMMAND_GENERATE_KEY 1

#define ALARM_KEY_DNSSEC_POLICY_EVENT      16

struct dnssec_policy_queue_parameter_generate_key
{
    struct dnssec_policy_key_suite *suite;
    zone_desc_t                    *zone_desc;
};

typedef struct dnssec_policy_queue dnssec_policy_queue;

struct dnssec_policy_queue
{
    struct dnssec_policy_queue *next;
    uint8_t                    *origin;
    time_t                      epoch; // 0 for ASAP

    // create one key with these parameters ...
    // first signature of a zone ... (with or without key generation)
    // ...

    uint8_t command;
    bool    queued;
    union
    {
        struct dnssec_policy_queue_parameter_generate_key generate_key;
    } parameters;
};

/**
 * Compare two dates together.
 * Absolute with Absolute
 * Relative with Relative
 *
 * Any other combination will return -1
 *
 * @param d1 first date
 * @param d2 second date
 * @return <0,0,>0 if d1 is less than, equal to, or greater than d2
 */

int zone_policy_date_compare(const zone_policy_date *d1, const zone_policy_date *d2);

/**
 * Retrieves the first day of the month.
 *
 * 0 is Sunday
 *
 * @param year 0-based
 * @param month 0-based
 * @return the number of the day of the month or an error code
 */

ya_result zone_policy_get_first_day_from_year_month(int year, int month);

/**
 * Retrieves the first day of the month.
 *
 * 0 is Sunday
 *
 * @param year 0-based
 * @param month 0-based
 * @param week 0 to 4, week of the day
 * @param wday 0 to 6, day of the week, 0 for Sunday
 * @return the number of the day of the month or an error code
 */

ya_result zone_policy_get_mday_from_year_month_week_wday(int year, int month, int week, int wday);

/**
 * Initialises an absolute date from a year, month, week and week-day
 *
 * ie: 2nd Wednesday of January 2001
 *
 * 0 is Sunday
 *
 * @param date the date to initialise
 * @param year 0-based
 * @param month 0-based
 * @param week 0 to 4, week of the day
 * @param wday 0 to 6, day of the week, 0 for Sunday
 * @return an error code
 */

ya_result zone_policy_date_init_from_year_month_week_wday(zone_policy_date *date, int year, int month, int week, int wday);

/**
 * Initialises an absolute date from a UNIX epoch
 *
 * @param date
 * @param epoch
 * @return an error code
 */

ya_result zone_policy_date_init_from_epoch(zone_policy_date *date, time_t epoch);

/**
 * Gets the UNIX epoch from an absolute date
 *
 * @param date
 * @param epoch a pointer to hold the result
 * @return an error code
 */

ya_result zone_policy_date_get_epoch(const zone_policy_date *date, time_t *epoch);

/**
 * Initialises the absolute date with an epoch plus time in seconds.
 *
 * @param date
 * @param epoch an epoch to add the seconds to
 * @param seconds
 * @return an error code
 */

ya_result zone_policy_date_init_after_epoch(zone_policy_date *date, time_t epoch, uint32_t seconds);

/**
 * Initialises the absolute date with an absolute date plus time in seconds.
 *
 * @param date
 * @param from an absolute date to add the seconds to
 * @param seconds
 * @return an error code
 */

ya_result zone_policy_date_init_after_date(zone_policy_date *date, const zone_policy_date *from, uint32_t seconds);

/**
 * Initialises a date using a rule applied on an epoch
 *
 * @param result_date
 * @param rule_date
 * @param after_epoch
 * @return
 */

ya_result zone_policy_date_init_from_rule_applied_with_epoch(zone_policy_date *result_date, const zone_policy_date *rule_date, time_t after_epoch);

/**
 * Initialises an epoch from a rule applied on an epoch
 *
 * @param rule_date
 * @param after_epoch
 * @param result_epoch
 * @return
 */

ya_result                      zone_policy_get_epoch_from_rule_applied_with_epoch(const zone_policy_date *rule_date, time_t after_epoch, time_t *result_epoch);

zone_policy_rule_definition_s *zone_policy_rule_definition_get_from_index(uint32_t index);

zone_policy_rule_definition_s *zone_policy_rule_definition_get_from_rule(const zone_policy_date *rule);

/**
 * This complicated functions initialises a date with the earliest matching of the rule starting from 'from'
 *
 * @param date
 * @param from
 * @param rule
 *
 * @return an error code
 */

ya_result zone_policy_date_init_at_next_date(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule);

ya_result zone_policy_table_init_from_date(zone_policy_table_s *tbl, zone_policy_table_s *with, zone_policy_date *from);

/**
 * Sets the DNSSEC mode of the zone using the policy.
 *
 * Expects zone_desc to be locked (for reading).
 */

ya_result zone_policy_process_dnssec_chain(zone_desc_t *zone_desc);

ya_result zone_policy_process(zone_desc_t *zone_desc);

ya_result zone_policy_roll_create_from_rules(const char *id, const zone_policy_rule_definition_s *generate, const zone_policy_rule_definition_s *publish, const zone_policy_rule_definition_s *activate,
                                             const zone_policy_rule_definition_s *inactive, const zone_policy_rule_definition_s *remove, const zone_policy_rule_definition_s *ds_publish, const zone_policy_rule_definition_s *ds_remove);

ya_result zone_policy_roll_create_from_relatives(const char *id, const zone_policy_relative_s *generate, uint8_t generate_from, const zone_policy_relative_s *publish, uint8_t publish_from, const zone_policy_relative_s *activate,
                                                 uint8_t activate_from, const zone_policy_relative_s *inactive, uint8_t inactive_from, const zone_policy_relative_s *remove, uint8_t remove_from
#if HAS_DS_PUBLICATION_SUPPORT
                                                 ,
                                                 const zone_policy_relative_s *ds_publish, uint8_t ds_publish_from, const zone_policy_relative_s *ds_remove, uint8_t ds_remove_from
#endif
);

dnssec_policy_roll      *dnssec_policy_roll_acquire_from_name(const char *id);
void                     dnssec_policy_roll_release(dnssec_policy_roll *dpr);
ya_result                dnssec_policy_roll_test_all(time_t active_at, uint32_t duration_seconds, bool print_text, bool log_text);

dnssec_denial           *dnssec_policy_denial_create(const char *id, uint8_t algorithm, uint16_t iterations, const uint8_t *salt, uint8_t salt_length, uint32_t resalting, bool optout);
dnssec_denial           *dnssec_policy_denial_acquire(const char *id);
void                     dnssec_policy_denial_release(dnssec_denial *dd);

dnssec_policy_key       *dnssec_policy_key_create(const char *id, uint8_t algorithm, uint16_t size, bool ksk, char *engine);
dnssec_policy_key       *dnssec_policy_key_acquire_from_name(const char *id);
void                     dnssec_policy_key_release(dnssec_policy_key *dpk);

ya_result                dnssec_policy_roll_test_at(struct dnssec_policy_roll *kr, time_t active_at, time_t *will_be_inactive_at, bool print_text, bool log_text);
ya_result                dnssec_policy_roll_test(struct dnssec_policy_roll *kr, time_t active_at, uint32_t duration_seconds, bool print_text, bool log_text);

dnssec_policy_key_suite *dnssec_policy_key_suite_create(const char *id, dnssec_policy_key *dpk, dnssec_policy_roll *dpr);
dnssec_policy_key_suite *dnssec_policy_key_suite_acquire_from_name(const char *id);
void                     dnssec_policy_key_suite_acquire(dnssec_policy_key_suite *dpks);
void                     dnssec_policy_key_suite_release(dnssec_policy_key_suite *dpks);

dnssec_policy           *dnssec_policy_create(char *name, dnssec_denial *denial, ptr_vector_t *key_suite);
dnssec_policy           *dnssec_policy_acquire_from_name(const char *id);
void                     dnssec_policy_acquire(dnssec_policy *dp);
void                     dnssec_policy_release(dnssec_policy *dp);

bool                     dnssec_policy_is_key_matching(dnssec_policy *dp, dnskey_t *key);
bool                     dnssec_policy_defines_ksk(dnssec_policy *dp);

#define CONFIG_DNSSEC_POLICY(fieldname_)                                                                                                                                                                                                       \
    {#fieldname_,                                                                                                                                                                                                                              \
     offsetof(CONFIG_TYPE, fieldname_),                                                                                                                                                                                                        \
     (config_set_field_function *)dnssec_policy_zone_desc_config,                                                                                                                                                                              \
     NULL,                                                                                                                                                                                                                                     \
     {._intptr = 0},                                                                                                                                                                                                                           \
     sizeof(dnssec_policy),                                                                                                                                                                                                                    \
     sizeof(((CONFIG_TYPE *)0)->fieldname_),                                                                                                                                                                                                   \
     CONFIG_TABLE_SOURCE_NONE,                                                                                                                                                                                                                 \
     CONFIG_FIELD_ALLOCATION_DIRECT},

ya_result dnssec_policy_zone_desc_config(const char *value, void *dest, anytype sizeoftarget);

void      dnssec_policy_initialise();

// remove all previously defined policies
void dnssec_policy_finalize();

/**
 * @}
 */
