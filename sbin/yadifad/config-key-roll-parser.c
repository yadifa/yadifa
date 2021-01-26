/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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

/** @defgroup yadifad
 *  @ingroup configuration
 *  @brief
 */

#include <strings.h>

#include <dnscore/format.h>
#include "config-key-roll-parser.h"


/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

const char *week[7]   = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
const char *month[12] = { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };

const char *key_roll_actions[7] = {
        KR_ACTION_GENERATE_NAME,
        KR_ACTION_PUBLISH_NAME,
        KR_ACTION_ACTIVATE_NAME,
        KR_ACTION_INACTIVE_NAME,
        KR_ACTION_REMOVE_NAME,
        KR_ACTION_DS_PUBLISH_NAME,
        KR_ACTION_DS_REMOVE_NAME,
};


/// @todo 20160601 gve -- probably this must be changed with accurate values (order!!!)
const u8 key_roll_actions_relative[7] = {
        KR_ACTION_GENERATE,
        KR_ACTION_PUBLISH,
        KR_ACTION_ACTIVATE,
        KR_ACTION_INACTIVE,
        KR_ACTION_REMOVE,
        KR_ACTION_DS_PUBLISH,
        KR_ACTION_DS_REMOVE,
};


/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS


/**
 * @fn ya_result key_roll_item_validate(s32 *dst, const char *src, u32 min, u32 max, const char *array[])
 *
 * @brief check if 'src' item exists in 'array' and put the result in 'dst'
 *
 * @details
 *
 * @param[in] const char *src
 * @param[out] s32       *dst
 *
 * @retval 0 or -1
 *
 * return ya_result
 */
ya_result
key_roll_item_validate(s32 *dst, const char *src, u32 min, u32 max, const char *array[])
{
    if(array != NULL)
    {
        if(max < min)
        {
            u32 tmp = max;
            max = min;
            min = tmp;
        }

        for(u32 i = 0; i <= max - min; i++)
        {
            if(strcasecmp(src, array[i]) == 0)
            {
                *dst = i + min;

                return 0;
            }
        }
    }

    return -1;
}


/**
 * @fn ya_result key_roll_item_parser(char *dest, size_t dest_size, const char **from, const char *delim)
 *
 * @brief parse 'from' which is a word with maybe a 'delim'eter
 *
 * @details
 * 'from' can have several values which if found will be given back in 'dest' and returned with '0'
 * the parser will stop if '\0' has been found, otherwise after finding a value 'dest'
 * return with '1'
 *
 * @param[in] const char *src
 * @param[out] s32       *dst
 *
 * @retval 0 or 1
 *
 * return ya_result
 */
ya_result
key_roll_item_parser(char *dest, size_t dest_size, const char **from, const char *delim)
{
    const char *to = *from;
    for(;;)
    {
        char c = *to;

        if(c == '\0')
        {
            size_t len = to - *from;

            if(len > dest_size)
            {
                return PARSE_BUFFER_TOO_SMALL_ERROR;
            }

            memcpy(dest, *from, len);
            dest[len] = '\0';

            return 0;
        }

        // for every delimiter, test if c if such a delimiter
        // if it is, then

        for(const char *d = delim; *d != 0; d++)
        {
            if(*d == c)
            {
                // end of word
                size_t len = to - *from;

                if(len > dest_size)
                {
                    return PARSE_BUFFER_TOO_SMALL_ERROR;
                }

                memcpy(dest, *from, len);
                dest[len] = '\0';

                // still need to go further
                *from = ++to;

                return 1;
            }
        }
        ++to;
    }
}


/**
 * @fn ya_result key_roll_item_value_check(s32 *dst, char *src, u32 min, u32 max, const char *array[])
 *
 * @brief check is 'src' is in the correct range (min -- max) and that the 'value' is known by the 'array'
 *
 * @details
 * check if known in 'array' is done by 'key_roll_item_validate'
 *
 * @param[in] const char *src
 * @param[out] s32       *dst
 *
 * @retval 0 or return_code
 *
 * return ya_result
 */
ya_result
key_roll_item_value_check(s32 *dst, char *src, u32 min, u32 max, const char *array[])
{
    ya_result return_code;

    if(FAIL(parse_u32_check_range(src, (u32 *)dst, min, max, BASE_10)))
    {
        if((strlen(src) == 1) && (*src == '*'))
        {
            *dst = -1;
        }
        else
        {
            if(FAIL(return_code = key_roll_item_validate(dst, src, min, max, array)))
            {
                return return_code;
            }
        }
    }

    return 0;
}


ya_result
key_roll_item_value_bitmap_get(u64 *value, const char **needle, char *key_roll_item, size_t key_roll_item_size, u32 min, u32 max, const char *array[])
{
    yassert((min < 64) && (max < 64) && (min <= max));
    
    ya_result return_code;

    *needle += strlen(key_roll_item);
    *needle  = (char *)parse_skip_spaces(*needle);
    if(**needle == '\0')
    {
        return PARSER_REACHED_END_OF_LINE;
    }

    if(FAIL(return_code = parse_next_token(key_roll_item, key_roll_item_size, *needle, " \t")))
    {
        return return_code;
    }

    char key_roll_item_part[16];
    const char *needle2 = key_roll_item;

    *value = 0;

    s32 value_temp;

    for(;;)
    {
        value_temp = 0; // because the value may not be set again on the next iteration

        return_code = key_roll_item_parser(key_roll_item_part, sizeof(key_roll_item_part), &needle2, ",");

        if(return_code == 0)
        {
            break;
        }
        else if(return_code == 1)
        {
            if(FAIL(return_code = key_roll_item_value_check(&value_temp, key_roll_item_part, min, max, array)))
            {
                return return_code;
            }
            
            yassert((value_temp >= 0) && (value_temp < 64));

            if(value_temp >= 0)
            {
                *value |= 1ULL << value_temp;
            }
        }
        else
        {
            return return_code;
        }
    }


    return_code = key_roll_item_value_check(&value_temp, key_roll_item_part, min, max, array);
    if(value_temp >= 0)
    {
        *value |= 1ULL << value_temp;
    }
    else
    {
        u64 tmp = 0;
        for(u32 i = min; i <= max; ++i)
        {
            tmp |= 1ULL << i;
        }
        *value = tmp;
    }

    return return_code;
}


ya_result
key_roll_item_value_get(s32 *value, const char **needle, char *key_roll_item, size_t key_roll_item_size, u32 min, u32 max, const char *array[])
{
    ya_result return_code;

    *needle += strlen(key_roll_item);
    *needle  = (char *)parse_skip_spaces(*needle);
    if(**needle == '\0')
    {
        return PARSER_REACHED_END_OF_LINE;
    }

    if(FAIL(return_code = parse_next_token(key_roll_item, key_roll_item_size, *needle, " \t")))
    {
        return return_code;
    }

    return_code = key_roll_item_value_check(value, key_roll_item, min, max, array);


    return return_code;
}


ya_result
key_roll_time_seconds(s32 *dst, const char *src)
{
    ya_result return_code;
    u32 src_len = (u32)strlen(src);

    char lc = src[src_len - 1];

    if(isdigit(lc))
    {
        return_code = parse_s32_check_range_len_base10(src, src_len, dst, 0, MAX_S32);
    }
    else
    {
        s64 mult = 1;
        src_len--;

        switch(lc)
        {
            case 'w':
            case 'W':
                mult = 60 * 60 * 24 * 7;
                break;
            case 'd':
            case 'D':
                mult = 60 * 60 * 24;
                break;
            case 'h':
            case 'H':
                mult = 60 * 60;
                break;
            case 'm':
            case 'M':
                mult = 60;
                break;
            case 's':
            case 'S':
                break;
            default:
            {
                return PARSER_UNKNOWN_TIME_UNIT;
            }
        }

        s32 time32;

        if(ISOK(return_code = parse_s32_check_range_len_base10(src, src_len, &time32, 0, MAX_S32)))
        {
            mult *= time32;

            if(mult <= MAX_S32)
            {
                *dst = (s32)mult;
            }
            else
            {
                return_code = PARSEINT_ERROR;
            }
        }
    }

    return return_code;
}


u8
key_roll_item_relative_to(u8 dst)
{
    return key_roll_actions_relative[dst];
}


ya_result
config_key_roll_parser_line(const char *key_roll_line, key_roll_line_s *krl, u8 action)
{
    ya_result return_code;
    char key_roll_item[256];
    krl->type = KEY_ROLL_LINE_CRON_TYPE;

    if(key_roll_line == NULL)
    {
        return PARSE_EMPTY_ARGUMENT;
    }

    memset(key_roll_item, 0, sizeof(key_roll_item));

    // 1. start parsing 2 first tokens to find key_roll type
    const char *needle = key_roll_line;

    // action
    krl->action = action;
/*
    // get second token
    needle += strlen(key_roll_line);
*/
    needle = (char*)parse_skip_spaces(needle);
    if(*needle == '\0')
    {
        // this is bad
        return -1;
    }

    // 2. if parser find for second token a "+" sign this means the NON-CRON key_roll type
    if(strchr(needle, '+') != NULL)
    {
        if(FAIL(return_code = parse_next_token(key_roll_item, sizeof(key_roll_item), needle, " \t")))
        {
            return return_code;
        }
        krl->type = KEY_ROLL_LINE_RELATIVE_TYPE;

        // relative seconds
        const char *p = key_roll_item;
        p++;

        u32 value;
        if(FAIL(return_code = key_roll_time_seconds((s32*)&value, p)))
        {
            return return_code;
        }
        krl->policy.relative.seconds = value;
        krl->policy.relative.type = ZONE_POLICY_RELATIVE;

        // 3. start parsing next two tokens for RELATIVE key_roll type

        // action relative to
        needle += strlen(key_roll_item);
        needle  = (char*)parse_skip_spaces(needle);
        if(*needle == '\0')
        {
            krl->relative_to = key_roll_item_relative_to((u8)krl->action);
        }
        else
        {
            if(FAIL(return_code = parse_next_token(key_roll_item, sizeof(key_roll_item), needle, " \t")))
            {
                return return_code;
            }

            if(FAIL(return_code = key_roll_item_validate(&krl->relative_to, key_roll_item, 0, 6, key_roll_actions)))
            {
                return return_code;
            }
        }
    }
    else
    {
        // 4. else start parsing next lines for CRON key_roll_type

        u64 bitmap;

        // minutes
        if(FAIL(return_code = key_roll_item_value_bitmap_get(&bitmap, &needle, key_roll_item, sizeof(key_roll_item), 0, 59, NULL)))
        {
            return return_code;
        }
        if(bitmap == 0) bitmap = 0x0fffffffffffffffLLU; // if no bits are set, all have to be
        krl->policy.cron.minute = bitmap;

        // hour
        if(FAIL(return_code = key_roll_item_value_bitmap_get(&bitmap, &needle, key_roll_item, sizeof(key_roll_item), 0, 23, NULL)))
        {
            return return_code;
        }
        if(bitmap == 0) bitmap = 0x0000000000ffffffLLU;
        krl->policy.cron.hour = bitmap;

        // day of month
        if(FAIL(return_code = key_roll_item_value_bitmap_get(&bitmap, &needle, key_roll_item, sizeof(key_roll_item), 1, 31, NULL)))
        {
            return return_code;
        }
        assert((bitmap & 1) == 0);      // because [1;31]
        bitmap >>= 1;                   // because the bitmap needs [0;30]
        if(bitmap == 0) bitmap = 0x000000007fffffffLLU;
        krl->policy.cron.day = bitmap;

        // month
        if(FAIL(return_code = key_roll_item_value_bitmap_get(&bitmap, &needle, key_roll_item, sizeof(key_roll_item), 1, 12, month)))
        {
            return return_code;
        }
        assert((bitmap & 1) == 0);      // because [1;12]
        bitmap >>= 1;                   // because the bitmap needs [0;11]
        if(bitmap == 0) bitmap = 0x0000000000000fffLLU;
        krl->policy.cron.month = (u16)bitmap;

        // day of week
        if(FAIL(return_code = key_roll_item_value_bitmap_get(&bitmap, &needle, key_roll_item, sizeof(key_roll_item), 0, 6, week)))
        {
            return return_code;
        }
        if(bitmap == 0) bitmap = 0x000000000000003fLLU;
        krl->policy.cron.weekday = bitmap;

        // week
        if(FAIL(return_code = key_roll_item_value_bitmap_get(&bitmap, &needle, key_roll_item, sizeof(key_roll_item), 0, 4, NULL)))
        {
            return return_code;
        }
        if(bitmap == 0) bitmap = 0x000000000000000fLLU;
        krl->policy.cron.week = bitmap;
    }

    return 0;
}




