#pragma once
#include "yatest.h"

struct yatest_dns_record_s
{
    const uint8_t *fqdn;
    uint16_t       rtype;
    uint16_t       rclass;
    int32_t        rttl;
    uint16_t       rdata_len;
    const uint8_t *rdata;
};

typedef struct yatest_dns_record_s yatest_dns_record_t;

struct yatest_dns_record_text_s
{
    const char    *fqdn;
    uint16_t       rtype;
    uint16_t       rclass;
    int32_t        rttl;
    uint16_t       rdata_len;
    const uint8_t *rdata;
};

typedef struct yatest_dns_record_text_s yatest_dns_record_text_t;

struct yatest_dns_query_s
{
    const char *fqdn;
    uint16_t    rtype;
    uint16_t    rclass;
};

typedef struct yatest_dns_query_s yatest_dns_query_t;

struct yatest_dns_query_to_records_s
{
    const yatest_dns_query_t  *query;
    const yatest_dns_record_t *answer;
};

typedef struct yatest_dns_query_to_records_s yatest_dns_query_to_records_t;

struct yatest_dns_query_to_records_text_s
{
    const yatest_dns_query_t       *query;
    const yatest_dns_record_text_t *answer;
};

typedef struct yatest_dns_query_to_records_text_s yatest_dns_query_to_records_text_t;

static inline size_t                              yatest_dns_name_len(const uint8_t *fqdn)
{
    size_t len = 0;
    for(;;)
    {
        uint8_t label_size = *fqdn;
        if(label_size > 63)
        {
            return 0;
        }
        if(label_size == 0)
        {
            ++len;
            return len;
        }
        ++label_size;
        len += label_size;
        fqdn += label_size;
        if(len > 255)
        {
            return 0;
        }
    }
}
