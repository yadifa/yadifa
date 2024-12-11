/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#include "yatest.h"
#include <dnscore/dnscore.h>
#include <dnscore/acl.h>
#include <dnscore/ptr_treeset.h>

#define MYKEY_NAME        (const uint8_t *)"\005mykey"
#define NOTMYKEY_NAME     (const uint8_t *)"\010notmykey"

#define ACL_MESSAGE_COUNT 12
#define ACL_LIST_COUNT    108

// there are 18 optimised handlers for ACLs.

/*
 * R: reject
 * A: accept
 * F: uses a filter
 *
 * V4 V6 TSIG: one letter per category
 *
 * RRI ARI FRI
 * RAI AAI FAI
 * RFI AFI FFI
 * RRF ARF FRF
 * RAF AAF FAF
 * RFF AFF FFF
 */

#define ACL_V4_LINE       "127.0.0.1,!127.0.0.2,192.168.1.0/24,!10.0.0.0/24"
#define ACL_V6_LINE       "::1,!::2,2002::/16,!2003::/16"
#define ACL_K_LINE        "key mykey"
#define ACL_V4B_LINE      "127.0.0.2,!127.0.0.3,192.168.2.0/24,!10.0.1.0/24"
#define ACL_V6B_LINE      "::2,!::3,2004::/16,!2005::/16"
#define ACL_KB_LINE       "key notmykey"
#define ACL_ANY_LINE      "any"
#define ACL_NONE_LINE     "none"
#define ACL_EMPTY_LINE    ""

#define S                 ","

#define V4A               "0.0.0.0/0"
#define V4R               "!0.0.0.0/0"
#define V4F               "127.0.0.1"
#define V6A               "::0/0"
#define V6R               "!::0/0"
#define V6F               "::1"
#define K                 "key mykey"

#define N4F               "!127.0.0.2" S V4F
#define N6F               "!::2" S V6F

#define V4Ap              "v4a"
#define V4Rp              "v4r"
#define V4Fp              "v4f"
#define V6Ap              "v6a"
#define V6Rp              "v6r"
#define V6Fp              "v6f"
#define Kp                "k"

#define ACL_RRI_LINE      V4R S V6R
#define ACL_ARI_LINE      V4A S V6R
#define ACL_FRI_LINE      V4F S V6R
#define ACL_RAI_LINE      V4R S V6A
#define ACL_AAI_LINE      V4A S V6A
#define ACL_FAI_LINE      V4F S V6A
#define ACL_RFI_LINE      V4R S V6F
#define ACL_AFI_LINE      V4A S V6F
#define ACL_FFI_LINE      V4F S V6F
#define ACL_RRF_LINE      V4R S V6R S K
#define ACL_ARF_LINE      V4A S V6R S K
#define ACL_FRF_LINE      V4F S V6R S K
#define ACL_RAF_LINE      V4R S V6A S K
#define ACL_AAF_LINE      V4A S V6A S K
#define ACL_FAF_LINE      V4F S V6A S K
#define ACL_RFF_LINE      V4R S V6F S K
#define ACL_AFF_LINE      V4A S V6F S K
#define ACL_FFF_LINE      V4F S V6F S K

#define ACL_RRIp_LINE     V4Rp S V6Rp
#define ACL_ARIp_LINE     V4Ap S V6Rp
#define ACL_FRIp_LINE     V4Fp S V6Rp
#define ACL_RAIp_LINE     V4Rp S V6Ap
#define ACL_AAIp_LINE     V4Ap S V6Ap
#define ACL_FAIp_LINE     V4Fp S V6Ap
#define ACL_RFIp_LINE     V4Rp S V6Fp
#define ACL_AFIp_LINE     V4Ap S V6Fp
#define ACL_FFIp_LINE     V4Fp S V6Fp
#define ACL_RRFp_LINE     V4Rp S V6Rp S Kp
#define ACL_ARFp_LINE     V4Ap S V6Rp S Kp
#define ACL_FRFp_LINE     V4Fp S V6Rp S Kp
#define ACL_RAFp_LINE     V4Rp S V6Ap S Kp
#define ACL_AAFp_LINE     V4Ap S V6Ap S Kp
#define ACL_FAFp_LINE     V4Fp S V6Ap S Kp
#define ACL_RFFp_LINE     V4Rp S V6Fp S Kp
#define ACL_AFFp_LINE     V4Ap S V6Fp S Kp
#define ACL_FFFp_LINE     V4Fp S V6Fp S Kp

#define ACL_NRRI_LINE     V4R S V6R
#define ACL_NARI_LINE     V4A S V6R
#define ACL_NFRI_LINE     N4F S V6R
#define ACL_NRAI_LINE     V4R S V6A
#define ACL_NAAI_LINE     V4A S V6A
#define ACL_NFAI_LINE     N4F S V6A
#define ACL_NRFI_LINE     V4R S N6F
#define ACL_NAFI_LINE     V4A S N6F
#define ACL_NFFI_LINE     N4F S N6F
#define ACL_NRRF_LINE     V4R S V6R S K
#define ACL_NARF_LINE     V4A S V6R S K
#define ACL_NFRF_LINE     N4F S V6R S K
#define ACL_NRAF_LINE     V4R S V6A S K
#define ACL_NAAF_LINE     V4A S V6A S K
#define ACL_NFAF_LINE     N4F S V6A S K
#define ACL_NRFF_LINE     V4R S N6F S K
#define ACL_NAFF_LINE     V4A S N6F S K
#define ACL_NFFF_LINE     N4F S N6F S K

#define ACL_COMBO_COUNT   18

static const char *acl_line_each_combo[ACL_COMBO_COUNT] = {ACL_RRI_LINE,
                                                           ACL_ARI_LINE,
                                                           ACL_FRI_LINE,
                                                           ACL_RAI_LINE,
                                                           ACL_AAI_LINE,
                                                           ACL_FAI_LINE,
                                                           ACL_RFI_LINE,
                                                           ACL_AFI_LINE,
                                                           ACL_FFI_LINE,
                                                           ACL_RRF_LINE,
                                                           ACL_ARF_LINE,
                                                           ACL_FRF_LINE,
                                                           ACL_RAF_LINE,
                                                           ACL_AAF_LINE,
                                                           ACL_FAF_LINE,
                                                           ACL_RFF_LINE,
                                                           ACL_AFF_LINE,
                                                           ACL_FFF_LINE};

static const char *acl_line_each_combop[ACL_COMBO_COUNT] = {ACL_RRIp_LINE,
                                                            ACL_ARIp_LINE,
                                                            ACL_FRIp_LINE,
                                                            ACL_RAIp_LINE,
                                                            ACL_AAIp_LINE,
                                                            ACL_FAIp_LINE,
                                                            ACL_RFIp_LINE,
                                                            ACL_AFIp_LINE,
                                                            ACL_FFIp_LINE,
                                                            ACL_RRFp_LINE,
                                                            ACL_ARFp_LINE,
                                                            ACL_FRFp_LINE,
                                                            ACL_RAFp_LINE,
                                                            ACL_AAFp_LINE,
                                                            ACL_FAFp_LINE,
                                                            ACL_RFFp_LINE,
                                                            ACL_AFFp_LINE,
                                                            ACL_FFFp_LINE};

static const char *acl_nline_each_combo[ACL_COMBO_COUNT] = {ACL_NRRI_LINE,
                                                            ACL_NARI_LINE,
                                                            ACL_NFRI_LINE,
                                                            ACL_NRAI_LINE,
                                                            ACL_NAAI_LINE,
                                                            ACL_NFAI_LINE,
                                                            ACL_NRFI_LINE,
                                                            ACL_NAFI_LINE,
                                                            ACL_NFFI_LINE,
                                                            ACL_NRRF_LINE,
                                                            ACL_NARF_LINE,
                                                            ACL_NFRF_LINE,
                                                            ACL_NRAF_LINE,
                                                            ACL_NAAF_LINE,
                                                            ACL_NFAF_LINE,
                                                            ACL_NRFF_LINE,
                                                            ACL_NAFF_LINE,
                                                            ACL_NFFF_LINE};

static bool        allow_any_v4(int index) { return index % 3 == 1; }

static bool        allow_any_v6(int index)
{
    index /= 3;
    return index % 3 == 1;
}

static bool allow_v4(int index) { return allow_any_v4(index) /* || allow_any_v6(index)*/; }

static bool allow_v4l(int index) { return index % 3 == 2; }

static bool allow_v6(int index) { return /*allow_any_v4(index) ||*/ allow_any_v6(index); }

static bool allow_v6l(int index)
{
    index /= 3;
    return index % 3 == 2;
}

static bool allow_mykey_only(int index) { return index >= 9; }

#define ACL_UNKNOWNTSIG_KEY_LINE "key myunknownkey"

static const uint8_t     mykey_mac[] = {0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
static const uint8_t     notmykey_mac[] = {0x91, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

static const uint8_t     v4_127_0_0_1[4] = {127, 0, 0, 1};
static const uint8_t     v4_127_0_0_2[4] = {127, 0, 0, 2};
static const uint8_t     v6_1[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t     v6_2[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

static access_control_t  ac;
static access_control_t  ac2;
static access_control_t  ac3;
static access_control_t  ac4;
static access_control_t  ac5;
static access_control_t  ac6;
static access_control_t  ac_ipv4_mask[32 + 1];
static access_control_t  ac_ipv6_mask[128 + 1];
static access_control_t  ac_ipv4_mask_full[32 + 1];
static access_control_t  ac_ipv6_mask_full[128 + 1];
static access_control_t  ac_copy;
static access_control_t  ac_combo[ACL_COMBO_COUNT];
static access_control_t  ac_combop[ACL_COMBO_COUNT];
static access_control_t  ac_combon[ACL_COMBO_COUNT];
static access_control_t *acp;
static dns_message_t    *message_v4_127_0_0_1;
static dns_message_t    *message_v4_127_0_0_2;
static dns_message_t    *message_v6_1;
static dns_message_t    *message_v6_2;
static dns_message_t    *message_v4_127_0_0_1_mykey;
static dns_message_t    *message_v4_127_0_0_2_mykey;
static dns_message_t    *message_v6_1_mykey;
static dns_message_t    *message_v6_2_mykey;
static dns_message_t    *message_v4_127_0_0_1_notmykey;
static dns_message_t    *message_v4_127_0_0_2_notmykey;
static dns_message_t    *message_v6_1_notmykey;
static dns_message_t    *message_v6_2_notmykey;

static dns_message_t    *messages[ACL_MESSAGE_COUNT];

address_match_list_t    *match_list[ACL_LIST_COUNT];

static dns_message_t    *acl_test_create_message()
{
    dns_message_t *mesg = dns_message_new_instance();
    dns_message_make_query(mesg, 1, (const uint8_t *)"\006yadifa\002eu", TYPE_A, CLASS_IN);
    return mesg;
}

static dns_message_t *acl_test_create_received_signed_message(host_address_t *sender, tsig_key_t *key)
{
    dns_message_t *mesg = acl_test_create_message();
    dns_message_set_answer(mesg);
    dns_message_set_sender_from_host_address(mesg, sender);
    if(key != NULL)
    {
        dns_message_tsig_set_key(mesg, key);
        dns_message_sign_answer(mesg);
    }
    return mesg;
}

static inline uint32_t acl_address_match_list_size(const address_match_list_t *aml) { return (aml != NULL) ? (aml->limit - aml->items) : 0; }

static void            acl_item_print_test_make_ipv4_mask(char *text, int maskbits)
{
    uint8_t ipv4[4] = {0, 0, 0, 0};
    if((maskbits & 7) == 0)
    {
        if((maskbits & 31) != 0)
        {
            sprintf(text, "192.168.1.1/%i", maskbits);
        }
        else
        {
            sprintf(text, "192.168.1.1");
        }
    }
    else
    {
        int i = 0;
        while(maskbits > 8)
        {
            ipv4[i] = 255;
            maskbits -= 8;
            ++i;
        }
        if(maskbits > 0)
        {
            ipv4[i] = 255 << (8 - maskbits);
        }
        sprintf(text, "192.168.1.1/%i.%i.%i.%i", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
    }
}

static void acl_item_print_test_make_ipv6_mask(char *text, int maskbits)
{
    uint16_t ipv6[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    if((maskbits & 7) == 0)
    {
        if((maskbits & 127) != 0)
        {
            sprintf(text, "2002:ffff:eeee:dddd:cccc::1/%i", maskbits);
        }
        else
        {
            sprintf(text, "2002:ffff:eeee:dddd:cccc::1");
        }
    }
    else
    {
        sprintf(text, "2002:ffff:eeee:dddd:cccc::1/");

        int         i = 0;
        const char *sep = "";
        while(maskbits > 16)
        {
            ipv6[i] = 65535;
            maskbits -= 16;
            ++i;
            strcat(text, sep);
            strcat(text, "ffff");
            sep = ":";
        }
        if(maskbits > 0)
        {
            ipv6[i] = 65535 << (16 - maskbits);
            char tmp[6];
            snprintf(tmp, sizeof(tmp), "%s%04x", sep, ipv6[i]);
            strcat(text, tmp);
            ++i;
        }
        if(i < 7)
        {
            strcat(text, "::");
        }
        else
        {
            if(i == 7)
            {
                strcat(text, ":0");
            }
        }
    }
}

static void acl_messages_init()
{
    host_address_t *ha_v4_127_0_0_1 = host_address_new_instance_ipv4(v4_127_0_0_1, NU16(53));
    host_address_t *ha_v4_127_0_0_2 = host_address_new_instance_ipv4(v4_127_0_0_2, NU16(53));
    host_address_t *ha_v6_1 = host_address_new_instance_ipv6(v6_1, NU16(53));
    host_address_t *ha_v6_2 = host_address_new_instance_ipv6(v6_2, NU16(53));

    tsig_key_t     *mykey = tsig_get(MYKEY_NAME);
    tsig_key_t     *notmykey = tsig_get(NOTMYKEY_NAME);

    message_v4_127_0_0_1 = acl_test_create_received_signed_message(ha_v4_127_0_0_1, NULL);
    message_v4_127_0_0_2 = acl_test_create_received_signed_message(ha_v4_127_0_0_2, NULL);
    message_v6_1 = acl_test_create_received_signed_message(ha_v6_1, NULL);
    message_v6_2 = acl_test_create_received_signed_message(ha_v6_2, NULL);

    message_v4_127_0_0_1_mykey = acl_test_create_received_signed_message(ha_v4_127_0_0_1, mykey);
    message_v4_127_0_0_2_mykey = acl_test_create_received_signed_message(ha_v4_127_0_0_2, mykey);
    message_v6_1_mykey = acl_test_create_received_signed_message(ha_v6_1, mykey);
    message_v6_2_mykey = acl_test_create_received_signed_message(ha_v6_2, mykey);

    message_v4_127_0_0_1_notmykey = acl_test_create_received_signed_message(ha_v4_127_0_0_1, notmykey);
    message_v4_127_0_0_2_notmykey = acl_test_create_received_signed_message(ha_v4_127_0_0_2, notmykey);
    message_v6_1_notmykey = acl_test_create_received_signed_message(ha_v6_1, notmykey);
    message_v6_2_notmykey = acl_test_create_received_signed_message(ha_v6_2, notmykey);

    messages[0] = message_v4_127_0_0_1;
    messages[1] = message_v4_127_0_0_2;
    messages[2] = message_v6_1;
    messages[3] = message_v6_2;
    messages[4] = message_v4_127_0_0_1_mykey;
    messages[5] = message_v4_127_0_0_2_mykey;
    messages[6] = message_v6_1_mykey;
    messages[7] = message_v6_2_mykey;
    messages[8] = message_v4_127_0_0_1_notmykey;
    messages[9] = message_v4_127_0_0_2_notmykey;
    messages[10] = message_v6_1_notmykey;
    messages[11] = message_v6_2_notmykey;
}

static void acl_test_define(const char *name, const char *definition)
{
    ya_result ret = acl_definition_add(name, definition);

    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_definition_add failed with %x (2)", ret);
        exit(1);
    }
}

static int acl_test_init()
{
    ya_result ret;
    dnscore_init();
    acl_register_errors();
    output_stream_t os;
    bytearray_output_stream_init(&os, NULL, 0);

    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA1);
    ret = tsig_register(NOTMYKEY_NAME, notmykey_mac, sizeof(notmykey_mac), HMAC_SHA1);

    if(FAIL(ret))
    {
        yatest_err("tsig_register failed with %x", ret);
        return 1;
    }

    acl_test_define("a-test", V4A S V6R);

    acl_messages_init();

    ret = acl_access_control_init_from_text(&ac, ACL_V4_LINE, ACL_V6_LINE, ACL_K_LINE, ACL_ANY_LINE, ACL_NONE_LINE, ACL_EMPTY_LINE);
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_access_control_init_from_text failed with %x", ret);
        return 1;
    }

    ret = acl_access_control_init_from_text(&ac2, ACL_V4B_LINE, ACL_V6B_LINE, ACL_KB_LINE, ACL_ANY_LINE, ACL_NONE_LINE, ACL_EMPTY_LINE);
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_access_control_init_from_text failed with %x (2)", ret);
        return 1;
    }

    ret = acl_definition_add("dummy", "any");
    if(FAIL(ret))
    {
        yatest_err("acl_definition_add dummy failed");
        return 1;
    }

    ret = acl_definition_add("dummy", "any");
    if(ret != ACL_DUPLICATE_ENTRY)
    {
        yatest_err("acl_definition_add dummy duplicate didn't fail");
        return 1;
    }

    ret = acl_definition_add("thisiswrong", "1.1.1.1/123");
    if(ISOK(ret))
    {
        yatest_err("acl_definition_add this-is-wrong didn't fail");
        return 1;
    }

    acl_test_define("v4", ACL_V4_LINE);
    acl_test_define("v6", ACL_V6_LINE);
    acl_test_define("a", ACL_ANY_LINE);
    acl_test_define("n", ACL_NONE_LINE);
    acl_test_define("v4b", ACL_V4B_LINE);
    acl_test_define("v6b", ACL_V6B_LINE);
    acl_test_define("kb", ACL_KB_LINE);

    acl_test_define("v4a", V4A);
    acl_test_define("v4r", V4R);
    acl_test_define("v4f", V4F);
    acl_test_define("v6a", V6A);
    acl_test_define("v6r", V6R);
    acl_test_define("v6f", V6F);
    acl_test_define("k", K);

    ret = acl_access_control_init_from_text(&ac3, "v4", "v6", "k", "a", "n", "");
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_access_control_init_from_text failed with %x (3)", ret);
        return 1;
    }

    ret = acl_access_control_init_from_text(&ac4, "!" ACL_V4_LINE, "!" ACL_V6_LINE, "!" ACL_K_LINE, "!" ACL_ANY_LINE, "!" ACL_NONE_LINE, ACL_EMPTY_LINE);
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_access_control_init_from_text failed with %x (4)", ret);
        return 1;
    }

    ret = acl_access_control_init_from_text(&ac5, "!" ACL_V4B_LINE, "!" ACL_V6B_LINE, "!" ACL_KB_LINE, "!" ACL_ANY_LINE, "!" ACL_NONE_LINE, ACL_EMPTY_LINE);
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_access_control_init_from_text failed with %x (5)", ret);
        return 1;
    }

    ret = acl_access_control_init_from_text(&ac6, "any", "none", "any", "none", "any", "");
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_access_control_init_from_text failed with %x (6)", ret);
        return 1;
    }

    for(int i = 0; i <= 32; ++i)
    {
        char text[64];
        snprintf(text, sizeof(text), "192.168.1.1/%i", i);
        ret = acl_access_control_init_from_text(&ac_ipv4_mask[i], text, text, text, text, text, text);
        if(FAIL(ret))
        {
            osformatln(termerr, "error: %r", ret);
            flusherr();
            yatest_err("acl_access_control_init_from_text failed with %x ipv4/%i", ret, i);
            return 1;
        }
    }

    for(int i = 0; i <= 128; ++i)
    {
        char text[64];
        snprintf(text, sizeof(text), "2002:ffff:eeee:dddd:cccc::1/%i", i);
        ret = acl_access_control_init_from_text(&ac_ipv6_mask[i], text, text, text, text, text, text);
        if(FAIL(ret))
        {
            osformatln(termerr, "error: %r", ret);
            flusherr();
            yatest_err("acl_access_control_init_from_text failed with %x ipv6/%i", ret, i);
            return 1;
        }
    }

    for(int i = 0; i <= 32; ++i)
    {
        char text[64];
        acl_item_print_test_make_ipv4_mask(text, i);
        ret = acl_access_control_init_from_text(&ac_ipv4_mask_full[i], text, text, text, text, text, text);
        if(FAIL(ret))
        {
            osformatln(termerr, "error: %r", ret);
            flusherr();
            yatest_err("acl_access_control_init_from_text failed with %x ipv4=%s (%i)", ret, text, i);
            return 1;
        }
    }

    for(int i = 0; i <= 128; ++i)
    {
        char text[128];
        acl_item_print_test_make_ipv6_mask(text, i);
        ret = acl_access_control_init_from_text(&ac_ipv6_mask_full[i], text, text, text, text, text, text);
        if(FAIL(ret))
        {
            osformatln(termerr, "error: %r", ret);
            flusherr();
            yatest_err("acl_access_control_init_from_text failed with %x ipv6=%s (%i)", ret, text, i);
            return 1;
        }
    }

    for(int i = 0; i <= 32; ++i)
    {
        bool equals = acl_address_control_equals(&ac_ipv4_mask[i], &ac_ipv4_mask_full[i]);
        if(!equals)
        {
            yatest_err("acl_address_control_equals failed to match ipv4/%i", i);
            return 1;
        }
    }

    for(int i = 0; i <= 128; ++i)
    {
        bool equals = acl_address_control_equals(&ac_ipv6_mask[i], &ac_ipv6_mask_full[i]);
        if(!equals)
        {
            yatest_err("acl_address_control_equals failed to match ipv6/%i", i);
            return 1;
        }
    }

    for(int i = 0; i < ACL_COMBO_COUNT; ++i)
    {
        ret = acl_access_control_init_from_text(&ac_combo[i], acl_line_each_combo[i], acl_line_each_combo[i], acl_line_each_combo[i], acl_line_each_combo[i], acl_line_each_combo[i], acl_line_each_combo[i]);
        if(FAIL(ret))
        {
            osformatln(termerr, "error: #%i: '%s': %r", i, acl_line_each_combo[i], ret);
            flusherr();
            yatest_err("acl_access_control_init_from_text failed with '%s': %x (ac_combo)", acl_line_each_combo[i], ret);
            return 1;
        }

        acl_address_match_set_to_stream(&os, &ac_combo[i].allow_query);
        output_stream_write_u8(&os, 0);
        yatest_log("ac_combo[%i] = '%s' = '%s'", i, acl_line_each_combo[i], bytearray_output_stream_buffer(&os));
        bytearray_output_stream_reset(&os);
        /*
                acl_check_access_filter_callback *cafcb = acl_get_check_access_filter(&ac_combo[i].allow_query);
                yatest_log("combo[%i] check = %p", i, cafcb);

                acl_query_access_filter_callback *qafcb = acl_get_query_access_filter(&ac_combo[i].allow_query);
                yatest_log("combo[%i] query = %p", i, qafcb);
        */
    }

    for(int i = 0; i < ACL_COMBO_COUNT; ++i)
    {
        ret = acl_access_control_init_from_text(&ac_combop[i], acl_line_each_combop[i], acl_line_each_combop[i], acl_line_each_combop[i], acl_line_each_combop[i], acl_line_each_combop[i], acl_line_each_combop[i]);
        if(FAIL(ret))
        {
            osformatln(termerr, "error: #%i: '%s': %r", i, acl_line_each_combo[i], ret);
            flusherr();
            yatest_err("acl_access_control_init_from_text failed with '%s': %x (ac_combop)", acl_line_each_combo[i], ret);
            return 1;
        }

        acl_check_access_filter_callback *cafcb = acl_get_check_access_filter(&ac_combop[i].allow_query);
        yatest_log("combop[%i] check = %p", i, cafcb);

        acl_query_access_filter_callback *qafcb = acl_get_query_access_filter(&ac_combop[i].allow_query);
        yatest_log("combop[%i] query = %p", i, qafcb);
    }

    for(int i = 0; i < ACL_COMBO_COUNT; ++i)
    {
        ret = acl_access_control_init_from_text(&ac_combon[i], acl_nline_each_combo[i], acl_nline_each_combo[i], acl_nline_each_combo[i], acl_nline_each_combo[i], acl_nline_each_combo[i], acl_nline_each_combo[i]);
        if(FAIL(ret))
        {
            osformatln(termerr, "error: #%i: '%s': %r", i, acl_line_each_combo[i], ret);
            flusherr();
            yatest_err("acl_access_control_init_from_text failed with '%s': %x (ac_combon)", acl_line_each_combo[i], ret);
            return 1;
        }

        acl_check_access_filter_callback *cafcb = acl_get_check_access_filter(&ac_combon[i].allow_query);
        yatest_log("combon[%i] check = %p", i, cafcb);

        acl_query_access_filter_callback *qafcb = acl_get_query_access_filter(&ac_combon[i].allow_query);
        yatest_log("combon[%i] query = %p", i, qafcb);
    }

    acl_access_control_copy(&ac_copy, &ac);

    acp = acl_access_control_new_instance();
    acl_access_control_copy(acp, &ac);

    int index = 0;
    match_list[index++] = &ac.allow_query.ipv4;
    match_list[index++] = &ac.allow_query.ipv6;
    match_list[index++] = &ac.allow_query.tsig;
    match_list[index++] = &ac.allow_update.ipv4;
    match_list[index++] = &ac.allow_update.ipv6;
    match_list[index++] = &ac.allow_update.tsig;
    match_list[index++] = &ac.allow_update_forwarding.ipv4;
    match_list[index++] = &ac.allow_update_forwarding.ipv6;
    match_list[index++] = &ac.allow_update_forwarding.tsig;
    match_list[index++] = &ac.allow_transfer.ipv4;
    match_list[index++] = &ac.allow_transfer.ipv6;
    match_list[index++] = &ac.allow_transfer.tsig;
    match_list[index++] = &ac.allow_notify.ipv4;
    match_list[index++] = &ac.allow_notify.ipv6;
    match_list[index++] = &ac.allow_notify.tsig;
    match_list[index++] = &ac.allow_control.ipv4;
    match_list[index++] = &ac.allow_control.ipv6;
    match_list[index++] = &ac.allow_control.tsig;
    match_list[index++] = &ac2.allow_query.ipv4;
    match_list[index++] = &ac2.allow_query.ipv6;
    match_list[index++] = &ac2.allow_query.tsig;
    match_list[index++] = &ac2.allow_update.ipv4;
    match_list[index++] = &ac2.allow_update.ipv6;
    match_list[index++] = &ac2.allow_update.tsig;
    match_list[index++] = &ac2.allow_update_forwarding.ipv4;
    match_list[index++] = &ac2.allow_update_forwarding.ipv6;
    match_list[index++] = &ac2.allow_update_forwarding.tsig;
    match_list[index++] = &ac2.allow_transfer.ipv4;
    match_list[index++] = &ac2.allow_transfer.ipv6;
    match_list[index++] = &ac2.allow_transfer.tsig;
    match_list[index++] = &ac2.allow_notify.ipv4;
    match_list[index++] = &ac2.allow_notify.ipv6;
    match_list[index++] = &ac2.allow_notify.tsig;
    match_list[index++] = &ac2.allow_control.ipv4;
    match_list[index++] = &ac2.allow_control.ipv6;
    match_list[index++] = &ac2.allow_control.tsig;
    match_list[index++] = &ac3.allow_query.ipv4;
    match_list[index++] = &ac3.allow_query.ipv6;
    match_list[index++] = &ac3.allow_query.tsig;
    match_list[index++] = &ac3.allow_update.ipv4;
    match_list[index++] = &ac3.allow_update.ipv6;
    match_list[index++] = &ac3.allow_update.tsig;
    match_list[index++] = &ac3.allow_update_forwarding.ipv4;
    match_list[index++] = &ac3.allow_update_forwarding.ipv6;
    match_list[index++] = &ac3.allow_update_forwarding.tsig;
    match_list[index++] = &ac3.allow_transfer.ipv4;
    match_list[index++] = &ac3.allow_transfer.ipv6;
    match_list[index++] = &ac3.allow_transfer.tsig;
    match_list[index++] = &ac3.allow_notify.ipv4;
    match_list[index++] = &ac3.allow_notify.ipv6;
    match_list[index++] = &ac3.allow_notify.tsig;
    match_list[index++] = &ac3.allow_control.ipv4;
    match_list[index++] = &ac3.allow_control.ipv6;
    match_list[index++] = &ac3.allow_control.tsig;
    match_list[index++] = &ac4.allow_query.ipv4;
    match_list[index++] = &ac4.allow_query.ipv6;
    match_list[index++] = &ac4.allow_query.tsig;
    match_list[index++] = &ac4.allow_update.ipv4;
    match_list[index++] = &ac4.allow_update.ipv6;
    match_list[index++] = &ac4.allow_update.tsig;
    match_list[index++] = &ac4.allow_update_forwarding.ipv4;
    match_list[index++] = &ac4.allow_update_forwarding.ipv6;
    match_list[index++] = &ac4.allow_update_forwarding.tsig;
    match_list[index++] = &ac4.allow_transfer.ipv4;
    match_list[index++] = &ac4.allow_transfer.ipv6;
    match_list[index++] = &ac4.allow_transfer.tsig;
    match_list[index++] = &ac4.allow_notify.ipv4;
    match_list[index++] = &ac4.allow_notify.ipv6;
    match_list[index++] = &ac4.allow_notify.tsig;
    match_list[index++] = &ac4.allow_control.ipv4;
    match_list[index++] = &ac4.allow_control.ipv6;
    match_list[index++] = &ac4.allow_control.tsig;
    match_list[index++] = &ac5.allow_query.ipv4;
    match_list[index++] = &ac5.allow_query.ipv6;
    match_list[index++] = &ac5.allow_query.tsig;
    match_list[index++] = &ac5.allow_update.ipv4;
    match_list[index++] = &ac5.allow_update.ipv6;
    match_list[index++] = &ac5.allow_update.tsig;
    match_list[index++] = &ac5.allow_update_forwarding.ipv4;
    match_list[index++] = &ac5.allow_update_forwarding.ipv6;
    match_list[index++] = &ac5.allow_update_forwarding.tsig;
    match_list[index++] = &ac5.allow_transfer.ipv4;
    match_list[index++] = &ac5.allow_transfer.ipv6;
    match_list[index++] = &ac5.allow_transfer.tsig;
    match_list[index++] = &ac5.allow_notify.ipv4;
    match_list[index++] = &ac5.allow_notify.ipv6;
    match_list[index++] = &ac5.allow_notify.tsig;
    match_list[index++] = &ac5.allow_control.ipv4;
    match_list[index++] = &ac5.allow_control.ipv6;
    match_list[index++] = &ac5.allow_control.tsig;
    match_list[index++] = &ac6.allow_query.ipv4;
    match_list[index++] = &ac6.allow_query.ipv6;
    match_list[index++] = &ac6.allow_query.tsig;
    match_list[index++] = &ac6.allow_update.ipv4;
    match_list[index++] = &ac6.allow_update.ipv6;
    match_list[index++] = &ac6.allow_update.tsig;
    match_list[index++] = &ac6.allow_update_forwarding.ipv4;
    match_list[index++] = &ac6.allow_update_forwarding.ipv6;
    match_list[index++] = &ac6.allow_update_forwarding.tsig;
    match_list[index++] = &ac6.allow_transfer.ipv4;
    match_list[index++] = &ac6.allow_transfer.ipv6;
    match_list[index++] = &ac6.allow_transfer.tsig;
    match_list[index++] = &ac6.allow_notify.ipv4;
    match_list[index++] = &ac6.allow_notify.ipv6;
    match_list[index++] = &ac6.allow_notify.tsig;
    match_list[index++] = &ac6.allow_control.ipv4;
    match_list[index++] = &ac6.allow_control.ipv6;
    match_list[index++] = &ac6.allow_control.tsig;

    if(index != ACL_LIST_COUNT)
    {
        yatest_err("bug in the test setup index=%i, expected %i", index, ACL_LIST_COUNT);
        exit(1);
    }

    yatest_log("acl_entry_count: %i", acl_entry_count());

    int                    measured_entry_count = 0;
    ptr_treemap_iterator_t iter;
    acl_entry_iterator_init(&iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        const char         *name = (const char *)node->key;
        // acl_entry_t *entry = (acl_entry_t*)node->value;
        yatest_log("entry: '%s'", name);
        ++measured_entry_count;
    }

    if(measured_entry_count != (int)acl_entry_count())
    {
        yatest_err("acl_entry_count() returns %i instead of %i", acl_entry_count(), measured_entry_count);
        return 1;
    }

    output_stream_close(&os);

    return 0;
}

static void acl_test_finalise()
{
    for(int i = 0; i < ACL_COMBO_COUNT; ++i)
    {
        acl_access_control_clear(&ac_combo[i]);
    }
    acl_access_control_clear(acp);
    acl_access_control_clear(&ac_copy);
    acl_access_control_clear(&ac2);
    acl_access_control_clear(&ac);

    acl_definitions_free();
}

static void remove_square_brackets(char *text)
{
    bool write = true;
    int  j = 0;
    for(int i = 0; text[i] != '\0'; ++i)
    {
        char c = text[i];
        if(c == '[')
        {
            write = false;
            continue;
        }
        if(c == ']')
        {
            write = true;
            continue;
        }
        if(write)
        {
            text[j++] = text[i];
        }
    }
    text[j] = '\0';
}

static int acl_message_check_against_combos(output_stream_t *os, access_control_t *combo, int mode)
{
    int ret;

    for(int acl_idx = 0; acl_idx < ACL_COMBO_COUNT; ++acl_idx)
    {
        access_control_t                 *ac = &combo[acl_idx];
        acl_check_access_filter_callback *cafcb = acl_get_check_access_filter(&ac->allow_query);
        acl_query_access_filter_callback *qafcb = acl_get_query_access_filter(&ac->allow_query);

        for(int mesg_idx = 0; mesg_idx < ACL_MESSAGE_COUNT; ++mesg_idx)
        {
            dns_message_t *mesg = messages[mesg_idx];
            /*
                        flushout();
                        osformat(termout, "check, mode=%i, acl[%2i], mesg[%2i], match_set=", mode, acl_idx, mesg_idx);
                        acl_address_match_set_to_stream(termout, &ac->allow_query);
                        osformatln(termout, "");
                        flushout();
            */
            const char *name;

            switch(mode)
            {
                case 0:
                {
                    ret = acl_check_access_filter(mesg, &ac->allow_query);
                    name = "";
                    break;
                }
                case 1:
                {
                    ret = cafcb(mesg, &ac->allow_query);
                    name = acl_get_check_access_filter_name(cafcb);
                    break;
                }
                case 2:
                {
                    ret = qafcb(mesg, &ac->allow_query);
                    name = acl_get_check_access_filter_name(cafcb);
                    break;
                }
                default:
                    yatest_err("bug in acl_message_check_against_combos: wrong mode %i", mode);
                    break;
            }

            bool           accepted = ret > 0; // 0 means ignored

            bool           signed_by_mykey = false;
            const uint8_t *tsig_name = (const uint8_t *)"";
            if(dns_message_has_tsig(mesg))
            {
                tsig_name = dns_message_tsig_get_name(mesg);
                signed_by_mykey = dnsname_equals(MYKEY_NAME, tsig_name);
            }

            osformat(os, "sender = %{sockaddr} ; key = %{dnsname} ; ACL =", dns_message_get_sender_sa(mesg), tsig_name);
            acl_address_match_set_to_stream(os, &ac->allow_query);
            output_stream_write_u8(os, 0);

            yatest_log("acl %2i mode %i (%s) mesg %2i: %08x: %s: accepted=%i", acl_idx, mode, name, mesg_idx, ret, bytearray_output_stream_buffer(os), accepted);

            host_address_t ha;
            host_address_set_with_socketaddress(&ha, (union socketaddress_u *)dns_message_get_sender_sa(mesg));

            bool should_allow;

            switch(ha.version)
            {
                case HOST_ADDRESS_IPV4:
                {
                    bool isl = ha.ip.v4.bytes[3] == 1;
                    if(isl)
                    {
                        should_allow = allow_v4l(acl_idx) || allow_v4(acl_idx);
                    }
                    else
                    {
                        should_allow = allow_v4(acl_idx);
                    }
                    break;
                }
                case HOST_ADDRESS_IPV6:
                {
                    bool isl = ha.ip.v6.bytes[15] == 1;
                    if(isl)
                    {
                        should_allow = allow_v6l(acl_idx) || allow_v6(acl_idx);
                    }
                    else
                    {
                        should_allow = allow_v6(acl_idx);
                    }
                    break;
                }
                default:
                {
                    yatest_err("bug in acl_message_check_against_combos");
                    return 1;
                }
            }

            if(should_allow)
            {
                // there is the key question
                if(allow_mykey_only(acl_idx))
                {
                    if(signed_by_mykey)
                    {
                        if(!accepted)
                        {
                            yatest_err("should have accepted (ipv%i + key) (%i,%i,%i)", ha.version, acl_idx, mode, mesg_idx);
                            // return 1;
                        }
                    }
                    else
                    {
                        if(accepted)
                        {
                            yatest_err("should not have accepted (ipv%i + key) (%i,%i,%i)", ha.version, acl_idx, mode, mesg_idx);
                            // return 1;
                        }
                    }
                }
                else
                {
                    // always accept
                    if(!accepted)
                    {
                        yatest_err("should have accepted (ipv%i) (%i,%i,%i)", ha.version, acl_idx, mode, mesg_idx);
                        // return 1;
                    }
                }
            }
            else
            {
                // never accepts
                if(accepted)
                {
                    yatest_err("should not have accepted (ipv%i) (%i,%i,%i)", ha.version, acl_idx, mode, mesg_idx);
                    // return 1;
                }
            }

            bytearray_output_stream_reset(os);
        }
    }
    return 0;
}

/**
 * Tests all combinations of possible optimisations
 */

static int acl_simple_test()
{
    int ret = acl_test_init();
    if(ret != 0)
    {
        return ret;
    }

    if(acl_address_match_set_isempty(&ac.allow_query))
    {
        yatest_err("acl_address_match_set_isempty returned true when it shouldn't have");
        return 2;
    }

    if(!acl_address_match_set_isempty(&ac.allow_control))
    {
        yatest_err("acl_address_match_set_isempty returned false when it shouldn't have");
        return 3;
    }

    // probe all combinations

    char            text_buffer[1024];
    output_stream_t os;
    bytearray_output_stream_init(&os, text_buffer, sizeof(text_buffer));

    for(int mode = 0; mode < 3; ++mode)
    {
        yatest_log("acl_simple_test: direct");

        ret = acl_message_check_against_combos(&os, ac_combo, mode);

        if(ret != 0)
        {
            return ret;
        }

        // reference variant

        yatest_log("acl_simple_test: reference");

        // ret = acl_message_check_against_combos(&os, ac_combop, mode);

        if(ret != 0)
        {
            return ret;
        }

        // negative variant

        yatest_log("acl_simple_test: negative");

        ret = acl_message_check_against_combos(&os, ac_combon, mode);

        if(ret != 0)
        {
            return ret;
        }
    }

    output_stream_close(&os);

    acl_test_finalise();

    return 0;
}

static int acl_parse_error_test()
{
    int ret = acl_test_init();
    if(ret != 0)
    {
        return ret;
    }

    static access_control_t ac_err;
    ret = acl_access_control_init_from_text(&ac_err, "this is not good", NULL, NULL, NULL, NULL, NULL);
    if(ISOK(ret))
    {
        yatest_err("acl_access_control_init_from_text has accepted garbage");
        return 1;
    }

    acl_access_control_clear(&ac_err);

    acl_test_finalise();

    return 0;
}

static int acl_nosuchkey_test()
{
    int ret = acl_test_init();
    if(ret != 0)
    {
        return ret;
    }

    static access_control_t ac_err;
    ret = acl_access_control_init_from_text(&ac_err, ACL_UNKNOWNTSIG_KEY_LINE, NULL, NULL, NULL, NULL, NULL);
    if(ISOK(ret))
    {
        yatest_err("acl_access_control_init_from_text has accepted garbage");
        return 1;
    }

    acl_access_control_clear(&ac_err);

    acl_test_finalise();

    return 0;
}

static int acl_match_equals_test()
{
    int ret = acl_test_init();

    if(ret != 0)
    {
        return ret;
    }

    char            text_buffer[1024];
    char            text_buffer2[1024];
    output_stream_t os;
    output_stream_t os2;
    bytearray_output_stream_init(&os, text_buffer, sizeof(text_buffer));
    bytearray_output_stream_init(&os2, text_buffer2, sizeof(text_buffer2));

    if(acl_address_match_item_compare(NULL, ac.allow_query.ipv4.items[0]) == 0)
    {
        yatest_err("acl_address_match_item_compare: incorrect match: NULL != !NULL");
        return 1;
    }

    if(acl_address_match_item_compare(ac.allow_query.ipv4.items[0], NULL) == 0)
    {
        yatest_err("acl_address_match_item_compare: incorrect match: !NULL != NULL");
        return 1;
    }

    if(acl_address_match_item_equals(NULL, ac.allow_query.ipv4.items[0]))
    {
        yatest_err("acl_address_match_item_equals: incorrect match: NULL != !NULL");
        return 1;
    }

    if(acl_address_match_item_equals(ac.allow_query.ipv4.items[0], NULL))
    {
        yatest_err("acl_address_match_item_equals: incorrect match: !NULL != NULL");
        return 1;
    }

    if(acl_address_match_list_equals(NULL, &ac.allow_query.ipv4))
    {
        yatest_err("acl_address_match_list_equals: incorrect match: NULL != !NULL");
        return 1;
    }

    if(acl_address_match_list_equals(&ac.allow_query.ipv4, NULL))
    {
        yatest_err("acl_address_match_list_equals: incorrect match: !NULL != NULL");
        return 1;
    }

    if(acl_address_match_set_equals(NULL, &ac.allow_query))
    {
        yatest_err("acl_address_match_set_equals: incorrect match: NULL != !NULL");
        return 1;
    }

    if(acl_address_match_set_equals(&ac.allow_query, NULL))
    {
        yatest_err("acl_address_match_set_equals: incorrect match: !NULL != NULL");
        return 1;
    }

    if(acl_address_control_equals(NULL, &ac))
    {
        yatest_err("acl_address_control_equals: incorrect match: NULL != !NULL");
        return 1;
    }

    if(acl_address_control_equals(&ac, NULL))
    {
        yatest_err("acl_address_control_equals: incorrect match: !NULL != NULL");
        return 1;
    }

    // probe all combinations (acl_address_match_set_equals)

    for(int acl_idx = 0; acl_idx < ACL_COMBO_COUNT; ++acl_idx)
    {
        access_control_t *ac = &ac_combo[acl_idx];

        acl_address_match_set_to_stream(&os, &ac->allow_query);
        output_stream_write_u8(&os, 0);
        remove_square_brackets(text_buffer);

        yatest_log("A %2i : '%s'", acl_idx, text_buffer);

        for(int acl2_idx = 0; acl2_idx < ACL_COMBO_COUNT; ++acl2_idx)
        {
            access_control_t *ac2 = &ac_combo[acl2_idx];

            acl_address_match_set_to_stream(&os2, &ac2->allow_query);
            output_stream_write_u8(&os2, 0);
            remove_square_brackets(text_buffer2);

            yatest_log("B %2i : '%s'", acl2_idx, text_buffer2);

            bool equals = strcmp(text_buffer, text_buffer2) == 0;
            bool match = acl_address_match_set_equals(&ac->allow_query, &ac2->allow_query);

            if(match != equals)
            {
                if(match)
                {
                    yatest_err("acl_address_match_set_equals: incorrect match: %i & %i", acl_idx, acl2_idx);
                }
                else
                {
                    yatest_err("acl_address_match_set_equals: expected match: %i & %i", acl_idx, acl2_idx);
                }
                return 1;
            }

            bytearray_output_stream_reset(&os2);
        }

        bytearray_output_stream_reset(&os);
    }

    // probe all combinations (acl_address_control_equals)

    for(int acl_idx = 0; acl_idx < ACL_COMBO_COUNT; ++acl_idx)
    {
        access_control_t *ac = &ac_combo[acl_idx];

        acl_address_match_set_to_stream(&os, &ac->allow_query);
        output_stream_write_u8(&os, ';');
        acl_address_match_set_to_stream(&os, &ac->allow_update);
        output_stream_write_u8(&os, ';');
        acl_address_match_set_to_stream(&os, &ac->allow_update_forwarding);
        output_stream_write_u8(&os, ';');
        acl_address_match_set_to_stream(&os, &ac->allow_transfer);
        output_stream_write_u8(&os, ';');
        acl_address_match_set_to_stream(&os, &ac->allow_notify);
        output_stream_write_u8(&os, ';');
        acl_address_match_set_to_stream(&os, &ac->allow_control);
        output_stream_write_u8(&os, 0);
        remove_square_brackets(text_buffer);

        yatest_log("A %2i : '%s'", acl_idx, text_buffer);

        for(int acl2_idx = 0; acl2_idx < ACL_COMBO_COUNT; ++acl2_idx)
        {
            access_control_t *ac2 = &ac_combo[acl2_idx];

            acl_address_match_set_to_stream(&os2, &ac2->allow_query);
            output_stream_write_u8(&os2, ';');
            acl_address_match_set_to_stream(&os2, &ac2->allow_update);
            output_stream_write_u8(&os2, ';');
            acl_address_match_set_to_stream(&os2, &ac2->allow_update_forwarding);
            output_stream_write_u8(&os2, ';');
            acl_address_match_set_to_stream(&os2, &ac2->allow_transfer);
            output_stream_write_u8(&os2, ';');
            acl_address_match_set_to_stream(&os2, &ac2->allow_notify);
            output_stream_write_u8(&os2, ';');
            acl_address_match_set_to_stream(&os2, &ac2->allow_control);
            output_stream_write_u8(&os2, 0);
            remove_square_brackets(text_buffer2);

            yatest_log("B %2i : '%s'", acl2_idx, text_buffer2);

            bool equals = strcmp(text_buffer, text_buffer2) == 0;
            bool match = acl_address_control_equals(ac, ac2);

            bool allow_query = acl_address_match_set_equals(&ac->allow_query, &ac2->allow_query);
            bool allow_update = acl_address_match_set_equals(&ac->allow_update, &ac2->allow_update);
            bool allow_update_forwarding = acl_address_match_set_equals(&ac->allow_update_forwarding, &ac2->allow_update_forwarding);
            bool allow_transfer = acl_address_match_set_equals(&ac->allow_transfer, &ac2->allow_transfer);
            bool allow_notify = acl_address_match_set_equals(&ac->allow_notify, &ac2->allow_notify);
            bool allow_control = acl_address_match_set_equals(&ac->allow_control, &ac2->allow_control);

            if(match != equals)
            {
                if(match)
                {
                    yatest_err("acl_address_control_equals: incorrect match: %i & %i (%i,%i,%i,%i,%i,%i)", acl_idx, acl2_idx, allow_query, allow_update, allow_update_forwarding, allow_transfer, allow_notify, allow_control);
                }
                else
                {
                    yatest_err("acl_address_control_equals: expected match: %i & %i (%i,%i,%i,%i,%i,%i)", acl_idx, acl2_idx, allow_query, allow_update, allow_update_forwarding, allow_transfer, allow_notify, allow_control);
                }
                return 1;
            }

            bytearray_output_stream_reset(&os2);
        }

        bytearray_output_stream_reset(&os);
    }

    // check items

    yatest_log("acl_address_match_item_equals");

    for(int list_idx = 0; list_idx < ACL_LIST_COUNT; ++list_idx)
    {
        address_match_list_t *list = match_list[list_idx];
        int                   list_size = acl_address_match_list_size(list);

        for(int list2_idx = 0; list2_idx < ACL_LIST_COUNT; ++list2_idx)
        {
            address_match_list_t *list2 = match_list[list2_idx];
            int                   list2_size = acl_address_match_list_size(list2);

            // acl_address_match_list_equals(list, list2);

            for(int item_idx = 0; item_idx < list_size; item_idx++)
            {
                address_match_item_t *item = list->items[item_idx];

                uint32_t              text_buffer_size = sizeof(text_buffer);
                acl_address_match_item_to_string(item, text_buffer, &text_buffer_size);
                for(int item2_idx = 0; item2_idx < list2_size; item2_idx++)
                {
                    address_match_item_t *item2 = list2->items[item2_idx];

                    uint32_t              text_buffer2_size = sizeof(text_buffer2);
                    acl_address_match_item_to_string(item2, text_buffer2, &text_buffer2_size);

                    bool match = acl_address_match_item_equals(item, item2);
                    bool equals = strcmp(text_buffer, text_buffer2) == 0;

                    if(match != equals)
                    {
                        yatest_log("itemA[%3i,%3i]='%s'", list_idx, item_idx, text_buffer);
                        yatest_log("itemB[%3i,%3i]='%s'", list2_idx, item2_idx, text_buffer2);

                        if(match)
                        {
                            yatest_err("acl_address_match_item_equals: incorrect match: %i,%i & %i,%i", list_idx, item_idx, list2_idx, item2_idx);
                            acl_address_match_item_equals(item, item2);
                        }
                        else
                        {
                            yatest_err("acl_address_match_item_equals: expected match: %i,%i & %i,%i", list_idx, item_idx, list2_idx, item2_idx);
                            acl_address_match_item_equals(item, item2);
                        }
                        return 1;
                    }

                    bytearray_output_stream_reset(&os2);
                }

                bytearray_output_stream_reset(&os);
            }
        }
    }

    output_stream_close(&os2);
    output_stream_close(&os);

    return 0;
}

static int acl_item_print_list_test(address_match_list_t *list, const char **expected)
{
    char            text_buffer[256];
    output_stream_t os;
    bytearray_output_stream_init(&os, text_buffer, sizeof(text_buffer));

    int list_size = acl_address_match_list_size(list);
    for(int item_idx = 0; item_idx < list_size; ++item_idx)
    {
        address_match_item_t *item = list->items[item_idx];
        acl_match_item_print(item, &os);
        output_stream_write_u8(&os, 0);
        const char *text = expected[item_idx];
        if(text == NULL)
        {
            yatest_err("bug in acl_item_print_list_test");
            return 1;
        }
        if(strcmp((char *)bytearray_output_stream_buffer(&os), text) != 0)
        {
            yatest_err("acl_item_print_list_test: expected '%s', got '%s'", text, bytearray_output_stream_buffer(&os));
            return 1;
        }
        bytearray_output_stream_reset(&os);
        yatest_log("acl_item_print_list_test: matcher is %s", acl_get_matcher_name(item->match));
    }

    output_stream_close(&os);
    return 0;
}

static int acl_items_print_list_test(address_match_list_t *list, const char **expected)
{
    char            text_buffer[1024];
    output_stream_t os;
    bytearray_output_stream_init(&os, text_buffer, sizeof(text_buffer));

    char            text_buffer2[1024];
    output_stream_t os2;
    bytearray_output_stream_init(&os2, text_buffer2, sizeof(text_buffer2));

    acl_match_item_print(NULL, &os);
    output_stream_write_u8(&os, 0);
    if(strcmp((char *)bytearray_output_stream_buffer(&os), "NULL") != 0)
    {
        yatest_err("acl_match_item_print: expected 'NULL'", bytearray_output_stream_buffer(&os));
        return 1;
    }
    bytearray_output_stream_reset(&os);

    if(strcmp(acl_get_matcher_name(NULL), "?") != 0)
    {
        yatest_err("acl_get_matcher_name is supposed to give '?' for an unknown matcher");
        return 1;
    }

    for(int i = 0; expected[i] != NULL; ++i)
    {
        if(i > 0)
        {
            output_stream_write_text(&os, ", ");
        }
        output_stream_write_text(&os, expected[i]);
    }
    output_stream_write_u8(&os, 0);

    acl_match_items_print(list->items, list->limit, &os2);
    output_stream_write_u8(&os2, 0);

    if(strcmp((char *)bytearray_output_stream_buffer(&os), (char *)bytearray_output_stream_buffer(&os2)) != 0)
    {
        yatest_err("acl_item_print_list_test: expected '%s', got '%s'", bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os2));
        return 1;
    }

    output_stream_close(&os2);
    output_stream_close(&os);
    return 0;
}

static int acl_item_print_test()
{
    acl_test_init();

    char            text_buffer[256];
    output_stream_t os;
    bytearray_output_stream_init(&os, text_buffer, sizeof(text_buffer));

    ptr_treeset_t matcher_set;
    ptr_treeset_init(&matcher_set);
    matcher_set.compare = ptr_treeset_ptr_node_compare;

    static const char *match_list_0_text[5] = {
        "127.0.0.1",      // match_list[0,0]
        "!127.0.0.2",     // match_list[0,1]
        "192.168.1.0/24", // match_list[0,2]
        "!10.0.0.0/24",   // match_list[0,3]
        NULL,
    };

    static const char *match_list_4_text[5] = {
        "::1",        // match_list[4,0]
        "!::2",       // match_list[4,1]
        "2002::/16",  // match_list[4,2]
        "!2003::/16", // match_list[4,3]
        NULL,
    };

    static const char *match_list_8_text[2] = {"key mykey.", // match_list[8,0]
                                               NULL};

    static const char *match_list_9_text[2] = {"any", // match_list[9,0]
                                               NULL};

    static const char *match_list_12_text[2] = {"none", // match_list[12,0]
                                                NULL};

    static const char *match_list_62_text[2] = {"!key mykey.", // match_list[62,0]
                                                NULL};

    int                ret;

    if((ret = acl_item_print_list_test(match_list[0], match_list_0_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_item_print_list_test(match_list[4], match_list_4_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_item_print_list_test(match_list[8], match_list_8_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_item_print_list_test(match_list[9], match_list_9_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_item_print_list_test(match_list[12], match_list_12_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_item_print_list_test(match_list[62], match_list_62_text)) != 0)
    {
        return ret;
    }

    if((ret = acl_items_print_list_test(match_list[0], match_list_0_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_items_print_list_test(match_list[4], match_list_4_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_items_print_list_test(match_list[8], match_list_8_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_items_print_list_test(match_list[9], match_list_9_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_items_print_list_test(match_list[12], match_list_12_text)) != 0)
    {
        return ret;
    }
    if((ret = acl_items_print_list_test(match_list[62], match_list_62_text)) != 0)
    {
        return ret;
    }

    for(int i = 1; i <= 32; ++i)
    {
        char              text[128];

        access_control_t *ac = &ac_ipv4_mask[i];
        acl_match_items_print(ac->allow_query.ipv4.items, ac->allow_query.ipv4.limit, &os);
        output_stream_write_u8(&os, 0);
        acl_item_print_test_make_ipv4_mask(text, i);
        if(strcmp((char *)bytearray_output_stream_buffer(&os), text) != 0)
        {
            yatest_err("acl_item_print_test: ipv4 mask %i: got '%s', expected '%s'", i, bytearray_output_stream_buffer(&os), text);
            return 1;
        }
        bytearray_output_stream_reset(&os);
    }

    for(int i = 1; i <= 128; ++i)
    {
        char              text[128];

        access_control_t *ac = &ac_ipv6_mask[i];
        acl_match_items_print(ac->allow_query.ipv6.items, ac->allow_query.ipv6.limit, &os);
        output_stream_write_u8(&os, 0);
        acl_item_print_test_make_ipv6_mask(text, i);
        if(strcmp((char *)bytearray_output_stream_buffer(&os), text) != 0)
        {
            yatest_err("acl_item_print_test: ipv6 mask %i: got '%s', expected '%s'", i, bytearray_output_stream_buffer(&os), text);
            return 1;
        }
        bytearray_output_stream_reset(&os);
    }

    output_stream_close(&os);

    acl_test_finalise();
    return 0;
}

static void acl_merge_test_print(output_stream_t *os, access_control_t *ac, const char *name)
{
    osformatln(os, "acl %s = {", name);
    osformat(os, "\tquery=");
    acl_address_match_set_to_stream(os, &ac->allow_query);
    osformat(os, "\n\tupdate=");
    acl_address_match_set_to_stream(os, &ac->allow_update);
    osformat(os, "\n\tupdate-forwarding=");
    acl_address_match_set_to_stream(os, &ac->allow_update_forwarding);
    osformat(os, "\n\ttransfer=");
    acl_address_match_set_to_stream(os, &ac->allow_transfer);
    osformat(os, "\n\tnotify=");
    acl_address_match_set_to_stream(os, &ac->allow_notify);
    osformat(os, "\n\tcontrol=");
    acl_address_match_set_to_stream(os, &ac->allow_control);
    osformatln(os, "}");
}

static int acl_merge_test()
{
    int ret;

    acl_test_init();
    output_stream_t  *os = termout;
    access_control_t *myac_clone = acl_access_control_new_instance();
    access_control_t *myac_target = acl_access_control_new_instance();
    access_control_t *myac_source = acl_access_control_new_instance();
    acl_merge_test_print(os, myac_target, "myac-empty");
    acl_merge_test_print(os, myac_source, "myac2-empty");
    if(myac_source->_rc != 1)
    {
        yatest_err("acl_merge_test myac_source rc == %i, expected 1 (new)", myac_source->_rc);
        return 1;
    }
    if(myac_target->_rc != 1)
    {
        yatest_err("acl_merge_test myac_target rc == %i, expected 1 (new)", myac_target->_rc);
        return 1;
    }
    ret = acl_access_control_init_from_text(myac_clone, ACL_V4_LINE, NULL, ACL_K_LINE, NULL, ACL_NONE_LINE, NULL);
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_merge_test: acl_access_control_init_from_text failed with %x (myac_clone)", ret);
        return 1;
    }
    ret = acl_access_control_init_from_text(myac_target, ACL_V4_LINE, NULL, ACL_K_LINE, NULL, ACL_NONE_LINE, NULL);
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_merge_test: acl_access_control_init_from_text failed with %x (myac_target)", ret);
        return 1;
    }
    ret = acl_access_control_init_from_text(myac_source, NULL, ACL_V6_LINE, ACL_K_LINE, ACL_ANY_LINE, NULL, ACL_EMPTY_LINE);
    if(FAIL(ret))
    {
        osformatln(termerr, "error: %r", ret);
        flusherr();
        yatest_err("acl_merge_test: acl_access_control_init_from_text failed with %x (myac_source)", ret);
        return 1;
    }

    if(myac_source->_rc != 1)
    {
        yatest_err("acl_merge_test myac_source rc == %i, expected 1 (copy)", myac_source->_rc);
        return 1;
    }
    if(myac_target->_rc != 1)
    {
        yatest_err("acl_merge_test myac_target rc == %i, expected 1 (copy)", myac_target->_rc);
        return 1;
    }
    if(myac_clone->_rc != 1)
    {
        yatest_err("acl_merge_test myac_target rc == %i, expected 1 (copy)", myac_clone->_rc);
        return 1;
    }
    acl_merge_test_print(os, myac_clone, "myac_clone");
    acl_merge_test_print(os, myac_target, "myac_target");
    acl_merge_test_print(os, myac_source, "myac_source");
    acl_merge_access_control(myac_target, myac_source);
    acl_merge_access_control(myac_clone, myac_source);
    acl_merge_test_print(os, myac_clone, "myac_clone_merged");
    acl_merge_test_print(os, myac_target, "myac_target_merged");
    if(myac_clone->_rc != 1)
    {
        yatest_err("acl_merge_test myac_clone rc == %i, expected 1 (merge)", myac_clone->_rc);
        return 1;
    }
    if(myac_target->_rc != 1)
    {
        yatest_err("acl_merge_test myac_target rc == %i, expected 1 (merge)", myac_target->_rc);
        return 1;
    }
    if(myac_source->_rc != 3)
    {
        yatest_err("acl_merge_test myac_source rc == %i, expected 3 (merge)", myac_source->_rc);
        return 1;
    }
    acl_access_control_acquire(myac_target);
    if(myac_target->_rc != 2)
    {
        yatest_err("acl_merge_test myac_target rc == %i, expected 2", myac_target->_rc);
        return 1;
    }
    acl_access_control_release(myac_target);
    if(myac_target->_rc != 1)
    {
        yatest_err("acl_merge_test myac_target rc == %i, expected 1", myac_target->_rc);
        return 1;
    }
    acl_unmerge_access_control(myac_clone);
    if(myac_source->_rc != 2)
    {
        yatest_err("acl_merge_test myac_source rc == %i, expected 2", myac_source->_rc);
        return 1;
    }
    acl_merge_test_print(os, myac_clone, "myac_clone_unmerged");
    acl_access_control_release(myac_source);
    if(myac_source->_rc != 1)
    {
        yatest_err("acl_merge_test myac_source rc == %i, expected 1", myac_source->_rc);
        return 1;
    }
    if(myac_target->_rc != 1)
    {
        yatest_err("acl_merge_test myac_target rc == %i, expected 1", myac_target->_rc);
        return 1;
    }
    acl_access_control_release(myac_target);
    acl_test_finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(acl_simple_test)
YATEST(acl_parse_error_test)
YATEST(acl_nosuchkey_test)
YATEST(acl_match_equals_test)
YATEST(acl_item_print_test)
YATEST(acl_merge_test)
YATEST_TABLE_END
