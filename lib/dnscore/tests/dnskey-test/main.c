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

#include "yatest.h"
#include "yatest_socket.h"
#include <dnscore/dnscore.h>
#include <dnscore/dnskey.h>
#include <dnscore/dnskey_rsa.h>
#include <dnscore/dnskey_ecdsa.h>
#include <dnscore/dnskey_eddsa.h>
#if DNSCORE_HAS_OQS_SUPPORT
#include <dnscore/dnskey_postquantumsafe.h>
#endif

#include "settings.h"
#include "dnscore/fdtools.h"
#include "dnscore/format.h"
#include "dnscore/ptr_vector.h"
#include "dnscore/dnskey_signature.h"
#include "dnscore/base64.h"
#include "dnscore/bytearray_input_stream.h"
#include "dnscore/zone_reader_text.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/dnskey_keyring.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/dns_message.h"
#include <dnscore/dns_packet_writer.h>

extern struct dnskey_inputs_s         dnskey_inputs[];
extern struct dnskey_private_inputs_s dnskey_private_inputs[];
static const char                    *test_key_algorithm_origin = "yadifa-dnskey-test.eu";
static const char                    *working_dirname = "/tmp/yadifa-lib-dnscore-tests-dnskey-test";
static bool                           g_sign_verify_test_uses_max_interval = false;
static bool                           sign_verify_test_dump_rdata = true;

// a list of signature whose result is expected to be a constant
// during the test, compare the result to what was obtained
// double as check for tag collision during generation

static const struct expected_signature_s expected_signature[] = {{3, 32493, "example.eu.", NULL},
                                                                 {5,
                                                                  65103,
                                                                  "example.eu.",
                                                                  "ZTXQin2jBAbHTjD6bzZMRXbO8LqZwiJjMNeoZtIm5maYxZRVHsbihXPipXR6FCBq5W7GBfvdEtFmFfDtUxmmYDo+nHIZ78AAptDXM9oR/"
                                                                  "tdosmueuQqXN0rr4QxvF3WRgLX3FFKtnH4+DJ0VjqA+S4wuBD8LfWAhADrJxiO9T04pcronexLhV/"
                                                                  "xIlNw8R+9Xo+YpArPEi31n+uxMorMC6Zh1K+ou8tfQCYX7bCxZLG+Tvk513aR9H1ZqmdXum0OxTdP6lW/ocZv/"
                                                                  "e8Nfv6GqyP8BIvJ3Ixjfec6znbJ8S1V8UXOwN7rzVPWn+59I004jJjcFM2kXp5i+rT+"
                                                                  "IVA952ino7s5fonULpGPJkTF0AQoR5WwMD7WeCGck8svReKu2OZjKJNIFpIHom9yL25M3B9d5rQDgt3i75fLnygvIzD/"
                                                                  "OHsszqtd+H9oolTw2GoJCu5XpKi22k+IPshxx3QRrcBxgr2DAx3FiFu1aMjfCDUwOT+lRoVkMhn+A+"
                                                                  "pQ0wshUoCmatIddLiCG1yfQfVSpxybRTvvs8xi8oyLs2lnyb2ZrE7sPLSfH8NSJgm31Xuc6rDMGHe0kthT+"
                                                                  "bHxJZGgVhghF9Io4qA5WyuxHDU8vE26XDtz3qF98Rc3h5AcTm2VJ2ZzI9TP6Rkth1Gjt2CYACHG2CmJ5i4YQUzRMd44D/5k="},
                                                                 {7,
                                                                  34614,
                                                                  "example.eu.",
                                                                  "B4Kuwm6EuoppyWDBi+PPvofhcb5HSqeC22yB142sdA4NcKVWxQeK4udcua+S/M6n5VJ7Gc2ed7lgkJBoptGi7Pr8dhcT/3ZWYls1IHaxl/"
                                                                  "7N4027qxnLefiiz1pMzOYxvjzN6qVIhKqeFdh3xfDAIl/"
                                                                  "aZiJ0oOr44y2SGUWZQaGHtn6WlMBlqHUpJtMVmJdcQjUFU5G8hvbLn7222RVrjWUfpjKgE2NbDrGvWIK/1MJmDNQSuiKBnnb/"
                                                                  "92LsAN6odZlUrV9ezFR6+6P7m8wT5KuB++w3mWQpXwn9Pn1dBrISxIWDoHyeqwub3mg34fs4oHaH4gPG5HFcby5qGqhM3fBehJHI3vUjOk/4vgM/"
                                                                  "+SJySMDh8yaKqpHaCTrVI0c/"
                                                                  "PQOimh9VZ9bVl7SU7yjIvHeRhvt6WmyFRO3ylwukTK2BQgfB49Dg2eDpX07MkSzUKaPeARf2SlH+C6rDYMWhR+"
                                                                  "FbdZvhnUdtXQ0gbnx4qsHRwdCdxYoGg8bssaQShwVg7nPz6uOa2s/04uZlPeSm5IMu9DLVFTiBw6Q+qgxE1J8Eeo0R/"
                                                                  "7WotruwSciuCLGwEne216WGNlHtNzbLpRU8EQOP14tn83uGPb13F2LN0l3oUJN2DtTjVflDKzvEgddpJZHWY8rcvEWzypb7YLjvMVo8qR3+"
                                                                  "Z6Ck3St3RDq25po="},
                                                                 {8,
                                                                  42405,
                                                                  "example.eu.",
                                                                  "M+rK8uDSvRZiojPjyApR0+oGCpkuIidIYbBuk+EP+tGajZfRJZfXgeg2TjoAe/D9szAS4RCBlFkUZDMNPRGrDOeH+JBSXhU2RRCah0u/"
                                                                  "JBRcKu1bHoar+4dxVAW6SWPJ/OJENgB78uedN8c8WOK/pF8pCxJhrdc2i78HV5rpaJk="},
                                                                 {8,
                                                                  44385,
                                                                  "example.eu.",
                                                                  "lTgi1j9/+WD+YDGeAdFCZRaJMVENE4zeQTgrEYl9uJCH3tinAMM/j5/2lvUszx/"
                                                                  "AHuWAjTqlgqQ1IvTzNj7FwGxiT3tIi2AuMd7I1E8ttcYSO1oFDs/cWfDaVtBPkN6JeiXU/"
                                                                  "TO7Ya8cfA904EGBnwPDuZ1AiFQzlIicMX7Upqn1P2LBXqFewPIlILXwcIwwMAY9VZ1UdK9Ql1s0qPrnP0833UQSoJOUbZMHOcY4ia8ZJha1WfjaPN"
                                                                  "BdqU0YDeIfqP8jsdeeq/"
                                                                  "ESb96ZoMZyuX+mc3NIjlVM7dVqSlV8gIzJas3q4VbkbnH0NxmPeP3KcJp3oznC4nveOpq4ERLdrU1AwMd3PkPbPnvxw+"
                                                                  "c44uNwbHw8cutYgPziwhmfaiQUNkCebmPbbXm6f6CgOF+jrSIiv1SVQ94mChWu23IqXvyUOPvGIQaLwkoDM5EgCGXQbCDv/+XDbUuB3V9Sx7CyAk/"
                                                                  "Ny6f4CO5sN7xnMUesx15ffWJ2Y64fB4OGhNjrHrTnOHKHKpwADWf+U23mir9+g82gMdb6JHCvyRRQSDw40/"
                                                                  "3nf6gvAeCwouB1Nel2Fw+zUKd26feCN1okH3Fnr7EAznWQJG76NkKkRfg65HWyBFz3Q2qUCtLnwL5ZsAx7SjSP6lJk0TrwRj9GoAKWPhM9O+"
                                                                  "xxt447v4QCv9T2d31XGsI="},
                                                                 {8,
                                                                  58273,
                                                                  "example.eu.",
                                                                  "WH7TTBoRVreSFDfX3nfry782F5Wa+"
                                                                  "i2racB3RGcydLfqOZrCNrHcP3HjzHeI5Fg3u2gErVpObvlxyCQxBzXGztFH9xuHBWM9JvtW59ewJxUUL5nS2+"
                                                                  "Nzi1t1ezgMxLAAIPbxjiQCrOLwh1hxarL9bZRlF1syjVg3rnDtLWhpghWUprxeEkZ79AomDI2v/FSJypip/ew8MBQdb8e9v3bqp0QF/0LteGx/"
                                                                  "BSEd8s5WWLEuGE4JYnPBHqEyvIdXz83v/zorhtc3x1inS2bIxp/"
                                                                  "V+1ElOQJDafQmV7dWnm2LGChHlV4iHBImGFBoJq9vkpXv7cw3k9S6Wi7bCxUpc2ZOqA=="},
                                                                 {10,
                                                                  34811,
                                                                  "example.eu.",
                                                                  "OyXAa8XOYlViyr8iTNjYIxzxy5c58TqAzE4P3bjqMz6xrulcQ2XL+hI9X0tEQEu3Ajigdlm91ZVA9FmeLz2UvbnmvaQlNIL3/tR9RhDAl2Aw9aXW/"
                                                                  "BY4vezYeQsR3/7DT1i0Y/ahgTbcn8JrxD7Pe7QauUnk/2bs8l8+Sqx7ltZucqZ4yvD/"
                                                                  "KcFwnLRlirimFOFiTfJ4ULIfIWpIXC1bf3QoPl7ApgKBe40R+"
                                                                  "t65JKrTEAuR3ErQFP4VjL3T8Qv6nXkvAFpdpPzASZW5GZZILZx22SwjLDOyCDrdfSNqAfj2+dLxLefQP9NP9xzWV5v7jgsrC3/"
                                                                  "3CB6iFdmEqU6ApLEx8q6X8yInIlEgioafIBS/"
                                                                  "BwgmNJUXS3HyC5i6uXRX+gwO2mn4QO7nQPcH7nNMc+5wIT0k2RxFFMY1xKZWnrUUn0GoG3aFYMXfxGogU5jvuvYzISAuaGbXCFYeXHpeHsXxwU+"
                                                                  "Pn1y77p9xGlrI1QJgAZvxUiHCApaeT/CxnQVwJL+ilvVP8tiS3sTwAmgT1D+vNlpP/+ou4pIZeNvGksYHqt0AN84blu1skNVpeq/"
                                                                  "Dod7k2Rb0ruM4a4xr6A6sJ57Cg0Z7BuCItD0EBE2b1U27hxd8boPVeO36/gUmQcvt8dEtQ+fU89NPUyOEdNYQr48eG0mr8dLisYU3inROUSo="},
                                                                 {13, 57775, "example.eu.", NULL},
                                                                 {14, 52751, "example.eu.", NULL},
                                                                 {15, 49344, "example.eu.", "HUL0aU89SVFz10R48oSfZF4lrqnpbUeBmEgyr32ZJNPrn8SJ2pezXvgd82QURrbeMhpFSExEMzyvih5D4D2FBQ=="},
                                                                 {16,
                                                                  7552,
                                                                  "example.eu.",
                                                                  "sYf71iQQgQ2Jqys9W7rSXdvhLG77nhB5IUY8FU7aEqztU5eLv6TAQre+bTbmKNjxRrkR3vGP0lSAHar271pOHPrT4oco9HQwfxwHNAYDDkO/"
                                                                  "TWGnb6zbVjLow2N/Z3UZdBlJzqXcGHKU3awhVzV8VSEA"},
                                                                 {0, 0, NULL, NULL}};

static const int                         dnskey_algorithm_list[] = {DNSKEY_ALGORITHM_RSAMD5,
                                                                    DNSKEY_ALGORITHM_DIFFIE_HELLMAN,
                                                                    DNSKEY_ALGORITHM_DSASHA1,
                                                                    DNSKEY_ALGORITHM_RSASHA1,
                                                                    DNSKEY_ALGORITHM_DSASHA1_NSEC3,
                                                                    DNSKEY_ALGORITHM_RSASHA1_NSEC3,
                                                                    DNSKEY_ALGORITHM_RSASHA256_NSEC3,
                                                                    DNSKEY_ALGORITHM_RSASHA512_NSEC3,
                                                                    DNSKEY_ALGORITHM_GOST,
                                                                    DNSKEY_ALGORITHM_ECDSAP256SHA256,
                                                                    DNSKEY_ALGORITHM_ECDSAP384SHA384,
                                                                    DNSKEY_ALGORITHM_ED25519,
                                                                    DNSKEY_ALGORITHM_ED448,
                                                                    -1};

static const uint8_t soa_rdata[] = {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 5, 'a', 'd', 'm', 'i', 'n', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 0, 1, 2, 3, 0, 0, 5, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 2, 0};

static int           network_test_udp_handler_base = 0;
static bool          network_test_udp_handler_break_fqdn = false;
static bool          network_test_udp_handler_cut_tctr = false;

static ya_result     cleanup_readdir_callback(const char *basedir, const char *file, uint8_t filetype, void *args)
{
    (void)args;
    if(filetype == DT_REG)
    {
        if((file != NULL) && (file[0] == 'K'))
        {
            unlink_ex(basedir, file);
        }
    }
    return SUCCESS;
}

static void init()
{
    dnscore_init();
    mkdir_ex(working_dirname, 0700, 0);
    readdir_forall(working_dirname, cleanup_readdir_callback, NULL);
}

static void finalise()
{
    readdir_forall(working_dirname, cleanup_readdir_callback, NULL);
    rmdir(working_dirname);
    dnscore_finalize();
}

static const struct expected_signature_s *expected_signature_get(uint16_t tag)
{
    for(int_fast32_t i = 0; expected_signature[i].alg != 0; ++i)
    {
        if(expected_signature[i].tag == tag)
        {
            return &expected_signature[i];
        }
    }
    return NULL;
}

static ya_result dnskey_test_signature_size(dnskey_t *key)
{
    uint8_t         *signature;
    bytes_signer_t   bytes_signer;
    bytes_verifier_t bytes_verifier;

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR; // no key
    }

    if(!dnskey_is_private(key))
    {
        return DNSSEC_ERROR_KEYRING_KEY_IS_NOT_PRIVATE; // not private
    }

    int      buffer_size = 65535;
    uint8_t *buffer = malloc(buffer_size);
    if(buffer == NULL)
    {
        return MAKE_ERRNO_ERROR(ENOMEM);
    }
    uint32_t signature_size = 0x1000000;
    signature = malloc(signature_size);
    if(buffer == NULL)
    {
        free(buffer);
        return MAKE_ERRNO_ERROR(ENOMEM);
    }
    for(int i = 0; i < buffer_size; ++i)
    {
        buffer[i] = i;
    }
    key->vtbl->signer_init(key, &bytes_signer);
    bytes_signer.vtbl->update(&bytes_signer, buffer, buffer_size);
    int64_t t_sig;
    yatest_timer_start(&t_sig);
    int32_t signature_generated = bytes_signer.vtbl->sign(&bytes_signer, signature, &signature_size);
    yatest_timer_stop(&t_sig);
    bytes_signer.vtbl->finalise(&bytes_signer);
    if(ISOK(signature_generated))
    {
        key->vtbl->verifier_init(key, &bytes_verifier);
        bytes_verifier.vtbl->update(&bytes_verifier, buffer, buffer_size);
        int64_t t_ver;
        yatest_timer_start(&t_ver);
        int32_t signature_verified = bytes_verifier.vtbl->verify(&bytes_verifier, signature, signature_size);
        yatest_timer_stop(&t_ver);
        if(ISOK(signature_verified))
        {
            yatest_log(
                "ALGORITHM: %3i %-18s sign: %6.4f verify: %6.4f size: %i", dnskey_get_algorithm(key), dns_encryption_algorithm_get_name(dnskey_get_algorithm(key)), yatest_timer_seconds(&t_sig), yatest_timer_seconds(&t_ver), signature_size);
        }
    }
    free(signature);
    free(buffer);

    if(ISOK(signature_generated))
    {
        return signature_size;
    }
    else
    {
        return signature_generated;
    }
}

static void sign_verify_test(dnskey_t *signing_key, dnskey_t *verifying_key)
{
    ya_result ret = 0;

    uint16_t  tag = dnskey_get_tag(signing_key);
    uint16_t  other_tag = dnskey_get_tag(verifying_key);

    char      signing_key_domain[DOMAIN_TEXT_BUFFER_SIZE];
    cstr_init_with_dnsname(signing_key_domain, dnskey_get_domain(signing_key));

    uint8_t algorithm = dnskey_get_algorithm(signing_key);

    if(tag != other_tag)
    {
        yatest_err("K%s+%03i+%05i tag do not match: expected %hu, got %hu", signing_key_domain, dnskey_get_algorithm(signing_key), dnskey_get_tag(signing_key), tag, other_tag);
        yatest_err("tags are not matching (%hu != %hu)", tag, other_tag);
        exit(1);
    }
    else
    {
        yatest_log("tags are matching (%hu == %hu)", tag, other_tag);
    }

    ptr_vector_t rrset;
    ptr_vector_init_empty(&rrset);

    ptr_vector_t rrset_different;
    ptr_vector_init_empty(&rrset_different);

    dns_resource_record_t *rr0 = dns_resource_record_new_instance();
    static uint8_t        *rr0_ns_rdata = (uint8_t *)"\003ns1\007example\002eu";
    dns_resource_record_set_record(rr0, dnskey_get_domain(signing_key), TYPE_NS, CLASS_IN, 86400, dnsname_len(rr0_ns_rdata), rr0_ns_rdata);

    dns_resource_record_t *rr1 = dns_resource_record_new_instance();
    static uint8_t        *rr1_ns_rdata = (uint8_t *)"\003ns2\007example\002eu";
    dns_resource_record_set_record(rr1, dnskey_get_domain(signing_key), TYPE_NS, CLASS_IN, 86400, dnsname_len(rr1_ns_rdata), rr1_ns_rdata);

    dns_resource_record_t *rr2 = dns_resource_record_new_instance();
    static uint8_t        *rr2_ns_rdata = (uint8_t *)"\003ns3\007example\002eu";
    dns_resource_record_set_record(rr2, dnskey_get_domain(signing_key), TYPE_NS, CLASS_IN, 86400, dnsname_len(rr2_ns_rdata), rr2_ns_rdata);

    dns_resource_record_t *rr3 = dns_resource_record_new_instance();
    static uint8_t        *rr3_ns_rdata = (uint8_t *)"\003ns4\007example\002eu";
    dns_resource_record_set_record(rr3, dnskey_get_domain(signing_key), TYPE_NS, CLASS_IN, 86400, dnsname_len(rr3_ns_rdata), rr3_ns_rdata);

    ptr_vector_append(&rrset, rr0);
    ptr_vector_append(&rrset, rr1);
    ptr_vector_append(&rrset, rr2);

    ptr_vector_append(&rrset_different, rr1);
    ptr_vector_append(&rrset_different, rr3);

    resource_record_view_t rrv;
    dns_resource_record_t *rrsig_rr = NULL;
    dns_resource_record_resource_record_view_init(&rrv);

    int32_t from_epoch = dnskey_get_activate_epoch(signing_key);
    int32_t to_epoch = dnskey_get_inactive_epoch(signing_key);

    for(int_fast32_t multi_test = 0; multi_test < 4; ++multi_test)
    {
        // sign
        int64_t t;

        if(!g_sign_verify_test_uses_max_interval)
        {
            dnskey_signature_t ds;
            dnskey_signature_init(&ds);
            dnskey_signature_set_validity(&ds, from_epoch, to_epoch);
            dnskey_signature_set_view(&ds, &rrv);
            dnskey_signature_set_rrset_reference(&ds, &rrset);
            dnskey_signature_set_canonised(&ds, false);

            yatest_timer_start(&t);
            ret = dnskey_signature_sign(&ds, signing_key, (void **)&rrsig_rr);
            yatest_timer_stop(&t);
            dnskey_signature_finalize(&ds);
        }
        else
        {
            yatest_timer_start(&t);
            ret = dnskey_sign_rrset_with_maxinterval(signing_key, &rrset, true, &rrv, 86400, (void **)&rrsig_rr);
            yatest_timer_stop(&t);
        }

        if(ret >= 0)
        {
            yatest_log("signature using algorithm %i = %s took %f seconds and %i bytes", algorithm, dns_encryption_algorithm_get_name(algorithm), yatest_timer_seconds(&t), rrsig_rr->rdata_size);
        }
        else
        {
            yatest_err("dnskey_signature_sign FAILED?");
            if((algorithm == DNSKEY_ALGORITHM_RSASHA1) || (algorithm == DNSKEY_ALGORITHM_RSASHA1_NSEC3))
            {
                yatest_err("It's %s, it has probably been disabled in the distribution.", dns_encryption_algorithm_get_name(algorithm));
                break;
            }
            else
            {
                yatest_err("Algorithm %s may be disabled in libssl?", dns_encryption_algorithm_get_name(algorithm));

                yatest_err("K%s+%03i+%05i failure", signing_key_domain, dnskey_get_algorithm(signing_key), dnskey_get_tag(signing_key));
                yatest_err("dnskey_signature_sign failed with %08x = %s (text#%i, first signature)", ret, error_gettext(ret), multi_test);
                exit(1);
            }
        }

        rdata_desc_t rrsig_desc = {rrsig_rr->tctr.rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
        formatln("signature: %{typerdatadesc}", &rrsig_desc);
        flushout();

        int      sig_len = rrsig_rr->rdata_size;
        uint8_t *sig = rrsig_rr->rdata;
        sig += 18;
        sig_len -= 18;
        while(*sig != 0)
        {
            sig_len -= *sig + 1;
            sig += *sig + 1;
        }
        --sig_len;
        ++sig;

        if(sign_verify_test_dump_rdata)
        {
            println("signature bytes:");
            osprint_dump(termout, sig, sig_len, 32, OSPRINT_DUMP_BUFFER);
            println("");
            flushout();
        }

        const struct expected_signature_s *expected = expected_signature_get(tag);
        if((expected != NULL) && (expected->base64 != NULL))
        {
            ya_result bin_len;

            uint8_t   bin[1024];
            bin_len = base64_decode(expected->base64, strlen(expected->base64), bin);

            if(bin_len < 0)
            {
                yatest_err("K%s+%03i+%05i failure", signing_key_domain, dnskey_get_algorithm(signing_key), dnskey_get_tag(signing_key));
                yatest_err("encoded base64 is wrong : bug in the test code: %08x = %s", bin_len, error_gettext(bin_len));
                exit(1);
            }

            if(bin_len != sig_len)
            {
                yatest_err("K%s+%03i+%05i failure", signing_key_domain, dnskey_get_algorithm(signing_key), dnskey_get_tag(signing_key));
                yatest_err("ERROR: signature size doesn't match: %i != %i", bin_len, sig_len);
                osprintln(termerr, "ERROR: got:");
                osprint_dump(termerr, sig, sig_len, 32, OSPRINT_DUMP_BUFFER);
                osprintln(termerr, "");
                osprintln(termerr, "ERROR: expected:");
                osprint_dump(termerr, bin, bin_len, 32, OSPRINT_DUMP_BUFFER);
                osprintln(termerr, "");
                flusherr();
                exit(1);
            }

            if(memcmp(bin, sig, bin_len) != 0)
            {
                yatest_err("K%s+%03i+%05i failure", signing_key_domain, dnskey_get_algorithm(signing_key), dnskey_get_tag(signing_key));
                yatest_err("ERROR: signature doesn't match expectations");
                osprintln(termerr, "ERROR: got:");
                osprint_dump(termerr, sig, sig_len, 32, OSPRINT_DUMP_BUFFER);
                osprintln(termerr, "");
                osprintln(termerr, "ERROR: expected:");
                osprint_dump(termerr, bin, bin_len, 32, OSPRINT_DUMP_BUFFER);
                osprintln(termerr, "");
                flusherr();
                exit(1);
            }

            yatest_log("SUCCESS: signature matches expectations");
        }
        else
        {
            yatest_log("signature isn't reproducible, test skipped");
        }

        // verify

        dnskey_signature_t ds_back;
        dnskey_signature_init(&ds_back);
        dnskey_signature_set_validity(&ds_back, from_epoch, to_epoch);
        dnskey_signature_set_view(&ds_back, &rrv);
        dnskey_signature_set_rrset_reference(&ds_back, &rrset);
        dnskey_signature_set_canonised(&ds_back, false);

        yatest_timer_start(&t);
        ya_result ret_verify = dnskey_signature_verify(&ds_back, verifying_key, rrsig_rr);
        yatest_timer_stop(&t);
        dnskey_signature_finalize(&ds_back);
        yatest_log("verification using algorithm %i = %s took %f seconds", algorithm, dns_encryption_algorithm_get_name(algorithm), yatest_timer_seconds(&t));

        if(ret_verify < 0)
        {
            yatest_err("K%s+%03i+%05i failure", signing_key_domain, dnskey_get_algorithm(signing_key), dnskey_get_tag(signing_key));
            yatest_err("dnskey_signature_verify: signature not verified (back)");
            exit(1);
        }

        yatest_log("signature verified (back)");

        dnskey_signature_t ds_other;
        dnskey_signature_init(&ds_other);
        dnskey_signature_set_validity(&ds_other, from_epoch, to_epoch);
        dnskey_signature_set_view(&ds_other, &rrv);
        dnskey_signature_set_rrset_reference(&ds_other, &rrset_different);
        dnskey_signature_set_canonised(&ds_other, false);

        yatest_timer_start(&t);
        ret_verify = dnskey_signature_verify(&ds_other, verifying_key, rrsig_rr);
        yatest_timer_stop(&t);
        dnskey_signature_finalize(&ds_other);
        yatest_log("rejection using algorithm %i = %s took %f seconds", algorithm, dns_encryption_algorithm_get_name(algorithm), yatest_timer_seconds(&t));

        if(ret_verify >= 0)
        {
            yatest_err("K%s+%03i+%05i failure", signing_key_domain, dnskey_get_algorithm(signing_key), dnskey_get_tag(signing_key));
            yatest_err("dnskey_signature_verify: signature should not have verified (other)");
            exit(1);
        }

        yatest_log("signature verified (other)");

        if(rrsig_rr != NULL)
        {
            dns_resource_record_delete(rrsig_rr);
            rrsig_rr = NULL;
        }
    } // for loop

    dns_resource_record_resource_record_view_finalise(&rrv);

    if(rrsig_rr != NULL)
    {
        dns_resource_record_delete(rrsig_rr);
        rrsig_rr = NULL;
    }

    dns_resource_record_delete(rr3);
    dns_resource_record_delete(rr2);
    dns_resource_record_delete(rr1);
    dns_resource_record_delete(rr0);

    ptr_vector_finalise(&rrset_different);
    ptr_vector_finalise(&rrset);
}

static void ensure_baos_equals(output_stream_t *aos, output_stream_t *bos, const char *name)
{
    if(bytearray_output_stream_size(aos) != bytearray_output_stream_size(bos))
    {
        yatest_err("%s stream sizes differs: %i != %i", name, bytearray_output_stream_size(aos), bytearray_output_stream_size(bos));
        exit(1);
    }
    if(memcmp(bytearray_output_stream_buffer(aos), bytearray_output_stream_buffer(bos), bytearray_output_stream_size(aos)) != 0)
    {
        yatest_err("%s stream values differs", name);
        exit(1);
    }
}

static void key_algorithm_test(struct dnskey_inputs_s *input)
{
    int ret;

    yatest_log("key_algorithm_test: name = %s, algorithm = %i, bits = %i", input->file_name, input->algorithm, input->bit_size);
    yatest_log("=======================================================================================================");

    dnskey_t       *key = NULL;
    dnskey_t       *pub_key = NULL;
    dnskey_t       *priv_key = NULL;

    output_stream_t key_pub_os;
    output_stream_t key_priv_os;
    output_stream_t reloaded_key_pub_os;
    output_stream_t reloaded_key_priv_os;

    char           *filename = (char *)malloc(PATH_MAX);
    char            key_domain[DOMAIN_TEXT_BUFFER_SIZE];

    ret = dnskey_newinstance(input->bit_size, input->algorithm, DNSKEY_FLAGS_ZSK, test_key_algorithm_origin, &key);
    if(ret < 0)
    {
        yatest_err("dnskey_newinstance failed with %08x = %s (ZSK)", ret, error_gettext(ret));
        exit(1);
    }

    time_t t = time(NULL);
    time_t t_publish = t + 86400;
    time_t t_active = t_publish + 86400;
    time_t t_inactive = t_active + 86400;
    time_t t_unpublish = t_inactive + 86400;
    dnskey_set_created_epoch(key, t);
    dnskey_set_publish_epoch(key, t_publish);
    dnskey_set_activate_epoch(key, t_active);
    dnskey_set_inactive_epoch(key, t_inactive);
    dnskey_set_delete_epoch(key, t_unpublish);

    cstr_init_with_dnsname(key_domain, dnskey_get_domain(key));

    bytearray_output_stream_init(&key_pub_os, NULL, 0);
    bytearray_output_stream_init(&key_priv_os, NULL, 0);
    bytearray_output_stream_init(&reloaded_key_pub_os, NULL, 0);
    bytearray_output_stream_init(&reloaded_key_priv_os, NULL, 0);

    yatest_log("PUBLIC KEY:");
    yatest_log("-----------");
    dnskey_store_public_key_to_stream(key, termout);
    output_stream_flush(termout);
    dnskey_store_public_key_to_stream(key, &key_pub_os);

    yatest_log("PRIVATE KEY:");
    yatest_log("------------");
    dnskey_store_private_key_to_stream(key, termout);
    output_stream_flush(termout);
    dnskey_store_public_key_to_stream(key, &key_priv_os);

    ret = dnskey_store_keypair_to_dir(key, working_dirname);

    if(ret < 0)
    {
        yatest_err("dnskey_store_keypair_to_dir '%s' failed with %08x = %s", working_dirname, ret, error_gettext(ret));
        exit(1);
    }

    ret = asnformat(&filename, PATH_MAX, "%s/K%{dnsname}+%03d+%05d.key", working_dirname, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));

    if(ret < 0)
    {
        yatest_err("asnformat failed");
        exit(1);
    }

    ret = dnskey_new_public_key_from_file(filename, &pub_key);

    if(ret < 0)
    {
        yatest_err("dnskey_new_public_key_from_file '%s' failed with %08x = %s", filename, ret, error_gettext(ret));
        exit(1);
    }

    free(filename);

    yatest_log("RELOADED PUBLIC KEY:");
    yatest_log("--------------------");
    dnskey_store_public_key_to_stream(pub_key, termout);
    output_stream_flush(termout);
    dnskey_store_public_key_to_stream(key, &reloaded_key_pub_os);

    ensure_baos_equals(&key_pub_os, &reloaded_key_pub_os, "PUBLIC KEY");

    ret = asnformat(&filename, PATH_MAX, "%s/K%{dnsname}+%03d+%05d.private", working_dirname, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));

    if(ret < 0)
    {
        yatest_err("asnformat failed");
        exit(1);
    }

    ret = dnskey_new_private_key_from_file(filename, &priv_key);

    if(ret < 0)
    {
        yatest_err("dnskey_new_private_key_from_file '%s' failed with %08x = %s", filename, ret, error_gettext(ret));
        exit(1);
    }

    free(filename);

    yatest_log("RELOADED PRIVATE KEY:");
    yatest_log("---------------------");
    dnskey_store_private_key_to_stream(priv_key, termout);
    output_stream_flush(termout);
    dnskey_store_public_key_to_stream(key, &reloaded_key_priv_os);

    ensure_baos_equals(&key_priv_os, &reloaded_key_priv_os, "PRIVATE KEY");

    yatest_log("generated key with loaded pub key");
    yatest_log("---------------------------------------------------------------------------------------");
    sign_verify_test(key, pub_key);

    yatest_log("generated key with loaded priv key");
    yatest_log("---------------------------------------------------------------------------------------");
    sign_verify_test(key, priv_key);

    output_stream_close(&reloaded_key_priv_os);
    output_stream_close(&reloaded_key_pub_os);
    output_stream_close(&key_priv_os);
    output_stream_close(&key_pub_os);

    if(priv_key != NULL)
    {
        dnskey_release(priv_key);
        priv_key = NULL;
    }

    if(pub_key != NULL)
    {
        dnskey_release(pub_key);
        pub_key = NULL;
    }

    if(key != NULL)
    {
        dnskey_release(key);
        key = NULL;
    }
}

static int key_algorithms_test()
{
    init();
    for(struct dnskey_inputs_s *p = &dnskey_inputs[0]; p->record_text != NULL; ++p)
    {
        key_algorithm_test(p);
    }
    finalise();
    return 0;
}

static int dnskey_sign_rrset_with_maxinterval_test()
{
    init();
    g_sign_verify_test_uses_max_interval = true;
    for(struct dnskey_inputs_s *p = &dnskey_inputs[0]; p->record_text != NULL; ++p)
    {
        key_algorithm_test(p);
    }
    finalise();
    return 0;
}

static void parse_dnskey_record(struct dnskey_inputs_s *input, resource_record_t *rr)
{
    yatest_log("algorithm: '%s'", dns_encryption_algorithm_get_name(input->algorithm));

    input_stream_t is;
    bytearray_input_stream_init_const(&is, input->record_text, strlen(input->record_text));

    yatest_log("PUBLIC KEY:");
    yatest_log("-----------");
    yatest_log(input->record_text);

    zone_reader_t zr;
    ya_result     ret = zone_reader_text_parse_stream(&zr, &is);
    if(ret < 0)
    {
        yatest_err("failed to init zone reader");
        exit(1);
    }

    zone_reader_text_ignore_missing_soa(&zr);

    ret = zone_reader_read_record(&zr, rr);
    if(ret < 0)
    {
        yatest_err("failed to read record: %08x = %s", ret, error_gettext(ret));
        exit(1);
    }

    zone_reader_close(&zr);
}

static dnskey_t *parse_public_key_record(struct dnskey_inputs_s *input)
{
    int                ret;
    resource_record_t *rr = (resource_record_t *)malloc(sizeof(resource_record_t));
    if(rr == NULL)
    {
        yatest_err("resource_record malloc failed: internal error");
        exit(1);
    }

    parse_dnskey_record(input, rr);

    dnskey_t *key = NULL;

    ret = dnskey_new_from_rdata(rr->rdata, rr->rdata_size, rr->name, &key);

    free(rr);

    if(ret < 0)
    {
        yatest_err("dnskey_new_from_rdata failed: %08x = %s", ret, error_gettext(ret));
        exit(1);
    }

    if(key == NULL)
    {
        yatest_err("dnskey_new_from_rdata returned success without a key");
        exit(1);
    }

    uint16_t size = dnskey_get_size(key);
    if(size != input->bit_size)
    {
        yatest_err("%s: failure: %i != %i (%i)", input->record_text, size, input->bit_size, input->bit_size - size);
        yatest_err("key size doesn't match");
        exit(1);
    }

    return key;
}

static int public_key_parse_test()
{
    init();
    for(struct dnskey_inputs_s *p = &dnskey_inputs[0]; p->record_text != NULL; ++p)
    {
        dnskey_t *key;
        key = parse_public_key_record(p);
        dnskey_release(key);
    }
    finalise();
    return 0;
}

static void parse_private_key_record(struct dnskey_private_inputs_s *input)
{
    dnskey_t       *key = NULL;
    ya_result       ret = ERROR;

    output_stream_t os;
    char            file_name[PATH_MAX];

    for(int_fast32_t i = 0; dnskey_inputs[i].record_text != NULL; ++i)
    {
        if(dnskey_inputs[i].tag == input->tag)
        {
            snformat(file_name, sizeof(file_name), "%s/%s", working_dirname, dnskey_inputs[i].file_name);
            file_output_stream_create(&os, file_name, 0640);
            osprint(&os, dnskey_inputs[i].record_text);
            output_stream_close(&os);
            ret = SUCCESS;
            break;
        }
    }

    yatest_log("file: %s", input->file_name);

    if(FAIL(ret))
    {
        yatest_err("could not find the associated public key for tag %u", input->tag);
        exit(1);
    }

    yatest_log("PRIVATE KEY:");
    yatest_log("------------");
    yatest_log(input->file_text);

    snformat(file_name, sizeof(file_name), "%s/%s", working_dirname, input->file_name);
    file_output_stream_create(&os, file_name, 0640);
    osprint(&os, input->file_text);
    output_stream_close(&os);

    formatln("FILE NAME: '%s'", file_name);

    ret = dnskey_new_private_key_from_file(file_name, &key);
    if(ret < 0)
    {
        yatest_err("failed to parse file '%s':\n%s\nerror is: %r", input->file_name, input->file_text, ret);
        exit(1);
    }

    yatest_log("RELOADED PUBLIC KEY:");
    yatest_log("--------------------");
    dnskey_store_public_key_to_stream(key, termout);
    flushout();
    yatest_log("");
    yatest_log("RELOADED PRIVATE KEY:");
    yatest_log("---------------------");
    dnskey_store_private_key_to_stream(key, termout);
    yatest_log("");

    uint16_t tag = dnskey_get_tag(key);

    if(tag != input->tag)
    {
        yatest_err("tag mismatch '%s': expected %hu, got %hu", input->file_text, input->tag, tag);
        yatest_err("key parse tag mismatch (%hu != %hu)", tag, input->tag);
        exit(1);
    }

    sign_verify_test(key, key);

    dnskey_release(key);
}

static int private_key_parse_test()
{
    init();
    for(struct dnskey_private_inputs_s *p = &dnskey_private_inputs[0]; p->file_text != NULL; ++p)
    {
        parse_private_key_record(p);
    }
    finalise();
    return 0;
}

static dnskey_t *dnskey_load_from_text_record(const char *record_text)
{
    input_stream_t is;
    bytearray_input_stream_init_const(&is, record_text, strlen(record_text));

    zone_reader_t zr;
    ya_result     ret = zone_reader_text_parse_stream(&zr, &is);
    if(ret < 0)
    {
        yatest_err("failed to init zone reader");
        exit(1);
    }

    resource_record_t rr;
    zone_reader_text_ignore_missing_soa(&zr);

    ret = zone_reader_read_record(&zr, &rr);
    if(ret < 0)
    {
        yatest_err("failed to read record: %08x = %s", ret, error_gettext(ret));
        exit(1);
    }

    dnskey_t *key = NULL;

    ret = dnskey_new_from_rdata(rr.rdata, rr.rdata_size, rr.name, &key);

    if(ret < 0)
    {
        yatest_err("dnskey_new_from_rdata failed: %08x = %s", ret, error_gettext(ret));
        exit(1);
    }

    if(key == NULL)
    {
        yatest_err("dnskey_new_from_rdata returned success without a key");
        exit(1);
    }

    return key;
}

static int dnskey_equals_test()
{
    init();
    for(struct dnskey_inputs_s *p = &dnskey_inputs[0]; p->record_text != NULL; ++p)
    {
        dnskey_t *p_key = dnskey_load_from_text_record(p->record_text);

        for(struct dnskey_inputs_s *q = p; q->record_text != NULL; ++q)
        {
            dnskey_t *q_key = dnskey_load_from_text_record(q->record_text);

            bool      pq_equals = dnskey_equals(p_key, q_key);
            if(p == q)
            {
                if(!pq_equals)
                {
                    yatest_err("p==q: comparison returned false");
                    exit(1);
                }
            }
            else
            {
                if(pq_equals)
                {
                    yatest_err("p!=q: comparison returned true");
                    exit(1);
                }
            }

            pq_equals = dnskey_public_equals(p_key, q_key);
            if(p == q)
            {
                if(!pq_equals)
                {
                    yatest_err("p==q: comparison returned false (public)");
                    exit(1);
                }
            }
            else
            {
                if(pq_equals)
                {
                    yatest_err("p!=q: comparison returned true (public)");
                    exit(1);
                }
            }

            dnskey_release(q_key);
        }

        dnskey_release(p_key);
    }
    finalise();
    return 0;
}

static int algorithms_test()
{
    init();
    for(int i = 0; dnskey_algorithm_list[i] >= 0; ++i)
    {
        int a = dnskey_algorithm_list[i];
        yatest_log("Algorithm at index %i has value %i", i, a);
        const dnskey_features_t *features = dnskey_supported_algorithm(a);
        if(features == NULL)
        {
            continue;
        }
        if(features->algorithm != a)
        {
            yatest_err("algorithm mismatch: expected %i, got %i", a, features->algorithm);
            return 1;
        }
        for(int j = 0; features->names[j] != NULL; ++j)
        {
            yatest_log("Name: '%s'", features->names[j]);
        }
        yatest_log("bits: min = %i, max = %i, ksk = %i, zsk = %i, multiple = %i", features->size_bits_min, features->size_bits_max, features->size_bits_ksk_default, features->size_bits_zsk_default, features->size_multiple);
        yatest_log("usage: %x", features->usage);
    }
    finalise();
    return 0;
}

static int algorithm_by_index_test()
{
    init();
    for(int i = 0; i < dnskey_supported_algorithm_count(); ++i)
    {
        const dnskey_features_t *features = dnskey_supported_algorithm_by_index(i);
        if(features == NULL)
        {
            yatest_err("Unexpected NULL features at index %i/%i", i, dnskey_supported_algorithm_count());
            return 1;
        }
        yatest_log("Algorithm at index %i has value %i", i, features->algorithm);

        for(int j = 0; features->names[j] != NULL; ++j)
        {
            yatest_log("Name: '%s'", features->names[j]);
        }
        yatest_log("bits: min = %i, max = %i, ksk = %i, zsk = %i, multiple = %i", features->size_bits_min, features->size_bits_max, features->size_bits_ksk_default, features->size_bits_zsk_default, features->size_multiple);
        yatest_log("usage: %x", features->usage);
    }

    if(dnskey_supported_algorithm_count() != 255)
    {
        if(dnskey_supported_algorithm_by_index(dnskey_supported_algorithm_count()) != NULL)
        {
            yatest_err("dnskey_supported_algorithm_by_index(out-of-range) didn't return NULL");
            return 1;
        }
    }
    else
    {
        yatest_log("dnskey_supported_algorithm_by_index(out-of-range) cannot be tested");
    }

    finalise();
    return 0;
}

static int fields_test()
{
    int ret;
    init();
    dnskey_t *key;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, test_key_algorithm_origin, &key);
    if(ret < 0)
    {
        yatest_err("dnskey_newinstance failed");
        return 1;
    }

    time_t t = time(NULL);
    time_t t_publish = t + 86400;
    time_t t_active = t_publish + 86400;
    time_t t_inactive = t_active + 86400;
    time_t t_unpublish = t_inactive + 86400;

    time_t created_epoch = dnskey_get_created_epoch(key);
    if(llabs((int64_t)created_epoch - (int64_t)t) > 60)
    {
        yatest_err("create_epoch appears to be wrong: %i too different from %i", created_epoch, t);
        return 1;
    }
    dnskey_set_created_epoch(key, t + 1);
    if(dnskey_get_created_epoch(key) != t + 1)
    {
        yatest_err("dnskey_set_created_epoch had no effect");
        return 1;
    }
    dnskey_set_created_epoch(key, t);
    time_t activate_epoch = dnskey_get_activate_epoch(key);
    if(activate_epoch != t)
    {
        yatest_err("dnskey_get_activate_epoch expected to equal to dnskey_get_created_epoch at this point");
        return 1;
    }

    bool is_published = dnskey_is_published(key, t);
    if(!is_published)
    {
        yatest_err("is_published is false");
        return 1;
    }
    bool is_unpublished = dnskey_is_unpublished(key, t);
    if(is_unpublished)
    {
        yatest_err("is_unpublished is true");
        return 1;
    }
    bool is_activated = dnskey_is_activated(key, t);
    if(!is_activated)
    {
        yatest_err("is_activated is false");
        return 1;
    }
    bool is_activated_lenient = dnskey_is_activated_lenient(key, t, 86400);
    if(!is_activated_lenient)
    {
        yatest_err("is_activated_lenient is false ");
        return 1;
    }
    bool is_deactivated = dnskey_is_deactivated(key, t);
    if(is_deactivated)
    {
        yatest_err("is_deactivated is true");
        return 1;
    }
    bool has_explicit_publish = dnskey_has_explicit_publish(key);
    if(has_explicit_publish)
    {
        yatest_err("has_explicit_publish is true");
        return 1;
    }
    bool has_explicit_delete = dnskey_has_explicit_delete(key);
    if(has_explicit_delete)
    {
        yatest_err("has_explicit_delete is true");
        return 1;
    }
    bool has_explicit_activate = dnskey_has_explicit_activate(key);
    if(has_explicit_activate)
    {
        yatest_err("has_explicit_activate is true");
        return 1;
    }
    bool has_explicit_deactivate = dnskey_has_explicit_deactivate(key);
    if(has_explicit_deactivate)
    {
        yatest_err("has_explicit_deactivate is true");
        return 1;
    }
    bool has_explicit_publish_or_delete = dnskey_has_explicit_publish_or_delete(key);
    if(has_explicit_publish_or_delete)
    {
        yatest_err("has_explicit_publish_or_delete is true");
        return 1;
    }
    bool has_explicit_publish_and_delete = dnskey_has_explicit_publish_and_delete(key);
    if(has_explicit_publish_and_delete)
    {
        yatest_err("has_explicit_publish_and_delete is true");
        return 1;
    }
    bool has_activate_and_deactivate = dnskey_has_activate_and_deactivate(key);
    if(has_activate_and_deactivate)
    {
        yatest_err("has_activate_and_deactivate is true");
        return 1;
    }
    bool has_activate_or_deactivate = dnskey_has_activate_or_deactivate(key);
    if(has_activate_or_deactivate)
    {
        yatest_err("has_activate_or_deactivate is true");
        return 1;
    }
    bool is_expired = dnskey_is_expired(key, t);
    if(is_expired)
    {
        yatest_err("is_expired is true");
        return 1;
    }
    bool is_expired_now = dnskey_is_expired_now(key);
    if(is_expired_now)
    {
        yatest_err("is_expired_now is true");
        return 1;
    }
    /*
    bool is_revoked = dnskey_is_revoked(key);
    if(is_revoked)
    {
        yatest_err("is_revoked is true");
        return 1;
    }
    */
    yatest_log("state: %08x", dnskey_state_get(key));
    uint32_t state = dnskey_state_get(key);
    dnskey_state_enable(key, 0x8000);
    if((state | 0x8000) != dnskey_state_get(key))
    {
        yatest_err("state wasn't properly set (enable)");
        return 1;
    }
    dnskey_state_disable(key, 0x8000);
    if(state != dnskey_state_get(key))
    {
        yatest_err("state wasn't properly set (disable)");
        return 1;
    }

    if(dnskey_get_flags(key) != DNSKEY_FLAGS_ZSK)
    {
        yatest_err("flags value %x != %x", dnskey_get_flags(key), DNSKEY_FLAGS_ZSK);
        return 1;
    }

    if(dnskey_get_publish_epoch(key) != dnskey_get_created_epoch(key))
    {
        yatest_err("dnskey_get_delete_epoch value doesn't match expectation (dnskey_get_created_epoch)");
        return 1;
    }

    if(dnskey_get_delete_epoch(key) != INT32_MAX)
    {
        yatest_err("dnskey_get_delete_epoch value doesn't match expectation (INT32_MAX)");
        return 1;
    }

    // publish/delete
    dnskey_set_delete_epoch(key, t_unpublish);

    if(dnskey_get_delete_epoch(key) != t_unpublish)
    {
        yatest_err("dnskey_get_delete_epoch didn't set the time properly");
        return 1;
    }

    if(!dnskey_has_explicit_delete(key))
    {
        yatest_err("dnskey_has_explicit_delete after dnskey_set_delete_epoch expected to be true");
        return 1;
    }
    if(!dnskey_is_published(key, t_active))
    {
        yatest_err("dnskey_is_published before delete-epoch expected to be true");
        return 1;
    }
    if(dnskey_is_unpublished(key, t_unpublish - 1))
    {
        yatest_err("dnskey_is_unpublished before delete-epoch expected to be false");
        return 1;
    }
    if(!dnskey_is_unpublished(key, t_unpublish + 1))
    {
        yatest_err("dnskey_is_unpublished after delete-epoch expected to be true");
        return 1;
    }
    dnskey_set_publish_epoch(key, t_publish);

    if(dnskey_get_publish_epoch(key) != t_publish)
    {
        yatest_err("dnskey_get_publish_epoch didn't set the time properly");
        return 1;
    }

    activate_epoch = dnskey_get_activate_epoch(key);
    if(activate_epoch != t_publish)
    {
        yatest_err("dnskey_get_activate_epoch expected to equal to dnskey_get_publish_epoch at this point");
        return 1;
    }

    if(!dnskey_has_explicit_publish(key))
    {
        yatest_err("dnskey_has_explicit_publish after dnskey_set_publish_epoch expected to be true");
        return 1;
    }
    if(!dnskey_has_explicit_publish_or_delete(key))
    {
        yatest_err("dnskey_has_explicit_publish_or_delete after dnskey_set_publish_epoch expected to be true");
        return 1;
    }
    if(!dnskey_is_published(key, t_active))
    {
        yatest_err("dnskey_is_published after publish-epoch expected to be true");
        return 1;
    }
    if(dnskey_is_published(key, t_publish - 1))
    {
        yatest_err("dnskey_is_published before publish-epoch expected to be false");
        return 1;
    }
    if(dnskey_is_published(key, t_unpublish + 1))
    {
        yatest_err("dnskey_is_published after delete-epoch expected to be false");
        return 1;
    }

    // active/inactive
    if(dnskey_is_activated(key, t_publish - 1))
    {
        yatest_err("dnskey_is_activated before publish-epoch without active/inactive expected to be false");
        return 1;
    }
    if(dnskey_is_activated(key, t_unpublish + 1))
    {
        yatest_err("dnskey_is_activated after delete-epoch without active/inactive expected to be false");
        return 1;
    }
    if(!dnskey_is_activated(key, t_publish + 1))
    {
        yatest_err("dnskey_is_activated after publish-epoch without active/inactive expected to be true");
        return 1;
    }
    if(!dnskey_is_activated(key, t_unpublish - 1))
    {
        yatest_err("dnskey_is_activated before delete-epoch without active/inactive expected to be true");
        return 1;
    }
    if(dnskey_is_deactivated(key, t_unpublish - 1))
    {
        yatest_err("dnskey_is_deactivated before delete-epoch without active/inactive expected to be false");
        return 1;
    }
    if(!dnskey_is_deactivated(key, t_unpublish + 1))
    {
        yatest_err("dnskey_is_deactivated after delete-epoch without active/inactive expected to be true");
        return 1;
    }
    dnskey_set_inactive_epoch(key, t_inactive);
    if(dnskey_is_activated(key, t_inactive + 1))
    {
        yatest_err("dnskey_is_activated after inactive-epoch without active/inactive expected to be false");
        return 1;
    }
    if(!dnskey_is_activated(key, t_inactive - 1))
    {
        yatest_err("dnskey_is_activated before inactive-epoch without active/inactive expected to be true");
        return 1;
    }
    dnskey_set_activate_epoch(key, t_active);
    if(!dnskey_is_activated(key, t_active + 1))
    {
        yatest_err("dnskey_is_activated after active-epoch without active/inactive expected to be true");
        return 1;
    }
    if(dnskey_is_activated(key, t_active - 1))
    {
        yatest_err("dnskey_is_activated before active-epoch without active/inactive expected to be false");
        return 1;
    }
    if(dnskey_is_deactivated(key, t_inactive - 1))
    {
        yatest_err("dnskey_is_deactivated before inactive-epoch without active/inactive expected to be false");
        return 1;
    }
    if(!dnskey_is_deactivated(key, t_inactive + 1))
    {
        yatest_err("dnskey_is_deactivated after inactive-epoch without active/inactive expected to be true");
        return 1;
    }
    is_activated_lenient = dnskey_is_activated_lenient(key, t_active - 43200, 86400);
    if(!is_activated_lenient)
    {
        yatest_err("is_activated_lenient is false (t_active - 43200, 86400)");
        return 1;
    }

    is_activated_lenient = dnskey_is_activated_lenient(key, INT32_MAX, 86400);
    if(is_activated_lenient)
    {
        yatest_err("is_activated_lenient is true (INT32_MAX, 86400)");
        return 1;
    }

    // to go through the 2nd branch of dnskey_get_inactive_epoch ...
    dnskey_set_inactive_epoch(key, 0);
    time_t inactive_epoch = dnskey_get_inactive_epoch(key);
    if((inactive_epoch < dnskey_get_activate_epoch(key)) || (inactive_epoch >= dnskey_get_delete_epoch(key)))
    {
        yatest_err("dnskey_get_inactive_epoch (2nd branch) failed");
        return 1;
    }
    // to go through the 2nd branch of dnskey_get_delete_epoch ...
    dnskey_set_delete_epoch(key, 0);
    dnskey_set_publish_epoch(key, 0);
    dnskey_set_inactive_epoch(key, t_inactive);
    time_t delete_epoch = dnskey_get_delete_epoch(key);
    if(delete_epoch < t_inactive)
    {
        yatest_err("dnskey_get_delete_epoch (2nd branch) failed");
        return 1;
    }
    finalise();
    return 0;
}

static int dnskey_newinstance_errors_test()
{
    int       ret;
    dnskey_t *key = NULL;
    init();
    uint8_t unsupported_algorithm = 250;
    ret = dnskey_newinstance(DNSSEC_MAXIMUM_KEY_SIZE + 1, unsupported_algorithm, 0, ".", &key);
    if(ret != DNSSEC_ERROR_KEYISTOOBIG)
    {
        yatest_err("dnskey_newinstance expected to fail with DNSSEC_ERROR_KEYISTOOBIG");
        return 1;
    }
    ret = dnskey_newinstance(DNSSEC_MAXIMUM_KEY_SIZE, unsupported_algorithm, 0, ".", &key);
    if(ret != DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM)
    {
        yatest_err("dnskey_newinstance expected to fail with DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM");
        return 1;
    }
    finalise();
    return 0;
}

static int dnskey_newemptyinstance_test()
{
    dnskey_t *key;
    init();
    uint8_t unsupported_algorithm = 250;

    key = dnskey_newemptyinstance(unsupported_algorithm, DNSKEY_FLAGS_ZSK, NULL);
    if(key == NULL)
    {
        yatest_err("dnskey_newemptyinstance returned NULL (null origin)");
        return 1;
    }
    dnskey_release(key);

    key = dnskey_newemptyinstance(unsupported_algorithm, DNSKEY_FLAGS_ZSK, "");
    if(key == NULL)
    {
        yatest_err("dnskey_newemptyinstance returned NULL (empty origin)");
        return 1;
    }
    dnskey_release(key);

    key = dnskey_newemptyinstance(unsupported_algorithm, DNSKEY_FLAGS_ZSK, "-_.._-");
    if(key != NULL)
    {
        yatest_err("dnskey_newemptyinstance didn't NULL (wrong fqdn)");
        return 1;
    }
    finalise();
    return 0;
}

static int dnskey_store_test()
{
    int ret;
    init();

    dnskey_t *key;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, test_key_algorithm_origin, &key);
    if(ret < 0)
    {
        yatest_err("dnskey_newinstance failed");
        return 1;
    }

    time_t t = time(NULL);
    time_t t_publish = t + 86400;
    time_t t_active = t_publish + 86400;
    time_t t_inactive = t_active + 86400;
    time_t t_unpublish = t_inactive + 86400;
    dnskey_set_created_epoch(key, t);
    dnskey_set_publish_epoch(key, t_publish);
    dnskey_set_activate_epoch(key, t_active);
    dnskey_set_inactive_epoch(key, t_inactive);
    dnskey_set_delete_epoch(key, t_unpublish);

    ret = dnskey_store_keypair_to_dir(key, working_dirname);
    if(ret < 0)
    {
        yatest_err("dnskey_store_keypair_to_dir failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ret = dnskey_delete_keypair_from_dir(key, working_dirname);
    if(ret < 0)
    {
        yatest_err("dnskey_delete_keypair_from_dir failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dnskey_release(key);

    finalise();
    return 0;
}

static int dnskey_chain_test()
{
    int ret;
    init();
    dnskey_t *key0;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, test_key_algorithm_origin, &key0);
    if(ret < 0)
    {
        yatest_err("dnskey_newinstance failed (key0)");
        return 1;
    }
    dnskey_t *key1;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, test_key_algorithm_origin, &key1);
    if(ret < 0)
    {
        yatest_err("dnskey_newinstance failed (key1)");
        return 1;
    }
    dnskey_add_to_chain(key1, &key0->next);
    dnskey_add_to_chain(key1, &key0->next);
    dnskey_remove_from_chain(key1, &key0->next);
    dnskey_remove_from_chain(key1, &key0->next);
    finalise();
    return 0;
}

static int dnskey_generate_ds_rdata_test()
{
    int                  ret;
    static const uint8_t fqdn[] = {0};
    static const uint8_t rdata[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30};

    static const uint8_t sha1_ds_rdata[] = {0xf0, 0xe1, 0x03, 0x01, 0x56, 0x89, 0x9c, 0x5f, 0x68, 0x0d, 0x61, 0x82, 0x5c, 0x2b, 0x9f, 0x51, 0x21, 0x2c, 0xa2, 0xfd, 0x00, 0x97, 0xf4, 0x93};

    static const uint8_t sha256_ds_rdata[] = {0xf0, 0xe1, 0x03, 0x02, 0xdd, 0xb3, 0x69, 0x39, 0xa1, 0xbf, 0x96, 0xd6, 0x5b, 0x70, 0x5e, 0x34, 0x48, 0xbb,
                                              0x31, 0x13, 0x9c, 0x66, 0xe3, 0xd5, 0x2b, 0xac, 0x3d, 0x17, 0x1a, 0xc7, 0x9d, 0x7c, 0x5c, 0x51, 0x32, 0x6d};

    uint8_t              ds_rdata[256];
    ret = dnskey_generate_ds_rdata(DS_DIGEST_SHA1, fqdn, rdata, sizeof(rdata), ds_rdata);
    if(memcmp(ds_rdata, sha1_ds_rdata, ret) == 0)
    {
        yatest_err("dnskey_generate_ds_rdata output doesn't match expectations (SHA1)");
        yatest_err("got:");
        yatest_hexdump_err(ds_rdata, ds_rdata + ret);
        yatest_err("expected:");
        yatest_hexdump_err(sha1_ds_rdata, sha1_ds_rdata + sizeof(sha1_ds_rdata));
        return 1;
    }
    ret = dnskey_generate_ds_rdata(DS_DIGEST_SHA256, fqdn, rdata, sizeof(rdata), ds_rdata);
    if(memcmp(ds_rdata, sha1_ds_rdata, ret) == 0)
    {
        yatest_err("dnskey_generate_ds_rdata output doesn't match expectations (SHA256)");
        yatest_err("got:");
        yatest_hexdump_err(ds_rdata, ds_rdata + ret);
        yatest_err("expected:");
        yatest_hexdump_err(sha256_ds_rdata, sha256_ds_rdata + sizeof(sha256_ds_rdata));
        return 1;
    }
    uint8_t unsupported_algorithm = 250;
    ret = dnskey_generate_ds_rdata(unsupported_algorithm, fqdn, rdata, sizeof(rdata), ds_rdata);
    if(ret != DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM)
    {
        yatest_err("dnskey_generate_ds_rdata expected to return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM");
        return 1;
    }
    return 0;
}

static int dnskey_digest_init_test()
{
    int ret;
    init();
    digest_t             ctx;
    static const char    text[] = "The quick brown fox jumps over the lazy dog";
    static const uint8_t algorithm[] = {DNSKEY_ALGORITHM_RSASHA1_NSEC3, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_ALGORITHM_ECDSAP384SHA384, DNSKEY_ALGORITHM_RSASHA512_NSEC3, DNSKEY_ALGORITHM_ED25519};

    static const uint8_t digest_sha1[] = {0x2F, 0xD4, 0xE1, 0xC6, 0x7A, 0x2D, 0x28, 0xFC, 0xED, 0x84, 0x9E, 0xE1, 0xBB, 0x76, 0xE7, 0x39, 0x1B, 0x93, 0xEB, 0x12};
    static const uint8_t digest_sha256[] = {0xD7, 0xA8, 0xFB, 0xB3, 0x07, 0xD7, 0x80, 0x94, 0x69, 0xCA, 0x9A, 0xBC, 0xB0, 0x08, 0x2E, 0x4F, 0x8D, 0x56, 0x51, 0xE4, 0x6D, 0x3C, 0xDB, 0x76, 0x2D, 0x02, 0xD0, 0xBF, 0x37, 0xC9, 0xE5, 0x92};
    static const uint8_t digest_sha386[] = {0xCA, 0x73, 0x7F, 0x10, 0x14, 0xA4, 0x8F, 0x4C, 0x0B, 0x6D, 0xD4, 0x3C, 0xB1, 0x77, 0xB0, 0xAF, 0xD9, 0xE5, 0x16, 0x93, 0x67, 0x54, 0x4C, 0x49,
                                            0x40, 0x11, 0xE3, 0x31, 0x7D, 0xBF, 0x9A, 0x50, 0x9C, 0xB1, 0xE5, 0xDC, 0x1E, 0x85, 0xA9, 0x41, 0xBB, 0xEE, 0x3D, 0x7F, 0x2A, 0xFB, 0xC9, 0xB1};
    static const uint8_t digest_sha512[] = {0x07, 0xE5, 0x47, 0xD9, 0x58, 0x6F, 0x6A, 0x73, 0xF7, 0x3F, 0xBA, 0xC0, 0x43, 0x5E, 0xD7, 0x69, 0x51, 0x21, 0x8F, 0xB7, 0xD0, 0xC8, 0xD7, 0x88, 0xA3, 0x09, 0xD7, 0x85, 0x43, 0x6B, 0xBB, 0x64,
                                            0x2E, 0x93, 0xA2, 0x52, 0xA9, 0x54, 0xF2, 0x39, 0x12, 0x54, 0x7D, 0x1E, 0x8A, 0x3B, 0x5E, 0xD6, 0xE1, 0xBF, 0xD7, 0x09, 0x78, 0x21, 0x23, 0x3F, 0xA0, 0x53, 0x8F, 0x3D, 0xB8, 0x54, 0xFE, 0xE6};

    struct digest_len_s
    {
        const uint8_t *data;
        int            size;
    };

    static const struct digest_len_s algorithm_digests[] = {
        {digest_sha1, sizeof(digest_sha1)}, {digest_sha256, sizeof(digest_sha256)}, {digest_sha386, sizeof(digest_sha386)}, {digest_sha512, sizeof(digest_sha512)}, {(const uint8_t *)text, sizeof(text) - 1}};

    for(size_t i = 0; i < sizeof(algorithm); ++i)
    {
        ret = dnskey_digest_init(&ctx, algorithm[i]);
        if(ret < 0)
        {
            yatest_err("dnskey_digest_init failed %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        digest_update(&ctx, text, sizeof(text) - 1);
        uint8_t digest[DIGEST_BUFFER_SIZE];
        memset(digest, 0xff, sizeof(digest));
        int digest_size = digest_get_size(&ctx);
        digest_final_copy_bytes(&ctx, digest, digest_size);
        // algorithm_digests[i].data, algorithm_digests[i].size
        if(digest_size != algorithm_digests[i].size)
        {
            yatest_err("algorithm[%i] digest size expected to be %i, got %i", i, digest_size, algorithm_digests[i].size);
            return 1;
        }
        if(memcmp(digest, algorithm_digests[i].data, digest_size))
        {
            yatest_err("algorithm[%i] value doesn't match", i);
            yatest_err("got:");
            yatest_hexdump_err(digest, digest + digest_size);
            yatest_err("expected:");
            yatest_hexdump_err(algorithm_digests[i].data, algorithm_digests[i].data + digest_size);
            return 1;
        }
        digest_finalise(&ctx);
    }

    uint8_t unsupported_algorithm = 250;
    ret = dnskey_digest_init(&ctx, unsupported_algorithm);
    if(ret >= 0)
    {
        yatest_err("dnskey_digest_init didn't fail (unsupported algorithm)");
        return 1;
    }

    finalise();
    return 0;
}

static int dnskey_new_from_rdata_error_test()
{
    int ret;
    init();
    static const uint8_t fqdn[] = {0};
    static const uint8_t rdata[] = {0, 1, 2, 250, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30};
    dnskey_t            *key = NULL;
    ret = dnskey_new_from_rdata(rdata, sizeof(rdata), fqdn, NULL);
    if(ret != UNEXPECTED_NULL_ARGUMENT_ERROR)
    {
        yatest_err("dnskey_new_from_rdata expexted to return UNEXPECTED_NULL_ARGUMENT_ERROR, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = dnskey_new_from_rdata(rdata, sizeof(rdata), fqdn, &key);
    if(ret != DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM)
    {
        yatest_err("dnskey_new_from_rdata expexted to return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int dnskey_matches_rdata_test()
{
    int ret;
    init();
    static const char *fqdn_text = ".";
    static const int   rdata_size_max = 2048;
    uint8_t           *rdata = (uint8_t *)malloc(rdata_size_max);

    if(rdata == NULL)
    {
        yatest_err("malloc unexpectedly failed (internal error)");
        return 1;
    }

    dnskey_t *key = NULL;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, fqdn_text, &key);
    if(ret < 0)
    {
        yatest_err("dnskey_newinstance unexpectedly failed (internal error) %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    uint32_t rdata_size = key->vtbl->dnskey_writerdata(key, rdata, rdata_size_max);

    if(!dnskey_matches_rdata(key, rdata, rdata_size))
    {
        yatest_err("dnskey_matches_rdata returned false");
        return 1;
    }

    for(uint32_t i = 0; i < rdata_size; ++i)
    {
        rdata[i] ^= 1;
        if(dnskey_matches_rdata(key, rdata, rdata_size))
        {
            yatest_err("dnskey_matches_rdata returned true (offset %u)", i);
            return 1;
        }
        rdata[i] ^= 1;
    }

    free(rdata);
    dnskey_release(key);

    finalise();
    return 0;
}

static int dnskey_init_dns_resource_record_test()
{
    int ret;
    init();
    dns_resource_record_t *rr = dns_resource_record_new_instance();

    static const char     *fqdn_text = ".";
    static const int       rdata_size_max = 2048;
    uint8_t               *rdata = (uint8_t *)malloc(rdata_size_max);

    if(rdata == NULL)
    {
        yatest_err("malloc unexpectedly failed (internal error)");
        return 1;
    }

    dnskey_t *key = NULL;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, fqdn_text, &key);
    if(ret < 0)
    {
        yatest_err("dnskey_newinstance unexpectedly failed (internal error) %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    uint32_t rdata_size = key->vtbl->dnskey_writerdata(key, rdata, rdata_size_max);

    dnskey_init_dns_resource_record(key, 86400, rr);

    if(rdata_size != rr->rdata_size)
    {
        yatest_err("dnskey_init_dns_resource_record_test rdata_size doesn't match %u != %u", rr->rdata_size, rdata_size);
        return 1;
    }

    if(memcmp(rr->rdata, rdata, rdata_size) != 0)
    {
        yatest_err("dnskey_init_dns_resource_record_test rdata doesn't match");
        return 1;
    }

    finalise();
    return 0;
}

static int dnskey_new_public_key_from_stream_test()
{
    int ret;
    init();

    static const char *dnskey_record =
        "example.eu. IN DNSKEY 256 3 8 "
        "AwEAAdeIrZf0lzKCsv78AWKssgk4QQbPX/IWDVKCWkWLo4ic4plOaZq4 "
        "Dltu59r1FUSNPxKHv7Nyv/DlK/5AnaGUR01iM10peFSCkc1RGbdKk98H "
        "FHgXnN3jeJXErvwabY47OE4XX04Qbb2KC7FVCfzjEdQIiXbHMdUE6N3T "
        "OcZ73ZgFPvP2qcKznagn++tNGlWCngykRcIF0qJvgvxzkJh+o/u2I4Kx "
        "JtqH5R4RQx3W6jHdl5ug8+CU6za5jqHxDlLAYphppF7PqRSkmyeqRQwp "
        "/ARTWcf2ykvN/X0h/IfspuB/x4HErZQ1LNsmck7q6NK1O+EmUjlxim6k "
        "//XIRh+yIqnT1gpi6StwoMlD4sVPBgj83TnY5jp3AyKJPsNVtQ0cyzGy "
        "Pcg6bn/e5n0FX7OKjFM3cDFpsRc0M52K3lBKqvLU/20kAQ9oDh3ucH4n "
        "k1HcJvsr0JdcAro8tx2hibdrwHTKIZq1uv5ElfMiP2SLb4Pwr8r+hyrT "
        "UaKIy/1L0d/ob/vrWowG9dagX9lBwc5zRwt4/76bZ1HQNK/U/O1ZJ7sC "
        "enaTNOutsMYZXjDWJXieH6LOPoPL7Vt8dDE3Xl+flTQmKt5Meo2UhYhO "
        "lHEL9jMV/A2tUA2CvHk5H9Ikd9HA6I9LikstYSSLn8+u/By/RjkCWGSD "
        "20g8eoqio6VD6dHX";

    static const int dnskey_record_until_b64 = 31;
    dnskey_t        *key = NULL;
    input_stream_t   is;

    for(int i = 0; i < dnskey_record_until_b64; ++i)
    {
        bytearray_input_stream_init_const(&is, dnskey_record, i);
        ret = dnskey_new_public_key_from_stream(&is, &key);
        if(ret >= 0)
        {
            yatest_err("dnskey_new_public_key_from_stream didn't fail with len %i", i);
            return 1;
        }
        if(key != NULL)
        {
            yatest_err("dnskey_new_public_key_from_stream failed but key is not NULL (len %i)", i);
            return 1;
        }
        input_stream_close(&is);
    }

    bytearray_input_stream_init_const(&is, dnskey_record, strlen(dnskey_record));
    ret = dnskey_new_public_key_from_stream(&is, &key);
    if(ret < 0)
    {
        yatest_err("dnskey_new_public_key_from_stream failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    if(key == NULL)
    {
        yatest_err("dnskey_new_public_key_from_stream succeeded but key is NULL");
        return 1;
    }
    input_stream_close(&is);
    dnskey_release(key);

    finalise();
    return 0;
}

static int dnskey_keyring_test()
{
    int ret;
    init();
    dnskey_keyring_t    *kr = dnskey_keyring_new();

    static const uint8_t fqdn[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
    static const char   *fqdn_text = "yadifa.eu";

    dnskey_t            *key = NULL;
    dnskey_t            *key2 = NULL;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, fqdn_text, &key);
    if(ret < 0)
    {
        yatest_err("dnskey_newinstance unexpectedly failed (internal error) %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    if(!dnskey_keyring_isempty(kr))
    {
        yatest_err("dnskey_keyring_isempty returned false");
        return 1;
    }

    if(dnskey_keyring_has_key(kr, DNSKEY_ALGORITHM_RSASHA256_NSEC3, 0x1234, fqdn))
    {
        yatest_err("dnskey_keyring_has_key returned true (empty)");
        return 1;
    }

    key2 = dnskey_keyring_acquire_key_at_index(kr, -1);
    if(key2 != NULL)
    {
        yatest_err("dnskey_keyring_acquire_key_at_index didn't return NULL (-1)");
    }
    key2 = dnskey_keyring_acquire_key_at_index(kr, 0);
    if(key2 != NULL)
    {
        yatest_err("dnskey_keyring_acquire_key_at_index didn't return NULL (0)");
    }
    key2 = dnskey_keyring_acquire_key_at_index(kr, 1);
    if(key2 != NULL)
    {
        yatest_err("dnskey_keyring_acquire_key_at_index didn't return NULL (1)");
    }

    ret = dnskey_keyring_add(kr, key);
    if(ret < 0)
    {
        yatest_err("dnskey_keyring_add failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ret = dnskey_keyring_add(kr, key);
    if(ret >= 0)
    {
        yatest_err("dnskey_keyring_add succeeded with %08x", ret);
        return 1;
    }

    if(dnskey_keyring_isempty(kr))
    {
        yatest_err("dnskey_keyring_isempty returned true");
        return 1;
    }

    if(dnskey_keyring_has_key(kr, dnskey_get_algorithm(key), dnskey_get_tag(key) ^ 1, dnskey_get_domain(key)))
    {
        yatest_err("dnskey_keyring_has_key returned true");
        return 1;
    }

    key2 = dnskey_keyring_acquire(kr, dnskey_get_algorithm(key), dnskey_get_tag(key) ^ 1, dnskey_get_domain(key));

    if(key2 != NULL)
    {
        yatest_err("dnskey_keyring_acquire did not return NULL");
        return 1;
    }

    if(!dnskey_keyring_has_key(kr, dnskey_get_algorithm(key), dnskey_get_tag(key), dnskey_get_domain(key)))
    {
        yatest_err("dnskey_keyring_has_key returned false");
        return 1;
    }

    key2 = dnskey_keyring_acquire(kr, dnskey_get_algorithm(key), dnskey_get_tag(key), dnskey_get_domain(key));
    if(key2 == NULL)
    {
        yatest_err("dnskey_keyring_acquire did return NULL");
        return 1;
    }
    dnskey_release(key2);

    key2 = dnskey_keyring_acquire_key_at_index(kr, 0);
    if(key2 == NULL)
    {
        yatest_err("dnskey_keyring_acquire_key_at_index returned NULL");
        return 1;
    }
    dnskey_release(key2);

    if(dnskey_keyring_remove(kr, dnskey_get_algorithm(key), dnskey_get_tag(key) ^ 1, dnskey_get_domain(key)))
    {
        yatest_err("dnskey_keyring_remove succeeded to remove wrong key");
        return 1;
    }

    if(!dnskey_keyring_remove(kr, dnskey_get_algorithm(key), dnskey_get_tag(key), dnskey_get_domain(key)))
    {
        yatest_err("dnskey_keyring_remove failed to remove key");
        return 1;
    }

    key2 = dnskey_keyring_acquire(kr, dnskey_get_algorithm(key), dnskey_get_tag(key), dnskey_get_domain(key));
    if(key2 != NULL)
    {
        yatest_err("dnskey_keyring_acquire did return NULL (after remove)");
        return 1;
    }

    const int keys_count = 4;

    for(int i = 0; i < keys_count; ++i)
    {
        ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, fqdn_text, &key);
        if(ret < 0)
        {
            yatest_err("dnskey_newinstance unexpectedly failed (internal error) %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        dnskey_keyring_add(kr, key);
    }

    dnskey_keyring_free(kr);
    finalise();
    return 0;
}

static yatest_socketserver_t mockserver = YATEST_SOCKETSERVER_UNINITIALISED;
static const char           *server_listen_address_text = "127.0.0.1";
static uint16_t              server_listen_port = 10053;
static const uint8_t         yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
// static const char *yadifa_eu_text = "yadifa.eu";

static void network_test_init(struct yatest_socketserver_s *ssctx)
{
    (void)ssctx;
    yatest_log("network_test_init");
}

static void network_test_udp_handler(struct yatest_socketserver_s *ssctx, yatest_serverclient_t *client)
{
    (void)ssctx;

    int ret;

    yatest_log("network_test_udp_handler(%p, %p)", ssctx, client);

    dnscore_init();

    dns_message_t *mesg = dns_message_new_instance();

    yatest_log("network_test_udp_handler(%p, %p) reading message", ssctx, client);

    dns_message_recv_udp_reset(mesg);

    ret = dns_message_recv_udp(mesg, ssctx->server_socket);
    if(ret < 0)
    {
        yatest_err("network_test_udp_handler: dns_message_read_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        return;
    }

    yatest_log("network_test_udp_handler has received message");

    dns_message_copy_sender_from_socket(mesg, client->sockfd);

    const socketaddress_t *csa = dns_message_get_sender(mesg);
    int                    csa_size = dns_message_get_sender_size(mesg);
    char                  *csa_text = yatest_sockaddr_to_string(&csa->sa);
    yatest_log("network_test_udp_handler: sender=%s, sender_size=%i", csa_text, csa_size);
    free(csa_text);

    // got a message
    ret = dns_message_process_query(mesg);
    if(ret < 0)
    {
        yatest_err("network_test_udp_handler: dns_message_process_query failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        return;
    }

    yatest_log("network_test_udp_handler has processed message");

    if(dns_message_get_query_class(mesg) != CLASS_IN)
    {
        yatest_err("network_test_udp_handler: query class not IN (%04x)", ntohs(dns_message_get_query_class(mesg)));
        return;
    }

    const socketaddress_t *sau = dns_message_get_sender(mesg);
    const struct sockaddr *sas = dns_message_get_sender_sa(mesg);
    char                  *sau_text = yatest_sockaddr_to_string(&sau->sa);
    char                  *sas_text = yatest_sockaddr_to_string(sas);
    int                    sender_size = dns_message_get_sender_size(mesg);
    yatest_log("network_test_udp_handler: received message from %s = %s (%i)", sau_text, sas_text, sender_size);
    free(sas_text);
    free(sau_text);

    yatest_log("network_test_udp_handler preparing reply");
    dns_message_set_answer(mesg);

    dns_message_set_authoritative(mesg);

    // create an answer with one SOA
    dns_packet_writer_t pw;
    dns_packet_writer_init_append_to_message(&pw, mesg);

    resource_record_t *rr = (resource_record_t *)malloc(sizeof(resource_record_t));
    if(rr == NULL)
    {
        yatest_err("resource_record malloc failed, internal error");
        exit(1);
    }

    parse_dnskey_record(&dnskey_inputs[network_test_udp_handler_base], rr);

    if(!network_test_udp_handler_break_fqdn)
    {
        dns_packet_writer_add_fqdn(&pw, dns_message_get_canonised_fqdn(mesg));
    }
    else
    {
        dns_packet_writer_add_u16(&pw, 0xffff);
    }

    if(!network_test_udp_handler_cut_tctr)
    {
        dns_packet_writer_add_u16(&pw, TYPE_DNSKEY);
        dns_packet_writer_add_u16(&pw, CLASS_IN);
        dns_packet_writer_add_u32(&pw, htonl(86400));
        dns_packet_writer_add_u16(&pw, htons(rr->rdata_size));
        dns_packet_writer_add_bytes(&pw, rr->rdata, rr->rdata_size);

        parse_dnskey_record(&dnskey_inputs[network_test_udp_handler_base + 1], rr);

        dns_packet_writer_add_fqdn(&pw, dns_message_get_canonised_fqdn(mesg));
        dns_packet_writer_add_u16(&pw, TYPE_DNSKEY);
        dns_packet_writer_add_u16(&pw, CLASS_IN);
        dns_packet_writer_add_u32(&pw, htonl(86400));
        dns_packet_writer_add_u16(&pw, htons(rr->rdata_size));
        dns_packet_writer_add_bytes(&pw, rr->rdata, rr->rdata_size);

        dns_packet_writer_add_fqdn(&pw, dns_message_get_canonised_fqdn(mesg));
        dns_packet_writer_add_u16(&pw, TYPE_SOA);
        dns_packet_writer_add_u16(&pw, CLASS_IN);
        dns_packet_writer_add_u32(&pw, htonl(86400));
        dns_packet_writer_add_u16(&pw, htons(sizeof(soa_rdata)));
        dns_packet_writer_add_bytes(&pw, soa_rdata, sizeof(soa_rdata));

        dns_packet_writer_add_fqdn(&pw, dns_message_get_canonised_fqdn(mesg));
        dns_packet_writer_add_u16(&pw, TYPE_SOA);
        dns_packet_writer_add_u16(&pw, CLASS_IN);
        dns_packet_writer_add_u32(&pw, htonl(86400));
        dns_packet_writer_add_u16(&pw, htons(sizeof(soa_rdata)));
        dns_packet_writer_add_bytes(&pw, soa_rdata, sizeof(soa_rdata));
    }

    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_answer_count(mesg, 3);
    dns_message_set_authority_count(mesg, 1);

    free(rr);

    yatest_log("network_test_udp_handler sending reply");

    ret = dns_message_send_udp(mesg, ssctx->server_socket);
    if(ret < 0)
    {
        yatest_err("network_test_udp_handler: dns_message_send_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        return;
    }
}

static void network_test_finalise(struct yatest_socketserver_s *ssctx)
{
    (void)ssctx;
    yatest_log("network_test_finalise");
}

static int dnskey_keyring_add_from_nameserver_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);
    int ret;
    init();
    dnskey_keyring_t *kr = dnskey_keyring_new();
    host_address_t   *ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);
    ret = dnskey_keyring_add_from_nameserver(kr, ha, yadifa_eu);
    if(ret < 0)
    {
        yatest_err("dnskey_keyring_add_from_nameserver failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    network_test_udp_handler_base = 2;
    network_test_udp_handler_break_fqdn = true;
    network_test_udp_handler_cut_tctr = false;

    ret = dnskey_keyring_add_from_nameserver(kr, ha, yadifa_eu);
    if(ret < 0)
    {
        yatest_err("dnskey_keyring_add_from_nameserver failed with %08x = %s (network_test_udp_handler_break_fqdn)", ret, error_gettext(ret));
        return 1;
    }

    network_test_udp_handler_base = 4;
    network_test_udp_handler_break_fqdn = false;
    network_test_udp_handler_cut_tctr = true;

    ret = dnskey_keyring_add_from_nameserver(kr, ha, yadifa_eu);
    if(ret < 0)
    {
        yatest_err("dnskey_keyring_add_from_nameserver failed with %08x = %s (network_test_udp_handler_cut_tctr)", ret, error_gettext(ret));
        return 1;
    }

    for(int i = 0;; ++i)
    {
        dnskey_t *key;
        key = dnskey_keyring_acquire_key_at_index(kr, i);
        if(key == NULL)
        {
            break;
        }
        yatest_log("key[%i]", i);
        dnskey_store_public_key_to_stream(key, termout);
        flushout();
        dnskey_release(key);
    }

    dnskey_keyring_free(kr);

    finalise();
    yatest_socketserver_stop(&mockserver);
    return 0;
}

static int dnskey_keyring_add_from_nameserver_broken_fqdn_test()
{
    network_test_udp_handler_base = 2;
    network_test_udp_handler_break_fqdn = true;
    network_test_udp_handler_cut_tctr = false;

    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);
    int ret;
    init();
    dnskey_keyring_t *kr = dnskey_keyring_new();
    host_address_t   *ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    ret = dnskey_keyring_add_from_nameserver(kr, ha, yadifa_eu);
    if(ret != RCODE_ERROR_CODE(FP_RCODE_FORMERR))
    {
        yatest_err("dnskey_keyring_add_from_nameserver expected to fail with FP_RCODE_FORMERR=%08x failed with %08x = %s", RCODE_ERROR_CODE(FP_RCODE_FORMERR), ret, error_gettext(ret));
        return 1;
    }

    for(int i = 0;; ++i)
    {
        dnskey_t *key;
        key = dnskey_keyring_acquire_key_at_index(kr, i);
        if(key == NULL)
        {
            break;
        }
        yatest_log("key[%i]", i);
        dnskey_store_public_key_to_stream(key, termout);
        flushout();
        dnskey_release(key);
    }

    dnskey_keyring_free(kr);

    finalise();
    yatest_socketserver_stop(&mockserver);
    return 0;
}

static int dnskey_keyring_add_from_nameserver_broken_tctr_test()
{
    network_test_udp_handler_base = 4;
    network_test_udp_handler_break_fqdn = false;
    network_test_udp_handler_cut_tctr = true;

    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);
    int ret;
    init();
    dnskey_keyring_t *kr = dnskey_keyring_new();
    host_address_t   *ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    ret = dnskey_keyring_add_from_nameserver(kr, ha, yadifa_eu);
    if(ret != RCODE_ERROR_CODE(FP_RCODE_FORMERR))
    {
        yatest_err("dnskey_keyring_add_from_nameserver expected to fail with FP_RCODE_FORMERR=%08x failed with %08x = %s", RCODE_ERROR_CODE(FP_RCODE_FORMERR), ret, error_gettext(ret));
        return 1;
    }

    for(int i = 0;; ++i)
    {
        dnskey_t *key;
        key = dnskey_keyring_acquire_key_at_index(kr, i);
        if(key == NULL)
        {
            break;
        }
        yatest_log("key[%i]", i);
        dnskey_store_public_key_to_stream(key, termout);
        flushout();
        dnskey_release(key);
    }

    dnskey_keyring_free(kr);

    finalise();
    yatest_socketserver_stop(&mockserver);
    return 0;
}

#if DNSCORE_HAS_OQS_SUPPORT

static void dnskey_postquantumsafe_algorithm_test(uint8_t algorithm)
{
    dnskey_t *key;
    int64_t   t;
    int       ret;
    sign_verify_test_dump_rdata = false;

    const char *algorithm_name = dns_encryption_algorithm_get_name(algorithm);

    yatest_log("%s: generating key", algorithm_name);

    yatest_timer_start(&t);

    ret = dnskey_newinstance((algorithm <= DNSKEY_ALGORITHM_RSASHA512_NSEC3) ? 2048 : 0, algorithm, DNSKEY_FLAGS_ZSK, "yadifa.eu", &key);
    if(ret < 0)
    {
        yatest_err("%s: dnskey_newinstance failed for algorithm %i: %08x = %s", algorithm_name, algorithm, ret, error_gettext(ret));

        exit(1);
    }

    yatest_timer_stop(&t);

    yatest_log("%s: generated in %f seconds, dnskey_get_size returned %i (%i bytes)", algorithm_name, yatest_timer_seconds(&t), dnskey_get_size(key), ((dnskey_get_size(key) + 7) >> 3));

    ret = dnskey_store_keypair_to_dir(key, "/tmp");
    if(ret < 0)
    {
        yatest_err("%s: dnskey_store_keypair_to_dir failed for algorithm %i: %08x = %s", algorithm_name, algorithm, ret, error_gettext(ret));
        exit(1);
    }

    int signature_expected_size = dnskey_test_signature_size(key);
    if(signature_expected_size < 65535 - (18 + 256))
    {
        yatest_log("%s: size of signature is %i which is usable for DNS", algorithm_name, signature_expected_size);
        sign_verify_test(key, key);
    }
    else
    {
        yatest_log("%s: size of signature is %i which is not usable for DNS", algorithm_name, signature_expected_size);
    }

    dnskey_release(key);
}

static int dnskey_postquantumsafe_experimental_test()
{
    dnscore_init();
    static const int standard[] = {DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_ALGORITHM_RSASHA512_NSEC3, DNSKEY_ALGORITHM_ECDSAP256SHA256, DNSKEY_ALGORITHM_ECDSAP384SHA384, DNSKEY_ALGORITHM_ED25519, DNSKEY_ALGORITHM_ED448, 0};
    for(uint8_t algorithm_index = 0; standard[algorithm_index] != 0; ++algorithm_index)
    {
        uint8_t algorithm = standard[algorithm_index];
        yatest_log("trying algorithm %i", algorithm);
        dnskey_postquantumsafe_algorithm_test(algorithm);
    }
    for(uint8_t algorithm = DNSKEY_ALGORITHM_DILITHIUM2; algorithm <= DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL; ++algorithm)
    {
        if(dns_encryption_algorithm_get_name(algorithm) == NULL)
        {
            continue;
        }
        yatest_log("trying algorithm %i", algorithm);
        dnskey_postquantumsafe_algorithm_test(algorithm);
    }
    dnscore_finalize();
    return 0;
}
#endif

YATEST_TABLE_BEGIN
YATEST(key_algorithms_test)
YATEST(dnskey_sign_rrset_with_maxinterval_test)
YATEST(public_key_parse_test)
YATEST(private_key_parse_test)
YATEST(dnskey_equals_test)
YATEST(algorithms_test)
YATEST(algorithm_by_index_test)
YATEST(fields_test)
YATEST(dnskey_newinstance_errors_test)
YATEST(dnskey_newemptyinstance_test)
YATEST(dnskey_store_test)
YATEST(dnskey_chain_test)
YATEST(dnskey_generate_ds_rdata_test)
YATEST(dnskey_digest_init_test)
YATEST(dnskey_new_from_rdata_error_test)
YATEST(dnskey_matches_rdata_test)
YATEST(dnskey_init_dns_resource_record_test)
YATEST(dnskey_new_public_key_from_stream_test)
YATEST(dnskey_keyring_test)
YATEST(dnskey_keyring_add_from_nameserver_test)
YATEST(dnskey_keyring_add_from_nameserver_broken_fqdn_test)
YATEST(dnskey_keyring_add_from_nameserver_broken_tctr_test)
#if DNSCORE_HAS_OQS_SUPPORT
YATEST(dnskey_postquantumsafe_experimental_test)
#endif
YATEST_TABLE_END
