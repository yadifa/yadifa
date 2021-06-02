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

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/zone_reader_text.h>
#include <dnscore/dnskey.h>
#include <dnscore/format.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/dnskey-signature.h>
#include <dnsdb/zdb-packed-ttlrdata.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/logger_channel_stream.h>

static ptr_vector g_allowed_algorithms = PTR_VECTOR_EMPTY; // if empty, all algorithms are allowed

static bool
algorithm_allowed(int a)
{
    int last_index = ptr_vector_last_index(&g_allowed_algorithms);
    if(last_index < 0)
    {
        return TRUE;
    }
    for(int i = 0; i <= last_index; ++i)
    {
        if((int)(intptr)ptr_vector_get(&g_allowed_algorithms, i) == a)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static void
main_logger_setup()
{
    output_stream stdout_os;
    fd_output_stream_attach(&stdout_os, dup_ex(1));
    buffer_output_stream_init(&stdout_os, &stdout_os, 65536);

    logger_channel *stdout_channel = logger_channel_alloc();
    logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
    logger_channel_register("stdout", stdout_channel);

    logger_handle_create("system", &g_system_logger);
    logger_handle_add_channel("system", MSG_ALL_MASK, "stdout");
}

struct dnskey_inputs_s
{
    const char * const record_text;
    u8 algorithm;
    u16 bit_size;
    u16 tag;
    const char * const domain_name;
    const char * const file_name;
};

struct dnskey_private_inputs_s
{
    u16 tag;
    const char * const file_name;
    const char * const file_text;
};

static struct dnskey_inputs_s dnskey_inputs[] =
{
// bits='516'
// tag=65103
{
"example.eu. IN DNSKEY 256 3 5 AwEAAc7AMk6Uw3pB+JnY+4f6plFFS5N4zE/l6POG88ImVUaz634CJrh3 KGhxfBQQidDudhJJ0b++J2M1jYzt0YKOp2XObu2njF9q5a7JTCJpvVLX 9m+dUvVtjNSt4eE2FUmTZ2S7TpyOICPDSSv7MHBqN9xFh8sQbToYUj5j pVIbnDUnnSqHFhbxz6jxBuMqNexQykUiukeIv99QJD4KPQeJJJSJSN9B wXDAnIHpJQcInYQivNednGmHNgVIAFpnvOUqvbYi3LBObLJ3AvoLQ8wX quOi/3aolf6JLi7N8DitEtCmLpUpt1VubW8K2OUJgkESvD5Pu4BZNyBm TcmtwuWk21hfjbKof7ftFDM3VlNSeItQnx8RJzE0HgfXJf2ui2k/H3GV WV7kPU7zuibeJWZq1rsDe/oSxXUw2K0YC897tMrA8nOuE2dJk7i5FQ5I hBx4Z1cBfYHrTVODlfKSG/kzqvoqwAAAXyIwIy+7Y980qcuwlSvY/Y6B p02m+73KSlTLYudWxdddkBb1i76ijxsDQGryXr22TfhWz9V4gnXae+7x KP5QAGh2Ly//obgvT186jMyDVAjaeI7wGiR2P3d/4wn1ZF2cm8GIVqvv MHha417P7GAjyvm0bna3lE+j5fO24DExJD9k2Ax3TqV1oJwNHYUX1huA Ttls1tB/eNHRodqT",
5, 4096, 65103, "example.eu.",
"Kexample.eu.+005+65103.key",
},
// bits='516'
// tag=34614
{
"example.eu. IN DNSKEY 256 3 7 AwEAAaHj5xpBzw+MFcvm0xJn5NF5bb/y+8DNsBiMWmiXyYL94lqGtUQk xkR0kTX1NK40ANnZc94lcOKRxOReYf791GUIP4se77nmyYj1Y6NJlzto hTNIjzYUrpK69egT2gTXzoNqXmGfhoVooZXtyFLwyKtt4PKEYNUtd9cr 1QvbBXuRP3hfMgJvxIrCQAKrP7LIyVvO91zTtpEUBqBAzyGTd06zVHee j1HJJadhR1Dgdoko2QhvdujCYJ2XlBFJNCDM88Oe95XjPbg2lhAZujzm WrzAloTlmSqnPOorYzvOE0pBwFW7CQlqyyrg3Abfd/lKxAgIzg72Y0Kj F/KGJUss/EJpySTqt4SiQe4L5VlaYNGfrBmkwpIuDbb74iWQtcT9N5+t UbWosbZex6UR7jBeMxSCSP5BNdSZD717SDLbU58oqUZM34a3s07TNzR2 lgHtQ+vRJqan0EszODsgmxeltntic1GK9SyxN1RZDjAQMAZX57PfdbbD +uZcFBKR1rBewYR7ssuGT4fsxD0icYN4RwFIKLLQXumelKGqs8aKOleH hOwHwTfX5RruJN0H3KCzI8DdePjgWGBl3KltjS3HJwmuddz8tOIgesKT mHePNtBQIOFGj2YLrZytYMo3VLP+osY2Ar3tNifsn6zDBx2vT4s4OTDs RU7jBWthFs9sprZh",
7, 4096, 34614, "example.eu.",
"Kexample.eu.+007+34614.key",
},
// bits='132'
// tag=42405
{
"example.eu. IN DNSKEY 256 3 8 AwEAAc0rvt3ksTHWqx+7xUk07MVPeaEsY2P5+hzroj5guid2KZotCloO p2FmkaF5yRS4GykURsSknQeK/19v5tywVDLXvmb8Dt4UXki0cWEzOn4t SImOFOOaXWNmssFJuZaZy98Ew1aBzwoSXzsW34Cbnni7t8Y5KXKHiPeW N5pRulSf",
8, 1024, 42405, "example.eu.",
"Kexample.eu.+008+42405.key",
},
// bits='516'
// tag=44385
{
"example.eu. IN DNSKEY 256 3 8 AwEAAdeIrZf0lzKCsv78AWKssgk4QQbPX/IWDVKCWkWLo4ic4plOaZq4 Dltu59r1FUSNPxKHv7Nyv/DlK/5AnaGUR01iM10peFSCkc1RGbdKk98H FHgXnN3jeJXErvwabY47OE4XX04Qbb2KC7FVCfzjEdQIiXbHMdUE6N3T OcZ73ZgFPvP2qcKznagn++tNGlWCngykRcIF0qJvgvxzkJh+o/u2I4Kx JtqH5R4RQx3W6jHdl5ug8+CU6za5jqHxDlLAYphppF7PqRSkmyeqRQwp /ARTWcf2ykvN/X0h/IfspuB/x4HErZQ1LNsmck7q6NK1O+EmUjlxim6k //XIRh+yIqnT1gpi6StwoMlD4sVPBgj83TnY5jp3AyKJPsNVtQ0cyzGy Pcg6bn/e5n0FX7OKjFM3cDFpsRc0M52K3lBKqvLU/20kAQ9oDh3ucH4n k1HcJvsr0JdcAro8tx2hibdrwHTKIZq1uv5ElfMiP2SLb4Pwr8r+hyrT UaKIy/1L0d/ob/vrWowG9dagX9lBwc5zRwt4/76bZ1HQNK/U/O1ZJ7sC enaTNOutsMYZXjDWJXieH6LOPoPL7Vt8dDE3Xl+flTQmKt5Meo2UhYhO lHEL9jMV/A2tUA2CvHk5H9Ikd9HA6I9LikstYSSLn8+u/By/RjkCWGSD 20g8eoqio6VD6dHX",
8, 4096, 44385, "example.eu.",
"Kexample.eu.+008+44385.key",
},
// bits='260'
// tag=58273
{
"example.eu. IN DNSKEY 256 3 8 AwEAAdIEAj1savm91TNpagAUoIFrez72YE31RYgLvgSu19oG8QhQLPW0 uHkQHGLexj0x68OxT+FGnHSW6voQnSQtD6jIgG83vW1p9awOEmRGUvhA TVG1tzssFopRRy3H/A6ERmlIlr39BHvw6/L73Axevv6iNzFhie8uDxP/ N4/liH92qIF1KfBDr4P7cGyzkgwaO4Zx1v1/qIOhKdUCQoSmALHarlNb 3szGYXSC5w6NCOs0ezvZ93LmFWKvPsHhZocdf9iZWw1sqEK9r702iJh9 vCmZe82vGeIE+NU3KvxFqKLLC7n2/eOnsI6JrrbOuk//UheDR6d/Vqjw kWdximAcHNM=",
8, 2048, 58273, "example.eu.",
"Kexample.eu.+008+58273.key",
},
// bits='516'
// tag=34811
{
"example.eu. IN DNSKEY 256 3 10 AwEAAdOFrsgf+p48/p4bIv/JyfwW6lr3bg0nFLYQJgZUe79wVjtXUymk xp7AlqmInhcRF0tA1Wk28vaEQXik5mYO++aYWRbtjry0lHSxfz41F50Z 7jrFjdHU1kw3+sMpFvpy8LA0pl5zaEOjfW6SFG2BPPoxv5nE1fED+IwS 7vhvLqi71F3Mp7uvLUB3/iVpeMhGUJFiJ1WttUZrHrkgjs1obyx0/oLA SBN0ruP3XG2LiV5dgdKmpyB8MBqQgsYCwbiU59+qaeHfsvNShtgSCVv4 tHREHowdcAf1ia9RmBBSyD9jIjPgiJdU/ciaIvNaOuA5r6vjcfmwOOs4 znT3FNnjIAaS7+RZWDs4HUKn/WXzr7hJMzri3gUsJmt5DGot6fsRqr8o APgZoA0Y540mut2G1jFWJ147Vqr6q7JvS20nZG7pO0TEzz3ZcZ9M2qK3 16U/YIfaDkyS0erbtvkDC/+emaG44vv5H7/IvmuCtmCs/S/KEzVsZ88K 0eremFC5012o0M6HzzyQoPYyyDwJEa+813mC3xUHlDjhPFdjqDbO7NH6 NmZ+rsev4xIXLLWZ9NGLAg0W9w7HA9XF7Gam+xqoj0Hyz3wz6QWEGEgc YiQ5PAsus19KoHwbrENvnzGpOI2lLtmx813GsmNh0pXdlGu/dtRWcTRv jlWF+XkStKB5irAN",
10, 4096, 34811, "example.eu.",
"Kexample.eu.+010+34811.key",
},
#if DNSCORE_HAS_ECDSA_SUPPORT
// bits='64'
// tag=57775
{
"example.eu. IN DNSKEY 256 3 13 sMept+nZXEKJtdgbqRKTSSMj8O/11kdqcinORHrSNoeF4sv56jxbIs4/ l/mk2n263pfJ9FnRSPOb0rPXtS3riQ==",
13, 256, 57775, "example.eu.",
"Kexample.eu.+013+57775.key",
},
// bits='96'
// tag=52751
{
"example.eu. IN DNSKEY 256 3 14 xmRq5JsFuw+Q5yTecxON5vL81GprkjX+pOUxZUxAb8wMuQj7TF8WQzyW lRiRvGWw0NU+JE/OV+2bWXawC3fd5ohjCTO5qHLQXO8iFui11am8dfI2 FbpeQR27iT7yF+XU",
14, 384, 52751, "example.eu.",
"Kexample.eu.+014+52751.key",
},
#endif
#if DNSCORE_HAS_EDDSA_SUPPORT
// bits='32'
// tag=49344
{
"example.eu. IN DNSKEY 256 3 15 7vd+WRTKhk4GZpNVuZ+6OK0VsaSD/NEEOmlu18pUf2I=",
15, 32 * 8, 49344, "example.eu.",
"Kexample.eu.+015+49344.key",
},
// bits='57'
// tag=7552
{
"example.eu. IN DNSKEY 256 3 16 ehOMj0BfWQKIFr5TniS5Dcgs8QA7rhfBB8zV/plzd5lBtlPr+vxckCus Rr1mWiuH8VWohT/1lQ6A",
16, 57 * 8, 7552, "example.eu.",
"Kexample.eu.+016+07552.key",
},
#endif
    {NULL, 0, 0, 0, NULL, NULL}
};

static struct dnskey_private_inputs_s dnskey_private_inputs[] =
{
 // tag=65103
{
    65103,
"Kexample.eu.+005+65103.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 5 (RSASHA1)\n"
    "Modulus: zsAyTpTDekH4mdj7h/qmUUVLk3jMT+Xo84bzwiZVRrPrfgImuHcoaHF8FBCJ0O52EknRv74nYzWNjO3Rgo6nZc5u7aeMX2rlrslMImm9Utf2b51S9W2M1K3h4TYVSZNnZLtOnI4gI8NJK/swcGo33EWHyxBtOhhSPmOlUhucNSedKocWFvHPqPEG4yo17FDKRSK6R4i/31AkPgo9B4kklIlI30HBcMCcgeklBwidhCK8152caYc2BUgAWme85Sq9tiLcsE5ssncC+gtDzBeq46L/dqiV/okuLs3wOK0S0KYulSm3VW5tbwrY5QmCQRK8Pk+7gFk3IGZNya3C5aTbWF+Nsqh/t+0UMzdWU1J4i1CfHxEnMTQeB9cl/a6LaT8fcZVZXuQ9TvO6Jt4lZmrWuwN7+hLFdTDYrRgLz3u0ysDyc64TZ0mTuLkVDkiEHHhnVwF9getNU4OV8pIb+TOq+irAAABfIjAjL7tj3zSpy7CVK9j9joGnTab7vcpKVMti51bF112QFvWLvqKPGwNAavJevbZN+FbP1XiCddp77vEo/lAAaHYvL/+huC9PXzqMzINUCNp4jvAaJHY/d3/jCfVkXZybwYhWq+8weFrjXs/sYCPK+bRudreUT6Pl87bgMTEkP2TYDHdOpXWgnA0dhRfWG4BO2WzW0H940dGh2pM=\n"
    "PublicExponent: AQAB\n"
    "PrivateExponent: aeNboI1mVE5HYZwUrv77gXIpE91xXpZUqaz7WPtC/5QUTxQQ+rbkdiFxN+GEhAItbI5sI3TjPVdnKL+AZwpix6xjecovBYt9GPi1yoY3VZ+P8ngzzckOsLphjnOhkW4yLRAVYe8UnNxetGzQ0TJFa8Ycly7Rkkh0jsmAGT5U0ZB5WReYg6XTAiZ3rY6n0WFLRv9TQmHSSzADb9bUjPB7UKvDK7zEstejEJH0ydZqvgsAhrmNKyr5ytimfabVwtUSFp9iQdXYq8pyNtfgID4a4r1Pc1lCgPuHMKd+mbhig4QpJXIZGGMXHyECFsO491T+Hje9wy1uI2TiACHDSNQXFg5aE6LFcffVNHtYO/xSCof/+oOd5DgZjYTXezMJDDLUqCyeaPRlj0xgt50aLL7sRJlfbXHhujI0Eb8UOEX+ha3CyDtc6008cTfjBkzWBQqoOkU+eOqZLpfjzDDhBoYoqgbZcItPo+f8LpzLRKhz+6EsEE/9xebRP0tfKy2kVkLRPWyU/OtnXKMHekccFjbpA/Rk8Q77Rch7Vf2Qbom428XcIUPIyVXV0/GETg349IO9kzHOFLo85QMsw1v9JnUbQ7btSqf6FyhxJ9NSW4KP9kazZRI4zNeqy1YhwDpo3CCp6C2NQ2xsjyXnPthdc41346tB3hm3beVLL537ZHUZlfk=\n"
    "Prime1: +fnpiP98oN+Jyr+ZLSZ7q9ZfZYN+WM+yUHF+/k3GrZZzfC4xt0MvGpm8TNMtWp5G0OuuHLMW8T79OUBGRqYdmgX0qWylq9mI0GjzQlrw623VA27RSebdQc83i1k9b38Xip8KQUlPtbB2KXI52l/6L3kWKq9PyCm7KtFgih4QDEyOk5EFeCFbzFe+vpEeL8e8djl/j9Ii1yc4hcd8zOhGZzi8MpFecnbGeEXSFAUgMGol/A+5JK3SIpix/e9URzZGKROmz+uWypquJjEVComMCSjxUz/d37usM8LBRp0oPwQEY6xV7ZJzUN3UNdJxVWbF4gBcmSjGkrAMc5arYs26dw==\n"
    "Prime2: 07uhD0Mt9qzgRffFPSOyn+QxwB9ZRSPPExZlBv0AiqYofK5jCfsA+3C6g+JQLhZ010am4VccEc5MYfbermtqXD2YEl0TEjtHNPKvL+SuP9Fj7ktalQs0GZBVkSabGTYBPnQ0oBCaiYS2X+OOLxtoUb2kwVWXM2gnnlaoWujDRPmuwhrakp/HrIIwbJ6Ke3JQZyJHsTlMQqwcOmnKVib4TdarM0jhX4ho3NFKBpUpmEVz9WIdFGhc1uN5CeiPQ25YziFmPcCrtaPEF0eYDh1N7KYxVhu3S8A61KA6x2nM4gEwpKNDlMnYjrTQXhMZqg7kGdb8dqtfoKiV5OrB9XPLxQ==\n"
    "Exponent1: uhZLvnuKuGuQNQlqqwzR1brxKy23GcAL2wySYBdgBotQjyoIQofWAfReE8bFJYdb6lz4MU80jgS5Fyx85Ez3DljOqG1D62k2CweFx2jRnkEV6MdPL7eYEEyE6cxWCrFOwhfg13cOyo+BdxscbC80nLCESuRU/Qnr1lUli8wTYESBguLbcnFK2BSd31lCYolLB6uIBXWGECqXTieSBSwIdQDsQKys5YL7/j7jw5mJO+FZQ4ok5mQrYSvQnNvUHmsN0bhaXr/fchWx/KZfJof8YjlDZRjPP6WC7MlXfgyyEC8aYWTCVufFxnZMaoCtc8jdGH/ybuXG5R3/NvD7xsKlww==\n"
    "Exponent2: VWUXUFCH+TVAPvfvVPlQ0av3ZMU/++K1Yb1mgasIzOK28ZJj32Kcwsx0bTyZmfz0ot6b78ZyS7woklo+9ZndC9bLvpxLVM8TqQc4INjabmLFKxa5MeOS37yWxjQL2d8uIUI891G7AjvEUmg0sEsdh9o02MTsdo9La1EIFaJLH0aUdTTfcsN+hNT9MtG+iItSYkYxJAk3+Kvxtp10Pcr52mr6IXUDcMRThrviX0VJwWBBpHYtxE1TJFgaOSTSox+eMYTG96D9oASs0bbOXOL0yr08qL4E70hYcekty7+gIobYV46Bc0D1VpkWcNrDPxNCbCmJKVN0/hcAXZNRJu3NAQ==\n"
    "Coefficient: mik7fifO6/GSGle1JjKiqq5b4QraD+vxWNNAGb3XnOTzXrnXP7tHVDyVNwqmLEUsb9166OKgCnn0awvyC+VNEYnHbgwdO8zQxcD4mm2ckD06z3NIoJ207hfi3wdOYETZI8iSFeJxQ0YqqYW1nLRf/f67CxSInBooyDtUl0eaJep78w0RI7j+J4XRypQITq0t79qeal35y2abYHDUBUywKSlxNSXFN8VHksFUXL4HZMmK9LbBVOWPh7MkOuXte03HfwaAxQ5wj96t+9hV0zu2zQo/HYK4iZuf5u1gQHHxKsDAwUMKGGKMqSWGpo4p3hy51qYA89/rx9fKgUDb5ZF+qg==\n"
    "Created: 20210426102254\n"
    "Publish: 20210426102254\n"
    "Activate: 20210426102254\n"
},
// tag=34614
{
    34614,
"Kexample.eu.+007+34614.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 7 (NSEC3RSASHA1)\n"
    "Modulus: oePnGkHPD4wVy+bTEmfk0Xltv/L7wM2wGIxaaJfJgv3iWoa1RCTGRHSRNfU0rjQA2dlz3iVw4pHE5F5h/v3UZQg/ix7vuebJiPVjo0mXO2iFM0iPNhSukrr16BPaBNfOg2peYZ+GhWihle3IUvDIq23g8oRg1S131yvVC9sFe5E/eF8yAm/EisJAAqs/ssjJW873XNO2kRQGoEDPIZN3TrNUd56PUcklp2FHUOB2iSjZCG926MJgnZeUEUk0IMzzw573leM9uDaWEBm6POZavMCWhOWZKqc86itjO84TSkHAVbsJCWrLKuDcBt93+UrECAjODvZjQqMX8oYlSyz8QmnJJOq3hKJB7gvlWVpg0Z+sGaTCki4NtvviJZC1xP03n61Rtaixtl7HpRHuMF4zFIJI/kE11JkPvXtIMttTnyipRkzfhrezTtM3NHaWAe1D69EmpqfQSzM4OyCbF6W2e2JzUYr1LLE3VFkOMBAwBlfns991tsP65lwUEpHWsF7BhHuyy4ZPh+zEPSJxg3hHAUgostBe6Z6Uoaqzxoo6V4eE7AfBN9flGu4k3QfcoLMjwN14+OBYYGXcqW2NLccnCa513Py04iB6wpOYd4820FAg4UaPZgutnK1gyjdUs/6ixjYCve02J+yfrMMHHa9Pizg5MOxFTuMFa2EWz2ymtmE=\n"
    "PublicExponent: AQAB\n"
    "PrivateExponent: cxq8pXGnDHHYyYpMBukxyzKgMvtLvrFAhKO+YGGT2Hw1ZZIj7diL0/5hhNDcbQPymvI+rPNICQAF0y28VXYaft9Xds4/Opl6L9PxzRa03XuaQXVUxen8mb0uvJzoxcq/Pbbydkzbc52KTjSr2zTyKNlOOICg7NGQRMAYkX5frpT+YNKmlw7q2pH0uzERcEfMy2cjf6/UPeDUOTr7Su8zxBRDeW2Wj1sKV7EV6M4/2ZPehF3kWOhjk4lDsOqwkqXGqA8uEDdrGcBOABKa1VQfrdbs7n7k4WvZJtJEkzAZjRGk9A+xBC4XWFxadNSM1AYxzVidUgwjVSzrCPgSKhpJHLlud+jrTuk9uPc0J6hFH4EWOEc100yxcdcXwm4U3e8a3CZwHq4s6n0cucgE8s2w1EG378RznoaeqTL9zb6oEa7XSRWScxYhqPGyYbyGryiN/xqLtHMjCJ98An3BWE5JkXwWDQ+JK9w6dOD79QVSbcOaItKt4qRKAYXtx86nB3FFG37kkIfrOJJGPf/Th5AJ9CUHjzNC9DDIVt4oqjmH2W6veNb09CJHw0pVHfnJ9bJAJe6+F3tprxV+SABrOaxyIVc0mnwU1ZXn6MZCqqay3xUgRmY9IqW5rC6Q7K1WggVW+T1FGu+mJJYw9YNn9j99OTq93OP4YmXEtlWQgB+wXQE=\n"
    "Prime1: 13pFTAjWWgDVm+4QGwPV/mBZ18zlccoyx3w24OoyjY0IJkhHfWKuGv1k8aHKcAOSA5ovjH5S4abtl8ieIFrAEr8J+/DhSsz+lznpLBm78BRXGG2Xc4w8DsAuEWSfBq0fzjGy7VYStP2X/hbfBVFKZT8sfvUeUdRK1p2l3JYSE0giDQdr0JjLqzDBhY6K+Cdenogy0Lhk8HdVjW0TAE9eUPcPQ1SwmRRbmRicsAbJdb/psSnfszgQdO3YpEkZk4A8S147cc+PwQzpMO3AhCcp8KBZOVDRfLVvWY9l7s9+asLBSbGWFl6aoiIxYiS14zq80NCqpA+hei0Jwp2QY7bWMQ==\n"
    "Prime2: wFXHCbavtSgdDXs6kMBUpZaRoJy5tvVArnbVkyuWzzvy0uD9Lf9ZsgpvvktAO69N08FMG6BxgKlZn4AJ1g18/JrMq2iYtZMXVl6Sjvyc7c1S+ng5yGrp12b+FvzRU/lPrmNQHvPWZZurcrkBKjXbMQ2i8kpdADKsVUSvJiil2lGFnYbWRXgO3vYaRtlWdbWzYXR7QiR5jQhcp1+yUAGPJm4WkmiREpyoDGkaMaGH0Y/QFL7VFmAAIUs3C80vQAfLBdmRZc363fqOO7Oayp7ASbHbwnxdkhUuEVoZ2xM1ZEUz91dmrKuWm1i8GatuA4ouCWbB7MiueuL76J1rfZpnMQ==\n"
    "Exponent1: ciN/b45C1PwaKnXJLDY09YDeNlR/uW3MxiSDAVKtIpPxHC4vSDisVvmgrenwzLLndmcHBtmnV4ZP1pXbRPItSgDN7hmjjTbXKQ3w+H5NMhfkJrlufzNqYLnl7SqqniO4dEWZLOTqFds61soQqsVrrgPvsvRuchQM7HAnepg3zOTpvJMQxjcZs32pFPDzpg1crocgu7ThKwtbUwXTCdgA8sxb1mOXBA9nkcoavZdqwae9xy2SJGHvPbD7j9J07NABoD6zKE81K6KGJ3fZAWepbJ/Tg2vO+8szx3IRIZXhtfWh40JhaUoFiRqpo/4kJtBnUgkmSq9I7unKgL9ry5X/EQ==\n"
    "Exponent2: BCETT9sTNKFy1jpCDJ+EcbWk1Lzoo8vqIpS8ixdReot/8BUSem1UAKWGtqAo9d8Snaw1tRYhubBpEyqNi4HooAe2wytQs/0/cARBwz4bJGPXFzeDjhD1ikFUzSuKVvIwSr8pFjEH9lB8Qs9D/iL/3LK9P9Rm4L01w/Lgi8ItpV1AsBwX94/XSeQgtkquN4K6Iip9BvN/hI6cZp+AVYVjDGEqrOP/0VV5qiKLhGtCXjZnMjrSmlNfTVevC9rQ2+AO9MYx/+yHKULa0N9PQHBeEnb2D9vZqmw3+/liOrjT2Z4+ul2u/6ADcLxb9XUfvIW37U2+dhXs4QiEff77Mswg0Q==\n"
    "Coefficient: EVtDhMxQRe7LhMhrDODObmO/hfmhs09izd+kgdFpkdUTREZbUlSnNGmjlvoFhE9K59VFrUdmFQ6IO7zJ7EfccZ/Wysj9HWMdFMxK8WHy7ClqarqdKJc2J3kqTH/Sg5fIJSx9AoQoUk4o0AFg9NGwv/9DTUaiItTnSVolyEfwwt7Qpq2myW/hPOpwxOpNmDFRMqcX79QIdNzr7lH6Gae4rGSsacfsnYt+YRhxrkeZiHXobZY71DoiaBVvuuoY8jVPzANGUzJv2Bmu6CpBmLvEC4O+MfMMTFRFfSQIuc/+Ve3vcC3EKD29f8JC0hsJ/fzqhoQf8QDhhZSa/ZKfLWkGbQ==\n"
    "Created: 20210426102255\n"
    "Publish: 20210426102255\n"
    "Activate: 20210426102255\n"
},
// tag=42405
{
    42405,
"Kexample.eu.+008+42405.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 8 (RSASHA256)\n"
    "Modulus: zSu+3eSxMdarH7vFSTTsxU95oSxjY/n6HOuiPmC6J3Ypmi0KWg6nYWaRoXnJFLgbKRRGxKSdB4r/X2/m3LBUMte+ZvwO3hReSLRxYTM6fi1IiY4U45pdY2aywUm5lpnL3wTDVoHPChJfOxbfgJueeLu3xjkpcoeI95Y3mlG6VJ8=\n"
    "PublicExponent: AQAB\n"
    "PrivateExponent: rZBxQeNiJwgz8X92UQzNs8kc2sTjO8NP28FWmjBXqmRio0Ow+yhkXphXYGPXQIjSqTi2+UlMcgIbMRBIG6+rOWfDdgVuKAT7heQMnWof7MBf3+b8fGRoKHUCClvnkXtelRiztSB4dsp2x/qUJ67IgZdVR/+MifzIBPHb8eDK09k=\n"
    "Prime1: 6hh3RqvGjKqIp2fiF+EaPuLqACrME2SLrV7HPECRRResNSqeJdoWbTxamlz0KfX9I4Apuer/L4yZSTq2YTdcPQ==\n"
    "Prime2: 4F5qpC0/4chqCHj/jukKwZvWF7Cy8IyThulhLQ1jpN99fk+E9fP8R7icoVa0O8L1Oub/QeNyK1uBIZolWj62Cw==\n"
    "Exponent1: ZES8einDbqbwx3uojP/fBQaeohmyta/AYC8TeYxSbNy55z/s41updXp/eFTORFbX6WfQ95BfY1d+pK4gRj23JQ==\n"
    "Exponent2: d+cdGFWyMOfYemSnNekmPWcZV5mvVsvZPxzTOK9SE9b3ipvWU1Yq+O0Yj0P1l4ZNZUfzG3QAHFmPPbTRx1OCFw==\n"
    "Coefficient: pBSPvk9IIUjy5BD8A05Olmk3ph1ypc6/PaJIfna34z7G1gekvKjzAYu4OxXGJJOnEDEsDLBT11WufYC2xKRWJA==\n"
    "Created: 20210426102256\n"
    "Publish: 20210426102256\n"
    "Activate: 20210426102256\n"
},
// tag=44385
{
    44385,
"Kexample.eu.+008+44385.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 8 (RSASHA256)\n"
    "Modulus: 14itl/SXMoKy/vwBYqyyCThBBs9f8hYNUoJaRYujiJzimU5pmrgOW27n2vUVRI0/Eoe/s3K/8OUr/kCdoZRHTWIzXSl4VIKRzVEZt0qT3wcUeBec3eN4lcSu/Bptjjs4ThdfThBtvYoLsVUJ/OMR1AiJdscx1QTo3dM5xnvdmAU+8/apwrOdqCf7600aVYKeDKRFwgXSom+C/HOQmH6j+7YjgrEm2oflHhFDHdbqMd2Xm6Dz4JTrNrmOofEOUsBimGmkXs+pFKSbJ6pFDCn8BFNZx/bKS839fSH8h+ym4H/HgcStlDUs2yZyTuro0rU74SZSOXGKbqT/9chGH7IiqdPWCmLpK3CgyUPixU8GCPzdOdjmOncDIok+w1W1DRzLMbI9yDpuf97mfQVfs4qMUzdwMWmxFzQznYreUEqq8tT/bSQBD2gOHe5wfieTUdwm+yvQl1wCujy3HaGJt2vAdMohmrW6/kSV8yI/ZItvg/Cvyv6HKtNRoojL/UvR3+hv++tajAb11qBf2UHBznNHC3j/vptnUdA0r9T87VknuwJ6dpM0662wxhleMNYleJ4fos4+g8vtW3x0MTdeX5+VNCYq3kx6jZSFiE6UcQv2MxX8Da1QDYK8eTkf0iR30cDoj0uKSy1hJIufz678HL9GOQJYZIPbSDx6iqKjpUPp0dc=\n"
    "PublicExponent: AQAB\n"
    "PrivateExponent: VobSWfyhbm+1+FOnIrv9xWHGCTvbYs6jjooyP1Ut07xX4//suWZGrUI65lYZsamato+00A+zKrx2Ct5Z6fIjJdfUkwQBALxiWDDEyCaycojfGM8x9IpLcKTDMwZRERaJJiCP7EEALWVsCEcBeXqXP64lsX+Ka+BKtDMGML6tWUhR25Mc18NP+aADrJUJi2aimKSiNKAtzXRC+6JRXEcLAhQ+8Uq5NGX1/zoi3anX3yj8okfdYD2oqBGaRz0E6Qe/DTzr9fwb/uOOPkBG8/ku6XWkx3g2AnSx3Th1rwO8gsgJifkxThyC43/tx+zahyym216NB+6jCoRHFZ7POA5Fh3c47Hf8C1TpGOUIE64PdsqYDWeT4qzhDGIb1z++rB0yFL3kObcFgC45b+0MEkJyhhWdF6qLtt+tDtJ8S3B7Brz/EU1kf6+FS565YD6o11F7jCEp1piprujq3w9pl8IVljZ3/9XQjDgMfLu0lMOJcznSHYprlyYS0MWMJORLYFeASYKG6bMbZdUhMHHP5bCW6O8k5Qk7RNM9KXaBfal9W2rPv4JkewKIZfTyFI1GwjyM5LB8LtUjdlaD/D0LcMv8PZHHDRK1yZFvt3TdupxDcEWKc9E1sG6+tqnJG17BLk3kAB2mlugQj/aA7PIy53Kieu/rrHtenBJiiKjgHC9tWQE=\n"
    "Prime1: +rLNfrXMppNLHecqPThxZ+liWVRL4fmQ+qAlRfjqkcPze59eFfmmMNEeLqzT6MMd8XyPTjoZKYxWJ2o75vMt6c2HPz3k89k0TwnXZnfO8PKj+H9JjVZ5BEc1UD1+87OoPEy8dDPG+GI0Q6ML03kI9t2bHrqfbm6WWbgtcEu3S2HmV/ZsABsWoyEQEEXs52BDu/7uAE5xVhBH2tQ11Q+x+c9hbVoTuBsdcysR6tG23IXblbJbl84//HR23Yu+8G30CkxZ7+gOCZ+cKj9f4jZUyxw9AHxzQ6asWtWe6+1ZkcDMfDv0LHSNaGepvytg14VhU7WK/5e0MTwBe7FPlRwGQQ==\n"
    "Prime2: 3BeBncTXr8vu13N+XUJJgbK1T2mqiqX1ZYRuHYhzJhr58muqgUAt2TEUl82ZagtKQAY5jPuPuiqXjMG6FhYU0opmhYaTU0A6NR5izHYyT6ZmrxXV7Vbs85u2eh56P3JIEWGGLjhI50Y0riRPnCvkNGckaCpn1+q+4lYqz4OzUV4sRyk8cEeVCQc7H521NhNoRAA1uGHGR1Tf+PZzBpWpe3QBw5mZXX0iUj9ntPs3okcyODVLAVPKn490SKlzhcBPU53ritcmwLtzj3MZbwwM1PoSw/g68fjtTcK00+MP0+cxEzwolaAXfLpcvtXWBoVMV7h3VFKbaOGaTWl/x6jCFw==\n"
    "Exponent1: Nk7Hj1xosekUi6zJDKwOfRkksf891P0QOAq7KFZM0jjlpPEYG6CSLN8QL8JGwZSLBwYZsTOKweJhw3YS9evWFWDtnHiXAXAbEcgq/kqT7MRTWwCP+WszGgcm+HPp7XcMyctBw9Z3ktULR1+pryz4ESpecSCyauTP8y2fwkTUtyLFGGcMbFVx6PK/nRbYxCKpaa9G9ZAIo0Exn6j65GXbAye2jk7GGMre7VT2M60sdMcWk24ow1DtsY21NjcQrNrU0+pITV0ytUj7Nne2GLX2Vm2OlW1gNtaDXcYLAEbRcW6XnY4LThoNjAFw1zXZa7a8J7sbGlVNtqCuHZKCj+WbQQ==\n"
    "Exponent2: j6hEMU+fnR6WmkjHbWXsBt033UrSR0eGAqpLGbnLt06aYPKHy2+xvXd8wo0vmvkdkOa/P9efe9t7KiP1K59kHfy6aGNr3EYq+CsKP/zSYAz0L0ooZY98gJHdrJ4iGzGj+rxWUerpIxQ/JH+M+xnnDZFZQSiUuWl/CMtHjEWhkPXQHu66hWsjy03N+Jf/BPnr757Xca9YNY0f2Cg88kpT4sHYuOyUH2KjOV4regUTzjd8fxXCDG697iI7u4XnYqEg5ipI6UoAAIMaLcLqEgKiiY1lHEb1aqWZd00krL0jwqO/85crwmZJjl8yVFnNJlpxdzxvnzmAORgwmGDJR/BOJw==\n"
    "Coefficient: AUNTQ+1KGzDe0M+xYZSRpZ+ipCX4J7FSHM1rfTN2FFAVtxmB93B5yccRQFivf6vv/hDTtY80+SkpXytZHGvuQxxoEiBqbNIqM51wtpFbyFmO0kU1LCruzgxg4dvwNpuSWPfVq/PKwp9cpJq6iY0jFvDUNYFJpi04YG/5AaL1LowNZv8mDlNxiiJHmL9wUQ2ULfrAJhStA2nsYhOMSkDPe1HhuOAcqf3TZnZC4Y1RfVjkh11jfnBNCKqwcoqSCij3qSpKpRoYYMnICEDik0EVkIY30krP8LGvRGbYyFTbddhZxxXo8frOC9wECzw5Qs+YRUH1lkfp+0oiX4ZOrsCMNw==\n"
    "Created: 20210426102256\n"
    "Publish: 20210426102256\n"
    "Activate: 20210426102256\n"
},
// tag=58273
{
    58273,
"Kexample.eu.+008+58273.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 8 (RSASHA256)\n"
    "Modulus: 0gQCPWxq+b3VM2lqABSggWt7PvZgTfVFiAu+BK7X2gbxCFAs9bS4eRAcYt7GPTHrw7FP4UacdJbq+hCdJC0PqMiAbze9bWn1rA4SZEZS+EBNUbW3OywWilFHLcf8DoRGaUiWvf0Ee/Dr8vvcDF6+/qI3MWGJ7y4PE/83j+WIf3aogXUp8EOvg/twbLOSDBo7hnHW/X+og6Ep1QJChKYAsdquU1vezMZhdILnDo0I6zR7O9n3cuYVYq8+weFmhx1/2JlbDWyoQr2vvTaImH28KZl7za8Z4gT41Tcq/EWoossLufb946ewjomuts66T/9SF4NHp39WqPCRZ3GKYBwc0w==\n"
    "PublicExponent: AQAB\n"
    "PrivateExponent: gnaLDa00J0COGQn7F2G486zZOxvCZ6teLk1dFXuoC4EUap2j0F8b2djwSVsquwkv9LlJbiB3QNYf0ohPlhGIEMm9P1nZCwcv3lo/gptNH3qSjZfc451Xw0UKep4pLrttIio9unhbOMNJUAC1idmxvGz47GwzS6nJJBr/YRyt1r+21qpYGlbzgVWCeKT/9nuFW+lfMZSGn+iK5x4bh30BbRkV4QGxu78YOrq40vs6TN3tBqxHtjVyUpyB7D4dDLzbIBm2DgRBKzpKz0QpnMoOaTzIisXXf66kL0aPxXVLG8P5zO8GpDC3R//nbG43DiCZptrqdZZa5Rb1j/6e8IH8wQ==\n"
    "Prime1: +IvZbYjrCpqfNoupCdo1DL3u78EY1jBigYW1/nApGN2SdRrL/2RsfQMwxS9wREfi/95ADyoxp12ZoaXs7YSmLjWaLW1Wt5p9K26mrfcM4qWwbrSa51V0iNYSy0N5IWPNfXVeXKiBoiK0T3P5cEdQEQTOtvkzHcO1esEFOgW5SeU=\n"
    "Prime2: 2FBZsZvrpdC0YtauhWgARdOJONyZLNh03j0H74h8pfehZRLJM+KWCBjd6AkkOvQoBN6S7NiYARwufGgQyTo97BdFQ5wynmmZ3r6loWDGv/CZNORE7aW6auDxK3r+OcU1dZztBLaZomms7kzO7cxfHtGu31qi1/y2HeaI/oNUAFc=\n"
    "Exponent1: di45MoYaDK686bi6pb6l3uspA8NzRdU34ZJsmRFH2VTx4NDfEw7zLvYnaHtIDI+J9lP9bbiIZ6Zv+Jbm84FRa0N9jgAhbaf9wHsasjl4XQSfweQKi9jsUmxH/3KT1DaabP8z4ScWjLuntOfWQXcHMTByAjq3/X0je7zv+Ujjc6k=\n"
    "Exponent2: p2Kd1YMa+SejvmvzhkXxGBdVswt4+CvTW3mMn31VPzR8znKYAS9P+5oKdRhF0dzG7uWwedgs34cILbp1atFHw15KecPvo4eBysxp7JOvmC080KHm+KJqu3OvC39UJC4HbShufFw0TGpLp+cFpRula3rEQA+pvUrPPhn7Xj8PjGc=\n"
    "Coefficient: ffFTo0/Ka3w/CIqBs8i+S4Ls/RSJGiqIEE1pB8nD9nrQvgDh/xaMMuTO6PaCgk/U70Ut0+7ov1tFhiW+/xi+6GxqRJkwngypugLRBUAKKTQ+G/0Y5Bs0ZhmOpal9seqBMX8zk6BsjhW/Q/S+RMxCjgBwPSDtoQZQ1JcnbERTU3U=\n"
    "Created: 20210426102256\n"
    "Publish: 20210426102256\n"
    "Activate: 20210426102256\n"
},
// tag=34811
{
    34811,
"Kexample.eu.+010+34811.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 10 (RSASHA512)\n"
    "Modulus: 04WuyB/6njz+nhsi/8nJ/BbqWvduDScUthAmBlR7v3BWO1dTKaTGnsCWqYieFxEXS0DVaTby9oRBeKTmZg775phZFu2OvLSUdLF/PjUXnRnuOsWN0dTWTDf6wykW+nLwsDSmXnNoQ6N9bpIUbYE8+jG/mcTV8QP4jBLu+G8uqLvUXcynu68tQHf+JWl4yEZQkWInVa21RmseuSCOzWhvLHT+gsBIE3Su4/dcbYuJXl2B0qanIHwwGpCCxgLBuJTn36pp4d+y81KG2BIJW/i0dEQejB1wB/WJr1GYEFLIP2MiM+CIl1T9yJoi81o64Dmvq+Nx+bA46zjOdPcU2eMgBpLv5FlYOzgdQqf9ZfOvuEkzOuLeBSwma3kMai3p+xGqvygA+BmgDRjnjSa63YbWMVYnXjtWqvqrsm9LbSdkbuk7RMTPPdlxn0zaorfXpT9gh9oOTJLR6tu2+QML/56Zobji+/kfv8i+a4K2YKz9L8oTNWxnzwrR6t6YULnTXajQzofPPJCg9jLIPAkRr7zXeYLfFQeUOOE8V2OoNs7s0fo2Zn6ux6/jEhcstZn00YsCDRb3DscD1cXsZqb7GqiPQfLPfDPpBYQYSBxiJDk8Cy6zX0qgfBusQ2+fMak4jaUu2bHzXcayY2HSld2Ua7921FZxNG+OVYX5eRK0oHmKsA0=\n"
    "PublicExponent: AQAB\n"
    "PrivateExponent: S1i2XuFNU+qkREukVvtZcOv0xTyYPiUqsoPkF6MmhZYNkYvUuuPQQKKXyII61jqnUo4gtx70wy1vaPtMexRhVM32Bj3O95dXvo2vpsggxjyDaPoQP6uSPoo+UCCl58bjx9CpZsGzZUyqlKWCk1NTFkh8WNkN4JGqirL/3w0z0LU/u734Ddojw3A63rbIaIbrki4lltaO2Su1QPrBA5hs6agvNQIraorI9bmaegcXgr7KTPBCXkb+l6fcfY5j1U1tn3XDy8r0ospF8FfUb6eTGEtfmkeuLZegWQw2n7HtVO8KMvKLlWSYFkoZoxgEGvVRh2g4pFnKnLeai32sNsU6FZeSfkEnaSZ9WB/RGGIr3qSdhSsCbISr3zraWIDNGZSaaIpAwdhEnCk+gAkmExsfB6ziSB7luxgxaOkmVu1S8tU62a0E1XV6/DL5tK2hPO6rXXLFkX4DQMRl+jh1l67AGqYiZMVaOj3T198ebagLPrrR0uxRvUb2jTKoUMs6S/qrspz3aZQnBXKCqCX6gnCJmHs9nnI3KqJucTlRcuYqESLrXBxMGYZeZieEu/CEIQAZTXq2xOAHV3GSo4etO0RC4DKH5rxwVWl+BTNd7LeGzWYFQ7u3gZX7LS2JzThkwd9SgEPrvBHvzzmzr3AnmU/W4RybL57x9LA6xIhOT1LHKeE=\n"
    "Prime1: 7nV5djw69XDIiHutG1SU1zbCelR6sMPgH5xX/sirjmLogMAM8447cSdlHDsxRN/7yhLJXNTIUcwC4y5Sw/w6cRLi6HSRpRRPoOUuynAp2fHVZX9CqqcUKJYYbKdgnjIbvOGZIyu9FEpjQ8n13gEgwxmRRKpCb9SxhILFwgp2m5rUgCEXIOyC37MAKZO017BgzpRLBW2JoB6WB1uPxrFBHVVTtEAgzoqCJhmmBpSzWO+tmKS8hTRi2PDX6tLzR11O4ovc4s8mRP9386pFueibYG4JBXn2OA/vosKe6NRgc1ZYS8qjck+YQkKetcsY9gIRuvmLy4xYDUEMPrlBVe+MmQ==\n"
    "Prime2: 4xTzl62lughanbu6zhxtHsC9wE1dcZwpFifHlMcfWogCd0vW7V7k1hiucYiV3PElJ293nC0NjF4k1TtbdsNoMZs3+7YRjzDIMugiDUtLGmwNkeGqCUa9CxEwb8uDVKtHDybH7v/Y5vCFW0+g65iIxT089tBndMC2UUipP/j8ZxSPcddfSVbkt7HBKwd/2IIzjPpms96Vy7xkeHxJQXFAeLuUnAAHhJuXY3NTa1O7UvotAYxeWs9xmYq3g42iIIcB3PQSixD4JuxZfggr/R8eeSgoyJi9sIBAti8r4LrqDKJZZAKAK3v4MA5eTYfibNBN724ugvBqbVrM6/z0bbKTlQ==\n"
    "Exponent1: IxylH+XKgK10ubQMT0PrDq1/gWfDERgmfkEVK+z8ZeDmf17ICWzeD9FPMBL/NDcO6jhN8h9ax8CUhEMj6LvRFylCxBu1/mq5NuXIOALABtl3JJTSijJD454GRql2rpSORQeq9uTP2JcDes3YKDJeUpwHKecwFStqYCqpV+MWh98KfztgHnb05l+DHJwlOsU72+82BLyWUT9vs/GlgApFnj4cLyRqMD9w3o9URQ/MQMI5+4n2QF7wVyVPhcI+FDoHDZCum68I4YwEa5qc3b0Ec/R/25CT0rl1/a9OmtX6xcDnC3HxEznpH4iTug0HxeGUHsXz8arepET5upqopjC5sQ==\n"
    "Exponent2: 3zDSkzxLbWOUnP/NBZQO9HEAj6f6thWElJAYq/RirrqLofFamAfy5zNvEYvrsDMcD3yRlWD6tgI6NZKXvU0mdctX5QD4lUKfItnhzis48AlP9RhV5bQvTldgwiDHPkryFsRJMnEpISM6D5teUPGlTCd6aiQ/6xMWnyHJqGTyv+YHbx7+Ork7KAmAEOjYEVc3j9L1asjVdl/+aCXQYpALjB7iW8nzmbTLwSWy0gSEU3QtFB6BBsRppT4gTR7CQTIw9Ji4ORM+tBMNisBBbBJQA0kjfLYTiw0jjW0jtUhBjpVrQs7qZtL8B0+4BIAQXl8GmtQyxuPB1yWt0CzZmZAxWQ==\n"
    "Coefficient: PLBuQCaLVfVH6+y1oEFK73o68QzLYkn6ftBT7/FA2o6j6fntZEjEavIS1vK+R3Co20xs68PbGsBXabu2jyXQIx5jUc2+iBQ9oSz4ReRDsiOKE2J1zAUGcItF8yEsmW3j4HEr8A47ivlisNgNoVp/DJ7j/Y0hC2b4WaaPjINEYRd/thzs12xL/kH3qM+z8qffpP9snpdfYLUWZZH1YzmiTNwgfe5GLC2T+E/VleNXNGzqzMJNmJsYL+syNSMfimgFS2gR52ZMo7U3GiywAiXYRE2sC+IkiNIrRIXw2wURZzXhtq38phf0MaTwqKsqUbuBQoJ0Hohf/MhNtaZP3LJ9Qg==\n"
    "Created: 20210426102257\n"
    "Publish: 20210426102257\n"
    "Activate: 20210426102257\n"
},
#if DNSCORE_HAS_ECDSA_SUPPORT
// tag=57775
{
    57775,
"Kexample.eu.+013+57775.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 13 (ECDSAP256SHA256)\n"
    "PrivateKey: fQPrUhBgf9qHbqCqpPxgJeYxXHxucGTrds8m7Opk3F4=\n"
    "Created: 20210426102258\n"
    "Publish: 20210426102258\n"
    "Activate: 20210426102258\n"
},
// tag=52751
{
    52751,
"Kexample.eu.+014+52751.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 14 (ECDSAP384SHA384)\n"
    "PrivateKey: NbHqn5nkSJO00Mn3qYn/EvQiy7rWZbD7DM4hWSmv9d49cZb2WqjOoepLvF18700R\n"
    "Created: 20210426102258\n"
    "Publish: 20210426102258\n"
    "Activate: 20210426102258\n"
},
#endif
#if DNSCORE_HAS_EDDSA_SUPPORT
// tag=49344
{
    49344,
"Kexample.eu.+015+49344.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 15 (ED25519)\n"
    "PrivateKey: aSJGqK3Zl76HMq0p4vt83rHf2gtKrDUqA/HSOdC+Sos=\n"
    "Created: 20210426102258\n"
    "Publish: 20210426102258\n"
    "Activate: 20210426102258\n"
},
// tag=7552
{
    7552,
"Kexample.eu.+016+07552.private",
    "Private-key-format: v1.3\n"
    "Algorithm: 16 (ED448)\n"
    "PrivateKey: HXg45UwYRlpsmK2MpbBM4DBF3gENi40y0eNicRaic0WwyEl1FA7V8WlqB35ovylb5xmchhniLoGH\n"
    "Created: 20210426102258\n"
    "Publish: 20210426102258\n"
    "Activate: 20210426102258\n"
},
#endif
    {0, NULL, NULL}
};

static void
parse_public_key_record(struct dnskey_inputs_s *input)
{
    if(!algorithm_allowed(input->algorithm))
    {
        return;
    }

    formatln("algorithm: '%s'", dns_encryption_algorithm_get_name(input->algorithm));
    flushout();

    input_stream is;
    bytearray_input_stream_init_const(&is, input->record_text, strlen(input->record_text));

    zone_reader zr;
    ya_result ret = zone_reader_text_parse_stream(&is, &zr);
    if(ISOK(ret))
    {
        resource_record rr;
        zone_reader_text_ignore_missing_soa(&zr);

        ret = zone_reader_read_record(&zr, &rr);

        dnssec_key *key = NULL;

        if(ISOK(ret = dnskey_new_from_rdata(rr.rdata, rr.rdata_size, rr.name, &key)))
        {
            if(key != NULL)
            {
                u16 size = dnskey_get_size(key);
                if(size == input->bit_size)
                {
                    formatln("%s: success", input->record_text);
                }
                else
                {
                    formatln("%s: failure: %i != %i (%i)", input->record_text, size, input->bit_size, input->bit_size - size);
                    osformatln(termerr, "%s: failure: %i != %i (%i)", input->record_text, size, input->bit_size, input->bit_size - size);
                }
            }
            else
            {
                formatln("could not load key: %r (internal)", ret);
                osformatln(termerr, "could not load key: %r (internal)", ret);
            }
        }
        else
        {
            formatln("could not load key: %r", ret);
            osformatln(termerr, "could not load key: %r", ret);
        }
    }
}

static void
parse_private_key_record(struct dnskey_private_inputs_s *input)
{
    dnssec_key *key = NULL;
    ya_result ret = ERROR;

    output_stream os;
    char file_name[PATH_MAX];

    for(int i = 0; dnskey_inputs[i].record_text != NULL; ++i)
    {
        if(dnskey_inputs[i].tag == input->tag)
        {
            if(!algorithm_allowed(dnskey_inputs[i].algorithm))
            {
                return;
            }

            snformat(file_name, sizeof(file_name),"/tmp/%s", dnskey_inputs[i].file_name);
            file_output_stream_create(&os, file_name, 0640);
            osprint(&os, dnskey_inputs[i].record_text);
            output_stream_close(&os);
            ret = SUCCESS;
            break;
        }
    }

    formatln("file: %s", input->file_name);
    flushout();

    if(FAIL(ret))
    {
        osformatln(termerr, "could not find the associated public key for tag %u", input->tag);
        exit(EXIT_FAILURE);
    }

    snformat(file_name, sizeof(file_name),"/tmp/%s", input->file_name);
    file_output_stream_create(&os, file_name, 0640);
    osprint(&os, input->file_text);
    output_stream_close(&os);

    if(ISOK(ret = dnskey_new_private_key_from_file(file_name, &key)))
    {
        u16 tag = dnskey_get_tag(key);

        if(tag != input->tag)
        {
            formatln("tag mismatch '%s': expected %hu, got %hu", input->file_text, input->tag, tag);
            osformatln(termerr, "tag mismatch '%s': expected %hu, got %hu", input->file_text, input->tag, tag);
            ret = INVALID_STATE_ERROR;
        }

        ptr_vector rrset;
        ptr_vector_init_empty(&rrset);

        ptr_vector rrset_different;
        ptr_vector_init_empty(&rrset_different);
        
        dns_resource_record *rr0 = dns_resource_record_new_instance();
        static u8* rr0_ns_rdata = (u8*)"\003ns1\007example\002eu";
        dns_resource_record_set_record(rr0, dnskey_get_domain(key), TYPE_NS, CLASS_IN, 86400, sizeof(rr0_ns_rdata), rr0_ns_rdata);
        
        dns_resource_record *rr1 = dns_resource_record_new_instance();
        static u8* rr1_ns_rdata = (u8*)"\003ns2\007example\002eu";
        dns_resource_record_set_record(rr1, dnskey_get_domain(key), TYPE_NS, CLASS_IN, 86400, sizeof(rr1_ns_rdata), rr1_ns_rdata);

        dns_resource_record *rr2 = dns_resource_record_new_instance();
        static u8* rr2_ns_rdata = (u8*)"\003ns3\007example\002eu";
        dns_resource_record_set_record(rr2, dnskey_get_domain(key), TYPE_NS, CLASS_IN, 86400, sizeof(rr2_ns_rdata), rr2_ns_rdata);

        ptr_vector_append(&rrset, rr0);
        ptr_vector_append(&rrset, rr1);

        ptr_vector_append(&rrset, rr2);

        resource_record_view rrv;
        dns_resource_record* rrsig_rr = NULL;
        dns_resource_record_resource_record_view_init(&rrv);

        s32 from_epoch = dnskey_get_activate_epoch(key);
        s32 to_epoch = dnskey_get_inactive_epoch(key);

        dnskey_signature ds;
        dnskey_signature_init(&ds);
        dnskey_signature_set_validity(&ds, from_epoch, to_epoch);
        dnskey_signature_set_view(&ds, &rrv);
        dnskey_signature_set_rrset_reference(&ds, &rrset);
        dnskey_signature_set_canonised(&ds, FALSE);
        ya_result ret = dnskey_signature_sign(&ds, key, (void **) &rrsig_rr);
        dnskey_signature_finalize(&ds);

        if(ISOK(ret))
        {
            rdata_desc rrsig_desc = { rrsig_rr->tctr.qtype, rrsig_rr->rdata_size, rrsig_rr->rdata };
            formatln("signature: %{typerdatadesc}", &rrsig_desc);

            dnskey_signature ds_back;
            dnskey_signature_init(&ds_back);
            dnskey_signature_set_validity(&ds_back, from_epoch, to_epoch);
            dnskey_signature_set_view(&ds_back, &rrv);
            dnskey_signature_set_rrset_reference(&ds_back, &rrset);
            dnskey_signature_set_canonised(&ds_back, FALSE);
            ret = dnskey_signature_sign(&ds_back, key, (void **) &rrsig_rr);
            dnskey_signature_finalize(&ds_back);

            ret = dnskey_signature_verify(&ds_back, key, rrsig_rr);

            if(ISOK(ret))
            {
                println("signature verified");
            }
            else
            {
                osformatln(termerr, "failed to verify signature: %r", ret);
            }

            dnskey_signature ds_other;
            dnskey_signature_init(&ds_other);
            dnskey_signature_set_validity(&ds_other, from_epoch, to_epoch);
            dnskey_signature_set_view(&ds_other, &rrv);
            dnskey_signature_set_rrset_reference(&ds_other, &rrset_different);
            dnskey_signature_set_canonised(&ds_other, FALSE);
            ret = dnskey_signature_sign(&ds_other, key, (void **) &rrsig_rr);
            dnskey_signature_finalize(&ds_other);

            ret = dnskey_signature_verify(&ds_other, key, rrsig_rr);

            if(FAIL(ret))
            {
                println("signature not verified as it should");
                ret = SUCCESS;
            }
            else
            {
                osprintln(termerr, "signature verified but shouldn't");
                ret = ERROR;
            }
        }
        else
        {
            formatln("signature failure with '%s': %r", input->file_text, ret);
            osformatln(termerr, "signature failure with '%s': %r", input->file_text, ret);
        }

        dns_resource_record_resource_record_view_finalise(&rrv);

        if(rrsig_rr != NULL)
        {
            dns_resource_record_free(rrsig_rr);
        }
        dns_resource_record_free(rr2);
        dns_resource_record_free(rr1);
        dns_resource_record_free(rr0);

        ptr_vector_destroy(&rrset_different);
        ptr_vector_destroy(&rrset);

        dnskey_release(key);
    }
    else
    {
        formatln("failed to parse file '%s':\n%s\nerror is: %r", input->file_name, input->file_text, ret);
        osformatln(termerr, "failed to parse file '%s':\n%s\nerror is: %r", input->file_name, input->file_text, ret);
        flushout();
        flusherr();
    }
}

static void parse_public_key_records()
{
    logger_flush();

    for(struct dnskey_inputs_s *p = &dnskey_inputs[0]; p->record_text != NULL; ++p)
    {
        parse_public_key_record(p);
        logger_flush();
        flushout();
        flusherr();
    }
}

static void parse_private_key_files()
{
    logger_flush();

    for(struct dnskey_private_inputs_s *p = &dnskey_private_inputs[0]; p->file_text != NULL; ++p)
    {
        parse_private_key_record(p);
        flushout();
        flusherr();
    }
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    println("note: arguments can be -L to enable the logger as well as any algorithm integer value, which will restrain the tests to these algorithms.\n");
    flushout();

    for(int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "-L") == 0)
        {
            logger_start();
            main_logger_setup();
            continue;
        }

        int a = atoi(argv[i]);

        if((a >= DNSKEY_ALGORITHM_RSAMD5) && (a <= DNSKEY_ALGORITHM_ED448))
        {
            ptr_vector_append(&g_allowed_algorithms, (void*)(intptr)a);
        }
    }

    parse_public_key_records();
    parse_private_key_files();

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
