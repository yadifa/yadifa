/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2020, EURid vzw. All rights reserved.
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

struct dnskey_inputs_s
{
    const char * const record_text;
    u8 algorithm;
    u16 bit_size;
    const char * const domain_name;
};

static struct dnskey_inputs_s dnskey_inputs[] =
{
    {
        // dnssec-keygen -a DSA -b 512 example.eu.
        "example.eu. IN DNSKEY 256 3 3 AK91wZvq1hFxV3NOf28aZ5XihW+d43hormb0MPbFaUhdcf6CFzf8TvCU T4V3XVEYCdTo3jPTP1I7I63bBvbU3TO1htqyYeoWV+cisDBeP50PnzWz 5ZOopIrvQlIi+e26cZG2d7xLEQKCDHSlUqfP1G21NtMgqt9VESk3pdc1 eKebWnIFOvRj7QWuQc6UzJMpHlEt5IDF+G5l1SffMywz2oNTOy4Vm6Rr DDG60YV7nHfpAktNEJdHZS74dLaNQotT5Sc8wRB3sLpqTh1mPxINRv1s Wunc",
        DNSKEY_ALGORITHM_DSASHA1, 512, "example.eu."
    },
    {
        // dnssec-keygen -a DSA -b 1024 example.eu.
        "example.eu. IN DNSKEY 256 3 3 CKd8mG7C5h53CcjTIHRhhPH5Arr3uEwgIPKbZry4e+R8jsE1yhpOXZvK opJ4VuRXdYJIYHJIsMVbGux9+fUsL3Jr+KuUJ9nlSgjmzUULJSmVRXT0 rCKBBFDpg0rwq/HFheMYCAt/3ZkQh/y1RX3emsMUCUBTgnb52Owsnoqx f0Gk0ucoyjcZBoDttTsFCV2oB+kFO1+SjDBlNtUz27GpT+QmbAVSBq3D OHifxhNVDqpmMcV300R1XK+QFIUsROeSTITztA3roldbfAqFl845BW7a EZhpbxVdKX8CtldK3H3ahzXA/rU94OfWwXDdFeu3+hfpa1m+hKVgXF3t zX+k460tx+pF/C3y1DDZ1wyivrvZ6mWyLA9mqk7XUgycgAYrW4VeakmB h3GljGkd9YzuePUeGLpoMIHQcFKYr8uAWkWe+jKF2XcISE80MSTHK4v/ RyQZe3c2DV+WoBOGUawwEngncDD92F03Vdp668YzW59t/YrazX7YVQVh 8557Vt1jVcudKwlreX8ljzgx3MIjxXCGO2gR",
        DNSKEY_ALGORITHM_DSASHA1, 1024, "example.eu."
    },
    {
        // dnssec-keygen -a RSASHA1 -b 1024 example.eu.
        "example.eu. IN DNSKEY 256 3 5 AwEAAbeGtfPfuq+8Uv8AAY3SRkMb1KuAtq4BHJXq44hB4qL3Ap0qI4L4 oMWYHUfKN/ya5D+Q9mVsSbhnfq+VH1JkpecBFgdys9T23FiYt7QFRTa2 Q34rMrL510+uKm2Tx98erTxrhmfHlBjOFZt38IugpedonxdzuaPeq3Rl IlI2nICN",
        DNSKEY_ALGORITHM_RSASHA1, 1024, "example.eu."
    },
    {
        // dnssec-keygen -a RSASHA1 -b 4096 example.eu.
        "example.eu. IN DNSKEY 256 3 5 AwEAAdxni9K5IoxZPJDbPs7xhWTpWp4Of03JudJPVzmBa3SIURryWLuK ecWs4kL/WZb1bFoqaZJSlAUEQHDTmnnyEJ41gVDUOZ90cRc4t7NwiO4Z 0HqQhUazDUWLFho2i+JnGztbsE9IjyVvjQHWE1Xa2MMG+0qaJDPWcpL6 daYHzi/2W+WrUscVjkvXIJkSUVrS1Clk65d8VdrG+rAkUxoIeYlXyKW6 tskL8eEDVUoBHkWzDHPZh1bA6VcYux2pNw0sLFnDvv8A9xJu0Nxv6o57 pzd21ngwzsnBxSdxqn+M8BbNFEKFh9SQTJ2k6Z9vHwStMLQntonYNgez ni/R/9iO0lvW5o7tmzHj14sb9oMQ8f5m/OGlZ9UjZg8h+Il59IEm7EEn rwkp8L/Tfw81O1jWaDX5GWaLAdwk6VgiCLQ1xp1DC13JxhaC4RGEhsWN TojEE4bla1Awos906mC9x1OY2XSGq4zmQqH+6xk/Pl6TKpE9PSJO3lCq 8JKfDVdaK3BITROhSQZjde9I9IMF30HAuAnc/SubkkvVWrSaFVtCevzb oyxVsL2tTItY1Em+NRJH77aVGRj6Iav4MDJlgkYoFlDPG1GLtLH/GaxW fgeDvpsNdkxckWLnS6sPGLPC9SyCC0VWXnmSqro5mN+g1XzlUHgC3X5c LcOmJI7f2GO2i83r",
        DNSKEY_ALGORITHM_RSASHA1, 4096, "example.eu."
    },
    {
        // dnssec-keygen -a ECDSAP256SHA256 example.eu
        "example.eu. IN DNSKEY 256 3 13 UFLtfeMQq9CSFQwMC/ids65uwuY9g7w8Obx+0ySea7SX30nZTCqAAOvZ JgdIs2gJU7+a3TBiiFgYehxsQufo3Q==",
        DNSKEY_ALGORITHM_ECDSAP256SHA256, 256, "example.eu."
    },
    {
        // dnssec-keygen -a ECDSAP384SHA384 example.eu.
        "example.eu. IN DNSKEY 256 3 14 aRBbx/S6IIDwnloCO7qkcs2MdyigDs46g6J0gM8wL+hfgvmO0Sifk/vW cFigqHXenJsmFZTqButEN6IZmYRtwp/icQw/ThAlEDsD0qMupmdqFQis Ky26e0Gooe6+gFYC",
        DNSKEY_ALGORITHM_ECDSAP256SHA256, 384, "example.eu."
    },

    {NULL, 0, 0, NULL}
};

static void parse_public_key_record(struct dnskey_inputs_s *input)
{
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
                    formatln("%s: failure: %i != %i", input->record_text, size, input->bit_size);
                }
            }
            else
            {
                formatln("could not load key: %r (internal)", ret);
            }
        }
        else
        {
            formatln("could not load key: %r", ret);
        }
    }
}

static void parse_public_key_records()
{
    for(struct dnskey_inputs_s *p = &dnskey_inputs[0]; p->record_text != NULL; ++p)
    {
        parse_public_key_record(p);
    }
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    parse_public_key_records();

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
