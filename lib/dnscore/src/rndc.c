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

#include "dnscore/bytearray_output_stream.h"
#include "dnscore/rndc.h"
#include "dnscore/host_address.h"
#include "dnscore/tsig.h"
#include "dnscore/base64.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/format.h"

#define RNDC_PASCAL_STRING          1
#define RNDC_DICTIONARY             2

#define RNDC_PARSE_DICT_FIELD_DEBUG 0
#define RNDC_MESSAGE_VERIFY_DEBUG   0
#define RNDC_MESSAGE_RECV_DEBUG     0

/*

 =>

0040               00 00 00 d2 00 00 00 01 05 5f 61 75       ........._au
0050   74 68 02 00 00 00 63 04 68 73 68 61 01 00 00 00   th....c.hsha....
0060   59 a3 65 46 37 6b 46 2b 4b 37 42 5a 78 78 4d 38   Y.eF7kF+K7BZxxM8
0070   63 4f 65 4c 66 58 51 54 45 74 33 42 75 63 4a 42   cOeLfXQTEt3BucJB
0080   56 75 43 68 51 32 6a 31 45 45 52 33 6b 3d 00 00   VuChQ2j1EER3k=..
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00b0   00 00 00 00 00 00 00 00 00 00 05 5f 63 74 72 6c   ..........._ctrl
00c0   02 00 00 00 3c 04 5f 73 65 72 01 00 00 00 0a 31   ....<._ser.....1
00d0   33 37 33 31 35 32 30 39 34 04 5f 74 69 6d 01 00   373152094._tim..
00e0   00 00 0a 31 36 37 38 31 31 34 39 30 38 04 5f 65   ...1678114908._e
00f0   78 70 01 00 00 00 0a 31 36 37 38 31 31 34 39 36   xp.....167811496
0100   38 05 5f 64 61 74 61 02 00 00 00 0e 04 74 79 70   8._data......typ
0110   65 01 00 00 00 04 6e 75 6c 6c                     e.....null

 0xd2-bytes
 0x00000001
  "_auth" 0x02 = dict 0x00000063 is length
    "hsha" 0x01 = string 0x00000059 is length
       base64 (HMAC) string, padded to 0x59 bytes with 0
  "_ctrl" 0x02 = dict 0x0000006c is length
    "_ser" 0x01 = string 0x0000000a is length
      1373152094
    "_tim" 0x01 = string 0x0000000a is length
      1678114908
    "_exp" 0x01 = string 0x0000000a is length
      1678114968
  "_data" 0x02 = dict 0x0000000e is length
    "type" 0x01 = string 0x00000004 is length
      null

 <=

0040               00 00 01 00 00 00 00 01 05 5f 61 75       ........._au
0050   74 68 02 00 00 00 63 04 68 73 68 61 01 00 00 00   th....c.hsha....
0060   59 a3 57 64 75 75 4d 4a 68 78 31 36 7a 4f 62 49   Y.WduuMJhx16zObI
0070   5a 63 4d 61 39 69 75 7a 36 6f 79 45 75 72 7a 68   ZcMa9iuz6oyEurzh
0080   44 68 71 6b 59 54 73 36 32 55 4f 44 73 3d 00 00   DhqkYTs62UODs=..
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00b0   00 00 00 00 00 00 00 00 00 00 05 5f 63 74 72 6c   ..........._ctrl
00c0   02 00 00 00 5d 04 5f 73 65 72 01 00 00 00 0a 31   ....]._ser.....1
00d0   33 37 33 31 35 32 30 39 34 04 5f 74 69 6d 01 00   373152094._tim..
00e0   00 00 0a 31 36 37 38 31 31 34 39 30 38 04 5f 65   ...1678114908._e
00f0   78 70 01 00 00 00 0a 31 36 37 38 31 31 34 39 36   xp.....167811496
0100   38 04 5f 72 70 6c 01 00 00 00 01 31 06 5f 6e 6f   8._rpl.....1._no
0110   6e 63 65 01 00 00 00 0a 31 33 39 38 33 30 38 32   nce.....13983082
0120   30 35 05 5f 64 61 74 61 02 00 00 00 1b 04 74 79   05._data......ty
0130   70 65 01 00 00 00 04 6e 75 6c 6c 06 72 65 73 75   pe.....null.resu
0140   6c 74 01 00 00 00 01 30                           lt.....0

 =>

0040               00 00 00 f9 00 00 00 01 05 5f 61 75       ........._au
0050   74 68 02 00 00 00 63 04 68 73 68 61 01 00 00 00   th....c.hsha....
0060   59 a3 41 6a 48 4b 67 6c 79 48 7a 33 53 46 46 48   Y.AjHKglyHz3SFFH
0070   4f 4e 4b 32 4e 74 52 57 4c 5a 78 72 58 61 4f 47   ONK2NtRWLZxrXaOG
0080   5a 54 52 37 79 70 4a 55 55 2f 30 4a 38 3d 00 00   ZTR7ypJUU/0J8=..
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00b0   00 00 00 00 00 00 00 00 00 00 05 5f 63 74 72 6c   ..........._ctrl
00c0   02 00 00 00 52 04 5f 73 65 72 01 00 00 00 0a 31   ....R._ser.....1
00d0   33 37 33 31 35 32 30 39 35 04 5f 74 69 6d 01 00   373152095._tim..
00e0   00 00 0a 31 36 37 38 31 31 34 39 30 38 04 5f 65   ...1678114908._e
00f0   78 70 01 00 00 00 0a 31 36 37 38 31 31 34 39 36   xp.....167811496
0100   38 06 5f 6e 6f 6e 63 65 01 00 00 00 0a 31 33 39   8._nonce.....139
0110   38 33 30 38 32 30 35 05 5f 64 61 74 61 02 00 00   8308205._data...
0120   00 1f 04 74 79 70 65 01 00 00 00 15 73 74 61 74   ...type.....stat
0130   75 73 20 64 6e 73 73 65 63 2d 6e 6f 6e 65 2e 65   us dnssec-none.e
0140   75                                                u

 <=

0040               00 00 03 89 00 00 00 01 05 5f 61 75       ........._au
0050   74 68 02 00 00 00 63 04 68 73 68 61 01 00 00 00   th....c.hsha....
0060   59 a3 30 74 31 65 56 2f 78 79 6e 35 7a 31 6c 41   Y.0t1eV/xyn5z1lA
0070   6d 2f 33 64 33 65 59 73 6d 46 42 2f 42 71 4b 59   m/3d3eYsmFB/BqKY
0080   43 7a 64 70 64 77 4f 2b 52 51 73 2b 30 3d 00 00   CzdpdwO+RQs+0=..
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00b0   00 00 00 00 00 00 00 00 00 00 05 5f 63 74 72 6c   ..........._ctrl
00c0   02 00 00 00 5d 04 5f 73 65 72 01 00 00 00 0a 31   ....]._ser.....1
00d0   33 37 33 31 35 32 30 39 35 04 5f 74 69 6d 01 00   373152095._tim..
00e0   00 00 0a 31 36 37 38 31 31 34 39 30 38 04 5f 65   ...1678114908._e
00f0   78 70 01 00 00 00 0a 31 36 37 38 31 31 34 39 36   xp.....167811496
0100   38 04 5f 72 70 6c 01 00 00 00 01 31 06 5f 6e 6f   8._rpl.....1._no
0110   6e 63 65 01 00 00 00 0a 31 33 39 38 33 30 38 32   nce.....13983082
0120   30 35 05 5f 64 61 74 61 02 00 00 02 a4 04 74 79   05._data......ty
0130   70 65 01 00 00 00 15 73 74 61 74 75 73 20 64 6e   pe.....status dn
0140   73 73 65 63 2d 6e 6f 6e 65 2e 65 75 06 72 65 73   ssec-none.eu.res
0150   75 6c 74 01 00 00 00 01 30 04 74 65 78 74 01 00   ult.....0.text..
0160   00 02 6e 76 65 72 73 69 6f 6e 3a 20 42 49 4e 44   ..nversion: BIND
0170   20 39 2e 31 38 2e 31 32 20 28 45 78 74 65 6e 64    9.18.12 (Extend
0180   65 64 20 53 75 70 70 6f 72 74 20 56 65 72 73 69   ed Support Versi
0190   6f 6e 29 20 3c 69 64 3a 39 39 37 38 33 66 39 3e   on) <id:99783f9>
01a0   20 28 6e 61 6d 65 64 20 31 32 37 2e 30 2e 35 33    (named 127.0.53
01b0   2e 35 29 0a 72 75 6e 6e 69 6e 67 20 6f 6e 20 6f   .5).running on o
01c0   72 6f 63 68 69 3a 20 4c 69 6e 75 78 20 78 38 36   rochi: Linux x86
01d0   5f 36 34 20 36 2e 32 2e 32 2d 61 72 74 69 78 31   _64 6.2.2-artix1
01e0   2d 31 20 23 31 20 53 4d 50 20 50 52 45 45 4d 50   -1 #1 SMP PREEMP
01f0   54 5f 44 59 4e 41 4d 49 43 20 46 72 69 2c 20 30   T_DYNAMIC Fri, 0
0200   33 20 4d 61 72 20 32 30 32 33 20 31 38 3a 32 34   3 Mar 2023 18:24
0210   3a 33 33 20 2b 30 30 30 30 0a 62 6f 6f 74 20 74   :33 +0000.boot t
0220   69 6d 65 3a 20 4d 6f 6e 2c 20 30 36 20 4d 61 72   ime: Mon, 06 Mar
0230   20 32 30 32 33 20 31 35 3a 30 31 3a 33 32 20 47    2023 15:01:32 G
0240   4d 54 0a 6c 61 73 74 20 63 6f 6e 66 69 67 75 72   MT.last configur
0250   65 64 3a 20 4d 6f 6e 2c 20 30 36 20 4d 61 72 20   ed: Mon, 06 Mar
0260   32 30 32 33 20 31 35 3a 30 31 3a 33 32 20 47 4d   2023 15:01:32 GM
0270   54 0a 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20   T.configuration
0280   66 69 6c 65 3a 20 2f 74 6d 70 2f 79 61 64 69 66   file: /tmp/yadif
0290   61 64 2d 73 65 72 76 65 72 2d 74 65 73 74 2f 73   ad-server-test/s
02a0   32 2f 65 74 63 2f 6e 61 6d 65 64 2e 63 6f 6e 66   2/etc/named.conf
02b0   0a 43 50 55 73 20 66 6f 75 6e 64 3a 20 33 32 0a   .CPUs found: 32.
02c0   77 6f 72 6b 65 72 20 74 68 72 65 61 64 73 3a 20   worker threads:
02d0   33 32 0a 55 44 50 20 6c 69 73 74 65 6e 65 72 73   32.UDP listeners
02e0   20 70 65 72 20 69 6e 74 65 72 66 61 63 65 3a 20    per interface:
02f0   33 32 0a 6e 75 6d 62 65 72 20 6f 66 20 7a 6f 6e   32.number of zon
0300   65 73 3a 20 35 34 20 28 30 20 61 75 74 6f 6d 61   es: 54 (0 automa
0310   74 69 63 29 0a 64 65 62 75 67 20 6c 65 76 65 6c   tic).debug level
0320   3a 20 30 0a 78 66 65 72 73 20 72 75 6e 6e 69 6e   : 0.xfers runnin
0330   67 3a 20 30 0a 78 66 65 72 73 20 64 65 66 65 72   g: 0.xfers defer
0340   72 65 64 3a 20 30 0a 73 6f 61 20 71 75 65 72 69   red: 0.soa queri
0350   65 73 20 69 6e 20 70 72 6f 67 72 65 73 73 3a 20   es in progress:
0360   30 0a 71 75 65 72 79 20 6c 6f 67 67 69 6e 67 20   0.query logging
0370   69 73 20 4f 4e 0a 72 65 63 75 72 73 69 76 65 20   is ON.recursive
0380   63 6c 69 65 6e 74 73 3a 20 30 2f 39 30 30 2f 31   clients: 0/900/1
0390   30 30 30 0a 74 63 70 20 63 6c 69 65 6e 74 73 3a   000.tcp clients:
03a0   20 30 2f 31 35 30 0a 54 43 50 20 68 69 67 68 2d    0/150.TCP high-
03b0   77 61 74 65 72 3a 20 30 0a 73 65 72 76 65 72 20   water: 0.server
03c0   69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e   is up and runnin
03d0   67                                                g


The way I understand:

 rnc TCP-connects to named

 R -> auth -> D
 D -> auth? -> R
 R -> query (auth) -> D
 D -> answer (auth) > R

00 00 00 d1 <- length
00 00 00 01 <- flags? type?
 sequence of pascal-strings/type/value

So, after some reading it's:

DICT (anonymous root)
_auth DICT
 hsha string base64 string

_ctrl DICT
 _ser PSTR
 _tim PSTR
 _exp PSTR
 _nonce PSTR

_data

DICT: BE32 2 , BE32 N : size in bytes - 1 followed by a sequence of pascal-string/type/value

BE32 1 : pascal string

 It's pretty trivial.

Looking at the weird 0 padding on the auth digest, I presume in named's implementation it's pre-padded with a
place-holder. Fine by me : it's easier.

0000   00 00 00 d2 00 00 00 01 05 5f 61 75 74 68 02 00   ........._auth..
0010   00 00 63 04 68 73 68 61 01 00 00 00 59 a3 64 45   ..c.hsha....Y.dE
0020   67 6d 6c 31 59 57 52 6b 38 48 67 32 39 4b 70 6a   gml1YWRk8Hg29Kpj
0030   69 37 69 75 33 52 41 73 52 67 6e 4b 67 37 78 71   i7iu3RAsRgnKg7xq
0040   74 71 36 66 2b 55 37 72 41 3d 00 00 00 00 00 00   tq6f+U7rA=......
0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0070   00 00 00 00 00 00 05 5f 63 74 72 6c 02 00 00 00   ......._ctrl....
0080   3c 04 5f 73 65 72 01 00 00 00 0a 32 33 30 37 38   <._ser.....23078
0090   39 35 31 38 30 04 5f 74 69 6d 01 00 00 00 0a 31   95180._tim.....1
00a0   36 37 38 31 39 36 37 33 30 04 5f 65 78 70 01 00   678196730._exp..
00b0   00 00 0a 31 36 37 38 31 39 36 37 39 30 05 5f 64   ...1678196790._d
00c0   61 74 61 02 00 00 00 0e 04 74 79 70 65 01 00 00   ata......type...
00d0   00 04 6e 75 6c 6c                                 ..null

0000   00 00 00 d6 00 00 00 01 05 5f 61 75 74 68 02 00   ........._auth..
0010   00 00 63 04 68 73 68 61 01 00 00 00 59 a3 43 52   ..c.hsha....Y.CR
0020   2f 70 39 2b 44 6e 2f 6a 34 61 7a 31 34 42 47 41   /p9+Dn/j4az14BGA
0030   35 66 62 51 51 54 37 45 47 65 64 6f 76 39 4d 65   5fbQQT7EGedov9Me
0040   79 55 43 37 4a 2b 38 58 63 3d 00 00 00 00 00 00   yUC7J+8Xc=......
0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0070   00 00 00 00 00 00 05 5f 63 74 72 6c 02 00 00 00   ......._ctrl....
0080   3c 04 5f 73 65 72 01 00 00 00 0a 32 33 30 37 38   <._ser.....23078
0090   39 35 31 38 31 04 5f 74 69 6d 01 00 00 00 0a 31   95181._tim.....1
00a0   36 37 38 31 39 37 33 31 36 04 5f 65 78 70 01 00   678197316._exp..
00b0   00 00 0a 31 36 37 38 31 39 37 33 31 36 05 5f 64   ...1678197316._d
00c0   61 74 61 02 00 00 00 0e 04 74 79 70 65 01 00 00   ata......type...
00d0   00 04 6e 75 6c 6c                                 ..null

*/

static ya_result rndc_message_dict_begin(rndc_message_t *rndcmsg)
{
    ya_result ret;
    if(FAIL(ret = output_stream_write_u8(&rndcmsg->baos, RNDC_DICTIONARY)))
    {
        return ret;
    }

    uint32_t offset = bytearray_output_stream_size(&rndcmsg->baos);
    if(FAIL(ret = output_stream_write_u32(&rndcmsg->baos, 0)))
    {
        return ret;
    }

    return (ya_result)offset;
}

static ya_result rndc_message_dict_entry(rndc_message_t *rndcmsg, void *name, size_t len)
{
    ya_result ret;
    if(FAIL(ret = output_stream_write_u8(&rndcmsg->baos, len)))
    {
        return ret;
    }
    ret = output_stream_write(&rndcmsg->baos, name, len);
    return ret;
}

static ya_result rndc_message_dict_end(rndc_message_t *rndcmsg, uint32_t offset)
{
    ya_result ret;

    uint32_t  current = bytearray_output_stream_size(&rndcmsg->baos);
    if(offset > current)
    {
        return INVALID_STATE_ERROR;
    }
    uint32_t delta = current - offset;

    bytearray_output_stream_setposition(&rndcmsg->baos, offset);

    if(FAIL(ret = output_stream_write_nu32(&rndcmsg->baos, delta - 4))) // minus the size of the field
    {
        return ret;
    }

    bytearray_output_stream_setposition(&rndcmsg->baos, current);

    ret = delta - 4;

    return ret;
}

static ya_result rndc_message_append_string(rndc_message_t *rndcmsg, const void *text, size_t len)
{
    ya_result ret;
    if(FAIL(ret = output_stream_write_u8(&rndcmsg->baos, RNDC_PASCAL_STRING)))
    {
        return ret;
    }
    if(FAIL(ret = output_stream_write_nu32(&rndcmsg->baos, len)))
    {
        return ret;
    }
    ret = output_stream_write(&rndcmsg->baos, text, len);
    return ret;
}

static ya_result rndc_message_append_integer_string(rndc_message_t *rndcmsg, uint32_t value)
{
    ya_result ret;
    int       text_len;
    char      text[12];
    text_len = snprintf(text, sizeof(text), "%i", value);
    ret = rndc_message_append_string(rndcmsg, text, text_len);
    return ret;
}

static ya_result rndc_message_append_auth_placeholder(rndc_message_t *rndcmsg)
{
    ya_result ret;
    if(FAIL(ret = rndc_message_dict_entry(rndcmsg, "_auth", 5)))
    {
        return ret;
    }

    uint32_t auth_begin = rndc_message_dict_begin(rndcmsg);

    rndc_message_dict_entry(rndcmsg, "hsha", 4);

    rndcmsg->auth_size = 0x59; // BASE64_ENCODED_SIZE(rndcmsg->tsig_key->mac_size + 4);
    uint8_t zeroes[0x59] = {0};
    zeroes[0] = rndcmsg->tsig_key->mac_algorithm;
    rndcmsg->auth_pointer = (char *)bytearray_output_stream_buffer(&rndcmsg->baos) + bytearray_output_stream_size(&rndcmsg->baos) + 5;
    rndc_message_append_string(rndcmsg, zeroes, rndcmsg->auth_size);
    ret = rndc_message_dict_end(rndcmsg, auth_begin);
    rndcmsg->auth_message = bytearray_output_stream_buffer(&rndcmsg->baos) + bytearray_output_stream_size(&rndcmsg->baos);
    return ret;
}

/*
 * ser: serial number
 * tim: epoch
 * exp: epoch?
 * nonce: no idea
 */

static ya_result rndc_message_append_ctrl(rndc_message_t *rndcmsg)
{
    ya_result ret;
    if(FAIL(ret = rndc_message_dict_entry(rndcmsg, "_ctrl", 5)))
    {
        return ret;
    }

    uint32_t ctrl_begin = rndc_message_dict_begin(rndcmsg);

    uint32_t ser = rndcmsg->ser;
    uint32_t nonce = rndcmsg->nonce;
    int64_t  tim = rndcmsg->tim;
    int64_t  exp = rndcmsg->exp;
    int      len;

    char     tmp[20];

    rndc_message_dict_entry(rndcmsg, "_ser", 4);
    len = snprintf(tmp, sizeof(tmp), "%u", ser);
    rndc_message_append_string(rndcmsg, tmp, len);

    rndc_message_dict_entry(rndcmsg, "_tim", 4);
    len = snprintf(tmp, sizeof(tmp), "%" PRIi64, tim);
    rndc_message_append_string(rndcmsg, tmp, len);

    rndc_message_dict_entry(rndcmsg, "_exp", 4);
    len = snprintf(tmp, sizeof(tmp), "%" PRIi64, exp);
    rndc_message_append_string(rndcmsg, tmp, len);

    if(rndcmsg->state_flags & RNDC_HAS_NONCE)
    {
        rndc_message_dict_entry(rndcmsg, "_nonce", 6);
        len = snprintf(tmp, sizeof(tmp), "%u", nonce);
        rndc_message_append_string(rndcmsg, tmp, len);
    }

    ret = rndc_message_dict_end(rndcmsg, ctrl_begin);

    return ret;
}

static ya_result rndc_message_sign(rndc_message_t *rndcmsg)
{

    tsig_hmac_t hmac = tsig_hmac_allocate();

    if(FAIL(hmac_init(hmac, rndcmsg->tsig_key->mac, rndcmsg->tsig_key->mac_size, rndcmsg->tsig_key->mac_algorithm)))
    {
        hmac_free(hmac);
        return ERROR;
    }

    const uint8_t *buffer = bytearray_output_stream_buffer(&rndcmsg->baos);
    const uint8_t *begin = rndcmsg->auth_message;
    const uint8_t *end = &buffer[bytearray_output_stream_size(&rndcmsg->baos)];

    uint32_t       hmac_bin_size;

    uint8_t        hmac_bin[HMAC_BUFFER_SIZE];
    hmac_bin_size = sizeof(hmac_bin);

    hmac_update(hmac, begin, end - begin);
    hmac_final(hmac, hmac_bin, &hmac_bin_size);

    base64_encode(hmac_bin, hmac_bin_size, rndcmsg->auth_pointer + 1);

    hmac_free(hmac);

    return SUCCESS;
}

static void      rndc_message_close(rndc_message_t *rndcmsg) { SET_U32_AT_P(bytearray_output_stream_buffer(&rndcmsg->baos), ntohl(bytearray_output_stream_size(&rndcmsg->baos) - 4)); }

static ya_result rndc_message_verify(rndc_message_t *rndcmsg)
{
    tsig_hmac_t hmac = tsig_hmac_allocate();

    if(FAIL(hmac_init(hmac, rndcmsg->tsig_key->mac, rndcmsg->tsig_key->mac_size, rndcmsg->tsig_key->mac_algorithm)))
    {
        hmac_free(hmac);
        return ERROR;
    }

    uint32_t hmac_bin_size;

    uint8_t  hmac_bin[HMAC_BUFFER_SIZE];
    hmac_bin_size = sizeof(hmac_bin);

    hmac_update(hmac, rndcmsg->auth_message, rndcmsg->auth_message_size);
    hmac_final(hmac, hmac_bin, &hmac_bin_size);

    int32_t auth_size = MIN(rndcmsg->auth_size - 1, strlen(rndcmsg->auth_pointer + 1));

#if RNDC_MESSAGE_VERIFY_DEBUG
    osprint_dump(termout, rndcmsg->auth_message, rndcmsg->auth_message_size, 32, OSPRINT_DUMP_HEXTEXT);
    format("\nexpected: ");
    base64_print(hmac_bin, hmac_bin_size, termout);
    format("\nobtained: ");
    output_stream_write(termout, rndcmsg->auth_pointer + 1, auth_size);
    println("");
    flushout();
#endif

    ya_result ret = base64_equals_binary(rndcmsg->auth_pointer + 1, auth_size, hmac_bin);

#if RNDC_MESSAGE_VERIFY_DEBUG
    formatln("equals: %i", ret);
    flushout();
#endif

    hmac_free(hmac);

    return ret;
}

// gets the command in the rndc message
ya_result rndc_message_type_get(rndc_message_t *rndcmsg, const void **commandp, uint32_t *sizep)
{
    if(((intptr_t)commandp & (intptr_t)sizep) == 0)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(rndcmsg->state_flags & RNDC_HAS_VALUE)
    {
        *commandp = rndcmsg->type_value;
        *sizep = rndcmsg->type_len;
        return SUCCESS;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

// sets the command in the rndc message
ya_result rndc_message_type_set(rndc_message_t *rndcmsg, const void *type_value, uint32_t type_size)
{
    if(type_value == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(type_size == 0 || type_size > 0x10000)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    if(rndcmsg->state_flags & RNDC_HAS_VALUE)
    {
        free(rndcmsg->type_value);
    }

    if((rndcmsg->type_value = (char *)malloc(type_size + 1)) != NULL)
    {
        memcpy(rndcmsg->type_value, type_value, type_size);
        rndcmsg->type_value[type_size] = '\0';
        rndcmsg->type_len = type_size;
        rndcmsg->state_flags |= RNDC_HAS_VALUE;
        return SUCCESS;
    }
    else
    {
        rndcmsg->state_flags &= ~RNDC_HAS_VALUE;
        rndcmsg->type_len = 0;
        return ERRNO_ERROR;
    }
}

// gets the text in the rndc message
ya_result rndc_message_text_get(rndc_message_t *rndcmsg, const void **text_valuep, uint32_t *text_sizep)
{
    if(((intptr_t)text_valuep & (intptr_t)text_sizep) == 0)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(rndcmsg->state_flags & RNDC_HAS_TEXT)
    {
        *text_valuep = rndcmsg->text_value;
        *text_sizep = rndcmsg->text_len;
        return SUCCESS;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

// sets the text in the rndc message
ya_result rndc_message_text_set(rndc_message_t *rndcmsg, const void *text_value, uint32_t text_size)
{
    if(text_value == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(text_size == 0 || text_size > 0x10000)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    if(rndcmsg->state_flags & RNDC_HAS_TEXT)
    {
        free(rndcmsg->text_value);
    }

    if((rndcmsg->text_value = (char *)malloc(text_size + 1)) != NULL)
    {
        memcpy(rndcmsg->text_value, text_value, text_size);
        rndcmsg->text_value[text_size] = '\0';
        rndcmsg->text_len = text_size;
        rndcmsg->state_flags |= RNDC_HAS_TEXT;
        return SUCCESS;
    }
    else
    {
        rndcmsg->state_flags &= ~RNDC_HAS_TEXT;
        rndcmsg->text_len = 0;
        return ERRNO_ERROR;
    }
}

// gets the err in the rndc message
ya_result rndc_message_err_get(rndc_message_t *rndcmsg, const void **err_valuep, uint32_t *err_sizep)
{
    if(((intptr_t)err_valuep & (intptr_t)err_sizep) == 0)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(rndcmsg->state_flags & RNDC_HAS_ERR)
    {
        *err_valuep = rndcmsg->err_value;
        *err_sizep = rndcmsg->err_len;
        return SUCCESS;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

// sets the err in the rndc message
ya_result rndc_message_err_set(rndc_message_t *rndcmsg, const void *err_value, uint32_t err_size)
{
    if(err_value == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(err_size == 0 || err_size > 0x10000)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    if(rndcmsg->state_flags & RNDC_HAS_ERR)
    {
        free(rndcmsg->err_value);
    }

    if((rndcmsg->err_value = (char *)malloc(err_size + 1)) != NULL)
    {
        memcpy(rndcmsg->err_value, err_value, err_size);
        rndcmsg->err_value[err_size] = '\0';
        rndcmsg->err_len = err_size;
        rndcmsg->state_flags |= RNDC_HAS_ERR;
        return SUCCESS;
    }
    else
    {
        rndcmsg->state_flags &= ~RNDC_HAS_ERR;
        rndcmsg->err_len = 0;
        return ERRNO_ERROR;
    }
}

ya_result rndc_message_result_set(rndc_message_t *rndcmsg, uint32_t value)
{
    rndcmsg->result = value;
    rndcmsg->state_flags |= RNDC_HAS_RESULT;
    return SUCCESS;
}

static void rndc_message_clear_err(rndc_message_t *rndcmsg)
{
    if(rndcmsg->state_flags & RNDC_HAS_ERR)
    {
        free(rndcmsg->err_value);
        rndcmsg->err_value = NULL;
        rndcmsg->err_len = 0;
        rndcmsg->state_flags &= ~RNDC_HAS_ERR;
    }
}

static void rndc_message_clear(rndc_message_t *rndcmsg)
{
    rndcmsg->auth_pointer = NULL;
    rndcmsg->auth_size = 0;
    rndcmsg->auth_message = NULL;
    rndcmsg->auth_message_size = 0;
    rndcmsg->parse_location = 0;

    bytearray_output_stream_setposition(&rndcmsg->baos, 0);
    output_stream_write_u32(&rndcmsg->baos, 0);
    output_stream_write_nu32(&rndcmsg->baos, 1);
}

static ya_result rndc_parse_integer(const char *ptr, int size, int64_t *valuep)
{
    char buffer[16];
    size = MIN(size, (int)(sizeof(buffer) - 1));
    memcpy(buffer, ptr, size);
    buffer[size] = '\0';
    *valuep = atoll(buffer);
    return SUCCESS;
}

static ya_result rndc_parse_dict_field(rndc_message_t *rndcmsg, const uint8_t *message_buffer, size_t message_size)
{
    while(message_size > 0)
    {
#if RNDC_PARSE_DICT_FIELD_DEBUG
        formatln("rndc_parse_dict_field(%p, %p, %llu)", rndcmsg, message_buffer, message_size);
        osprint_dump(termout, message_buffer, message_size, 32, OSPRINT_DUMP_HEXTEXT);
        println("");
#endif
        // field: read length, read name, read type
        uint8_t        field_name_len = message_buffer[0];
        const char    *field_name = (char *)&message_buffer[1];
        uint8_t        field_type = message_buffer[1 + field_name_len];
        const uint8_t *field_begin = &message_buffer[6 + field_name_len];
        uint32_t       field_len = ntohl(GET_U32_AT_P(&message_buffer[2 + field_name_len]));
        const uint8_t *field_limit = field_begin + field_len;

        if(field_limit > &message_buffer[message_size])
        {
            return INVALID_PROTOCOL;
        }

        switch(field_type)
        {
            case RNDC_PASCAL_STRING:
            {
                switch(rndcmsg->parse_location)
                {
                    case RNDC_PARSE_DICT_AUTH:
                    {
                        if((field_name_len == 4) && (memcmp(field_name, "hsha", 4) == 0))
                        {
                            rndcmsg->auth_pointer = (char *)field_begin;
                            rndcmsg->auth_size = field_len;

                            if(rndc_message_verify(rndcmsg) != 0)
                            {
                                return INVALID_MESSAGE;
                            }
                        }
                        break;
                    }
                    case RNDC_PARSE_DICT_CTRL:
                    {
                        if(field_name_len == 4)
                        {
                            if(memcmp(field_name, "_ser", 4) == 0)
                            {
                            }
                            else if(memcmp(field_name, "_tim", 4) == 0)
                            {
                            }
                            else if(memcmp(field_name, "_exp", 4) == 0)
                            {
                            }
                        }
                        else if(field_name_len == 6)
                        {
                            if(memcmp(field_name, "_nonce", 6) == 0)
                            {
                                int64_t value;
                                rndc_parse_integer((const char *)field_begin, field_len, &value);
                                if(rndcmsg->state_flags & RNDC_HAS_NONCE)
                                {
                                    if(rndcmsg->nonce != (uint32_t)value)
                                    {
                                        return INVALID_MESSAGE;
                                    }
                                }
                                else
                                {
                                    rndcmsg->nonce = (uint32_t)value;
                                    rndcmsg->state_flags |= RNDC_HAS_NONCE;
                                }
                            }
                        }
                        break;
                    }
                    case RNDC_PARSE_DICT_DATA:
                    {
                        if((field_name_len == 6) && (memcmp(field_name, "result", 6) == 0))
                        {
                            int64_t value;
                            rndc_parse_integer((const char *)field_begin, field_len, &value);
                            rndcmsg->result = (uint32_t)value;
                            rndcmsg->state_flags |= RNDC_HAS_RESULT;
                        }
                        else if((field_name_len == 3) && (memcmp(field_name, "err", 3) == 0))
                        {
                            rndc_message_err_set(rndcmsg, field_begin, field_len);
                        }
                        else if((field_name_len == 4) && (memcmp(field_name, "text", 4) == 0))
                        {
                            /// @note 20230316 edf -- maybe I also should do a set text for symmetry (or only do that)
                            // rndc_message_text_set(rndcmsg, field_begin, field_len);
                            // for symmetry ...
                            output_stream_write(&rndcmsg->text_output, field_begin, field_len);
                        }
                        else if((field_name_len == 4) && (memcmp(field_name, "type", 4) == 0))
                        {
                            rndc_message_type_set(rndcmsg, field_begin, field_len);
                        }
                        break;
                    }
                }
                break;
            }
            case RNDC_DICTIONARY:
            {
                if(rndcmsg->parse_location == RNDC_PARSE_DICT_TOP)
                {
                    if(field_name_len == 5)
                    {
                        if(memcmp(field_name, "_auth", 5) == 0)
                        {
                            // parse auth
                            rndcmsg->parse_location = RNDC_PARSE_DICT_AUTH;

                            // sets what is being signed
                            rndcmsg->auth_message = field_limit;
                            rndcmsg->auth_message_size = &message_buffer[message_size] - field_limit;
                        }
                        else if(memcmp(field_name, "_ctrl", 5) == 0)
                        {
                            // parse ctrl
                            rndcmsg->parse_location = RNDC_PARSE_DICT_CTRL;
                        }
                        else if(memcmp(field_name, "_data", 5) == 0)
                        {
                            // parse data
                            rndcmsg->parse_location = RNDC_PARSE_DICT_DATA;
                        }
                        else
                        {
                            return INVALID_PROTOCOL;
                        }
                        rndc_parse_dict_field(rndcmsg, field_begin, field_len);
                        rndcmsg->parse_location = RNDC_PARSE_DICT_TOP;
                    }
                }
                else
                {
                    return INVALID_PROTOCOL;
                }
            }
        }

        message_size -= field_limit - message_buffer;
        message_buffer = field_limit;
    } // for

    return SUCCESS;
}

static ya_result rndc_message_init(rndc_message_t *rndcmsg, struct tsig_key_s *tsig_key)
{
    if(((intptr_t)rndcmsg & (intptr_t)tsig_key) == 0)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    ZEROMEMORY(rndcmsg, sizeof(rndc_message_t));

    bytearray_output_stream_init_ex(&rndcmsg->baos, NULL, 512, BYTEARRAY_DYNAMIC);
    output_stream_set_void(&rndcmsg->tcp_os);
    input_stream_set_void(&rndcmsg->tcp_is);
    rndcmsg->text_output = *(termout);
    rndcmsg->tsig_key = tsig_key;

    rndcmsg->ser = 2307895180;

    output_stream_write_u32(&rndcmsg->baos, 0);
    output_stream_write_nu32(&rndcmsg->baos, 1);
    return SUCCESS;
}

void rndc_message_finalise(rndc_message_t *rndcmsg)
{
    if(rndcmsg->state_flags & RNDC_HAS_VALUE)
    {
        free(rndcmsg->type_value);
        rndcmsg->type_value = NULL;
        rndcmsg->type_len = 0;
        rndcmsg->state_flags &= ~RNDC_HAS_VALUE;
    }
    if(rndcmsg->state_flags & RNDC_HAS_ERR)
    {
        free(rndcmsg->err_value);
        rndcmsg->err_value = NULL;
        rndcmsg->err_len = 0;
        rndcmsg->state_flags &= ~RNDC_HAS_ERR;
    }
    if(rndcmsg->state_flags & RNDC_HAS_TEXT)
    {
        free(rndcmsg->text_value);
        rndcmsg->text_value = NULL;
        rndcmsg->text_len = 0;
        rndcmsg->state_flags &= ~RNDC_HAS_TEXT;
    }
    output_stream_close(&rndcmsg->baos);
    output_stream_set_void(&rndcmsg->baos);
    if(rndcmsg->state_flags & RNDC_CONNECTED)
    {
        output_stream_close(&rndcmsg->tcp_os);
        input_stream_close(&rndcmsg->tcp_is);

        rndcmsg->state_flags &= ~RNDC_CONNECTED;
    }
}

static uint32_t rndc_message_begin(rndc_message_t *rndcmsg)
{
    // put the auth
    rndc_message_append_auth_placeholder(rndcmsg);

    // setup the tim & exp fields
    time_t epoch = time(NULL);
    rndcmsg->tim = epoch;
    rndcmsg->exp = epoch;

    rndc_message_append_ctrl(rndcmsg);

    // begin the handshake

    rndc_message_dict_entry(rndcmsg, "_data", 5);
    uint32_t data_begin = rndc_message_dict_begin(rndcmsg);
    return data_begin;
}

static void rndc_message_end(rndc_message_t *rndcmsg, uint32_t data_begin)
{
    rndc_message_dict_end(rndcmsg, data_begin);
    rndc_message_close(rndcmsg);
}

static ya_result rndc_message_send(rndc_message_t *rndcmsg)
{
    ya_result ret;
    ret = output_stream_write(&rndcmsg->tcp_os, bytearray_output_stream_buffer(&rndcmsg->baos), bytearray_output_stream_size(&rndcmsg->baos));
    return ret;
}

static ya_result rndc_message_recv(rndc_message_t *rndcmsg)
{
    // receive a message (handshake end)

    ya_result ret;

    uint32_t  rndc_message_length = 0;
    uint8_t  *rndc_buffer;
    uint8_t   _rndc_buffer[1024];

    if(FAIL(ret = input_stream_read_nu32(&rndcmsg->tcp_is, &rndc_message_length)))
    {
        return ret;
    }

    if((rndc_message_length > 0x10000) || (rndc_message_length <= 20)) //  an arbitrary limit on the message size
    {
        return BUFFER_WOULD_OVERFLOW; // don't want to
    }

    if(rndc_message_length < sizeof(_rndc_buffer))
    {
        rndc_buffer = &_rndc_buffer[0];
    }
    else
    {
        rndc_buffer = (uint8_t *)malloc(rndc_message_length);
    }

    ret = input_stream_read_fully(&rndcmsg->tcp_is, rndc_buffer, rndc_message_length);

#if RNDC_MESSAGE_RECV_DEBUG
#endif

    if(FAIL(ret)) // couldn't read the message
    {
        return BUFFER_WOULD_OVERFLOW; // don't want to
    }

#if RNDC_MESSAGE_RECV_DEBUG
    osprint_dump(termout, rndc_buffer, rndc_answer_length, 32, OSPRINT_DUMP_HEXTEXT);
#endif

    // this parses the field AND checks the handshake

    if(FAIL(ret = rndc_parse_dict_field(rndcmsg, rndc_buffer + 4, rndc_message_length - 4)))
    {
        return ret;
    }

    if(rndc_buffer != &_rndc_buffer[0])
    {
        free(rndc_buffer);
    }

    return ret;
}

ya_result rndc_recv_process(rndc_message_t *rndcmsg, rndc_recv_process_callback *process_callback, void *args)
{
    ya_result ret;

    rndcmsg->state_flags &= ~RNDC_HAS_QUERY;

    if(FAIL(ret = rndc_message_recv(rndcmsg)))
    {
        rndc_message_clear(rndcmsg);
        return ret;
    }

    // parse the query (it may be "none" for the handshake)
    // execute the query
    // answer the query:
    // _ add the nonce field if it's not set yet
    // _ convert the output as text
    // _ reply

    process_callback(rndcmsg, args);

    rndc_message_clear(rndcmsg);

    // all the common message begin (no serial increase)

    uint32_t data_begin = rndc_message_begin(rndcmsg);

    // we are in "_data" and we need to add fields

    // rndcmsg->result
    rndc_message_dict_entry(rndcmsg, "result", 6);
    rndc_message_append_integer_string(rndcmsg, rndcmsg->result);

    if(rndcmsg->state_flags & RNDC_HAS_VALUE)
    {
        rndc_message_dict_entry(rndcmsg, "type", 4);
        rndc_message_append_string(rndcmsg, rndcmsg->type_value, rndcmsg->type_len);
    }
    if(rndcmsg->state_flags & RNDC_HAS_ERR)
    {
        rndc_message_dict_entry(rndcmsg, "err", 4);
        rndc_message_append_string(rndcmsg, rndcmsg->err_value, rndcmsg->err_len);
    }
    if(rndcmsg->state_flags & RNDC_HAS_TEXT)
    {
        rndc_message_dict_entry(rndcmsg, "text", 4);
        rndc_message_append_string(rndcmsg, rndcmsg->text_value, rndcmsg->text_len);
    }

    // close the message

    rndc_message_end(rndcmsg, data_begin);

    // sign it

    rndc_message_sign(rndcmsg);

    rndc_message_clear_err(rndcmsg);

    // send begin handshake message

    if(FAIL(ret = rndc_message_send(rndcmsg)))
    {
        rndc_message_clear(rndcmsg);
        return ret;
    }

    // cleanup intermediary data

    rndc_message_clear(rndcmsg);

    return ret;
}

ya_result rndc_send(rndc_message_t *rndcmsg, const void *command, size_t command_size)
{
    ya_result ret;

    // increases serial number
    ++rndcmsg->ser;
    rndcmsg->state_flags &= ~RNDC_HAS_RESULT;

    // all the common message begin (no serial increase)

    uint32_t data_begin = rndc_message_begin(rndcmsg);

    // we are in "_data" and we need to add fields

    rndc_message_dict_entry(rndcmsg, "type", 4);
    rndc_message_append_string(rndcmsg, command, command_size);

    // close the message

    rndc_message_end(rndcmsg, data_begin);

    // sign it

    rndc_message_sign(rndcmsg);

    // send begin handshake message

    if(FAIL(ret = rndc_message_send(rndcmsg)))
    {
        rndc_message_clear(rndcmsg);
        return ret;
    }

    // cleanup intermediary data

    rndc_message_clear(rndcmsg);

    rndc_message_clear_err(rndcmsg);

    if(FAIL(ret = rndc_message_recv(rndcmsg)))
    {
        rndc_message_clear(rndcmsg);
        return ret;
    }

    rndc_message_clear(rndcmsg);

    return ret;
}

ya_result rndc_send_command(rndc_message_t *rndcmsg, const char *command)
{
    ya_result ret;
    ret = rndc_send(rndcmsg, command, strlen(command));
    return ret;
}

ya_result rndc_init_and_connect(rndc_message_t *rndcmsg, const host_address_t *ha, struct tsig_key_s *tsig_key)
{
    if(((intptr_t)rndcmsg & (intptr_t)ha & (intptr_t)tsig_key) == 0)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    ya_result ret;

    // build message

    rndc_message_init(rndcmsg, tsig_key); // can only fail if one of the argument is NULL

    // connect

    if(FAIL(ret = tcp_input_output_stream_connect_host_address(ha, &rndcmsg->tcp_is, &rndcmsg->tcp_os, 3)))
    {
        formatln("connect: %{hostaddr} failed with %r", ha, ret);
        return ret;
    }

    rndcmsg->state_flags |= RNDC_CONNECTED;

    if(FAIL(ret = rndc_send(rndcmsg, "null", 4)))
    {
        rndc_message_finalise(rndcmsg);
        return ret;
    }

    // handshake is done
    rndcmsg->state_flags |= RNDC_HANDSHAKED;

    return ret;
}

ya_result rndc_init_and_recv_from_socket(rndc_message_t *rndcmsg, int sockfd, struct tsig_key_s *tsig_key)
{
    if(((intptr_t)rndcmsg & (intptr_t)tsig_key) == 0)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    ya_result ret;

    // build message

    if(ISOK(ret = rndc_message_init(rndcmsg, tsig_key))) // can only fail if one of the argument is NULL
    {
        fd_input_stream_attach(&rndcmsg->tcp_is, sockfd);
        fd_output_stream_attach_noclose(&rndcmsg->tcp_os, sockfd);

        rndcmsg->state_flags |= RNDC_CONNECTED;

        if(ISOK(ret = rndc_message_recv(rndcmsg)))
        {
            rndc_message_clear(rndcmsg);

            rndcmsg->nonce = rand();
            rndcmsg->state_flags |= RNDC_HAS_NONCE;

            uint32_t data_begin = rndc_message_begin(rndcmsg);

            // we are in "_data" and we need to add fields

            rndc_message_dict_entry(rndcmsg, "type", 4);
            rndc_message_append_string(rndcmsg, "null", 4);
            rndc_message_dict_entry(rndcmsg, "result", 6);
            rndc_message_append_integer_string(rndcmsg, rndcmsg->result);

            // close the message

            rndc_message_end(rndcmsg, data_begin);

            // sign it

            rndc_message_sign(rndcmsg);

            // send begin handshake message

            if(FAIL(ret = rndc_message_send(rndcmsg)))
            {
                rndc_message_clear(rndcmsg);
                return ret;
            }

            // cleanup intermediary data

            rndc_message_clear(rndcmsg);
        }
    }

    return ret;
}

void      rndc_disconnect(rndc_message_t *rndcmsg) { rndc_message_finalise(rndcmsg); }

ya_result rndc_result(rndc_message_t *rndcmsg, uint32_t *resultp)
{
    if(resultp != NULL)
    {
        if(rndcmsg->state_flags & RNDC_HAS_RESULT)
        {
            *resultp = rndcmsg->result;
            return SUCCESS;
        }
        else
        {
            return INVALID_STATE_ERROR;
        }
    }
    else
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
}
/*
#define NAMED_ERROR_SUCCESS        0
#define NAMED_ERROR_NOMEMORY       1
#define NAMED_ERROR_NOPERM         6
#define NAMED_ERROR_NOSPACE        19
#define NAMED_ERROR_NOTFOUND       23
#define NAMED_ERROR_FAILURE        25
#define NAMED_ERROR_NOTIMPLEMENTED 27
#define NAMED_ERROR_NOMORE         29
#define NAMED_ERROR_INVALIDFILE    30
#define NAMED_ERROR_UNEXPECTED     34
#define NAMED_ERROR_FILENOTFOUND   38
*/
uint32_t yadifa_error_to_named_error(ya_result code)
{
    if(ISOK(code))
    {
        return NAMED_ERROR_SUCCESS;
    }
    else
    {
        switch(code)
        {
            case FEATURE_NOT_IMPLEMENTED_ERROR:
                return NAMED_ERROR_NOTIMPLEMENTED;
            case UNKNOWN_NAME:
                return NAMED_ERROR_NOTFOUND;
            default:
                return NAMED_ERROR_FAILURE;
        }
    }
}
