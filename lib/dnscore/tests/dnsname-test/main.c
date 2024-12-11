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
#include <dnscore/dnsname.h>

static bool          is_dnsname_char[256];
static bool          is_rname_char[256];
static const uint8_t label_empty[1] = {0};
static const uint8_t label_empty_bis[1] = {0};
static const uint8_t label_www[4] = {3, 'w', 'w', 'w'};
static const uint8_t label_yadifa[7] = {6, 'y', 'a', 'd', 'i', 'f', 'a'};
static const uint8_t label_eu[3] = {2, 'e', 'u'};
static const uint8_t label_yadifa_uppercase[7] = {6, 'Y', 'a', 'D', 'i', 'F', 'A'};
static const uint8_t label_padifa[7] = {6, 'p', 'a', 'd', 'i', 'f', 'a'};
static const uint8_t label_eurid[6] = {5, 'e', 'u', 'r', 'i', 'd'};
static const uint8_t label_wrongcharset[] = {4, 'b', 'a', 'd', 255};
static const uint8_t fqdn_www_yadifa_eu[] = {3, 'w', 'w', 'w', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t fqdn_www_yadifa_eu_uppercase[] = {3, 'w', 'W', 'w', 6, 'Y', 'A', 'd', 'I', 'f', 'A', 2, 'e', 'U', 0};
static const uint8_t fqdn_www_padifa_eu[] = {3, 'w', 'w', 'w', 6, 'p', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
// static const uint8_t fqdn_www_eurid_eu[] = {3 ,'w','w','w', 5, 'e','u','r','i','d', 2, 'e','u', 0};
static const uint8_t     fqdn_www_wrongcharset_eu[] = {3, 'w', 'w', 'w', 4, 'b', 'a', 'd', 255, 2, 'e', 'u', 0};
static const uint8_t     fqdn_label_too_long[] = {64,  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                                                  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 0};

static const uint8_t     fqdn_domain_too_long[256] = {1, 'A', 1, 'B', 1, 'C', 1, 'D', 1, 'E', 1, 'F', 1, 'G', 1, 'H', 1, 'I', 1, 'J', 1, 'K', 1, 'L', 1, 'M', 1, 'N', 1, 'O', 1, 'P', 1, 'Q', 1,   'R', 1, 'S', 1, 'T', 1, 'U', 1, 'V',
                                                      1, 'W', 1, 'X', 1, 'Y', 1, 'Z', 1, 'a', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 1, 'j', 1, 'k', 1, 'l', 1, 'm', 1,   'n', 1, 'o', 1, 'p', 1, 'q', 1, 'r',
                                                      1, 's', 1, 't', 1, 'u', 1, 'v', 1, 'w', 1, 'x', 1, 'y', 1, 'z', 1, '0', 1, '1', 1, '2', 1, '3', 1, '4', 1, '5', 1, '6', 1, '7', 1, '8', 1,   '9', 1, 'A', 1, 'B', 1, 'C', 1, 'D',
                                                      1, 'E', 1, 'F', 1, 'G', 1, 'H', 1, 'I', 1, 'J', 1, 'K', 1, 'L', 1, 'M', 1, 'N', 1, 'O', 1, 'P', 1, 'Q', 1, 'R', 1, 'S', 1, 'T', 1, 'U', 1,   'V', 1, 'W', 1, 'X', 1, 'Y', 1, 'Z',
                                                      1, 'a', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 1, 'j', 1, 'k', 1, 'l', 1, 'm', 1, 'n', 1, 'o', 1, 'p', 1, 'q', 1,   'r', 1, 's', 1, 't', 1, 'u', 1, 'v',
                                                      1, 'w', 1, 'x', 1, 'y', 1, 'z', 1, '0', 1, '1', 1, '2', 1, '3', 1, '4', 1, '5', 1, '6', 1, '7', 1, '8', 1, '9', 1, 'A', 1, 'B', 2, 'C', 'x', 0};

static const uint8_t     fqdn_127size1labels_mixedcase[255] = {1, 'A', 1, 'B', 1, 'C', 1, 'D', 1, 'E', 1, 'F', 1, 'G', 1, 'H', 1, 'I', 1, 'J', 1, 'K', 1, 'L', 1, 'M', 1, 'N', 1, 'O', 1, 'P', 1, 'Q', 1, 'R', 1, 'S', 1, 'T', 1, 'U', 1, 'V',
                                                               1, 'W', 1, 'X', 1, 'Y', 1, 'Z', 1, 'a', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 1, 'j', 1, 'k', 1, 'l', 1, 'm', 1, 'n', 1, 'o', 1, 'p', 1, 'q', 1, 'r',
                                                               1, 's', 1, 't', 1, 'u', 1, 'v', 1, 'w', 1, 'x', 1, 'y', 1, 'z', 1, '0', 1, '1', 1, '2', 1, '3', 1, '4', 1, '5', 1, '6', 1, '7', 1, '8', 1, '9', 1, 'A', 1, 'B', 1, 'C', 1, 'D',
                                                               1, 'E', 1, 'F', 1, 'G', 1, 'H', 1, 'I', 1, 'J', 1, 'K', 1, 'L', 1, 'M', 1, 'N', 1, 'O', 1, 'P', 1, 'Q', 1, 'R', 1, 'S', 1, 'T', 1, 'U', 1, 'V', 1, 'W', 1, 'X', 1, 'Y', 1, 'Z',
                                                               1, 'a', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 1, 'j', 1, 'k', 1, 'l', 1, 'm', 1, 'n', 1, 'o', 1, 'p', 1, 'q', 1, 'r', 1, 's', 1, 't', 1, 'u', 1, 'v',
                                                               1, 'w', 1, 'x', 1, 'y', 1, 'z', 1, '0', 1, '1', 1, '2', 1, '3', 1, '4', 1, '5', 1, '6', 1, '7', 1, '8', 1, '9', 1, 'A', 1, 'B', 1, 'C', 0};

static const uint8_t     fqdn_127size1labels[255] = {1, 'a', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 1, 'j', 1, 'k', 1, 'l', 1, 'm', 1, 'n', 1, 'o', 1, 'p', 1, 'q', 1, 'r', 1, 's', 1, 't', 1, 'u', 1, 'v',
                                                     1, 'w', 1, 'x', 1, 'y', 1, 'z', 1, 'a', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 1, 'j', 1, 'k', 1, 'l', 1, 'm', 1, 'n', 1, 'o', 1, 'p', 1, 'q', 1, 'r',
                                                     1, 's', 1, 't', 1, 'u', 1, 'v', 1, 'w', 1, 'x', 1, 'y', 1, 'z', 1, '0', 1, '1', 1, '2', 1, '3', 1, '4', 1, '5', 1, '6', 1, '7', 1, '8', 1, '9', 1, 'a', 1, 'b', 1, 'c', 1, 'd',
                                                     1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 1, 'j', 1, 'k', 1, 'l', 1, 'm', 1, 'n', 1, 'o', 1, 'p', 1, 'q', 1, 'r', 1, 's', 1, 't', 1, 'u', 1, 'v', 1, 'w', 1, 'x', 1, 'y', 1, 'z',
                                                     1, 'a', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 1, 'j', 1, 'k', 1, 'l', 1, 'm', 1, 'n', 1, 'o', 1, 'p', 1, 'q', 1, 'r', 1, 's', 1, 't', 1, 'u', 1, 'v',
                                                     1, 'w', 1, 'x', 1, 'y', 1, 'z', 1, '0', 1, '1', 1, '2', 1, '3', 1, '4', 1, '5', 1, '6', 1, '7', 1, '8', 1, '9', 1, 'a', 1, 'b', 1, 'c', 0};

static const uint8_t     fqdn_3size63_labels[] = {63,  'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                                  'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 63,  'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                                  'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                                  'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 63,  'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                                  'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                                  'c', 'c', 'c', 'c', 'c', 'c', 'c', 61,  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                                                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 0};

static const uint8_t     fqdn_4labels_eu_labels[] = {63,  'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                                     'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 63,  'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                                     'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                                     'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 63,  'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                                     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                                     'c', 'c', 'c', 'c', 'c', 'c', 'c', 58,  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                                                     'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 2,   'e', 'u', 0};

static const char *const text_127size1labels =
    "A.B.C.D.E.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z."
    "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z."
    "0.1.2.3.4.5.6.7.8.9."
    "A.B.C.D.E.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z."
    "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z."
    "0.1.2.3.4.5.6.7.8.9.A.B.C";

static const char *const text_127size1labels_dot =
    "A.B.C.D.E.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z."
    "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z."
    "0.1.2.3.4.5.6.7.8.9."
    "A.B.C.D.E.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z."
    "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z."
    "0.1.2.3.4.5.6.7.8.9.A.B.C";

static const char *const text_3size63labels =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

static const char *const text_4size63labels =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

static const char *const text_lastlabeltoolong =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

static const char *const text_3size63labels_dot =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." //   1 + 63     = 64
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb." // + 1 + 63     = 128
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc." // + 1 + 63     = 192
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.";  // + 1 + 61 + 1 = 255

static const char *const text_hardtoreach_dot =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." //   1 + 63     = 64
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb." // + 1 + 63     = 128
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc." // + 1 + 63     = 192
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.e."; // + 1 + 60 + 1 + 1 + 1 = 256

static const char *const text_4labels_eu =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

static const char *const text_4labels_eu_too_long =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

static const char *const text_labeltoolong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";

static const char *const text_domaintoolong =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

static const char *const text_domaintoolong2 =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd."
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.";

static const char *const text_www_yadifa_eu = "www.yadifa.eu";
static const char *const text_www_yadifa_eu_dot = "www.yadifa.eu.";
static const char *const text_www_yadifa = "www.yadifa";

static const char *const text_double_dot_fqdn = "new..key4";
// static const uint8_t fqdn_double_dot[] = {3, 'n', 'e', 'w', 0};

static const char *const      text_double_dot = "..";
static const char *const      text_fqdn_double_dot = "fqdn..";

static const char *const      text_dot = ".";
static const uint8_t          fqdn_root[] = {0};
static const uint8_t          fqdn_eu[] = {2, 'e', 'u', 0};

static const char *const      text_stars = "**.*.***.";
static const uint8_t          fqdn_stars[] = {2, '*', '*', 1, '*', 3, '*', '*', '*', 0};
static const char *const      text_fqdn_star = "fqdn.*";
static const uint8_t          fqdn_fqdn_star[] = {4, 'f', 'q', 'd', 'n', 1, '*', 0};
static const char *const      text_star = "*";
static const char *const      text_star_dot = "*.";
static const uint8_t          fqdn_star[] = {1, '*', 0};
static const char *const      text_empty = "";

static const char *const      text_endswithescape = "ends.with.escape\\";
static const char *const      text_admin_yadifa_eu = "admin\\@yadifa.eu";
static const uint8_t          fqdn_adminATyadifa_eu[] = {12, 'a', 'd', 'm', 'i', 'n', '@', 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};

static const uint8_t         *label_vector_www_yadifa_eu[3] = {label_www, label_yadifa, label_eu};
static const int              label_vector_www_yadifa_eu_top = 2;
static const uint8_t         *label_stack_www_yadifa_eu[3] = {label_eu, label_yadifa, label_www};
static const int              label_stack_www_yadifa_eu_top = 2;

static const dnsname_vector_t dnsname_vector_www_yadifa_eu = {2, {label_www, label_yadifa, label_eu}};

static const dnsname_stack_t  dnsname_stack_www_yadifa_eu = {2, {label_eu, label_yadifa, label_www}};

struct fqdn_text_conversion_table_s
{
    const uint8_t    *fqdn;
    size_t            fqdn_size;
    const char *const text;
    int               error_code;
};

struct fqdn_text_origin_conversion_table_s
{
    const uint8_t    *fqdn;
    size_t            fqdn_size;
    const char *const text;
    const uint8_t    *origin;
    int               error_code;
};

static struct fqdn_text_conversion_table_s fqdn_text_conversion_table[] = {{fqdn_root, sizeof(fqdn_root), text_dot, 0},
                                                                           {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, 0},
                                                                           {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, 0},
                                                                           {fqdn_127size1labels, sizeof(fqdn_127size1labels), text_127size1labels, 0},
                                                                           {fqdn_127size1labels, sizeof(fqdn_127size1labels), text_127size1labels_dot, 0},
                                                                           {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, 0},
                                                                           {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, 0},
                                                                           {NULL, 0, text_4size63labels, DOMAIN_TOO_LONG},
                                                                           {NULL, 0, text_lastlabeltoolong, LABEL_TOO_LONG},
                                                                           {fqdn_stars, sizeof(fqdn_stars), text_stars, 0},
                                                                           {fqdn_fqdn_star, sizeof(fqdn_fqdn_star), text_fqdn_star, 0},
                                                                           {fqdn_star, sizeof(fqdn_star), text_star, 0},
                                                                           {fqdn_star, sizeof(fqdn_star), text_star_dot, 0},
                                                                           {NULL, 0, text_labeltoolong, LABEL_TOO_LONG},
                                                                           {NULL, 0, text_domaintoolong, DOMAIN_TOO_LONG},
                                                                           {NULL, 0, text_domaintoolong2, DOMAIN_TOO_LONG},
                                                                           {NULL, 0, text_double_dot_fqdn, DOMAINNAME_INVALID},
                                                                           {NULL, 0, text_double_dot, DOMAINNAME_INVALID},
                                                                           {NULL, 0, text_fqdn_double_dot, DOMAINNAME_INVALID},
                                                                           {NULL, 0, text_empty, DOMAINNAME_INVALID},
                                                                           {NULL, 0, NULL, 0}};

static struct fqdn_text_conversion_table_s fqdn_text_conversion_rname_table[] = {{NULL, 0, text_endswithescape, DOMAINNAME_INVALID},
                                                                                 {fqdn_adminATyadifa_eu, sizeof(fqdn_adminATyadifa_eu), text_admin_yadifa_eu, 0},
                                                                                 {fqdn_root, sizeof(fqdn_root), text_dot, 0},
                                                                                 {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, 0},
                                                                                 {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, 0},
                                                                                 {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels, 0},
                                                                                 {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels_dot, 0},
                                                                                 {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, 0},
                                                                                 {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, 0},
                                                                                 {NULL, 0, text_4size63labels, DOMAIN_TOO_LONG},
                                                                                 {NULL, 0, text_lastlabeltoolong, LABEL_TOO_LONG},
                                                                                 {NULL, 0, text_stars, INVALID_CHARSET},
                                                                                 {NULL, 0, text_fqdn_star, INVALID_CHARSET},
                                                                                 {NULL, 0, text_star, INVALID_CHARSET},
                                                                                 {NULL, 0, text_star_dot, INVALID_CHARSET},
                                                                                 {NULL, 0, text_labeltoolong, LABEL_TOO_LONG},
                                                                                 {NULL, 0, text_domaintoolong, DOMAIN_TOO_LONG},
                                                                                 {NULL, 0, text_domaintoolong2, DOMAIN_TOO_LONG},
                                                                                 {NULL, 0, text_double_dot_fqdn, DOMAINNAME_INVALID},
                                                                                 {NULL, 0, text_double_dot, DOMAINNAME_INVALID},
                                                                                 {NULL, 0, text_fqdn_double_dot, DOMAINNAME_INVALID},
                                                                                 {NULL, 0, text_empty, DOMAINNAME_INVALID},
                                                                                 {NULL, 0, NULL, 0}};

static struct fqdn_text_conversion_table_s fqdn_text_conversion_mixedcase_table[] = {{fqdn_root, sizeof(fqdn_root), text_dot, 0},
                                                                                     {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, 0},
                                                                                     {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, 0},
                                                                                     {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels, 0},
                                                                                     {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels_dot, 0},
                                                                                     {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, 0},
                                                                                     {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, 0},
                                                                                     {NULL, 0, text_4size63labels, DOMAIN_TOO_LONG},
                                                                                     {NULL, 0, text_lastlabeltoolong, LABEL_TOO_LONG},
                                                                                     {fqdn_stars, sizeof(fqdn_stars), text_stars, 0},
                                                                                     {fqdn_fqdn_star, sizeof(fqdn_fqdn_star), text_fqdn_star, 0},
                                                                                     {fqdn_star, sizeof(fqdn_star), text_star, 0},
                                                                                     {fqdn_star, sizeof(fqdn_star), text_star_dot, 0},
                                                                                     {NULL, 0, text_labeltoolong, LABEL_TOO_LONG},
                                                                                     {NULL, 0, text_domaintoolong, DOMAIN_TOO_LONG},
                                                                                     {NULL, 0, text_domaintoolong2, DOMAIN_TOO_LONG},
                                                                                     {NULL, 0, text_double_dot_fqdn, DOMAINNAME_INVALID},
                                                                                     {NULL, 0, text_double_dot, DOMAINNAME_INVALID},
                                                                                     {NULL, 0, text_fqdn_double_dot, DOMAINNAME_INVALID},
                                                                                     {NULL, 0, text_empty, DOMAINNAME_INVALID},
                                                                                     {NULL, 0, NULL, 0}};

#if UNUSED
static struct fqdn_text_conversion_table_s fqdn_text_conversion_strict_table[] = {{fqdn_root, sizeof(fqdn_root), text_dot, 0},
                                                                                  {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, 0},
                                                                                  {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, 0},
                                                                                  {fqdn_127size1labels, sizeof(fqdn_127size1labels), text_127size1labels, 0},
                                                                                  {fqdn_127size1labels, sizeof(fqdn_127size1labels), text_127size1labels_dot, 0},
                                                                                  {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, 0},
                                                                                  {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, 0},
                                                                                  {NULL, 0, text_4size63labels, DOMAIN_TOO_LONG},
                                                                                  {NULL, 0, text_lastlabeltoolong, LABEL_TOO_LONG},
                                                                                  {NULL, 0, text_stars, DOMAINNAME_INVALID},
                                                                                  {NULL, 0, text_fqdn_star, INVALID_CHARSET},
                                                                                  {fqdn_star, sizeof(fqdn_star), text_star, 0},
                                                                                  {fqdn_star, sizeof(fqdn_star), text_star_dot, 0},
                                                                                  {NULL, 0, text_labeltoolong, LABEL_TOO_LONG},
                                                                                  {NULL, 0, text_domaintoolong, DOMAIN_TOO_LONG},
                                                                                  {NULL, 0, text_domaintoolong2, DOMAIN_TOO_LONG},
                                                                                  {NULL, 0, text_double_dot_fqdn, DOMAINNAME_INVALID},
                                                                                  {NULL, 0, text_double_dot, DOMAINNAME_INVALID},
                                                                                  {NULL, 0, text_fqdn_double_dot, DOMAINNAME_INVALID},
                                                                                  {NULL, 0, text_empty, DOMAINNAME_INVALID},
                                                                                  {NULL, 0, NULL, 0}};
#endif

static struct fqdn_text_conversion_table_s        fqdn_text_conversion_mixedcase_strict_table[] = {{fqdn_root, sizeof(fqdn_root), text_dot, 0},
                                                                                                   {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, 0},
                                                                                                   {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, 0},
                                                                                                   {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels, 0},
                                                                                                   {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels_dot, 0},
                                                                                                   {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, 0},
                                                                                                   {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, 0},
                                                                                                   {NULL, 0, text_4size63labels, DOMAIN_TOO_LONG},
                                                                                                   {NULL, 0, text_lastlabeltoolong, LABEL_TOO_LONG},
                                                                                                   {NULL, 0, text_stars, DOMAINNAME_INVALID},
                                                                                                   {NULL, 0, text_fqdn_star, INVALID_CHARSET},
                                                                                                   {fqdn_star, sizeof(fqdn_star), text_star, 0},
                                                                                                   {fqdn_star, sizeof(fqdn_star), text_star_dot, 0},
                                                                                                   {NULL, 0, text_labeltoolong, LABEL_TOO_LONG},
                                                                                                   {NULL, 0, text_domaintoolong, DOMAIN_TOO_LONG},
                                                                                                   {NULL, 0, text_domaintoolong2, DOMAIN_TOO_LONG},
                                                                                                   {NULL, 0, text_double_dot_fqdn, DOMAINNAME_INVALID},
                                                                                                   {NULL, 0, text_double_dot, DOMAINNAME_INVALID},
                                                                                                   {NULL, 0, text_fqdn_double_dot, DOMAINNAME_INVALID},
                                                                                                   {NULL, 0, text_empty, DOMAINNAME_INVALID},
                                                                                                   {NULL, 0, NULL, 0}};

static struct fqdn_text_conversion_table_s        fqdn_text_conversion_mixedcase_strict_nostar_table[] = {{fqdn_root, sizeof(fqdn_root), text_dot, 0},
                                                                                                          {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, 0},
                                                                                                          {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, 0},
                                                                                                          {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels, 0},
                                                                                                          {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels_dot, 0},
                                                                                                          {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, 0},
                                                                                                          {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, 0},
                                                                                                          {NULL, 0, text_4size63labels, DOMAIN_TOO_LONG},
                                                                                                          {NULL, 0, text_lastlabeltoolong, LABEL_TOO_LONG},
                                                                                                          {NULL, 0, text_stars, INVALID_CHARSET},
                                                                                                          {NULL, 0, text_fqdn_star, INVALID_CHARSET},
                                                                                                          {NULL, 0, text_star, INVALID_CHARSET},
                                                                                                          {NULL, 0, text_star_dot, INVALID_CHARSET},
                                                                                                          {NULL, 0, text_labeltoolong, LABEL_TOO_LONG},
                                                                                                          {NULL, 0, text_domaintoolong, DOMAIN_TOO_LONG},
                                                                                                          {NULL, 0, text_domaintoolong2, DOMAIN_TOO_LONG},
                                                                                                          {NULL, 0, text_double_dot_fqdn, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, text_double_dot, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, text_fqdn_double_dot, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, text_empty, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, NULL, 0}};

static struct fqdn_text_conversion_table_s        fqdn_text_conversion_strict_nostar_table[] = {{fqdn_root, sizeof(fqdn_root), text_dot, 0},
                                                                                                {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, 0},
                                                                                                {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, 0},
                                                                                                {fqdn_127size1labels, sizeof(fqdn_127size1labels), text_127size1labels, 0},
                                                                                                {fqdn_127size1labels, sizeof(fqdn_127size1labels), text_127size1labels_dot, 0},
                                                                                                {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, 0},
                                                                                                {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, 0},
                                                                                                {NULL, 0, text_4size63labels, DOMAIN_TOO_LONG},
                                                                                                {NULL, 0, text_lastlabeltoolong, LABEL_TOO_LONG},
                                                                                                {NULL, 0, text_stars, INVALID_CHARSET},
                                                                                                {NULL, 0, text_fqdn_star, INVALID_CHARSET},
                                                                                                {NULL, 0, text_star, INVALID_CHARSET},
                                                                                                {NULL, 0, text_star_dot, INVALID_CHARSET},
                                                                                                {NULL, 0, text_labeltoolong, LABEL_TOO_LONG},
                                                                                                {NULL, 0, text_domaintoolong, DOMAIN_TOO_LONG},
                                                                                                {NULL, 0, text_domaintoolong2, DOMAIN_TOO_LONG},
                                                                                                {NULL, 0, text_double_dot_fqdn, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, text_double_dot, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, text_fqdn_double_dot, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, text_empty, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, NULL, 0}};

static struct fqdn_text_origin_conversion_table_s fqdn_text_origin_conversion_mixedcase_strict_table[] = {{NULL, 0, text_hardtoreach_dot, fqdn_root, DOMAIN_TOO_LONG},
                                                                                                          {fqdn_root, sizeof(fqdn_root), text_dot, fqdn_root, 0},
                                                                                                          {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, fqdn_root, 0},
                                                                                                          {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, fqdn_root, 0},
                                                                                                          {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels, fqdn_root, 0},
                                                                                                          {fqdn_127size1labels_mixedcase, sizeof(fqdn_127size1labels_mixedcase), text_127size1labels_dot, fqdn_root, 0},
                                                                                                          {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, fqdn_root, 0},
                                                                                                          {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, fqdn_root, 0},
                                                                                                          {NULL, 0, text_4size63labels, fqdn_root, DOMAIN_TOO_LONG},
                                                                                                          {NULL, 0, text_lastlabeltoolong, fqdn_root, LABEL_TOO_LONG},

                                                                                                          {NULL, 0, text_star, fqdn_4labels_eu_labels, DOMAIN_TOO_LONG},

                                                                                                          {fqdn_root, sizeof(fqdn_root), text_dot, fqdn_eu, 0},
                                                                                                          {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa, fqdn_eu, 0},
                                                                                                          {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, fqdn_eu, 0},
                                                                                                          {fqdn_4labels_eu_labels, sizeof(fqdn_4labels_eu_labels), text_4labels_eu, fqdn_eu, 0},
                                                                                                          {NULL, 0, text_4labels_eu_too_long, fqdn_eu, DOMAIN_TOO_LONG},

                                                                                                          {NULL, 0, text_stars, fqdn_root, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, text_fqdn_star, fqdn_root, INVALID_CHARSET},
                                                                                                          {fqdn_star, sizeof(fqdn_star), text_star, fqdn_root, 0},
                                                                                                          {fqdn_star, sizeof(fqdn_star), text_star_dot, fqdn_root, 0},
                                                                                                          {NULL, 0, text_labeltoolong, fqdn_root, LABEL_TOO_LONG},
                                                                                                          {NULL, 0, text_domaintoolong, fqdn_root, DOMAIN_TOO_LONG},
                                                                                                          {NULL, 0, text_domaintoolong2, fqdn_root, DOMAIN_TOO_LONG},
                                                                                                          {NULL, 0, text_double_dot_fqdn, fqdn_root, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, text_double_dot, fqdn_root, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, text_fqdn_double_dot, fqdn_root, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, text_empty, fqdn_root, DOMAINNAME_INVALID},
                                                                                                          {NULL, 0, NULL, NULL, 0}};

static struct fqdn_text_origin_conversion_table_s fqdn_text_origin_conversion_strict_table[] = {{NULL, 0, text_hardtoreach_dot, fqdn_root, DOMAIN_TOO_LONG},
                                                                                                {fqdn_root, sizeof(fqdn_root), text_dot, fqdn_root, 0},
                                                                                                {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu, fqdn_root, 0},
                                                                                                {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, fqdn_root, 0},
                                                                                                {fqdn_127size1labels, sizeof(fqdn_127size1labels), text_127size1labels, fqdn_root, 0},
                                                                                                {fqdn_127size1labels, sizeof(fqdn_127size1labels), text_127size1labels_dot, fqdn_root, 0},
                                                                                                {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels, fqdn_root, 0},
                                                                                                {fqdn_3size63_labels, sizeof(fqdn_3size63_labels), text_3size63labels_dot, fqdn_root, 0},
                                                                                                {NULL, 0, text_4size63labels, fqdn_root, DOMAIN_TOO_LONG},
                                                                                                {NULL, 0, text_lastlabeltoolong, fqdn_root, LABEL_TOO_LONG},

                                                                                                {NULL, 0, text_star, fqdn_4labels_eu_labels, DOMAIN_TOO_LONG},

                                                                                                {fqdn_root, sizeof(fqdn_root), text_dot, fqdn_eu, 0},
                                                                                                {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa, fqdn_eu, 0},
                                                                                                {fqdn_www_yadifa_eu, sizeof(fqdn_www_yadifa_eu), text_www_yadifa_eu_dot, fqdn_eu, 0},
                                                                                                {fqdn_4labels_eu_labels, sizeof(fqdn_4labels_eu_labels), text_4labels_eu, fqdn_eu, 0},
                                                                                                {NULL, 0, text_4labels_eu_too_long, fqdn_eu, DOMAIN_TOO_LONG},

                                                                                                {NULL, 0, text_stars, fqdn_root, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, text_fqdn_star, fqdn_root, INVALID_CHARSET},
                                                                                                {fqdn_star, sizeof(fqdn_star), text_star, fqdn_root, 0},
                                                                                                {fqdn_star, sizeof(fqdn_star), text_star_dot, fqdn_root, 0},
                                                                                                {NULL, 0, text_labeltoolong, fqdn_root, LABEL_TOO_LONG},
                                                                                                {NULL, 0, text_domaintoolong, fqdn_root, DOMAIN_TOO_LONG},
                                                                                                {NULL, 0, text_domaintoolong2, fqdn_root, DOMAIN_TOO_LONG},
                                                                                                {NULL, 0, text_double_dot_fqdn, fqdn_root, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, text_double_dot, fqdn_root, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, text_fqdn_double_dot, fqdn_root, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, text_empty, fqdn_root, DOMAINNAME_INVALID},
                                                                                                {NULL, 0, NULL, NULL, 0}};

static void                                       init()
{
    dnscore_init();
#if DNSCORE_HAS_FULL_ASCII7
    // dnsname
    is_dnsname_char[0] = false;
    for(int i = 1; i < 128; ++i)
    {
        is_dnsname_char[i] = true;
    }
    is_dnsname_char['.'] = false;
    // is_dnsname_char['*'] = false;
    for(int i = 128; i < 256; ++i)
    {
        is_dnsname_char[i] = false;
    }
    // rname
    for(int i = 0; i < 256; ++i)
    {
        is_rname_char[i] = false;
    }
    for(int i = 33; i < 127; ++i)
    {
        is_rname_char[i] = true;
    }
    is_rname_char['*'] = false;
#else
    for(int i = 0; i < 256; ++i)
    {
        is_dnsname_char[i] = false;
        is_rname_char[i] = false;
    }
    for(int i = '0'; i <= '9'; ++i)
    {
        is_dnsname_char[i] = true;
        is_rname_char[i] = true;
    }
    for(int i = 'A'; i <= 'Z'; ++i)
    {
        is_dnsname_char[i] = true;
        is_rname_char[i] = true;
    }
    for(int i = 'a'; i <= 'z'; ++i)
    {
        is_dnsname_char[i] = true;
        is_rname_char[i] = true;
    }
    is_dnsname_char['-'] = true;
    is_rname_char['-'] = true;
    is_dnsname_char['_'] = true;
    is_rname_char['_'] = true;
    is_dnsname_char['*'] = true;
    is_rname_char['*'] = true;
    is_rname_char['!'] = true;
    is_rname_char['+'] = true;
    is_rname_char['.'] = true;
    is_rname_char['='] = true;
    is_rname_char['~'] = true;
#endif
}

static void finalise() { dnscore_finalize(); }

static int  dnsname_is_charspace_test()
{
    init();
    for(int i = 0; i < 256; ++i)
    {
        if(dnsname_is_charspace(i) != is_dnsname_char[i])
        {
            yatest_err("dnsname_is_charspace(%i = '%c') gives %i, expected %i", i, (i >= ' ') ? i : '.', dnsname_is_charspace(i), is_dnsname_char[i]);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int dnslabel_compare_test()
{
    int ret;
    init();
    if((ret = dnslabel_compare(label_empty, label_empty_bis)) != 0)
    {
        yatest_err("dnslabel_compare label_empty returned %i, expected 0", ret);
        return 1;
    }
    if((ret = dnslabel_compare(label_yadifa, label_yadifa)) != 0)
    {
        yatest_err("dnslabel_compare label_yadifa returned %i, expected 0", ret);
        return 1;
    }
    if((ret = dnslabel_compare(label_yadifa, label_padifa)) == 0)
    {
        yatest_err("dnslabel_compare label_yadifa, label_padifa returned %i, expected !0", ret);
        return 1;
    }
    if((ret = dnslabel_compare(label_yadifa, label_eurid)) == 0)
    {
        yatest_err("dnslabel_compare label_yadifa, label_eurid returned %i, expected !0", ret);
        return 1;
    }
    if((ret = dnslabel_compare(label_yadifa, label_empty)) == 0)
    {
        yatest_err("dnslabel_compare label_yadifa, label_empty returned %i, expected !0", ret);
        return 1;
    }
    if((ret = dnslabel_compare(label_empty, label_padifa)) == 0)
    {
        yatest_err("dnslabel_compare label_empty, label_padifa returned %i, expected !0", ret);
        return 1;
    }
    if((ret = dnslabel_compare(label_empty, label_eurid)) == 0)
    {
        yatest_err("dnslabel_compare label_empty, label_eurid returned %i, expected !0", ret);
        return 1;
    }
    uint8_t label_a[64];
    uint8_t label_b[64];
    for(uint8_t i = 1; i < 64; ++i)
    {
        label_a[0] = i;
        for(uint8_t k = 1; k <= i; ++k)
        {
            label_a[k] = 'a' + k;
        }
        // copy the label
        memcpy(label_b, label_a, i + 1);

        if(dnslabel_compare(label_a, label_b) != 0)
        {
            yatest_err("dnslabel_equals(a,b) should have returned 0");
            return 1;
        }
        if(dnslabel_compare(label_b, label_a) != 0)
        {
            yatest_err("dnslabel_equals(b,a) should have returned 0");
            return 1;
        }
        for(uint8_t j = 1; j <= i; ++j)
        {
            label_b[j]++;
            if(dnslabel_compare(label_a, label_b) >= 0)
            {
                yatest_err("dnslabel_equals(a,b) should have returned < 0");
                return 1;
            }
            if(dnslabel_compare(label_b, label_a) <= 0)
            {
                yatest_err("dnslabel_equals(b,a) should have returned > 0");
                return 1;
            }
            label_b[j]--;
        }
        label_b[0]--;
        if(dnslabel_compare(label_a, label_b) <= 0)
        {
            yatest_err("dnslabel_equals(a,b) should have returned > 0 (len)");
            return 1;
        }
        if(dnslabel_compare(label_b, label_a) >= 0)
        {
            yatest_err("dnslabel_equals(b,a) should have returned < 0 (len)");
            return 1;
        }
    }
    finalise();
    return 0;
}

static int dnslabel_verify_charspace_test()
{
    init();
    if(!dnslabel_verify_charspace(label_yadifa))
    {
        yatest_err("dnslabel_verify_charspace label_yadifa returned false");
        return 1;
    }
    if(dnslabel_verify_charspace(label_wrongcharset))
    {
        yatest_err("dnslabel_verify_charspace label_wrongcharset returned true");
        return 1;
    }
    if(dnslabel_verify_charspace(fqdn_label_too_long))
    {
        yatest_err("dnslabel_verify_charspace label_too_long returned true");
        return 1;
    }
    finalise();

    return 0;
}

static int dnsname_verify_charspace_test()
{
    init();
    if(!dnsname_verify_charspace(fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_verify_charspace fqdn_www_yadifa_eu returned false");
        return 1;
    }
    if(dnsname_verify_charspace(fqdn_www_wrongcharset_eu))
    {
        yatest_err("dnsname_verify_charspace fqdn_www_wrongcharset_eu returned true");
        return 1;
    }
    if(dnsname_verify_charspace(fqdn_label_too_long))
    {
        yatest_err("dnslabel_verify_charspace fqdn_label_too_long returned true");
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_is_rname_charspace_test()
{
    init();
    for(int i = 0; i < 256; ++i)
    {
        if(dnsname_is_rname_charspace(i) != is_rname_char[i])
        {
            yatest_err("dnsname_is_rname_charspace(%i = '%c') gives %i, expected %i", i, (i >= ' ') ? i : '.', dnsname_is_rname_charspace(i), is_rname_char[i]);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int dnsname_verify_rname_charspace_test()
{
    init();
    if(!dnsname_verify_rname_charspace(fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_verify_rname_charspace fqdn_www_yadifa_eu returned false");
        return 1;
    }
    if(dnsname_verify_rname_charspace(fqdn_www_wrongcharset_eu))
    {
        yatest_err("dnsname_verify_rname_charspace fqdn_www_wrongcharset_eu returned true");
        return 1;
    }
    if(dnsname_verify_rname_charspace(fqdn_label_too_long))
    {
        yatest_err("dnsname_verify_rname_charspace fqdn_label_too_long returned true");
        return 1;
    }
    finalise();
    return 0;
}

static int dnslabel_locase_verify_charspace_test()
{
    init();
    uint8_t label[256];
    memcpy(label, label_yadifa_uppercase, sizeof(label_yadifa_uppercase));
    if(!dnslabel_locase_verify_charspace(label))
    {
        yatest_err("dnslabel_locase_verify_charspace returned false");
        return 1;
    }
    if(memcmp(label_yadifa, label, sizeof(label_yadifa)) != 0)
    {
        yatest_err("dnslabel_locase_verify_charspace didn't lower the case");
        return 1;
    }
    memcpy(label, label_wrongcharset, sizeof(label_wrongcharset));
    if(dnslabel_locase_verify_charspace(label))
    {
        yatest_err("dnslabel_locase_verify_charspace returned true");
        return 1;
    }
    memcpy(label, fqdn_label_too_long, sizeof(fqdn_label_too_long));
    if(dnslabel_locase_verify_charspace(label))
    {
        yatest_err("dnslabel_verify_charspace label_too_long returned true");
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_locase_verify_charspace_test()
{
    init();
    uint8_t fqdn[1024];
    memcpy(fqdn, fqdn_www_yadifa_eu_uppercase, sizeof(fqdn_www_yadifa_eu_uppercase));
    if(!dnsname_locase_verify_charspace(fqdn))
    {
        yatest_err("dnsname_locase_verify_charspace returned false");
        return 1;
    }
    if(memcmp(fqdn_www_yadifa_eu, fqdn, sizeof(fqdn_www_yadifa_eu)) != 0)
    {
        yatest_err("dnsname_locase_verify_charspace didn't lower the case");
        return 1;
    }
    memcpy(fqdn, fqdn_www_wrongcharset_eu, sizeof(fqdn_www_wrongcharset_eu));
    if(dnsname_locase_verify_charspace(fqdn))
    {
        yatest_err("dnsname_locase_verify_charspace returned true");
        return 1;
    }
    memcpy(fqdn, fqdn_label_too_long, sizeof(fqdn_label_too_long));
    if(dnsname_locase_verify_charspace(fqdn))
    {
        yatest_err("dnslabel_verify_charspace fqdn_label_too_long returned true");
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_init_with_cstr_common_test(int (*dnsname_init_function)(uint8_t *fqdn, const char *str), const char *function_name, struct fqdn_text_conversion_table_s *table)
{
    int ret;
    init();
    uint8_t fqdn[DOMAIN_LENGTH_MAX + 257];

    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        int                  expected_fqdn_size = table[i].fqdn_size;
        const char *const    text = table[i].text;
        int                  expected_ret = table[i].error_code;

        yatest_log("%s(%s), expected return value = %08x = %i", function_name, text, expected_ret, expected_ret);

        memset(fqdn, 0xac, DOMAIN_LENGTH_MAX);
        fqdn[DOMAIN_LENGTH_MAX] = 0xfe;
        ret = dnsname_init_function(fqdn, text);

        if(fqdn[DOMAIN_LENGTH_MAX] != 0xfe)
        {
            yatest_err("%s '%s' appears to have overwritten memory", function_name, text);
            return 1;
        }

        if(expected_ret == 0)
        {
            if(ret < 0)
            {
                yatest_err("%s '%s' failed with %08x = %s", function_name, text, ret, error_gettext(ret));
                return 1;
            }
        }
        else
        {
            if(expected_ret < 0)
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' failed with %08x = %s, expected %08x = %s", function_name, text, ret, error_gettext(ret), expected_ret, error_gettext(expected_ret));
                    return 1;
                }
                continue;
            }
            else
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' got %08x, expected %08x = %s", function_name, text, ret, expected_ret, error_gettext(expected_ret));
                    return 1;
                }
            }
        }
        if(ret != expected_fqdn_size)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected %i", function_name, text, ret, expected_fqdn_size);
            return 1;
        }
        if(memcmp(fqdn, expected_fqdn, ret) != 0)
        {
            yatest_err("%s '%s' unexpected value: got / expected", function_name, text);
            yatest_hexdump_err(fqdn, fqdn + ret);
            yatest_hexdump_err(expected_fqdn, expected_fqdn + ret);
            return 1;
        }
    }

    finalise();
    return 0;
}

static int dnsname_init_with_charp_common_test(int (*dnsname_init_function)(uint8_t *fqdn, const char *str, uint32_t str_len), const char *function_name, struct fqdn_text_conversion_table_s *table)
{
    int ret;
    init();
    uint8_t fqdn[DOMAIN_LENGTH_MAX + 257];

    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        int                  expected_fqdn_size = table[i].fqdn_size;
        const char *const    text = table[i].text;
        int                  expected_ret = table[i].error_code;

        yatest_log("%s(%s), expected return value = %08x = %i", function_name, text, expected_ret, expected_ret);

        memset(fqdn, 0xac, DOMAIN_LENGTH_MAX);
        fqdn[DOMAIN_LENGTH_MAX] = 0xfe;

        ret = dnsname_init_function(fqdn, text, strlen(text));

        if(fqdn[DOMAIN_LENGTH_MAX] != 0xfe)
        {
            yatest_err("%s '%s' appears to have overwritten memory", function_name, text);
            return 1;
        }

        if(expected_ret == 0)
        {
            if(ret < 0)
            {
                yatest_err("%s '%s' failed with %08x = %s", function_name, text, ret, error_gettext(ret));
                return 1;
            }
        }
        else
        {
            if(expected_ret < 0)
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' failed with %08x = %s, expected %08x = %s", function_name, text, ret, error_gettext(ret), expected_ret, error_gettext(expected_ret));
                    return 1;
                }
                continue;
            }
            else
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' got %08x, expected %08x = %s", function_name, text, ret, expected_ret);
                    return 1;
                }
            }
        }
        if(ret != expected_fqdn_size)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected %i", function_name, text, ret, expected_fqdn_size);
            return 1;
        }
        if(memcmp(fqdn, expected_fqdn, ret) != 0)
        {
            yatest_err("%s '%s' unexpected value: got / expected", function_name, text);
            yatest_hexdump_err(fqdn, fqdn + ret);
            yatest_hexdump_err(expected_fqdn, expected_fqdn + ret);
            return 1;
        }
    }

    finalise();
    return 0;
}

static int dnsname_init_with_charp_and_origin_common_test(int (*dnsname_init_function)(uint8_t *fqdn, const char *str, uint32_t str_len, const uint8_t *origin), const char *function_name, struct fqdn_text_origin_conversion_table_s *table)
{
    int ret;
    init();
    uint8_t fqdn[DOMAIN_LENGTH_MAX + 257];

    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        int                  expected_fqdn_size = table[i].fqdn_size;
        const char *const    text = table[i].text;
        int                  expected_ret = table[i].error_code;
        const uint8_t       *origin = table[i].origin;
        char                 origin_text[DOMAIN_LENGTH_MAX];
        cstr_init_with_dnsname(origin_text, origin);

        yatest_log("%s(%s, %s), expected return value = %08x = %i", function_name, text, origin_text, expected_ret, expected_ret);

        memset(fqdn, 0xac, DOMAIN_LENGTH_MAX);
        fqdn[DOMAIN_LENGTH_MAX] = 0xfe;

        ret = dnsname_init_function(fqdn, text, strlen(text), origin);

        if(fqdn[DOMAIN_LENGTH_MAX] != 0xfe)
        {
            yatest_err("%s '%s' + '%s' appears to have overwritten memory", function_name, text, origin_text);
            return 1;
        }

        if(expected_ret == 0)
        {
            if(ret < 0)
            {
                yatest_err("%s '%s' + '%s' failed with %08x = %s", function_name, text, origin_text, ret, error_gettext(ret));
                return 1;
            }
        }
        else
        {
            if(expected_ret < 0)
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' + '%s' failed with %08x = %s, expected %08x = %s", function_name, text, origin_text, ret, error_gettext(ret), expected_ret, error_gettext(expected_ret));
                    return 1;
                }
                continue;
            }
            else
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' + '%s' got %08x, expected %08x = %s", function_name, text, origin_text, ret, expected_ret);
                    return 1;
                }
            }
        }
        if(ret != expected_fqdn_size)
        {
            yatest_err("%s '%s' + '%s' unexpected len: got %i, expected %i", function_name, text, origin_text, ret, expected_fqdn_size);
            return 1;
        }
        if(memcmp(fqdn, expected_fqdn, ret) != 0)
        {
            yatest_err("%s '%s' + '%s' unexpected value: got / expected", function_name, text, origin_text);
            yatest_hexdump_err(fqdn, fqdn + ret);
            yatest_hexdump_err(expected_fqdn, expected_fqdn + ret);
            return 1;
        }
    }

    finalise();
    return 0;
}

static int dnsname_init_with_cstr_locase_test() { return dnsname_init_with_cstr_common_test(dnsname_init_with_cstr_locase, "dnsname_init_with_cstr_locase", fqdn_text_conversion_table); }

static int dnsname_init_check_star_with_cstr_test() { return dnsname_init_with_cstr_common_test(dnsname_init_check_star_with_cstr, "dnsname_init_check_star_with_cstr", fqdn_text_conversion_mixedcase_strict_table); }

static int dnsname_init_with_charp_test() { return dnsname_init_with_charp_common_test(dnsname_init_with_charp, "dnsname_init_with_charp", fqdn_text_conversion_mixedcase_table); }

static int dnsname_init_with_charp_locase_test() { return dnsname_init_with_charp_common_test(dnsname_init_with_charp_locase, "dnsname_init_with_charp_locase", fqdn_text_conversion_table); }

static int dnsname_init_check_with_charp_locase_test() { return dnsname_init_with_charp_common_test(dnsname_init_check_with_charp_locase, "dnsname_init_check_with_charp_locase", fqdn_text_conversion_table); }

static int dnsname_init_check_star_with_charp_test() { return dnsname_init_with_charp_common_test(dnsname_init_check_star_with_charp, "dnsname_init_check_star_with_charp", fqdn_text_conversion_mixedcase_strict_table); }

static int dnsname_init_check_nostar_with_charp_test() { return dnsname_init_with_charp_common_test(dnsname_init_check_nostar_with_charp, "dnsname_init_check_nostar_with_charp", fqdn_text_conversion_mixedcase_strict_nostar_table); }

static int dnsname_init_check_nostar_with_charp_locase_test()
{
    return dnsname_init_with_charp_common_test(dnsname_init_check_nostar_with_charp_locase, "dnsname_init_check_nostar_with_charp_locase", fqdn_text_conversion_strict_nostar_table);
}

static int dnsname_init_check_star_with_charp_and_origin_test()
{
    return dnsname_init_with_charp_and_origin_common_test(dnsname_init_check_star_with_charp_and_origin, "dnsname_init_check_star_with_charp_and_origin", fqdn_text_origin_conversion_mixedcase_strict_table);
}

static int dnsname_init_check_star_with_charp_and_origin_locase_test()
{
    return dnsname_init_with_charp_and_origin_common_test(dnsname_init_check_star_with_charp_and_origin_locase, "dnsname_init_check_star_with_charp_and_origin_locase", fqdn_text_origin_conversion_strict_table);
}

static int dnsrname_init_check_with_cstr_test() { return dnsname_init_with_cstr_common_test(dnsrname_init_check_with_cstr, "dnsrname_init_check_with_cstr", fqdn_text_conversion_rname_table); }

static int dnsrname_init_check_with_charp_test() { return dnsname_init_with_charp_common_test(dnsrname_init_check_with_charp, "dnsrname_init_check_with_charp", fqdn_text_conversion_rname_table); }

static int cstr_get_dnsname_len_test()
{
    int ret;
    init();
    struct fqdn_text_conversion_table_s *table = fqdn_text_conversion_table;
    const char                          *function_name = "cstr_get_dnsname_len";
    for(int i = 0; table[i].text != NULL; ++i)
    {
        int               expected_fqdn_size = table[i].fqdn_size;
        const char *const text = table[i].text;
        int               expected_ret = table[i].error_code;

        // the function doesn't test for that
        if((expected_ret == INVALID_CHARSET) || (expected_ret == DOMAINNAME_INVALID))
        {
            continue;
        }

        yatest_log("%s(%s), expected return value = %08x = %i", function_name, text, expected_ret, expected_ret);

        ret = cstr_get_dnsname_len(text);

        if(expected_ret == 0)
        {
            if(ret < 0)
            {
                yatest_err("%s '%s' failed with %08x = %s", function_name, text, ret, error_gettext(ret));
                return 1;
            }
        }
        else
        {
            if(expected_ret < 0)
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' failed with %08x = %s, expected %08x = %s", function_name, text, ret, error_gettext(ret), expected_ret, error_gettext(expected_ret));
                    return 1;
                }
                continue;
            }
            else
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' got %08x, expected %08x = %s", function_name, text, ret, expected_ret);
                    return 1;
                }
            }
        }
        if(ret != expected_fqdn_size)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected %i", function_name, text, ret, expected_fqdn_size);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int cstr_init_with_dnsname_test()
{
    int ret;
    init();
    struct fqdn_text_conversion_table_s *table = fqdn_text_conversion_table;
    const char                          *function_name = "cstr_init_with_dnsname";
    char                                 text_buffer[DOMAIN_TEXT_BUFFER_SIZE + 1];
    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        // int expected_fqdn_size = table[i].fqdn_size;
        const char *const text = table[i].text;
        int               expected_ret = table[i].error_code;
        size_t            text_len = strlen(text);
        if(text[text_len - 1] != '.')
        {
            ++text_len;
        }

        // the function doesn't test for that
        if((expected_ret == INVALID_CHARSET) || (expected_ret == DOMAINNAME_INVALID) || (expected_ret == DOMAIN_TOO_LONG) || (expected_ret == LABEL_TOO_LONG))
        {
            continue;
        }

        yatest_log("%s(%s), expected return value = %08x = %i, expected length = %i", function_name, text, expected_ret, expected_ret, text_len);

        memset(text_buffer, 0xac, DOMAIN_TEXT_BUFFER_SIZE);
        text_buffer[DOMAIN_TEXT_BUFFER_SIZE] = '!';
        ret = cstr_init_with_dnsname(text_buffer, expected_fqdn);
        if(text_buffer[DOMAIN_TEXT_BUFFER_SIZE] != '!')
        {
            yatest_err("%s '%s' appears to have overwritten memory", function_name, text);
            return 1;
        }
        if(expected_ret == 0)
        {
            if(ret < 0)
            {
                yatest_err("%s '%s' failed with %08x = %s", function_name, text, ret, error_gettext(ret));
                return 1;
            }
        }
        else
        {
            if(expected_ret < 0)
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' failed with %08x = %s, expected %08x = %s", function_name, text, ret, error_gettext(ret), expected_ret, error_gettext(expected_ret));
                    return 1;
                }
                continue;
            }
            else
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' got %08x, expected %08x = %s", function_name, text, ret, expected_ret);
                    return 1;
                }
            }
        }
        if(ret != (int)text_len)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected %i", function_name, text, ret, text_len);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int dnslabel_equals_test()
{
    init();
    uint8_t label_a[64];
    uint8_t label_b[64];
    for(uint8_t i = 1; i < 64; ++i)
    {
        label_a[0] = i;
        for(uint8_t k = 1; k <= i; ++k)
        {
            label_a[k] = 'a' + k;
        }
        // copy the label
        memcpy(label_b, label_a, i + 1);

        if(!dnslabel_equals(label_a, label_b))
        {
            yatest_err("dnslabel_equals(a,b) should have returned true");
            return 1;
        }
        if(!dnslabel_equals(label_b, label_a))
        {
            yatest_err("dnslabel_equals(b,a) should have returned true");
            return 1;
        }
        for(uint8_t j = 1; j <= i; ++j)
        {
            label_b[j]++;
            if(dnslabel_equals(label_a, label_b))
            {
                yatest_err("dnslabel_equals(a,b) should have returned false");
                return 1;
            }
            if(dnslabel_equals(label_b, label_a))
            {
                yatest_err("dnslabel_equals(b,a) should have returned false");
                return 1;
            }
            label_b[j]--;
        }
        label_b[0]--;
        if(dnslabel_equals(label_a, label_b))
        {
            yatest_err("dnslabel_equals(a,b) should have returned false (len)");
            return 1;
        }
        if(dnslabel_equals(label_b, label_a))
        {
            yatest_err("dnslabel_equals(b,a) should have returned false (len)");
            return 1;
        }
    }

    finalise();
    return 0;
}

static int dnslabel_equals_ignorecase_left1_test()
{
    init();
    uint8_t label_a[64];
    uint8_t label_b[64];
    for(uint8_t i = 1; i < 64; ++i)
    {
        label_a[0] = i;
        for(uint8_t k = 1; k <= i; ++k)
        {
            label_a[k] = 'a' + k;
        }
        // copy the label
        memcpy(label_b, label_a, i + 1);

        if(!dnslabel_equals_ignorecase_left1(label_a, label_b))
        {
            yatest_err("dnslabel_equals(a,b) should have returned true");
            return 1;
        }
        if(!dnslabel_equals_ignorecase_left1(label_b, label_a))
        {
            yatest_err("dnslabel_equals(b,a) should have returned true");
            return 1;
        }

        for(uint8_t j = 1; j <= i; ++j)
        {
            label_b[j]++;
            if(dnslabel_equals_ignorecase_left1(label_a, label_b))
            {
                yatest_err("dnslabel_equals(a,b) should have returned false");
                return 1;
            }
            if(dnslabel_equals_ignorecase_left1(label_b, label_a))
            {
                yatest_err("dnslabel_equals(b,a) should have returned false");
                return 1;
            }
            label_b[j]--;

            uint8_t c = label_b[j];
            if((c >= 'a') && (c <= 'z'))
            {
                label_b[j] ^= 32;
                if(!dnslabel_equals_ignorecase_left1(label_a, label_b))
                {
                    yatest_err("dnslabel_equals(a,b) should have returned true (ignorecase)");
                    return 1;
                }
                label_b[j] ^= 32;
            }
        }
        label_b[0]--;
        if(dnslabel_equals_ignorecase_left1(label_a, label_b))
        {
            yatest_err("dnslabel_equals(a,b) should have returned false (len)");
            return 1;
        }
        if(dnslabel_equals_ignorecase_left1(label_b, label_a))
        {
            yatest_err("dnslabel_equals(b,a) should have returned false (len)");
            return 1;
        }
    }

    finalise();
    return 0;
}

static int dnsname_equals_ignorecase3_test()
{
    init();
    uint8_t label_a[DOMAIN_LENGTH_MAX];
    uint8_t label_b[DOMAIN_LENGTH_MAX];
    for(uint8_t i = 1; i < 64; ++i)
    {
        label_a[0] = i;
        for(uint8_t k = 1; k <= i; ++k)
        {
            label_a[k] = 'a' + k;
        }
        label_a[i + 1] = 0;
        // copy the label
        memcpy(label_b, label_a, i + 1);
        label_b[i + 1] = 0;

        if(!dnsname_equals_ignorecase3(label_a, label_b))
        {
            yatest_err("dnsname_equals_ignorecase3(a,b) should have returned true");
            return 1;
        }
        if(!dnsname_equals_ignorecase3(label_b, label_a))
        {
            yatest_err("dnsname_equals_ignorecase3(b,a) should have returned true");
            return 1;
        }

        for(uint8_t j = 1; j <= i; ++j)
        {
            label_b[j]++;
            if(dnsname_equals_ignorecase3(label_a, label_b))
            {
                yatest_err("dnsname_equals_ignorecase3(a,b) should have returned false");
                return 1;
            }
            if(dnsname_equals_ignorecase3(label_b, label_a))
            {
                yatest_err("dnsname_equals_ignorecase3(b,a) should have returned false");
                return 1;
            }
            label_b[j]--;

            uint8_t c = label_b[j];
            if((c >= 'a') && (c <= 'z'))
            {
                label_b[j] ^= 32;
                if(!dnsname_equals_ignorecase3(label_a, label_b))
                {
                    yatest_err("dnsname_equals_ignorecase3(a,b) should have returned true (ignorecase)");
                    return 1;
                }
                label_b[j] ^= 32;
            }
        }
        label_b[0]--;
        if(dnsname_equals_ignorecase3(label_a, label_b))
        {
            yatest_err("dnsname_equals_ignorecase3(a,b) should have returned false (len)");
            return 1;
        }
        if(dnsname_equals_ignorecase3(label_b, label_a))
        {
            yatest_err("dnsname_equals_ignorecase3(b,a) should have returned false (len)");
            return 1;
        }
    }

    finalise();
    return 0;
}

static int dnslabel_equals_ignorecase_left4_test()
{
    init();
    uint8_t label_a[DOMAIN_LENGTH_MAX];
    uint8_t label_b[DOMAIN_LENGTH_MAX];
    for(uint8_t i = 1; i < 64; ++i)
    {
        label_a[0] = i;
        for(uint8_t k = 1; k <= i; ++k)
        {
            label_a[k] = 'a' + k;
        }
        label_a[i + 1] = 0;
        // copy the label
        memcpy(label_b, label_a, i + 1);
        label_b[i + 1] = 0;

        if(!dnslabel_equals_ignorecase_left4(label_a, label_b))
        {
            yatest_err("dnslabel_equals_ignorecase_left4(a,b) should have returned true");
            return 1;
        }
        if(!dnslabel_equals_ignorecase_left4(label_b, label_a))
        {
            yatest_err("dnslabel_equals_ignorecase_left4(b,a) should have returned true");
            return 1;
        }

        for(uint8_t j = 1; j <= i; ++j)
        {
            label_b[j]++;
            if(dnslabel_equals_ignorecase_left4(label_a, label_b))
            {
                yatest_err("dnslabel_equals_ignorecase_left4(a,b) should have returned false");
                return 1;
            }
            if(dnslabel_equals_ignorecase_left4(label_b, label_a))
            {
                yatest_err("dnslabel_equals_ignorecase_left4(b,a) should have returned false");
                return 1;
            }
            label_b[j]--;

            uint8_t c = label_b[j];
            if((c >= 'a') && (c <= 'z'))
            {
                label_b[j] ^= 32;
                if(!dnslabel_equals_ignorecase_left4(label_a, label_b))
                {
                    yatest_err("dnslabel_equals_ignorecase_left4(a,b) should have returned true (ignorecase)");
                    return 1;
                }
                label_b[j] ^= 32;
            }
        }
        label_b[0]--;
        if(dnslabel_equals_ignorecase_left4(label_a, label_b))
        {
            yatest_err("dnslabel_equals_ignorecase_left4(a,b) should have returned false (len)");
            return 1;
        }
        if(dnslabel_equals_ignorecase_left4(label_b, label_a))
        {
            yatest_err("dnslabel_equals_ignorecase_left4(b,a) should have returned false (len)");
            return 1;
        }
    }

    finalise();
    return 0;
}

static int dnsname_is_subdomain_test()
{
    init();

    if(!dnsname_is_subdomain(fqdn_www_yadifa_eu, fqdn_root))
    {
        yatest_err("dnsname_is_subdomain(www.yadifa.eu,.) should have returned true");
        return 1;
    }

    if(!dnsname_is_subdomain(fqdn_www_yadifa_eu, fqdn_eu))
    {
        yatest_err("dnsname_is_subdomain(www.yadifa.eu,eu) should have returned true");
        return 1;
    }

    if(!dnsname_is_subdomain(fqdn_www_yadifa_eu, fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_is_subdomain(www.yadifa.eu,www.yadifa.eu) should have returned true");
        return 1;
    }

    if(dnsname_is_subdomain(fqdn_root, fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_is_subdomain(www.yadifa.eu,.) should have returned false");
        return 1;
    }

    if(dnsname_is_subdomain(fqdn_eu, fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_is_subdomain(eu,www.yadifa.eu) should have returned false");
        return 1;
    }

    finalise();
    return 0;
}

static int dnsname_len_with_size_test()
{
    int ret;
    init();
    struct fqdn_text_conversion_table_s *table = fqdn_text_conversion_table;
    const char                          *function_name = "dnsname_len_with_size";
    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        int                  expected_fqdn_size = table[i].fqdn_size;
        const char *const    text = table[i].text;
        int                  expected_ret = table[i].error_code;

        if(expected_fqdn == NULL)
        {
            continue;
        }
        // the function doesn't test for that
        if((expected_ret == INVALID_CHARSET) || (expected_ret == DOMAINNAME_INVALID))
        {
            continue;
        }

        yatest_log("%s(%s), expected return value = %08x = %i", function_name, text, expected_ret, expected_ret);

        ret = dnsname_len_with_size(expected_fqdn, expected_fqdn_size);

        if(expected_ret == 0)
        {
            if(ret < 0)
            {
                yatest_err("%s '%s' failed with %08x = %s", function_name, text, ret, error_gettext(ret));
                return 1;
            }
        }
        else
        {
            if(expected_ret < 0)
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' failed with %08x = %s, expected %08x = %s", function_name, text, ret, error_gettext(ret), expected_ret, error_gettext(expected_ret));
                    return 1;
                }
                continue;
            }
            else
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' got %08x, expected %08x = %s", function_name, text, ret, expected_ret);
                    return 1;
                }
            }
        }
        if(ret != expected_fqdn_size)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected %i", function_name, text, ret, expected_fqdn_size);
            return 1;
        }

        ret = dnsname_len_with_size(expected_fqdn, expected_fqdn_size - 1);
        if(ret != BUFFER_WOULD_OVERFLOW)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected BUFFER_WOULD_OVERFLOW = %i", function_name, text, ret, BUFFER_WOULD_OVERFLOW);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int dnsname_len_checked_with_size_test()
{
    int ret;
    init();
    struct fqdn_text_conversion_table_s *table = fqdn_text_conversion_table;
    const char                          *function_name = "dnsname_len_checked_with_size";
    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        int                  expected_fqdn_size = table[i].fqdn_size;
        const char *const    text = table[i].text;
        int                  expected_ret = table[i].error_code;

        if(expected_fqdn == NULL)
        {
            continue;
        }
        // the function doesn't test for that
        if((expected_ret == INVALID_CHARSET) || (expected_ret == DOMAINNAME_INVALID))
        {
            continue;
        }

        yatest_log("%s(%s), expected return value = %08x = %i", function_name, text, expected_ret, expected_ret);

        ret = dnsname_len_checked_with_size(expected_fqdn, expected_fqdn_size);

        if(expected_ret == 0)
        {
            if(ret < 0)
            {
                yatest_err("%s '%s' failed with %08x = %s", function_name, text, ret, error_gettext(ret));
                return 1;
            }
        }
        else
        {
            if(expected_ret < 0)
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' failed with %08x = %s, expected %08x = %s", function_name, text, ret, error_gettext(ret), expected_ret, error_gettext(expected_ret));
                    return 1;
                }
                continue;
            }
            else
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' got %08x, expected %08x = %s", function_name, text, ret, expected_ret);
                    return 1;
                }
            }
        }
        if(ret != expected_fqdn_size)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected %i", function_name, text, ret, expected_fqdn_size);
            return 1;
        }

        ret = dnsname_len_checked_with_size(expected_fqdn, expected_fqdn_size - 1);
        if(ret != BUFFER_WOULD_OVERFLOW)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected BUFFER_WOULD_OVERFLOW = %i", function_name, text, ret, BUFFER_WOULD_OVERFLOW);
            return 1;
        }
    }

    ret = dnsname_len_checked_with_size(fqdn_domain_too_long, sizeof(fqdn_domain_too_long));
    if(ret != DOMAIN_TOO_LONG)
    {
        yatest_err("%s fqdn_domain_too_long unexpected len: got %i, expected DOMAIN_TOO_LONG = %i", function_name, ret, DOMAIN_TOO_LONG);
        return 1;
    }

    finalise();
    return 0;
}

static int dnsname_len_checked_test()
{
    int ret;
    init();
    struct fqdn_text_conversion_table_s *table = fqdn_text_conversion_table;
    const char                          *function_name = "dnsname_len_checked";
    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        int                  expected_fqdn_size = table[i].fqdn_size;
        const char *const    text = table[i].text;
        int                  expected_ret = table[i].error_code;

        if(expected_fqdn == NULL)
        {
            continue;
        }
        // the function doesn't test for that
        if((expected_ret == INVALID_CHARSET) || (expected_ret == DOMAINNAME_INVALID))
        {
            continue;
        }

        yatest_log("%s(%s), expected return value = %08x = %i", function_name, text, expected_ret, expected_ret);

        ret = dnsname_len_checked(expected_fqdn);

        if(expected_ret == 0)
        {
            if(ret < 0)
            {
                yatest_err("%s '%s' failed with %08x = %s", function_name, text, ret, error_gettext(ret));
                return 1;
            }
        }
        else
        {
            if(expected_ret < 0)
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' failed with %08x = %s, expected %08x = %s", function_name, text, ret, error_gettext(ret), expected_ret, error_gettext(expected_ret));
                    return 1;
                }
                continue;
            }
            else
            {
                if(ret != expected_ret)
                {
                    yatest_err("%s '%s' got %08x, expected %08x = %s", function_name, text, ret, expected_ret);
                    return 1;
                }
            }
        }
        if(ret != expected_fqdn_size)
        {
            yatest_err("%s '%s' unexpected len: got %i, expected %i", function_name, text, ret, expected_fqdn_size);
            return 1;
        }
    }

    ret = dnsname_len_checked(fqdn_domain_too_long);
    if(ret != DOMAIN_TOO_LONG)
    {
        yatest_err("%s fqdn_domain_too_long unexpected len: got %i, expected DOMAIN_TOO_LONG = %i", function_name, ret, DOMAIN_TOO_LONG);
        return 1;
    }

    finalise();
    return 0;
}

static int dnsname_getdepth_test()
{
    uint32_t ret;
    init();
    ret = dnsname_getdepth(fqdn_root);
    if(ret != 0)
    {
        yatest_err("dnsname_getdepth(root) returned %u instead of %u", ret, 0);
        return 1;
    }
    ret = dnsname_getdepth(fqdn_127size1labels);
    if(ret != 127)
    {
        yatest_err("dnsname_getdepth(fqdn_127size1labels) returned %u instead of %u", ret, 127);
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_dup_free_test()
{
    init();
    struct fqdn_text_conversion_table_s *table = fqdn_text_conversion_table;
    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        const char *const    text = table[i].text;

        if(expected_fqdn == NULL)
        {
            continue;
        }

        uint8_t *fqdn = dnsname_dup(expected_fqdn);
        if(fqdn == NULL)
        {
            yatest_err("dnsname_dup(%s) returned NULL", text);
            return 1;
        }
        if(!dnsname_equals(fqdn, expected_fqdn))
        {
            yatest_err("dnsname_equals(fqdn, %s) returned false", text);
            return 1;
        }
        dnsname_free(fqdn);
    }
    finalise();
    return 0;
}

static int dnsname_copy_test()
{
    init();
    struct fqdn_text_conversion_table_s *table = fqdn_text_conversion_table;

    uint8_t                              fqdn[DOMAIN_LENGTH_MAX + 1];
    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        uint32_t             expected_fqdn_size = table[i].fqdn_size;
        const char *const    text = table[i].text;

        if(expected_fqdn == NULL)
        {
            continue;
        }
        memset(fqdn, 0xac, sizeof(fqdn));

        uint32_t fqdn_len = dnsname_copy(fqdn, expected_fqdn);
        if(fqdn_len != expected_fqdn_size)
        {
            yatest_err("dnsname_copy(fqdn, %s) returned %u instead of %u", text, fqdn_len, expected_fqdn_size);
            return 1;
        }
        if(!dnsname_equals(fqdn, expected_fqdn))
        {
            yatest_err("dnsname_equals(fqdn, %s) returned false", text);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int dnsname_copy_checked_test()
{
    init();
    struct fqdn_text_conversion_table_s *table = fqdn_text_conversion_table;

    uint8_t                              fqdn[DOMAIN_LENGTH_MAX + 1];
    for(int i = 0; table[i].text != NULL; ++i)
    {
        const uint8_t *const expected_fqdn = table[i].fqdn;
        uint32_t             expected_fqdn_size = table[i].fqdn_size;
        const char *const    text = table[i].text;

        if(expected_fqdn == NULL)
        {
            continue;
        }
        memset(fqdn, 0xac, sizeof(fqdn));

        uint32_t fqdn_len = dnsname_copy_checked(fqdn, expected_fqdn);
        if(fqdn_len != expected_fqdn_size)
        {
            yatest_err("dnsname_copy_checked(fqdn, %s) returned %u instead of %u", text, fqdn_len, expected_fqdn_size);
            return 1;
        }
        if(!dnsname_equals(fqdn, expected_fqdn))
        {
            yatest_err("dnsname_equals(fqdn, %s) returned false", text);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int dnslabel_vector_to_dnsname_test()
{
    init();
    uint8_t fqdn[DOMAIN_LENGTH_MAX];
    memset(fqdn, 0xac, sizeof(fqdn));
    uint32_t fqdn_len = dnslabel_vector_to_dnsname(label_vector_www_yadifa_eu, label_vector_www_yadifa_eu_top, fqdn);
    if(fqdn_len != sizeof(fqdn_www_yadifa_eu))
    {
        yatest_err("dnslabel_vector_to_dnsname returned %u instead of %u", fqdn_len, sizeof(fqdn_www_yadifa_eu));
        return 1;
    }
    if(!dnsname_equals(fqdn, fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_equals(fqdn, www.yadifa.eu) returned false");
        return 1;
    }
    if(dnslabel_vector_len(label_vector_www_yadifa_eu, label_vector_www_yadifa_eu_top) != fqdn_len)
    {
        yatest_err("dnslabel_vector_to_dnsname returned %u instead of %u", dnslabel_vector_len(label_vector_www_yadifa_eu, label_vector_www_yadifa_eu_top), fqdn_len);
        return 1;
    }
    finalise();
    return 0;
}

static int dnslabel_vector_to_cstr_test()
{
    init();
    char text[DOMAIN_TEXT_BUFFER_SIZE];
    memset(text, 0xac, sizeof(text));
    uint32_t text_len = dnslabel_vector_to_cstr(label_vector_www_yadifa_eu, label_vector_www_yadifa_eu_top, text);
    if(text_len != strlen(text_www_yadifa_eu_dot))
    {
        yatest_err("dnslabel_vector_to_cstr returned %u instead of %u ('%s'!='%s')", text_len, strlen(text_www_yadifa_eu_dot), text, text_www_yadifa_eu_dot);
        return 1;
    }
    if(strcmp(text, text_www_yadifa_eu_dot) != 0)
    {
        yatest_err("strcmp(text, www.yadifa.eu) returned !=0 ('%s'!='%s')", text, text_www_yadifa_eu_dot);
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_vector_sub_to_dnsname_test()
{
    uint8_t fqdn[DOMAIN_LENGTH_MAX];
    memset(fqdn, 0xac, sizeof(fqdn));
    init();
    const uint8_t *expected_fqdn = fqdn_www_yadifa_eu;
    for(int i = 0; i <= 3; ++i)
    {
        uint32_t fqdn_len = dnsname_vector_sub_to_dnsname(&dnsname_vector_www_yadifa_eu, i, fqdn);
        if(fqdn_len != dnsname_len(expected_fqdn))
        {
            yatest_err("dnsname_vector_sub_to_dnsname %i didn't return the expected value: %u != %u", i, fqdn_len, dnsname_len(expected_fqdn));
            return 1;
        }
        expected_fqdn += expected_fqdn[0] + 1;
    }
    finalise();
    return 0;
}

static int dnsname_vector_copy_test()
{
    init();
    dnsname_vector_t fqdn_vector;

    if(dnsname_vector_copy(&fqdn_vector, &dnsname_vector_www_yadifa_eu) != (uint32_t)dnsname_vector_www_yadifa_eu.size)
    {
        yatest_err("dnsname_vector_len returned %u insteadl of %u", dnsname_vector_copy(&fqdn_vector, &dnsname_vector_www_yadifa_eu), dnsname_vector_www_yadifa_eu.size);
        return 1;
    }
    if(dnsname_vector_len(&fqdn_vector) != sizeof(fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_vector_len returned %u insteadl of %u", dnsname_vector_len(&fqdn_vector), fqdn_www_yadifa_eu);
        return 1;
    }

    finalise();
    return 0;
}

static int dnsname_vector_len_test()
{
    init();
    if(dnsname_vector_len(&dnsname_vector_www_yadifa_eu) != sizeof(fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_vector_len returned %u insteadl of %u", dnsname_vector_len(&dnsname_vector_www_yadifa_eu), fqdn_www_yadifa_eu);
        return 1;
    }
    finalise();
    return 0;
}

static int dnslabel_stack_to_dnsname_test()
{
    init();
    uint8_t fqdn[DOMAIN_LENGTH_MAX];
    memset(fqdn, 0xac, sizeof(fqdn));
    uint32_t fqdn_len = dnslabel_stack_to_dnsname(label_stack_www_yadifa_eu, label_stack_www_yadifa_eu_top, fqdn);
    if(fqdn_len != sizeof(fqdn_www_yadifa_eu))
    {
        yatest_err("dnslabel_stack_to_dnsname returned %u instead of %u", fqdn_len, sizeof(fqdn_www_yadifa_eu));
        return 1;
    }
    if(!dnsname_equals(fqdn, fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_equals(fqdn, www.yadifa.eu) returned false");
        return 1;
    }
    finalise();
    return 0;
}

static int dnslabel_stack_to_cstr_test()
{
    init();
    char text[DOMAIN_TEXT_BUFFER_SIZE];
    memset(text, 0xac, sizeof(text));
    uint32_t text_len = dnslabel_stack_to_cstr(label_stack_www_yadifa_eu, label_stack_www_yadifa_eu_top, text);
    if(text_len != strlen(text_www_yadifa_eu_dot))
    {
        yatest_err("dnslabel_stack_to_cstr returned %u instead of %u ('%s'!='%s')", text_len, strlen(text_www_yadifa_eu_dot), text, text_www_yadifa_eu_dot);
        return 1;
    }
    if(strcmp(text, text_www_yadifa_eu_dot) != 0)
    {
        yatest_err("strcmp(text, www.yadifa.eu) returned !=0 ('%s'!='%s')", text, text_www_yadifa_eu_dot);
        return 1;
    }
    text_len = dnslabel_stack_to_cstr(NULL, -1, text);
    if(text_len != 1)
    {
        yatest_err("dnslabel_stack_to_cstr returned %u instead of %u", text_len, 1);
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_stack_to_dnsname_test()
{
    uint8_t fqdn[DOMAIN_LENGTH_MAX + 1];
    init();
    uint32_t fqdn_len = dnsname_stack_to_dnsname(&dnsname_stack_www_yadifa_eu, fqdn);
    if(fqdn_len != sizeof(fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_stack_to_dnsname returned %u instead of %u", fqdn_len, sizeof(fqdn_www_yadifa_eu));
        return 1;
    }
    if(!dnsname_equals(fqdn, fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_equals returned false");
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_stack_len_test()
{
    init();
    uint32_t fqdn_len = dnsname_stack_len(&dnsname_stack_www_yadifa_eu);
    if(fqdn_len != sizeof(fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_stack_to_dnsname returned %u instead of %u", fqdn_len, sizeof(fqdn_www_yadifa_eu));
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_stack_to_cstr_test()
{
    init();
    char text[DOMAIN_TEXT_BUFFER_SIZE];
    memset(text, 0xac, sizeof(text));
    uint32_t text_len = dnsname_stack_to_cstr(&dnsname_stack_www_yadifa_eu, text);
    if(text_len != strlen(text_www_yadifa_eu_dot))
    {
        yatest_err("dnsname_stack_to_cstr returned %u instead of %u ('%s'!='%s')", text_len, strlen(text_www_yadifa_eu_dot), text, text_www_yadifa_eu_dot);
        return 1;
    }
    if(strcmp(text, text_www_yadifa_eu_dot) != 0)
    {
        yatest_err("strcmp(text, www.yadifa.eu) returned !=0 ('%s'!='%s')", text, text_www_yadifa_eu_dot);
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_equals_dnsname_stack_test()
{
    init();
    if(!dnsname_equals_dnsname_stack(fqdn_www_yadifa_eu, &dnsname_stack_www_yadifa_eu))
    {
        yatest_err("dnsname_equals_dnsname_stack returned false");
        return 1;
    }
    if(dnsname_equals_dnsname_stack(fqdn_www_padifa_eu, &dnsname_stack_www_yadifa_eu))
    {
        yatest_err("dnsname_equals_dnsname_stack returned true");
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_under_dnsname_stack_test()
{
    init();
    if(!dnsname_under_dnsname_stack(fqdn_www_yadifa_eu, &dnsname_stack_www_yadifa_eu))
    {
        yatest_err("dnsname_under_dnsname_stack returned false");
        return 1;
    }
    if(dnsname_under_dnsname_stack(fqdn_www_padifa_eu, &dnsname_stack_www_yadifa_eu))
    {
        yatest_err("dnsname_under_dnsname_stack returned true");
        return 1;
    }
    finalise();
    return 0;
}

static int dnsname_stack_push_pop_peek_test()
{
    init();
    dnsname_stack_t fqdn_stack;
    fqdn_stack.size = -1;
    dnsname_stack_push_label(&fqdn_stack, fqdn_eu);
    dnsname_stack_push_label(&fqdn_stack, label_yadifa);
    dnsname_stack_push_label(&fqdn_stack, label_www);
    if(dnsname_stack_peek_label(&fqdn_stack) != label_www)
    {
        yatest_err("dnsname_stack_peek_label didn't point to label_www");
        return 1;
    }

    if(!dnsname_equals_dnsname_stack(fqdn_www_yadifa_eu, &fqdn_stack))
    {
        yatest_err("dnsname_equals_dnsname_stack returned false");
        return 1;
    }
    dnsname_stack_pop_label(&fqdn_stack);
    dnsname_stack_pop_label(&fqdn_stack);
    dnsname_stack_pop_label(&fqdn_stack);
    finalise();
    return 0;
}

static int dnsname_zdup_zfree_test()
{
    init();
    uint8_t *fqdn = dnsname_zdup(fqdn_www_yadifa_eu);
    if(!dnsname_equals(fqdn, fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_zdup didn't duplicate the name");
        return 1;
    }
    dnsname_zfree(fqdn);

    fqdn = dnsname_zdup_from_name(text_www_yadifa_eu_dot);
    if(!dnsname_equals(fqdn, fqdn_www_yadifa_eu))
    {
        yatest_err("dnsname_zdup_from_name didn't duplicate the name");
        return 1;
    }
    dnsname_zfree(fqdn);
    finalise();
    return 0;
}

static int dnslabel_zdup_zfree_test()
{
    init();
    uint8_t *label = dnslabel_zdup(label_yadifa);
    if(!dnslabel_equals(label, label_yadifa))
    {
        yatest_err("dnslabel_zdup didn't duplicate the name");
        return 1;
    }
    dnslabel_zfree(label);

    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(dnsname_is_charspace_test)
YATEST(dnslabel_compare_test)
YATEST(dnslabel_verify_charspace_test)
YATEST(dnsname_verify_charspace_test)
YATEST(dnsname_verify_rname_charspace_test)
YATEST(dnsname_is_rname_charspace_test)
YATEST(dnslabel_locase_verify_charspace_test)
YATEST(dnsname_locase_verify_charspace_test)
YATEST(dnsname_init_with_cstr_locase_test)
YATEST(dnsname_init_check_star_with_cstr_test)
YATEST(dnsname_init_with_charp_test)
YATEST(dnsname_init_with_charp_locase_test)
YATEST(dnsname_init_check_with_charp_locase_test)
YATEST(dnsname_init_check_star_with_charp_test)
YATEST(dnsname_init_check_nostar_with_charp_test)
YATEST(dnsname_init_check_nostar_with_charp_locase_test)
YATEST(dnsname_init_check_star_with_charp_and_origin_test)
YATEST(dnsname_init_check_star_with_charp_and_origin_locase_test)
YATEST(dnsrname_init_check_with_cstr_test)
YATEST(dnsrname_init_check_with_charp_test)
YATEST(cstr_get_dnsname_len_test)
YATEST(cstr_init_with_dnsname_test)
YATEST(dnslabel_equals_test)
YATEST(dnslabel_equals_ignorecase_left1_test)
YATEST(dnslabel_equals_ignorecase_left4_test)
YATEST(dnsname_is_subdomain_test)
YATEST(dnsname_equals_ignorecase3_test)
YATEST(dnsname_len_with_size_test)
YATEST(dnsname_len_checked_with_size_test)
YATEST(dnsname_len_checked_test)
YATEST(dnsname_getdepth_test)
YATEST(dnsname_dup_free_test)
YATEST(dnsname_copy_test)
YATEST(dnsname_copy_checked_test)
YATEST(dnslabel_vector_to_dnsname_test)
YATEST(dnslabel_vector_to_cstr_test)
YATEST(dnsname_vector_sub_to_dnsname_test)
YATEST(dnsname_vector_copy_test)
YATEST(dnsname_vector_len_test)
YATEST(dnslabel_stack_to_dnsname_test)
YATEST(dnslabel_stack_to_cstr_test)
YATEST(dnsname_stack_to_dnsname_test)
YATEST(dnsname_stack_len_test)
YATEST(dnsname_stack_to_cstr_test)
YATEST(dnsname_equals_dnsname_stack_test)
YATEST(dnsname_under_dnsname_stack_test)
YATEST(dnsname_stack_push_pop_peek_test)
YATEST(dnsname_zdup_zfree_test)
YATEST(dnslabel_zdup_zfree_test)
YATEST_TABLE_END
