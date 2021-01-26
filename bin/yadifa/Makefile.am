################################################################################
#
#  Copyright (c) 2011-2021, EURid vzw. All rights reserved.
#  The YADIFA TM software product is provided under the BSD 3-clause license:
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#         * Redistributions of source code must retain the above copyright
#           notice, this list of conditions and the following disclaimer.
#         * Redistributions in binary form must reproduce the above copyright
#           notice, this list of conditions and the following disclaimer in the
#           documentation and/or other materials provided with the distribution.
#         * Neither the name of EURid nor the names of its contributors may be
#           used to endorse or promote products derived from this software
#           without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
################################################################################        

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION

include ../../mk/common-settings.mk

if HAS_TOOLS
if HAS_CTRL

if HAS_YADIFA
AM_CFLAGS += -DHAS_YADIFA=1
endif

AM_CFLAGS += -I$(top_srcdir)/lib/dnscore/include -I$(top_builddir)/lib/dnscore/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnsdb/include -I$(top_builddir)/lib/dnsdb/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnslg/include -I$(top_builddir)/lib/dnslg/include 
AM_CFLAGS += -I$(top_srcdir)/lib/dnstcl/include -I$(top_builddir)/lib/dnstcl/include

bin_PROGRAMS = yadifa

yadifa_LDADD=
#yadifa_LDADD+=$(abs_top_builddir)/lib/dnstcl/libdnstcl.la
yadifa_LDADD+=$(abs_top_builddir)/lib/dnslg/libdnslg.la
yadifa_LDADD+=$(abs_top_builddir)/lib/dnsdb/libdnsdb.la
yadifa_LDADD+=$(abs_top_builddir)/lib/dnscore/libdnscore.la

yadifa_SOURCES  = \
		  main.c \
		  message-viewer-dig.c \
		  message-viewer-json.c \
		  message-viewer-parse.c \
		  message-viewer-wire.c \
		  message-viewer-xml.c \
		  query-result.c \
		  common.c \
		  module.c \
		  ya-conf.c

noinst_HEADERS  = \
		  main.h \
		  client_error.h \
		  common-config.h \
		  message-viewer-dig.h \
		  message-viewer-json.h \
		  message-viewer-parse.h \
		  message-viewer-wire.h \
		  message-viewer-xml.h \
		  query-result.h \
		  common.h \
		  module.h \
		  ya-conf.h

yadifa_SOURCES += module/ctrl.c
noinst_HEADERS += module/ctrl.h

if HAS_ZONESIGN
yadifa_SOURCES += module/zonesign.c
noinst_HEADERS += module/zonesign.h
endif

if HAS_KEYGEN
    yadifa_SOURCES += module/keygen.c
    noinst_HEADERS += module/keygen.h
endif

if HAS_DNSSEC_TOOLS
    yadifa_SOURCES += module/dnssec-tool.c
    noinst_HEADERS += module/dnssec-tool.h
endif

BUILT_SOURCES=client-config.h buildinfo.h

endif

include ../../mk/common-labels.mk

if HAS_TOOLS
client-config.h: ../../config.h
	cp ../../config.h client-config.h

CLEANFILES += client-config.h

endif
endif

features:

