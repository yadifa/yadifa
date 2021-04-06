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

include ../../mk/common-settings.mk

AM_CFLAGS += -DDNSLG_BUILD=1

AM_CFLAGS += -I$(top_srcdir)/lib/dnscore/include -I$(top_builddir)/lib/dnscore/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnsdb/include -I$(top_builddir)/lib/dnsdb/include
#AM_CFLAGS += -I$(top_srcdir)/lib/dnslg/include -I$(top_builddir)/lib/dnslg/include 
#AM_CFLAGS += -I$(top_srcdir)/lib/dnstcl/include -I$(top_builddir)/lib/dnstcl/include

dist_noinst_DATA = VERSION

lib_LTLIBRARIES= libdnslg.la
libdnslg_la_LDFLAGS = -version-info 7:4:0
libdnslg_la_LIBADD=$(top_builddir)/lib/dnscore/libdnscore.la

I=include/dnslg

FEATURESFILE=dnslg-config-features.h
FEATURES=$(I)/$(FEATURESFILE)
FEATURESDIR=lib/dnslg/include/dnslg
FEATURESSRC=$(top_builddir)/$(FEATURESDIR)/dnslg-config.h

# libdnslg_ladir=.

# alphabetically please

pkgincludedir = $(includedir)/dnslg

# NOTE: the first one on this list must always be the one used to trigger $(FEATURES)
pkginclude_HEADERS = \
		     include/dnslg/config-load.h \
		     include/dnslg/config-resolver.h \
		     include/dnslg/dns.h \
		     include/dnslg/resolv-conf.h \
		     include/dnslg/resolv.h

nodist_include_HEADERS = $(FEATURES)

libdnslg_la_SOURCES = \
		      src/config-load.c \
		      src/config-resolver.c \
		      src/dns.c \
		      src/resolv-conf.c \
		      src/resolv.c


include ../../mk/common-labels.mk

all: REVISION $(FEATURESSRC)

REVISION:
	(svn info 2>/dev/null;if [ $$? -ne 0 ];then echo "Revision: 0";fi)|grep Revision:|sed 's/^Revision: *//' > REVISION

$(srcdir)/src/config-load.c: $(FEATURES) $(FEATURESSRC)

$(FEATURESSRC): ../../config.h
	mkdir -p $(top_builddir)/$(FEATURESDIR)
	cp ../../config.h $(FEATURESSRC)

CLEANFILES += $(FEATURESSRC)

features: $(FEATURES)

$(FEATURES): ../../config.log REVISION VERSION $(FEATURESSRC)
VP=DNSLG
	mkdir -p $(I)
	echo "#pragma once" > $(FEATURES)
	grep "^#define" $(FEATURESSRC) | sed -e 's/^#define /#define $(VP)_/' >> $(FEATURES)
	echo '#undef $(VP)_VERSION' >> $(FEATURES)

	which printf > /dev/null 2>&1
	if [ $$? -eq 0 ];then \
		printf '// version %i.%i.%i.%i-%i\n' $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2 \3/') 0 $$(cat REVISION) >> $(FEATURES) ; \
		printf '#define $(VP)_VERSION 0x%02x%02x%02x%02x%04xLL' $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2 \3/') 0 $$(cat REVISION) >> $(FEATURES) ; \
	else \
		echo "#define $(VP)_VERSION_(vmain_,vsub_,vminor_,vpatch_,vrevision_) ((vmain_)<<40)|((vsub_)<<32)|((vminor_)<<24)|((vpatch_)<<16)|(vrevision_)" >> $(FEATURES) ; \
		echo "#define $(VP)_VERSION_VMAIN_ $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1')" >> $(FEATURES) ; \
		echo "#define $(VP)_VERSION_VSUB_ $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\2')" >> $(FEATURES) ; \
		echo "#define $(VP)_VERSION_VMINOR_ $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\3')" >> $(FEATURES) ; \
		echo "#define $(VP)_VERSION_VPATCH_ 0 >> $(FEATURES)" ; \
		echo "#define $(VP)_VERSION_VREVISION_ $$(cat REVISION)" >> $(FEATURES) ; \
		echo '#define $(VP)_VERSION $(VP)_VERSION_($(VP)_VERSION_VMAIN_,$(VP)_VERSION_VSUB_,$(VP)_VERSION_VMINOR_,$(VP)_VERSION_VPATCH_,$(VP)_VERSION_VREVISION_)' >> $(FEATURES) ; \
	fi
	echo "// $(FEATURES)" >> $(FEATURES)
	echo >> $(FEATURES)
