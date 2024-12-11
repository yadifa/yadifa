################################################################################
#
# Copyright (c) 2011-2024, EURid vzw. All rights reserved.
# The YADIFA TM software product is provided under the BSD 3-clause license:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#        * Redistributions of source code must retain the above copyright
#          notice, this list of conditions and the following disclaimer.
#        * Redistributions in binary form must reproduce the above copyright
#          notice, this list of conditions and the following disclaimer in the
#          documentation and/or other materials provided with the distribution.
#        * Neither the name of EURid nor the names of its contributors may be
#          used to endorse or promote products derived from this software
#          without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
################################################################################

ACLOCAL_AMFLAGS = -I m4

include ../../mk/common_settings.mk

AM_CFLAGS += -DDNSLG_BUILD=1

AM_CFLAGS += -I$(top_srcdir)/lib/dnscore/include -I$(top_builddir)/lib/dnscore/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnsdb/include -I$(top_builddir)/lib/dnsdb/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnslg/include -I$(top_builddir)/lib/dnslg/include 
#AM_CFLAGS += -I$(top_srcdir)/lib/dnstcl/include -I$(top_builddir)/lib/dnstcl/include

lib_LTLIBRARIES= libdnslg.la
libdnslg_la_LDFLAGS = -version-info 10:0:0
libdnslg_la_LIBADD=$(top_builddir)/lib/dnscore/libdnscore.la

I=include/dnslg

FEATURESFILE=dnslg_config_features.h
FEATURES=$(I)/$(FEATURESFILE)
FEATURESDIR=lib/dnslg/include/dnslg
FEATURESSRC=$(top_builddir)/$(FEATURESDIR)/dnslg_config.h

# libdnslg_ladir=.

# alphabetically please

pkgincludedir = $(includedir)/dnslg
pkginclude_HEADERS = \
	include/dnslg/config_load.h \
	include/dnslg/config_resolver.h \
	include/dnslg/dns.h \
	include/dnslg/resolv_conf.h \
	include/dnslg/resolv.h


libdnslg_la_SOURCES = \
		      src/config_load.c \
		      src/config_resolver.c \
		      src/dns.c \
		      src/resolv_conf.c \
		      src/resolv.c

BUILT_SOURCES = $(FEATURES)

include ../../mk/common_labels.mk

all: $(FEATURESSRC)

$(srcdir)/src/config_load.c: $(FEATURES) $(FEATURESSRC)

$(FEATURESSRC): ../../config.h
	mkdir -p $(top_builddir)/$(FEATURESDIR)
	cp ../../config.h $(FEATURESSRC)

CLEANFILES += $(FEATURESSRC)

features: $(FEATURES)

$(FEATURES): ../../config.log ../../VERSION $(FEATURESSRC)
VP=DNSLG
	mkdir -p $(I)
	echo "#pragma once" > $(FEATURES)
	grep "^#define" $(FEATURESSRC) | sed -e 's/^#define /#define $(VP)_/' >> $(FEATURES)
	echo '#undef $(VP)_VERSION' >> $(FEATURES)

	echo "// $(FEATURES)" >> $(FEATURES)
	echo >> $(FEATURES)

install-data-local: $(FEATURES)
	mkdir -p $(DESTDIR)$(prefix)/include/dnslg
	/usr/bin/install -c -m 644 $(FEATURES) $(DESTDIR)$(prefix)/$(FEATURES)

