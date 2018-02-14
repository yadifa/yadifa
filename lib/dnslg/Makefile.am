################################################################################
#
# Copyright (c) 2011-2018, EURid vzw. All rights reserved.
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
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
################################################################################
#
#       SVN Program:
#               $URL: https://svn.int.eurid.eu/svn/sysdevel/projects/yadifa/tags/release-2.3.8-public/lib/dnslg/Makefile.am $
#
#       Last Update:
#               $Date: 2018-02-12 10:54:47 +0100 (Mon, 12 Feb 2018) $
#
#               $Revision: 7682 $
#
#       Purpose:
#               YADIFA dnslg Makefile.am script
#
################################################################################

srcdir =        @srcdir@
libdir =        @libdir@
top_srcdir =    @top_srcdir@
VPATH =         @srcdir@

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION

lib_LTLIBRARIES= libdnslg.la

I=include/dnslg

FEATURESFILE=dnslg-config-features.h
FEATURES=$(I)/$(FEATURESFILE)

# alphabetically please

# NOTE: the first one on this list must always be the one used to trigger $(FEATURES)
pkginclude_HEADERS = \
		     $(FEATURES) \
		     include/dnslg/config-load.h \
		     include/dnslg/config-resolver.h \
		     include/dnslg/dns.h \
		     include/dnslg/resolv-conf.h \
		     include/dnslg/resolv.h

libdnslg_la_SOURCES = \
		      src/config-load.c \
		      src/config-resolver.c \
		      src/dns.c \
		      src/resolv-conf.c \
		      src/resolv.c

libdnslg_la_LDFLAGS = -version-info 6:3:0

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

all: REVISION

REVISION:
	(svn info 2>/dev/null;if [ $$? -ne 0 ];then echo "Revision: 0";fi)|grep Revision:|sed 's/^Revision: *//' > REVISION

src/config-resolver.c: features

features: $(FEATURES)

$(FEATURES): config.log REVISION VERSION
	echo "#pragma once" > $(FEATURES)
VP=DNSLG
if HAS_TSIG_SUPPORT
	echo "#define DNSLG_HAS_TSIG_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSLG_HAS_TSIG_SUPPORT 0" >> $(FEATURES)
endif
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

