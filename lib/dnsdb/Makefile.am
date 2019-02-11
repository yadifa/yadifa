################################################################################
#
# Copyright (c) 2011-2019, EURid vzw. All rights reserved.
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
##############################################################################
#
#	YADIFA dnsdb Makefile.am script
#
#      	Makefile.am script
#
#	$URL: https://svn.int.eurid.eu/svn/sysdevel/projects/yadifa/tags/release-2.3.9-public/lib/dnsdb/Makefile.am $
#
#       $Date: 2019-02-11 11:02:46 +0100 (Mon, 11 Feb 2019) $
#
#       $Revision: 8497 $
#
#	$Author: ericdf $
#
##############################################################################

srcdir = @srcdir@
libdir = @libdir@
top_srcdir = @top_srcdir@
VPATH = @srcdir@

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION

lib_LTLIBRARIES = libdnsdb.la

I = include/dnsdb

FEATURESFILE=zdb-config-features.h
FEATURES=$(I)/$(FEATURESFILE)

# alphabetically please

pkginclude_HEADERS = \
	$(FEATURES) \
	$(I)/avl.h \
	$(I)/btree.h \
	$(I)/dictionary.h \
	$(I)/dictionary-node.h \
	$(I)/dnsdb-config.h \
	$(I)/dnsrdata.h \
	$(I)/dnssec.h \
	$(I)/dnssec_config.h \
	$(I)/dnssec-keystore.h \
	$(I)/hash.h \
	$(I)/htable.h \
	$(I)/htbt.h \
	$(I)/journal.h \
	$(I)/journal_ix.h \
	$(I)/journal-cjf.h \
	$(I)/journal-cjf-common.h \
	$(I)/journal-cjf-idxt.h \
	$(I)/journal-cjf-page.h \
	$(I)/journal-cjf-page-cache.h \
	$(I)/journal-cjf-page-output-stream.h \
	$(I)/chain-replay.h \
	$(I)/nsec.h \
	$(I)/nsec-chain-replay.h \
	$(I)/nsec3.h \
	$(I)/nsec3_collection.h \
	$(I)/nsec3_hash.h \
	$(I)/nsec3-chain-replay.h \
	$(I)/nsec3_item.h \
	$(I)/nsec3_load.h \
	$(I)/nsec3_name_error.h \
	$(I)/nsec3_nodata_error.h \
	$(I)/nsec3_owner.h \
	$(I)/nsec3_types.h \
	$(I)/nsec3_zone.h \
	$(I)/nsec_collection.h \
	$(I)/nsec_common.h \
	$(I)/rr_canonize.h \
	$(I)/rrsig.h \
	$(I)/xfr_copy.h \
	$(I)/zdb.h \
	$(I)/zdb_config.h \
	$(I)/zdb_error.h \
	$(I)/zdb_icmtl.h \
	$(I)/zdb_record.h \
	$(I)/zdb_rr_label.h \
	$(I)/zdb_sanitize.h \
	$(I)/zdb_types.h \
	$(I)/zdb_utils.h \
	$(I)/zdb_cache.h \
	$(I)/zdb_zone.h \
	$(I)/zdb-lock.h \
	$(I)/zdb-zone-arc.h \
	$(I)/zdb-zone-dnssec.h \
	$(I)/zdb-zone-find.h \
	$(I)/zdb-zone-garbage.h \
	$(I)/zdb-zone-journal.h \
	$(I)/zdb-zone-lock.h \
	$(I)/zdb-zone-lock-monitor.h \
	$(I)/zdb-zone-answer-axfr.h \
	$(I)/zdb-zone-answer-ixfr.h \
	$(I)/zdb-zone-maintenance.h \
	$(I)/zdb-packed-ttlrdata.h \
	$(I)/zdb_zone_axfr_input_stream.h \
	$(I)/zdb_zone_label.h \
	$(I)/zdb_zone_label_iterator.h \
	$(I)/zdb_zone_load.h \
	$(I)/zdb_zone_load_interface.h \
	$(I)/zdb-zone-path-provider.h \
	$(I)/zdb_zone_process.h \
	$(I)/zdb-zone-reader-filter.h \
	$(I)/zdb_zone_write.h \
	$(I)/nsec3-forall-label.h

libdnsdb_la_SOURCES = \
	src/avl.c \
	src/dictionary.c \
	src/dictionary_btree.c \
	src/dictionary_htbt.c \
	src/hash.c \
	src/hash_table_values.c \
	src/htable.c \
	src/htbt.c \
	src/journal-cjf-idxt.c \
	src/journal-cjf-page-cache.c \
	src/journal-cjf-page-output-stream.c \
	src/journal-cjf-page.c \
	src/journal-cjf.c \
	src/journal.c \
	src/journal_ix.c \
	src/xfr_copy.c \
	src/zdb-zone-answer-axfr.c \
	src/zdb-zone-answer-ixfr.c \
	src/zdb-zone-arc.c \
	src/zdb-zone-dnssec.c \
	src/zdb-zone-find.c \
	src/zdb-zone-garbage.c \
	src/zdb-zone-journal.c \
	src/zdb-zone-lock.c \
        src/zdb-zone-lock-monitor.c \
	src/zdb-zone-path-provider.c \
	src/zdb-zone-reader-filter.c \
	src/zdb.c \
	src/zdb_cache.c \
	src/zdb_error.c \
	src/zdb_icmtl.c \
	src/zdb_query_ex.c \
	src/zdb_query_ex_wire.c \
	src/zdb_record.c \
	src/zdb_rr_label.c \
	src/zdb_sanitize.c \
	src/zdb_utils.c \
	src/zdb_zone.c \
	src/zdb_zone_axfr_input_stream.c \
	src/zdb_zone_label.c \
	src/zdb_zone_label_iterator.c \
	src/zdb_zone_load.c \
	src/zdb_zone_process.c \
	src/zdb_zone_store_axfr.c \
	src/zdb_zone_write_text.c \
	src/zdb_zone_write_unbound.c

# DNSSEC is defined if either NSEC3 or NSEC are defined

if HAS_DYNUPDATE_SUPPORT

pkginclude_HEADERS += \
	$(I)/dynupdate.h \
	$(I)/dynupdate-diff.h

libdnsdb_la_SOURCES += \
	src/dynupdate_check_prerequisites.c \
	src/dynupdate-diff.c \
	src/dynupdate-diff-nochain.c \
	src/dynupdate-diff-nsec.c \
	src/dynupdate-diff-nsec3.c \
	src/zdb-zone-maintenance.c \
	src/zdb-zone-maintenance-rrsig.c \
	src/zdb-zone-maintenance-nsec.c \
	src/zdb-zone-maintenance-nsec3.c
endif
			
if HAS_DNSSEC_SUPPORT
libdnsdb_la_SOURCES += \
	src/dnssec.c \
	src/dnssec-keystore.c \
	src/nsec_common.c \
	src/rr_canonize.c \
	src/rrsig.c \
	src/zdb_update_signatures.c \
	src/zdb-packed-ttlrdata.c
endif
			
if HAS_NSEC3_SUPPORT
libdnsdb_la_SOURCES += \
	src/nsec3.c \
	src/nsec3_collection.c \
	src/nsec3_hash.c \
	src/nsec3_item.c \
	src/nsec3-chain-replay.c  \
	src/nsec3_load.c \
	src/nsec3_name_error.c \
	src/nsec3_nodata_error.c \
	src/nsec3_owner.c \
	src/nsec3_zone.c \
	src/nsec3-forall-label.c
endif

if HAS_NSEC_SUPPORT
libdnsdb_la_SOURCES += \
	src/nsec.c \
	src/nsec-chain-replay.c  \
	src/nsec_collection.c
endif

libdnsdb_la_LDFLAGS = -version-info 6:3:0

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

all: REVISION

REVISION:
	(svn info 2>/dev/null;if [ $$? -ne 0 ];then echo "Revision: 0";fi)|grep Revision:|sed 's/^Revision: *//' > REVISION

src/avl.c: $(FEATURES)

features: $(FEATURES)

$(FEATURES): config.log REVISION VERSION
	echo "#pragma once" > $(FEATURES)
if HAS_DNSSEC_SUPPORT
	echo "#define ZDB_HAS_DNSSEC_SUPPORT 1" >> $(FEATURES)
else
	echo "#define ZDB_HAS_DNSSEC_SUPPORT 0" >> $(FEATURES)
endif
if HAS_NSEC_SUPPORT
	echo "#define ZDB_HAS_NSEC_SUPPORT 1" >> $(FEATURES)
else
	echo "#define ZDB_HAS_NSEC_SUPPORT 0" >> $(FEATURES)
endif
if HAS_NSEC3_SUPPORT
	echo "#define ZDB_HAS_NSEC3_SUPPORT 1" >> $(FEATURES)
else
	echo "#define ZDB_HAS_NSEC3_SUPPORT 0" >> $(FEATURES)
endif
if HAS_ACL_SUPPORT
	echo "#define ZDB_HAS_ACL_SUPPORT 1" >> $(FEATURES)
else
	echo "#define ZDB_HAS_ACL_SUPPORT 0" >> $(FEATURES)
endif
if HAS_TSIG_SUPPORT
	echo "#define ZDB_HAS_TSIG_SUPPORT 1" >> $(FEATURES)
else
	echo "#define ZDB_HAS_TSIG_SUPPORT 0" >> $(FEATURES)
endif
if HAS_NSID_SUPPORT
	echo "#define ZDB_HAS_NSID_SUPPORT 1" >> $(FEATURES)
else
	echo "#define ZDB_HAS_NSID_SUPPORT 0" >> $(FEATURES)
endif
if HAS_MUTEX_DEBUG_SUPPORT
	echo "#define ZDB_HAS_MUTEX_DEBUG_SUPPORT 1" >> $(FEATURES)
else
	echo "#define ZDB_HAS_MUTEX_DEBUG_SUPPORT 0" >> $(FEATURES)
endif
VP=DNSDB
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

#if XXX
#	echo "#define ZDB_XXX 1" >> $(FEATURES)
#else
#	echo "#define ZDB_XXX 0" >> $(FEATURES)
#endif

