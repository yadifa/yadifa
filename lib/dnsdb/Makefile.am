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

AM_CFLAGS += -DDNSDB_BUILD=1
AM_CFLAGS += -I$(top_srcdir)/lib/dnscore/include -I$(top_builddir)/lib/dnscore/include

lib_LTLIBRARIES = libdnsdb.la
libdnsdb_la_LDFLAGS = -version-info 10:0:0
libdnsdb_la_LIBADD=$(top_builddir)/lib/dnscore/libdnscore.la

I = include/dnsdb

FEATURESFILE=zdb_config_features.h
FEATURES=$(I)/$(FEATURESFILE)
FEATURESDIR=lib/dnsdb/include/dnsdb
FEATURESSRC=$(top_builddir)/$(FEATURESDIR)/dnsdb_config.h

# libdnsdb_ladir=.

# alphabetically please

pkgincludedir = $(includedir)/dnsdb
pkginclude_HEADERS = \
	$(I)/avl.h \
	$(I)/btree.h \
	$(I)/dictionary.h \
	$(I)/dictionary_node.h \
	$(I)/dnsrdata.h \
	$(I)/dnssec.h \
	$(I)/dnssec_config.h \
	$(I)/dnssec_keystore.h \
	$(I)/htable.h \
	$(I)/htbt.h \
	$(I)/journal.h \
	$(I)/journal_ix.h \
	$(I)/journal_jnl.h \
	$(I)/journal_cjf.h \
	$(I)/journal_cjf_common.h \
	$(I)/journal_cjf_idxt.h \
	$(I)/journal_cjf_page_output_stream.h \
	$(I)/journal_cjf_page.h \
	$(I)/journal_cjf_page_cache.h \
	$(I)/chain_replay.h \
	$(I)/nsec.h \
	$(I)/nsec_chain_replay.h \
	$(I)/nsec3.h \
	$(I)/nsec3_collection.h \
	$(I)/nsec3_chain_replay.h \
	$(I)/nsec3_item.h \
	$(I)/nsec3_load.h \
	$(I)/nsec3_owner.h \
	$(I)/nsec3_types.h \
	$(I)/nsec3_zone.h \
	$(I)/nsec_collection.h \
	$(I)/nsec_common.h \
	$(I)/rrsig.h \
	$(I)/xfr_copy.h \
	$(I)/zdb.h \
	$(I)/zdb_config.h \
	$(I)/zdb_error.h \
	$(I)/zdb_icmtl.h \
	$(I)/zdb_query_to_wire_append.h \
	$(I)/zdb_query_to_wire_append_nsec3.h \
	$(I)/zdb_query_to_wire_append_nsec.h \
	$(I)/zdb_query_to_wire_append_soa.h \
	$(I)/zdb_query_to_wire_append_type_rrsigs.h \
	$(I)/zdb_query_to_wire_context.h \
	$(I)/zdb_query_to_wire.h \
	$(I)/zdb_record.h \
	$(I)/zdb_rr_label.h \
	$(I)/zdb_sanitize.h \
	$(I)/zdb_types.h \
	$(I)/zdb_cache.h \
	$(I)/zdb_zone.h \
	$(I)/zdb_lock.h \
	$(I)/zdb_zone_arc.h \
	$(I)/zdb_zone_dnssec.h \
	$(I)/zdb_zone_find.h \
	$(I)/zdb_zone_garbage.h \
	$(I)/zdb_zone_journal.h \
	$(I)/zdb_zone_lock.h \
	$(I)/zdb_zone_lock_monitor.h \
	$(I)/zdb_zone_answer_axfr.h \
	$(I)/zdb_zone_answer_ixfr.h \
	$(I)/zdb_zone_maintenance.h \
	$(I)/zdb_ttlrdata.h \
	$(I)/zdb_packed_ttlrdata.h \
	$(I)/zdb_zone_axfr_input_stream.h \
	$(I)/zdb_zone_label.h \
	$(I)/zdb_zone_label_iterator.h \
	$(I)/zdb_zone_label_iterator_ex.h \
	$(I)/zdb_zone_load.h \
	$(I)/zdb_zone_path_provider.h \
	$(I)/zdb_zone_process.h \
	$(I)/zdb_zone_reader_filter.h \
	$(I)/zdb_zone_resource_record.h \
	$(I)/zdb_zone_resource_record_set.h \
	$(I)/zdb_zone_resource_record_sets.h \
	$(I)/zdb_zone_write.h \
	$(I)/nsec3_forall_label.h


libdnsdb_la_SOURCES = \
	src/avl.c \
	src/dictionary.c \
	src/dictionary_btree.c \
	src/dictionary_htbt.c \
	src/htable.c \
	src/htbt.c \
	src/journal.c \
	src/journal_ix.c \
	src/journal_cjf.c \
	src/journal_cjf_idxt.c \
	src/journal_cjf_page.c \
	src/journal_cjf_page_cache.c \
	src/journal_cjf_page_output_stream.c \
	src/journal_cjf_ro.c \
	src/journal_jnl.c \
	src/xfr_copy.c \
	src/zdb_zone_answer_axfr.c \
	src/zdb_zone_answer_ixfr.c \
	src/zdb_zone_arc.c \
	src/zdb_zone_dnssec.c \
	src/zdb_zone_find.c \
	src/zdb_zone_garbage.c \
	src/zdb_zone_journal.c \
	src/zdb_zone_lock.c \
	src/zdb_zone_lock_monitor.c \
	src/zdb_zone_path_provider.c \
	src/zdb_zone_reader_filter.c \
	src/zdb_zone_resource_record.c \
	src/zdb_zone_resource_record_set.c \
	src/zdb_zone_resource_record_sets.c \
	src/zdb_zone_resource_record_sets_collection.c \
	src/zdb.c \
	src/zdb_cache.c \
	src/zdb_error.c \
	src/zdb_icmtl.c \
	src/zdb_query_to_wire_append.c \
	src/zdb_query_to_wire_append_nsec3.c \
	src/zdb_query_to_wire_append_nsec.c \
	src/zdb_query_to_wire_append_soa.c \
	src/zdb_query_to_wire_append_type_rrsigs.c \
	src/zdb_query_to_wire.c \
	src/zdb_record.c \
	src/zdb_rr_label.c \
	src/zdb_sanitize.c \
	src/zdb_zone.c \
	src/zdb_zone_axfr_input_stream.c \
	src/zdb_zone_label.c \
	src/zdb_zone_label_iterator.c \
	src/zdb_zone_label_iterator_ex.c \
	src/zdb_zone_load.c \
	src/zdb_zone_process.c \
	src/zdb_zone_store_axfr.c \
	src/zdb_zone_write_text.c \
	src/zdb_zone_write_unbound.c

BUILT_SOURCES = $(FEATURES)

# DNSSEC is defined if either NSEC3 or NSEC are defined

if HAS_PRIMARY_SUPPORT

pkginclude_HEADERS += \
	$(I)/dynupdate.h \
	$(I)/dynupdate_diff.h \
	$(I)/dynupdate_message.h

libdnsdb_la_SOURCES += \
	src/dynupdate_check_prerequisites.c \
	src/dynupdate_diff.c \
	src/dynupdate_message.c \
	src/dynupdate_diff_nochain.c \
	src/dynupdate_diff_nsec.c \
	src/dynupdate_diff_nsec3.c \
	src/zdb_zone_maintenance.c \
	src/zdb_zone_maintenance_rrsig.c \
	src/zdb_zone_maintenance_nsec.c \
	src/zdb_zone_maintenance_nsec3.c
endif

libdnsdb_la_SOURCES += \
	src/dnssec.c \
	src/dnssec_keystore.c \
	src/nsec_common.c \
	src/rrsig.c \
	src/zdb_packed_ttlrdata.c
			
libdnsdb_la_SOURCES += \
	src/nsec3.c \
	src/nsec3_collection.c \
	src/nsec3_item.c \
	src/nsec3_chain_replay.c  \
	src/nsec3_load.c \
	src/nsec3_owner.c \
	src/nsec3_zone.c \
	src/nsec3_forall_label.c

libdnsdb_la_SOURCES += \
	src/nsec.c \
	src/nsec_chain_replay.c  \
	src/nsec_collection.c

include ../../mk/common_labels.mk

all: $(FEATURESSRC)

$(srcdir)/src/avl.c: $(FEATURES) $(FEATURESSRC)

$(FEATURESSRC): ../../config.h
	mkdir -p $(top_builddir)/$(FEATURESDIR)
	cp ../../config.h $(FEATURESSRC)

CLEANFILES += $(FEATURESSRC)

features: $(FEATURES)

$(FEATURES): ../../config.log ../../VERSION $(FEATURESSRC)
VP=ZDB
	mkdir -p $(I)
	echo "#pragma once" > $(FEATURES)
	grep "^#define" $(FEATURESSRC) | sed -e 's/^#define /#define $(VP)_/' >> $(FEATURES)
	echo '#undef $(VP)_VERSION' >> $(FEATURES)

	echo "// $(FEATURES)" >> $(FEATURES)
	echo >> $(FEATURES)

install-data-local: $(FEATURES)
	mkdir -p $(DESTDIR)$(prefix)/include/dnsdb
	/usr/bin/install -c -m 644 $(FEATURES) $(DESTDIR)$(prefix)/$(FEATURES)

