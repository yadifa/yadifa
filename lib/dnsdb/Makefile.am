################################################################################
#
# Copyright (c) 2011, EURid. All rights reserved.
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
	$(I)/dnssec_keystore.h \
	$(I)/dnssec_scheduler.h \
	$(I)/dnssec_task.h \
	$(I)/dynupdate.h \
	$(I)/hash.h \
	$(I)/htable.h \
	$(I)/htbt.h \
	$(I)/icmtl_input_stream.h \
	$(I)/journal.h \
	$(I)/journal_ix.h \
	$(I)/nsec.h \
	$(I)/nsec3.h \
	$(I)/nsec3_collection.h \
	$(I)/nsec3_hash.h \
	$(I)/nsec3_icmtl.h \
	$(I)/nsec3_item.h \
	$(I)/nsec3_load.h \
	$(I)/nsec3_name_error.h \
	$(I)/nsec3_nodata_error.h \
	$(I)/nsec3_owner.h \
	$(I)/nsec3_rrsig_updater.h \
	$(I)/nsec3_types.h \
	$(I)/nsec3_update.h \
	$(I)/nsec3_zone.h \
	$(I)/nsec_collection.h \
	$(I)/nsec_common.h \
	$(I)/rr_canonize.h \
	$(I)/rrsig.h \
	$(I)/rrsig_updater.h \
	$(I)/zdb.h \
	$(I)/zdb_alloc.h \
	$(I)/zdb_config.h \
	$(I)/zdb_dnsname.h \
	$(I)/zdb_error.h \
	$(I)/zdb_icmtl.h \
	$(I)/zdb_listener.h \
	$(I)/zdb_record.h \
	$(I)/zdb_rr_label.h \
	$(I)/zdb_sanitize.h \
	$(I)/zdb_types.h \
	$(I)/zdb_utils.h \
	$(I)/zdb_zone.h \
	$(I)/zdb-zone-answer-axfr.h \
	$(I)/zdb-zone-answer-ixfr.h \
	$(I)/zdb_zone_axfr_input_stream.h \
	$(I)/zdb_zone_label.h \
	$(I)/zdb_zone_label_iterator.h \
	$(I)/zdb_zone_load.h \
	$(I)/zdb_zone_load_interface.h \
	$(I)/zdb_zone_process.h \
	$(I)/zdb-zone-reader-filter.h \
	$(I)/zdb_zone_write.h

libdnsdb_la_SOURCES = \
	src/avl.c \
	src/dictionary.c \
	src/dictionary_btree.c \
	src/dictionary_htbt.c \
	src/dynupdate_check_prerequisites.c \
	src/dynupdate_icmtlhook.c \
	src/dynupdate_update.c \
	src/hash.c \
	src/hash_table_values.c \
	src/htable.c \
	src/htbt.c \
	src/icmtl_input_stream.c \
	src/journal.c \
	src/journal_ix.c \
	src/zdb.c \
	src/zdb_alloc.c \
	src/zdb_dnsname.c \
	src/zdb_error.c \
	src/zdb_icmtl.c \
	src/zdb_listener.c \
	src/zdb_query_ex.c \
	src/zdb_query_ex_wire.c \
	src/zdb_record.c \
	src/zdb_rr_label.c \
	src/zdb_sanitize.c \
	src/zdb_utils.c \
	src/zdb_zone.c \
	src/zdb-zone-answer-axfr.c \
	src/zdb-zone-answer-ixfr.c \
	src/zdb_zone_axfr_input_stream.c \
	src/zdb_zone_label.c \
	src/zdb_zone_label_iterator.c \
	src/zdb_zone_load.c \
	src/zdb_zone_process.c \
	src/zdb-zone-reader-filter.c \
	src/zdb_zone_store_axfr.c \
	src/zdb_zone_update_ixfr.c \
	src/zdb_zone_write_text.c \
	src/zdb_zone_write_unbound.c

# DNSSEC is defined if either NSEC3 or NSEC are defined
			
libdnsdb_la_SOURCES += \
	src/dnssec.c \
	src/dnssec_keystore.c \
	src/dnssec_process.c \
	src/nsec_common.c \
	src/rr_canonize.c \
	src/rrsig.c \
	src/rrsig_updater.c \
	src/zdb_update_signatures.c
			
libdnsdb_la_SOURCES += \
	src/nsec3.c \
	src/nsec3_collection.c \
	src/nsec3_hash.c \
	src/nsec3_item.c \
	src/nsec3_icmtl.c  \
	src/nsec3_load.c \
	src/nsec3_name_error.c \
	src/nsec3_nodata_error.c \
	src/nsec3_owner.c \
	src/nsec3_rrsig_updater.c \
	src/nsec3_update.c \
	src/nsec3_zone.c

libdnsdb_la_SOURCES += \
	src/nsec.c \
	src/nsec_collection.c

libdnsdb_la_LDFLAGS = -version-info 2:0:0

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

src/avl.c: $(FEATURES)

$(FEATURES): config.log
	echo "#pragma once" > $(FEATURES)
	echo "#define ZDB_HAS_RRCACHE_ENABLED 0" >> $(FEATURES)
	echo "#define ZDB_HAS_DNSSEC_SUPPORT 1" >> $(FEATURES)
	echo "#define ZDB_HAS_NSEC_SUPPORT 1" >> $(FEATURES)
	echo "#define ZDB_HAS_NSEC3_SUPPORT 1" >> $(FEATURES)
	echo "#define ZDB_HAS_ACL_SUPPORT 1" >> $(FEATURES)
	echo "#define ZDB_HAS_TSIG_SUPPORT 1" >> $(FEATURES)

