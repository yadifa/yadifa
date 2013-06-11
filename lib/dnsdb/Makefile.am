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

pkginclude_HEADERS = include/dnsdb/dnsdb-config.h include/dnsdb/avl.h include/dnsdb/btree.h include/dnsdb/dictionary.h include/dnsdb/dnskey.h include/dnsdb/dnsrdata.h include/dnsdb/dnssec_config.h include/dnsdb/dnssec_dsa.h include/dnsdb/dnssec.h include/dnsdb/dnssec_keystore.h include/dnsdb/dnssec_rsa.h include/dnsdb/dnssec_scheduler.h include/dnsdb/dnssec_task.h include/dnsdb/dynupdate.h include/dnsdb/hash.h include/dnsdb/htable.h include/dnsdb/htbt.h include/dnsdb/icmtl_input_stream.h include/dnsdb/nsec3_collection.h include/dnsdb/nsec3.h include/dnsdb/nsec3_hash.h include/dnsdb/nsec3_item.h include/dnsdb/nsec3_icmtl.h include/dnsdb/nsec3_load.h include/dnsdb/nsec3_name_error.h include/dnsdb/nsec3_nodata_error.h include/dnsdb/nsec3_owner.h include/dnsdb/nsec3_types.h include/dnsdb/nsec3_update.h include/dnsdb/nsec3_zone.h include/dnsdb/nsec_common.h include/dnsdb/nsec.h include/dnsdb/nsec_collection.h include/dnsdb/rrsig.h include/dnsdb/zdb_alloc.h include/dnsdb/zdb_config.h include/dnsdb/zdb_dnsname.h include/dnsdb/zdb_error.h include/dnsdb/zdb.h include/dnsdb/zdb_icmtl.h include/dnsdb/zdb_listener.h include/dnsdb/zdb_record.h include/dnsdb/zdb_rr_label.h include/dnsdb/zdb_store.h include/dnsdb/zdb_types.h include/dnsdb/zdb_utils.h include/dnsdb/zdb_zone.h include/dnsdb/zdb_zone_label.h include/dnsdb/zdb_zone_label_iterator.h include/dnsdb/zdb_zone_write.h include/dnsdb/zonefile.h include/dnsdb/zdb_sanitize.h include/dnsdb/zdb_zone_load.h include/dnsdb/zdb_zone_load_interface.h

libdnsdb_la_SOURCES = src/avl.c src/dictionary_btree.c src/dictionary.c src/dictionary_htbt.c src/zdb_dnsname.c \
			src/hash.c src/hash_table_values.c src/htable.c src/htbt.c \
			src/zdb_alloc.c src/zdb.c src/zdb_error.c src/zdb_query_ex.c src/zdb_query_ex_wire.c \
			src/zdb_record.c src/zdb_rr_label.c \
			src/zdb_utils.c \
			src/zdb_zone_load.c \
			src/zdb_zone_write_text.c src/zdb_zone_write_unbound.c \
			src/zdb_zone.c src/zdb_zone_label.c src/zdb_zone_label_iterator.c \
			src/zonefile.c src/zdb_store.c \
			src/zdb_zone_update_ixfr.c src/zdb_zone_store_axfr.c \
			src/dynupdate_check_prerequisites.c src/dynupdate_update.c \
			src/dynupdate_icmtlhook.c src/zdb_listener.c src/zdb_icmtl.c src/icmtl_input_stream.c \
			src/scheduler_queue_zone_write.c src/scheduler_queue_zone_write_axfr.c src/scheduler_queue_zone_write_ixfr.c src/scheduler_queue_zone_freeze.c src/scheduler_queue_zone_unfreeze.c src/zdb_sanitize.c
			
# DNSSEC is defined if either NSEC3 or NSEC are defined
			
if HAS_DNSSEC_SUPPORT
libdnsdb_la_SOURCES +=	src/dnssec.c src/dnskey.c src/dnssec_keystore.c src/dnssec_process.c src/dnssec_rsa.c \
			src/rr_canonize.c src/rrsig.c src/rrsig_updater.c \
			src/nsec_common.c \
			src/zdb_update_signatures.c \
			src/scheduler_queue_dnskey_create.c src/scheduler_task_rrsig_update_commit.c
endif
			
if HAS_NSEC3_SUPPORT
libdnsdb_la_SOURCES +=	src/nsec3.c src/nsec3_collection.c src/nsec3_hash.c src/nsec3_item.c src/nsec3_icmtl.c \
			src/nsec3_load.c src/nsec3_name_error.c src/nsec3_nodata_error.c \
			src/nsec3_owner.c src/nsec3_update.c src/nsec3_zone.c \
			src/nsec3_rrsig_updater.c \
			src/scheduler_queue_nsec3_update.c src/scheduler_task_nsec3_rrsig_update_commit.c
endif

if HAS_NSEC_SUPPORT
libdnsdb_la_SOURCES +=	src/nsec.c src/nsec_collection.c
endif

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

