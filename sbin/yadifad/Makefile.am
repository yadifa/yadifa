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

ACLOCAL_AMFLAGS = -I ../../m4

include ../../mk/common_settings.mk

BUILT_SOURCES=buildinfo.h server_config.h

sbin_PROGRAMS = yadifad

AM_CFLAGS += -I$(top_srcdir)/lib/dnscore/include -I$(top_builddir)/lib/dnscore/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnsdb/include -I$(top_builddir)/lib/dnsdb/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnstcl/include -I$(top_builddir)/lib/dnstcl/include

yadifad_LDADD=
yadifad_LDADD+=$(abs_top_builddir)/lib/dnsdb/libdnsdb.la
yadifad_LDADD+=$(abs_top_builddir)/lib/dnscore/libdnscore.la

yadifad_SOURCES = \
    main.c \
	yadifad.c \
	axfr.c \
	config_main.c \
    config_rndc.c \
	config_zone.c \
	confs.c \
	database_service_zone_desc_load.c \
	database_service_zone_desc_unload.c \
	database_service_zone_download.c \
	database_service_zone_freeze.c \
	database_service_zone_load.c \
	database_service_zone_mount.c \
	database_service_zone_store.c \
	database_service_zone_unfreeze.c \
	database_service_zone_unload.c \
	database_service_zone_unmount.c \
	database_service.c \
	database.c \
	ixfr.c \
	log_query.c \
	log_statistics.c \
	notify.c \
	poll_util.c \
	process_class_ch.c \
	server_sm.c \
	server.c \
	server_context.c \
    server_dns_tcp.c \
    server_dns_tls.c \
	server_process_message_common.c \
	server_process_message_udp.c \
	server_process_message_tcp.c \
    server_rndc.c \
	signals.c \
	zone.c

yadifad_DEPENDENCIES = server_config.h buildinfo.h

noinst_HEADERS = \
    yadifad.h \
	axfr.h \
	config_error.h \
	confs.h \
	database_service_zone_desc_load.h \
	database_service_zone_desc_unload.h \
	database_service_zone_download.h \
	database_service_zone_freeze.h \
	database_service_zone_load.h \
	database_service_zone_mount.h \
	database_service_zone_store.h \
	database_service_zone_unfreeze.h \
	database_service_zone_unload.h \
	database_service_zone_unmount.h \
	database_service.h \
	database.h \
	dnssec_policy.h \
	ixfr.h \
	log_query.h \
	log_statistics.h \
	notify.h \
	poll_util.h \
	process_class_ch.h \
	server_sm.h \
	server.h \
	server_context.h \
	server_dns_tcp.h \
    server_dns_tls.h \
	server_error.h \
	server_process_message_common.h \
    server_rndc.h \
	signals.h \
	zone.h \
	zone_desc.h \
	zone_source.h

yadifad_SOURCES += server_rw.c
noinst_HEADERS += server_rw.h

if HAVE_SENDMMSG
#if IS_LINUX_FAMILY (note: now works on FreeBSD 13.2)
yadifad_SOURCES += server_mm.c
noinst_HEADERS += server_mm.h
#endif
endif
	
if HAS_EVENT_DYNAMIC_MODULE
yadifad_SOURCES += dynamic_module_handler.c
noinst_HEADERS += dynamic_module_handler.h
# pkgincludedir is already defined to $(includedir)/yadifa (as the package name is yadifa)
# pkgincludedir = $(includedir)/yadifad
pkginclude_HEADERS = dynamic_module_interface.h
endif

if HAS_NSID_SUPPORT
yadifad_SOURCES += config_nsid.c
endif

if HAS_CTRL

yadifad_SOURCES += config_control.c \
	ctrl.c \
	ctrl_query.c \
	ctrl_zone.c

noinst_HEADERS += ctrl.h ctrl_query.h ctrl_zone.h

yadifad_SOURCES += ctrl_notify.c \
	ctrl_query_axfr.c \
	ctrl_query_message.c \
	ctrl_update.c

noinst_HEADERS += ctrl_notify.h \
	ctrl_query_axfr.h \
	ctrl_query_message.h \
	ctrl_update.h

endif # HAS_CTRL

if HAS_RRL_SUPPORT
yadifad_SOURCES += rrl.c
noinst_HEADERS += rrl.h
endif

if HAS_DYNUPDATE_SUPPORT
yadifad_SOURCES += dynupdate_query_service.c
noinst_HEADERS += dynupdate_query_service.h
endif

if HAS_RRSIG_MANAGEMENT_SUPPORT
if HAS_PRIMARY_SUPPORT
yadifad_SOURCES += database_service_zone_resignature.c \
    config_denial.c \
    config_dnssec_policy.c \
    config_key_roll.c \
    config_key_suite.c \
    config_key_template.c \
    config_key_roll_parser.c \
    zone_signature_policy.c \
    zone_signature_date_next.c \
    zone_signature_date_prev.c

noinst_HEADERS += database_service_zone_resignature.h \
    config_dnssec_policy.h \
    config_key_roll_parser.h \
    zone_signature_policy.h
endif
endif

dist_noinst_DATA = contributions/20170225-libressl-detection-and-fix.patch \
 contributions/20190112-escape-character-fix.patch \
 contributions/20190112-txt-record-parsing-improvements.patch \
 contributions/20190323-yadifa-2.3.9-pmtudisc_omit.patch \
 contributions/20190911-sighup-crash-fix.patch \
 contributions/20201106-musl-support.patch \
 contributions/20210301-dynupdate-error-code.patch \
 contributions/20210810-null-tsig-crash-fix.patch

include ../../mk/common_labels.mk

server_config.h: ../../config.h
	cp ../../config.h server_config.h

CLEANFILES += server_config.h

features:

