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

ACLOCAL_AMFLAGS = -I ../../m4

include ../../mk/common-settings.mk

BUILT_SOURCES=buildinfo.h server-config.h

dist_noinst_DATA = VERSION

sbin_PROGRAMS = yadifad

AM_CFLAGS += -I$(top_srcdir)/lib/dnscore/include -I$(top_builddir)/lib/dnscore/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnsdb/include -I$(top_builddir)/lib/dnsdb/include
AM_CFLAGS += -I$(top_srcdir)/lib/dnstcl/include -I$(top_builddir)/lib/dnstcl/include

yadifad_LDADD=
yadifad_LDADD+=$(abs_top_builddir)/lib/dnsdb/libdnsdb.la
yadifad_LDADD+=$(abs_top_builddir)/lib/dnscore/libdnscore.la

yadifad_SOURCES = \
	main.c \
	axfr.c \
	config_main.c \
	config_zone.c \
	confs.c \
	database-service-zone-desc-load.c \
	database-service-zone-desc-unload.c \
	database-service-zone-download.c \
	database-service-zone-freeze.c \
	database-service-zone-load.c \
	database-service-zone-mount.c \
	database-service-zone-store.c \
	database-service-zone-unfreeze.c \
	database-service-zone-unload.c \
	database-service-zone-unmount.c \
	database-service.c \
	database.c \
	ixfr.c \
	log_query.c \
	log_statistics.c \
	notify.c \
	poll-util.c \
	process_class_ch.c \
	server-sm.c \
	server.c \
	server_context.c \
	server_process_message_udp.c \
	signals.c \
	zone.c

yadifad_DEPENDENCIES = server-config.h buildinfo.h

noinst_HEADERS = \
	axfr.h \
	config_error.h \
	confs.h \
	database-service-zone-desc-load.h \
	database-service-zone-desc-unload.h \
	database-service-zone-download.h \
	database-service-zone-freeze.h \
	database-service-zone-load.h \
	database-service-zone-mount.h \
	database-service-zone-store.h \
	database-service-zone-unfreeze.h \
	database-service-zone-unload.h \
	database-service-zone-unmount.h \
	database-service.h \
	database.h \
	dnssec-policy.h \
	ixfr.h \
	log_query.h \
	log_statistics.h \
	notify.h \
	poll-util.h \
	process_class_ch.h \
	server-sm.h \
	server.h \
	server_context.h \
	server_error.h \
	signals.h \
	zone.h \
	zone_desc.h \
	zone-source.h

yadifad_SOURCES += server-rw.c
noinst_HEADERS += server-rw.h

if HAVE_SENDMMSG
if IS_LINUX_FAMILY
yadifad_SOURCES += server-mm.c
noinst_HEADERS += server-mm.h
endif
endif
	
if HAS_EVENT_DYNAMIC_MODULE
yadifad_SOURCES += dynamic-module-handler.c
noinst_HEADERS += dynamic-module-handler.h
# pkgincludedir is already defined to $(includedir)/yadifa (as the package name is yadifa)
# pkgincludedir = $(includedir)/yadifad
pkginclude_HEADERS = dynamic-module-interface.h
endif

if HAS_NSID_SUPPORT
yadifad_SOURCES += config-nsid.c
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
if HAS_MASTER_SUPPORT
yadifad_SOURCES += database-service-zone-resignature.c \
    config-denial.c \
    config-dnssec-policy.c \
    config-key-roll.c \
    config-key-suite.c \
    config-key-template.c \
    config-key-roll-parser.c \
    zone-signature-policy.c \
    zone-signature-date-next.c \
    zone-signature-date-prev.c

noinst_HEADERS += database-service-zone-resignature.h \
    config-dnssec-policy.h \
    config-key-roll-parser.h \
    zone-signature-policy.h
endif
endif

dist_noinst_DATA += contributions/20170225-libressl-detection-and-fix.patch \
 contributions/20190112-escape-character-fix.patch \
 contributions/20190112-txt-record-parsing-improvements.patch \
 contributions/20190323-yadifa-2.3.9-pmtudisc_omit.patch \
 contributions/20190911-sighup-crash-fix.patch \
 contributions/20201106-musl-support.patch \
 contributions/20210301-dynupdate-error-code.patch



include ../../mk/common-labels.mk

server-config.h: ../../config.h
	cp ../../config.h server-config.h

CLEANFILES += server-config.h

features:

