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
################################################################################

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION

sbin_PROGRAMS = yadifad

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
	database-service-zone-save.c \
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
	server-mt.c \
	server.c \
	server_context.c \
	signals.c \
	zone.c

if HAS_NSID_SUPPORT
yadifad_SOURCES += config-nsid.c
endif

noinst_HEADERS = \
	axfr.h \
	config.h \
	config_error.h \
	confs.h \
	database-service-zone-desc-load.h \
	database-service-zone-desc-unload.h \
	database-service-zone-download.h \
	database-service-zone-freeze.h \
	database-service-zone-load.h \
	database-service-zone-mount.h \
	database-service-zone-save.h \
	database-service-zone-unfreeze.h \
	database-service-zone-unload.h \
	database-service-zone-unmount.h \
	database-service.h \
	database.h \
	ixfr.h \
	log_query.h \
	log_statistics.h \
	notify.h \
	poll-util.h \
	process_class_ch.h \
	server-mt.h \
	server.h \
	server_context.h \
	server_error.h \
	signals.h \
	zone.h \
	zone_data.h \
	zone_desc.h

if HAS_CTRL
yadifad_SOURCES +=	config_control.c \
	ctrl.c \
	ctrl_query.c \
	ctrl_zone.c

noinst_HEADERS +=	ctrl.h \
	ctrl_query.h \
	ctrl_zone.h
endif

if HAS_ACL_SUPPORT 
yadifad_SOURCES += acl.c config_acl.c
noinst_HEADERS += config_acl.h
endif

if HAS_RRL_SUPPORT
yadifad_SOURCES += rrl.c
noinst_HEADERS += rrl.h
endif

if HAS_ACL_SUPPORT
noinst_HEADERS += acl.h
endif

if HAS_DYNUPDATE_SUPPORT
yadifad_SOURCES += dynupdate_query_service.c
noinst_HEADERS += dynupdate_query_service.h
endif

if HAS_RRSIG_MANAGEMENT_SUPPORT
yadifad_SOURCES += database-service-zone-resignature.c
noinst_HEADERS += database-service-zone-resignature.h
endif

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

