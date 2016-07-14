################################################################################
#
# Copyright (c) 2011-2016, EURid. All rights reserved.
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

OC=yadifad.conf
OCE=$(OC).example
MC=yadifa.conf
MCE=$(MC).example
KC=keys.conf
KCE=$(KC).example
YI=yadifad.init
YIE=$(YI).example
YS=yadifad.service
YSE=$(YS).example
YC=yadifa
YCE=$(YC).bash_completion
YD=yadifad
YDE=$(YD).bash_completion
BC=/etc/bash_completion.d/

doc_DATA = $(OC) $(MC) $(KC) $(YI) $(YS) $(YDE) $(YCE) \
				yadifad-master.conf.example yadifad-slave.conf.example \
				yadifad.init.debian	yadifad.init.rhel \
				yadifad.logrotate \
				yadifad.service.arch yadifad.service.debian yadifad.service.rhel

noinst_HEADERS = $(OCE) $(MCE) $(KCE) $(YIE) $(YSE) $(YDE) $(YCE) \
				yadifad-master.conf.example yadifad-slave.conf.example \
				yadifad.init.debian yadifad.init.rhel \
				yadifad.logrotate \
				yadifad.service.arch yadifad.service.debian yadifad.service.rhel

$(OC): $(OCE)
	cat $(OCE) | sed "s@\"\(.*\)/var/\(.*\)\"@\"$(localstatedir)/\2\"@" > $(OC)

$(MC): $(MCE)
	cp $(MCE) $(MC)

$(KC): $(KCE)
	cat $(KCE) | sed "s@ChangeThisKey@`head -c 16 /dev/urandom | openssl enc -base64 2>/dev/null`@" > $(KC)

$(YI): $(YIE)
	cat $(YIE) | sed "s@^PREFIX=.*@PREFIX=\"$(prefix)\"@" > $(YI)

$(YS): $(YSE)
	cat $(YSE) | sed -e "s@/usr/sbin@$(sbindir)@g" -e "s@/etc/yadifa@$(sysconfdir)@g" -e "s@/var@$(localstatedir)@g" > $(YS)

$(YC): $(YCE)
	cp $(YCE) $(YC)

$(YD): $(YDE)
	cp $(YDE) $(YD)

all: $(YI) $(OC) $(MC) $(KC) $(YC) $(YD)

install-data-hook: $(OC)
	mkdir -p $(DESTDIR)$(sysconfdir)
	touch $(DESTDIR)$(sysconfdir)/$(OC)
	if [ -d "$(BC)" -a -w "$(BC)" ] ; then cp $(YC) $(YD) $(BC) ; fi

clean-local:
	rm -f $(YI) $(OC) $(MC) $(KC) $(YS) $(YC) $(YD)

release: $(YI) $(OC) $(MC) $(KC) $(YS) $(YC) $(YD)

profile: $(YI) $(OC) $(MC) $(KC) $(YS) $(YC) $(YD)

debug: $(YI) $(OC) $(MC) $(KC) $(YS) $(YC) $(YD)

features:

