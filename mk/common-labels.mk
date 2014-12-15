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

YCFLAGS=$(YSCFLAGS)

YLDFLAGS=$(YNLDFLAGS)

release:
	echo YCFLAGS=$(YRCFLAGS)
	echo YLDFLAGS=$(YRLDFLAGS)
	$(MAKE) all "YCFLAGS=$(YRCFLAGS)" "YLDFLAGS=$(YRLDFLAGS)"

profile:
	echo YCFLAGS=$(YPCFLAGS)
	echo YLDFLAGS=$(YPLDFLAGS)
	$(MAKE) all "YCFLAGS=$(YPCFLAGS)" "YLDFLAGS=$(YPLDFLAGS)"

debug:
	echo YCFLAGS=$(YDCFLAGS)
	echo YLDFLAGS=$(YDLDFLAGS)
	$(MAKE) all "YCFLAGS=$(YDCFLAGS)" "YLDFLAGS=$(YDLDFLAGS)"

rebuild: clean debug

buildinfo.h: config.log
	echo \#pragma once > buildinfo.h 2> /dev/null
	echo // generated file, do not modify >> buildinfo.h 2> /dev/null
	echo \#define BUILD_OPTIONS \"$$(grep "./configure" config.log | head -1 | sed 's/.*\.\/configure *//')\" >> buildinfo.h 2> /dev/null

