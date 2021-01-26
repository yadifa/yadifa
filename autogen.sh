#!/bin/sh
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

doe()
{
    err=$?
    if [ $err -ne 0 ]
    then
      echo $*
      exit $err
    fi
}

OS=$(uname -s)
SED=sed
if [ ! "$OS" = "Darwin" ]
then
    libtoolize
    doe "libtoolize failed"
else
    glibtoolize
    doe "glibtoolize failed"
    SED=gsed
fi

AM_VER_HI=''
AM_VER_LO=''
AM_VER=$(automake --version|grep ^automake|$SED -e 's/.* //' -e 's/\./ /g')

if [ "x$AM_VER" = "x" ]
then
  echo "could not get automake version"
  exit 1
fi

for i in $AM_VER
do
    if [ "x$AM_VER_HI" = "x" ]
    then
        AM_VER_HI=$i
    else
	AM_VER_LO=$i
        break
   fi
done

if [ $AM_VER_HI -eq 1 ]
then
	if [ $AM_VER_LO -lt 14 ]
	then
		echo 'patching configure.ac for automake < 1.14'
		$SED -i 's/^#.*AM_PROG_CC_C_O/AM_PROG_CC_C_O/' configure.ac
	fi
fi

aclocal
doe "aclocal failed"
autoheader -Wall
doe "autoheader failed"
automake --add-missing -Wall
doe "automake failed"
autoconf -i -Wall
doe "autoconf failed"
#echo "autogen done"
