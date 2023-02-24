#!/bin/sh
################################################################################
#
#  Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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

if [ "x$DEBUG" = "x" ]; then
    DEBUG=0
fi

debug()
{
    if [ $DEBUG -ne 0 ]; then
        echo $*
    fi
}

doe()
{
    err=$?
    if [ $err -ne 0 ]; then
      echo $*
      exit $err
    fi
}

OS=$(uname -s)

if [ ! "$OS" = "Darwin" ]; then
    SED=sed
else
    SED=gsed
fi

debug "autogen starting with OS='$OS'"

AM_VER_HI=''
AM_VER_LO=''
AM_VER=$(automake --version|grep ^automake|$SED -e 's/.* //' -e 's/\./ /g')

if [ "x$AM_VER" = "x" ]; then
  echo "could not get automake version"
  exit 1
fi

for i in $AM_VER
do
    if [ "x$AM_VER_HI" = "x" ]; then
        AM_VER_HI=$i
    else
	AM_VER_LO=$i
        break
    fi
done

debug "automake version <$AM_VER_HI . $AM_VER_LO>"

AC_VER_HI=''
AC_VER_LO=''
AC_VER=$(autoconf --version|grep ^autoconf|$SED -e 's/.* //' -e 's/\./ /g')

if [ "x$AC_VER" = "x" ]; then
  echo "could not get autoconf version"
  exit 1
fi

for i in $AC_VER
do
    if [ "x$AC_VER_HI" = "x" ]
    then
        AC_VER_HI=$i
    else
	AC_VER_LO=$i
        break
   fi
done

debug "autoconf version <$AC_VER_HI . $AC_VER_LO>"

####

if [ $AM_VER_HI -eq 1 ]; then
	if [ $AM_VER_LO -lt 14 ]; then
		echo 'patching configure.ac for automake < 1.14'
		$SED -i 's/^#.*AM_PROG_CC_C_O/AM_PROG_CC_C_O/' configure.ac
	fi
fi

if [ $AC_VER_HI -eq 2 ]
then
	echo "patching prerequisites"
	$SED -i "s/^AC_PREREQ.*/AC_PREREQ([$AC_VER_HI.$AC_VER_LO])/" configure.ac

	if [ $AC_VER_LO -lt 60 ]; then
		for f in $(find . -name \*.m4)
		do
			grep AS_HELP_STRING $f > /dev/null 2>&1
			if [ $? -eq 0 ]; then debug "patching $f for AC_HELP_STRING usage";fi
			$SED -i 's/AS_HELP_STRING/AC_HELP_STRING/' $f
		done
	else
		for f in $(find . -name \*.m4)
		do
			grep AC_HELP_STRING $f > /dev/null 2>&1
			if [ $? -eq 0 ]; then debug "patching $f for AS_HELP_STRING usage";fi
			$SED -i 's/AC_HELP_STRING/AS_HELP_STRING/' $f
		done
	fi
fi

if [ ! "$OS" = "Darwin" ]; then
    debug "libtoolize"
    libtoolize --force
    doe "libtoolize failed"
else
    debug "glibtoolize (OSX)"
    glibtoolize
    doe "glibtoolize failed"
fi

debug "aclocal"
aclocal
doe "aclocal failed"

debug "autoheader"
autoheader -Wall
doe "autoheader failed"

debug "automake"
automake --add-missing -Wall
doe "automake failed"

debug "autoconf"
autoconf -i -Wall
doe "autoconf failed"

debug "autogen done"

