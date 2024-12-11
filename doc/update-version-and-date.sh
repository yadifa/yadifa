#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

d=$(date +'%Y-%m-%d')
ed=$(date +'%Y\\-%m\\-%d')
version=$(cat $SCRIPTPATH/../VERSION)

echo version: $version
echo date: $d
echo escaped date: $ed

cd $SCRIPTPATH

for f in *.man
do
	echo processing escaped date of $f
	sed -i "s/20[0-9][0-9]\\\\-[0-9][0-9]\\\\-[0-9][0-9]/$ed/" $f
done

for f in *.tex
do
	echo processing date of $f
	sed -i "s/20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]/$d/" $f
done

for f in *.man *.tex
do
	echo processing version of $f
	sed -i -e "s/Version: [1-3]\\.[0-9]*[0-9]\\.[0-9]*[0-9]/Version: $version/" -e "s/{[1-3]\\.[0-9]*[0-9]\\.[0-9]*[0-9]}/{$version}/" -e "s/\"[1-3]\\.[0-9]*[0-9]\\.[0-9]*[0-9]\"/{$version}/" -e "s/YADIFA [1-3]\\.[0-9]*[0-9]\\.[0-9]*[0-9]/YADIFA $version/" $f
done
