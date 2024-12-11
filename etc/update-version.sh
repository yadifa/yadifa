#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

version=$(cat $SCRIPTPATH/../VERSION)

cd $SCRIPTPATH

echo version: $version

for f in *.example *.conf
do
	echo processing version of $f
	sed -i -e "s/\"[1-3]\\.[0-9]*[0-9]\\.[0-9]*[0-9]\"/\"$version\"/" -e "s/yadifa-[1-3]\\.[0-9]*[0-9]\\.[0-9]*[0-9]/yadifa-$version/" -e "s/since [1-3]\\.[0-9]*[0-9]\\.[0-9]*[0-9]/since $version/"  $f
done

echo Fixing CMakeLists.txt
sed -i -e "s/read_version(\".*\")/read_version(\"$version\")/" -e "s/set(PACKAGE_VERSION\s.*)/set(PACKAGE_VERSION \"$version\")/" -e "s/set(VERSION\s.*)/set(VERSION \"$version\")/" ../CMakeLists.txt

