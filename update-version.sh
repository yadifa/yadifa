#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

cd $SCRIPTPATH

version=$(cat VERSION)

echo version: $version

./doc/update-version-and-date.sh
./etc/update-version.sh

