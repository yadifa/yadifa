#!/bin/sh
#
# Builds the source using cmake into a
#
# ./gcovr-build.sh
#

BUILD_DIRECTORY="/tmp/yadifa-gcovr"
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

doe()
{
  if [ $? -ne 0 ]; then
    echo "ERROR: $*"
    exit 1
  fi
}

if [ ! "x$1" = "x" ]; then
  BUILD_DIRECTORY="$1"
fi

echo "BUILD_DIRECTORY=$BUILD_DIRECTORY"

which gcovr > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "gcovr is not in the path"
  exit 2
fi

which ninja > /dev/null 2>&1
if [ $? -eq 0 ]; then
  GENERATOR="-G Ninja"
else
  echo "NOTE: consider installing ninja as it reduces the build time to about 10% of an make build"
fi

rm -rf "$BUILD_DIRECTORY"
doe "cleaning-up"

mkdir -p "$BUILD_DIRECTORY"
doe "making '$BUILD_DIRECTORY' directory"
cd $BUILD_DIRECTORY
doe "switching to '$BUILD_DIRECTORY' directory"
cmake $GENERATOR "$SCRIPTPATH" -DCMAKE_BUILD_TYPE=Debug -DDEBUG=0 -DNDEBUG=1 -DWITH_COVERAGE:BOOL=ON -DLOGGING_DISABLED:BOOL=ON
doe "cmake"
T0=$(date +'%s')
cmake --build .
T1=$(date +'%s')
doe "build"
BUILD_TIME=$((T1 - T0))
echo "build took $BUILD_TIME seconds"
ctest -T test --rerun-failed --output-on-failure
mkdir gcovr
# Only excludes tests
#gcovr --filter "$SCRIPTPATH" -e "/.*/tests/" --html gcovr/coverage.html --html-details
# Excludes everything but dnscore
gcovr --filter "$SCRIPTPATH" -e "/.*/tests/" -e "/.*/dnsdb/" -e "/.*/dnslg/" -e "/.*/dnstcl/" -e "/.*/glibchooks/" -e "/.*/bin/yadifa/" -e "/.*/sbin/yadifad/" -e "/.*/sbin/yakeyrolld/" --html gcovr/coverage.html --html-details
