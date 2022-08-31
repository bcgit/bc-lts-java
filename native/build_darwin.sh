#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


if [ -z "$JAVA_HOME" ]
then
      echo "\$JAVA_HOME is empty"
      exit 1;
fi

set -e

#
# Remove target dir
#
rm -rf "${SCRIPT_DIR}../core/src/main/resources/native/darwin/*"


#
# This may hold settings for a different target so remove it first.
#
rm -f CMakeCache.txt

cmake .

make clean; make; make install

# get installed lib
installedLib=`make install | tail -1 |awk '{print $3;}'`
installDir=$(dirname "$installedLib")
libName=$(basename "$installedLib")

