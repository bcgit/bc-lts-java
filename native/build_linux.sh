#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -e

if [ -z "$JAVA_HOME" ]
then
      echo "\$JAVA_HOME is empty"
      exit 1;
fi


arch=$(uname -i)

#
# Path to architecture based install location.
#
installDir="${SCRIPT_DIR}/target/linux/${arch}"


#
# Remove target dir
#
rm -rf "${SCRIPT_DIR}/target/linux/${arch}"


#
# This may hold settings for a different target so remove it first.
#
rm -f CMakeCache.txt

cmake .

make clean; make;

# Do the actual install so if it fails we can see what is happening.
make install

#
# rather than mess with clean task we remove everything in the install location
# that is not the java native library.
#
#find $installDir -type f ! -name $libName -delete

#
# Using ldd extract the oneapi libs from the native lib's dependency list anf
# copy them into the same directory as the installed native lib while
# compiling a list in depListFileInJavaResources for the java side to read at
# runtime.
#

depListFileInJavaResources="$installDir/deps.list";
touch "$depListFileInJavaResources"

#
## "vaes/libbc-fips-vaes"
#libs=("probe/libbc-probe" "sse/libbc-fips-sse" "avx/libbc-fips-avx");
#for name in "${libs[@]}"; do
#  installedLib="${installDir}/${name}.so"
#  installedLibName="$(basename -- $installedLib)"

#if test -f "$installedLib"; then
#
#ldd "$installedLib" | grep oneapi | awk '{print $3;}' | while read -r oneApiLib; do
#  cp $oneApiLib $installDir
#  echo "${installedLibName}:$(basename -- $oneApiLib)" >> $depListFileInJavaResources
#  done
#else
#  echo "Not found: $installedLibName"
#fi
#done
#
#
##
#sort $depListFileInJavaResources | uniq > "${installDir}/list"
#mv "${installDir}/list" $depListFileInJavaResources




