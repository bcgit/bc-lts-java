#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
#iccVar=`command -v icc`
#if [ -z "${iccVar}" ]
#then

  #
  # Can be installed from: https://www.intel.com/content/www/us/en/developer/tools/oneapi/toolkits.html
  #

#    source /opt/intel/oneapi/setvars.sh intel64
#    source /opt/intel/oneapi/compiler/latest/env/vars.sh

#fi

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

#cmake -DCMAKE_C_COMPILER=icc -DCMAKE_CXX_COMPILER=icpc .

cmake $@ .

make clean; make;

# Do the actual install so if it fails we can see what is happening.
make install


#
# Every assembly source declares .note.GNU-stack, so the libraries link with a
# non-executable stack and need no execstack post-processing. Verify it here so
# a new assembly file that omits the section fails the build instead of
# shipping an executable stack.
#
for target in "target/linux/x86_64/avx/libbc-lts-avx.so" \
              "target/linux/x86_64/vaes/libbc-lts-vaes.so" \
              "target/linux/x86_64/vaesf/libbc-lts-vaesf.so"; do
  if [[ -f "$target" ]]; then
    if readelf -lW "$target" | grep GNU_STACK | grep -q E; then
      echo "ERROR: $target has an executable stack; an assembly source is missing its .note.GNU-stack section"
      exit 1
    fi
    echo "verified non-executable stack: $target"
  else
    echo "Skipping: $target"
  fi
done

#
# rather than mess with clean task we remove everything in the install location
# that is not the java native library.
#
#find $installDir -type f ! -name $libName -delete

exit;

#
# Using ldd extract the oneapi libs from the native lib's dependency list anf
# copy them into the same directory as the installed native lib while
# compiling a list in depListFileInJavaResources for the java side to read at
# runtime.
#

depListFileInJavaResources="$installDir/deps.list";
touch "$depListFileInJavaResources"

## "vaes/libbc-lts-vaes"
libs=("probe/libbc-probe" "avx/libbc-lts-avx" "vaes/libbc-lts-vaes" "vaesf/libbc-lts-vaesf");
for name in "${libs[@]}"; do
  installedLib="${installDir}/${name}.so"
  installedLibName="$(basename -- $installedLib)"

if test -f "$installedLib"; then

#ldd "$installedLib" | grep lib | awk '{print $3;}' | while read -r oneApiLib; do

for oneApiLib in `ldd "$installedLib" | grep lib | awk '{print $3;}'`; do
  echo $oneApiLib $installDir
  cp $oneApiLib $installDir
  echo "${installedLibName}:$(basename -- $oneApiLib)" >> $depListFileInJavaResources
  done
else
  echo "Not found: $installedLibName"
fi
done



sort $depListFileInJavaResources | uniq > "${installDir}/list"
mv "${installDir}/list" $depListFileInJavaResources




