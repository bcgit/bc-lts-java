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
# execstack is found in the prelink package on ubuntu
# sudo apt install prelink
#

if [ -x "$(command -v execstack)" ]; then

echo "Execstack:"

targets=( "target/linux/x86_64/avx/libbc-lts-avx.so" "target/linux/x86_64/vaes/libbc-lts-vaes.so" "target/linux/x86_64/vaesf/libbc-lts-vaesf.so" )

for target in "${targets[@]}"
do
  if [[ -f "$target" ]]; then
     execstack -c "$target"
     echo "applied execstack to $target"
  else
    echo "Skipping: $target"
  fi

done

else
echo ""
echo "!! WARNING !!"
echo "!! 'execstack' is not install on this build host"
echo "!! For release builds make sure the build host has the 'prelink' package installed"
echo "!! The JVM will report a stackguard warning without it"
echo "!! For general testing this is probably ok but if you can install it then do"
echo ""
fi

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




