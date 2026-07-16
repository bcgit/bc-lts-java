#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#
# Builds the native libraries for ARM64 (aarch64) Linux.
#
#   * On an ARM64 host it builds natively.
#   * On an Intel/x86_64 host it cross-compiles ("transpiles") the ARM64
#     binaries using the aarch64-linux-gnu cross toolchain.
#     On Debian/Ubuntu install it with:
#         sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
#     Override the compilers with the ARM_CC / ARM_CXX env vars if your
#     toolchain uses a different prefix.
#
# The CMakeLists.txt selects the ARM build path purely from
# CMAKE_SYSTEM_PROCESSOR, so cross-compiling only requires pointing CMake at
# the cross compiler and telling it the target arch is aarch64.
#

set -e

if [ -z "$JAVA_HOME" ]
then
      echo "\$JAVA_HOME is empty"
      exit 1;
fi

#
# This script always targets ARM64 Linux. The CMake ARM Linux path installs to
# target/linux/arm64 regardless of host, so mirror that here.
#
targetArch="arm64"
hostArch=$(uname -m)

#
# Path to architecture based install location.
#
installDir="${SCRIPT_DIR}/target/linux/${targetArch}"

#
# Extra cmake args, only populated when we have to cross-compile.
#
crossArgs=()

case "$hostArch" in
  aarch64 | arm64)
    echo "Host is ARM64 ($hostArch) -- building natively for ARM64 Linux."
    ;;
  x86_64 | amd64 | i?86)
    echo "Host is Intel ($hostArch) -- cross-compiling for ARM64 Linux."

    #
    # Allow the toolchain to be overridden (different distro prefix, custom path).
    #
    ARM_CC="${ARM_CC:-aarch64-linux-gnu-gcc}"
    ARM_CXX="${ARM_CXX:-aarch64-linux-gnu-g++}"

    if ! command -v "$ARM_CC" >/dev/null 2>&1; then
      echo ""
      echo "!! ERROR !!"
      echo "!! aarch64 cross compiler '$ARM_CC' was not found on the PATH."
      echo "!! Install the cross toolchain, e.g. on Debian/Ubuntu:"
      echo "!!     sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu"
      echo "!! or set ARM_CC / ARM_CXX to point at your aarch64 cross compilers."
      echo ""
      exit 1
    fi

    crossArgs+=(
      -DCMAKE_SYSTEM_NAME=Linux
      -DCMAKE_SYSTEM_PROCESSOR=aarch64
      -DCMAKE_C_COMPILER="$ARM_CC"
    )

    # The C++ compiler is only referenced by generator expressions that never
    # fire (all sources are C), so only pass it if it is actually installed.
    if command -v "$ARM_CXX" >/dev/null 2>&1; then
      crossArgs+=( -DCMAKE_CXX_COMPILER="$ARM_CXX" )
    fi

    echo "Using cross compiler: $(command -v "$ARM_CC")"
    ;;
  *)
    echo "!! ERROR !!"
    echo "!! Unrecognised host architecture '$hostArch'."
    echo "!! Run this on an ARM64 host to build natively, or on an x86_64 host"
    echo "!! with the aarch64-linux-gnu cross toolchain installed."
    exit 1
    ;;
esac

#
# Remove target dir
#
rm -rf "${installDir}"

#
# CMakeCache.txt / CMakeFiles may hold settings (including the selected
# compiler) for a different target so remove them first -- CMake refuses to
# switch compilers within an existing cache.
#
rm -f CMakeCache.txt
rm -rf CMakeFiles

cmake "${crossArgs[@]}" "$@" .

make clean; make;

# Do the actual install so if it fails we can see what is happening.
make install

