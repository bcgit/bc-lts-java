#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

cd /workspace/bc-lts-java
source ci/common.sh


export JAVA_HOME=`openjdk_21`
export PATH=$JAVA_HOME/bin:$PATH

env


# Build headers
./gradlew clean compileJava

(
  # Compile native code
 cd native_c
 ./build_linux.sh
)


#
# Do a build to ensure it complies and no checkstyle rules of failing.
#
./gradlew clean cleanNative build -x test


