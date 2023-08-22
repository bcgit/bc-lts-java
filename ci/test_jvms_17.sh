#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

# Runs ant scripts that target different JVMs.

cd /workspace/bc-lts-java
source ci/common.sh


export JAVA_HOME=`openjdk_11`
export PATH=$JAVA_HOME/bin:$PATH
export PATH=$PATH:`ant-bin-1-10`


./gradlew clean compileJava
(cd native_c; ./build_linux.sh;)
./gradlew clean cleanNative withNative build compileTestJava -x test

ant -f test17.xml


