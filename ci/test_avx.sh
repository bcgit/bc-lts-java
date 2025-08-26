#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

cd /workspace/bc-lts-java
source ci/common.sh


export JAVA_HOME=`openjdk_21`
export PATH=$JAVA_HOME/bin:$PATH


./gradlew clean compileJava
(cd native_c; ./build_linux.sh;)
./gradlew clean cleanNative withNative build -x test

java -Dorg.bouncycastle.native.cpu_variant=avx -cp prov/build/libs/bcprov-lts8on-`./version.sh`.jar org.bouncycastle.util.DumpInfo


# testAVX task will run against jdk 21, we can skip the specific test target for that JVM.

./gradlew -Pdebug_build=true -Pskip.pqc.tests testAVX testAVXNoPC -x test -x test21AVX -x test21AVXNoPC

