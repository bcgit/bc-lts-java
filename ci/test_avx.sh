#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

cd /workspace/bc-lts-java
source ci/common.sh


export JAVA_HOME=`openjdk_21`
export PATH=$JAVA_HOME/bin:$PATH

#
# The tls java25 source set (META-INF/versions/25) compiles with a JDK 25 toolchain, resolved
# through org.gradle.java.installations.fromEnv. Required to build, not just to test - see
# README.md. The image must provide openjdk_25.
#
export LTS_JDK25=`openjdk_25`


./gradlew clean compileJava
(cd native_c; ./build_linux.sh;)
./gradlew clean cleanNative withNative build -x test

java -Dorg.bouncycastle.native.cpu_variant=avx -cp prov/build/libs/bcprov-lts8on-`./version.sh`.jar org.bouncycastle.util.DumpInfo


# testAVX will run against jdk 21, we can skip test21AVX test target in this case.

./gradlew -Pdebug_build=true -Pskip.pqc.tests testAVX -x test -x test21AVX

