#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

# Runs ant scripts that target different JVMs.

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
export PATH=$PATH:`ant-bin-1-10`


./gradlew clean compileJava
(cd native_c; ./build_linux.sh;)
./gradlew clean cleanNative withNative build compileTestJava -x test

ant -f test11.xml


