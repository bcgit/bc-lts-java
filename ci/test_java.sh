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

# test will run against jdk 21, we can skip test21 test target in this case.

./gradlew clean cleanNative build -x test21


