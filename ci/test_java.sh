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

# test21 and test21NoPC task will run against jdk 21, we can skip the specific test target for that JVM in this case

./gradlew clean cleanNative build testNoPC -x test21 -x test21NoPC


