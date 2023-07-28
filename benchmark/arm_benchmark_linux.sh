#!/bin/bash

export script_loc=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

pushd $script_loc

arm_benchmark_linux_cbc.sh
arm_benchmark_linux_cfb.sh
arm_benchmark_linux_ctr.sh
arm_benchmark_linux_ecb.sh
arm_benchmark_linux_gcm.sh
arm_benchmark_linux_sha.sh

popd