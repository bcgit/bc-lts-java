#!/bin/bash

export script_loc=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
echo $script_loc

version=`bash $script_loc/../version.sh`
#
export ltsLib="$script_loc/../../bc-lts-java-jars/${version}/bcprov-lts8on-${version}.jar"
#
echo $ltsLib

java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose
pushd $script_loc
../gradlew clean build

echo "ECB-JCE (NEON)"
java -Xmx2g "-Dorg.bouncycastle.native.cpu_variant=neon-le" -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb_jce

echo "ECB (NEON)"
java -Xmx2g "-Dorg.bouncycastle.native.cpu_variant=neon-le" -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb



echo "ECB-JCE (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb_jce

echo "ECB (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb

java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport ECB ecb_report_c.html ECBNative_JCE-neon.csv ECBNative-neon.csv  ECBJava-java.csv
popd