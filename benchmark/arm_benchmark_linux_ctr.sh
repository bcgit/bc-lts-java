#!/bin/bash

export script_loc=$(dirname -- $(readlink -f - "$0"))
echo $script_loc

version=`bash $script_loc/../version.sh`
#
export ltsLib="$script_loc/../../bc-lts-java-jars/${version}/bcprov-lts8on-${version}.jar"
#
echo $ltsLib

java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose
pushd $script_loc
../gradlew clean build


echo "CTR (Neon le)"
java -Xmx2g "-Dorg.bouncycastle.native.cpu_variant=neon-le" -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ctr

echo "CTR (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ctr

java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CTR ctr_report_c.html CTRNative_JCE-neon-le.csv CTRJava_JCE-java.csv
popd