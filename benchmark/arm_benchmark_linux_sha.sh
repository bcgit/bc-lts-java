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


echo ""
java -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib" org.bouncycastle.util.DumpInfo

echo "SHA java"
java -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha
echo "SHA neon le"
java "-Dorg.bouncycastle.native.cpu_variant=neon-le" -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha

java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport SHA sha_report.html SHAJava-java.csv SHANative-neon-le.csv

popd