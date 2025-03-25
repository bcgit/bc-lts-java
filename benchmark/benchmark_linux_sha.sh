#!/bin/bash
# usage: benchmark_linux_sha.sh <version>
# where <version> is one the versions in the bc-lts-java-jars repository

export ltsLib="../../bc-lts-java-jars/$1/bcprov-lts8on-$1.jar"

java -version

java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose

vaesf=`java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose | fgrep VAESF | fgrep supported`
vaes=`java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose | fgrep "VAES " | fgrep supported`

../gradlew clean build

echo "nSHA java"
java -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha
echo "SHA avx"
java -Dorg.bouncycastle.native.cpu_variant=avx -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha
if [ -n "$vaes" ]
then
    echo "SHA vaes"
    java -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha
fi
if [ -n "$vaesf" ]
then
    echo "SHA vaesf"
    java -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha
fi


if [ -n "$vaesf" ]
then
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport SHA sha_report.html SHAJava-java.csv SHANative-vaesf.csv SHANative-vaes.csv SHANative-avx.csv
elif [ -n "$vaes" ]
then
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport SHA sha_report.html SHAJava-java.csv SHANative-vaes.csv SHANative-avx.csv
else
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport SHA sha_report.html SHAJava-java.csv SHANative-avx.csv
fi
