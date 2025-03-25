#!/bin/bash
# usage: benchmark_linux_cbc.sh <version>
# where <version> is one the versions in the bc-lts-java-jars repository


export ltsLib="../../bc-lts-java-jars/$1/bcprov-lts8on-$1.jar"

java -version

java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose


vaesf=`java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose | fgrep VAESF | fgrep supported`
vaes=`java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose | fgrep "VAES " | fgrep supported`

../gradlew clean build


echo $vaesf
if [ -n "$vaesf" ]
then
   echo "CBC-NI (JCE VAESF)"
   java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cbc
fi

if [ -n "$vaes" ]
then
    echo "CBC-NI (VAES)"
    java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cbc
fi

echo "CBC-NI (AVX)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cbc

echo "CBC-NI (JAVA)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cbc

if [ -n "$vaesf" ]
then
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CBC cbc_report_c.html CBCNative-vaesf.csv CBCNative-vaes.csv CBCNative-avx.csv CBCJava-java.csv
elif [ -n "$vaes" ]
then
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CBC cbc_report_c.html CBCNative-vaes.csv CBCNative-avx.csv CBCJava-java.csv
else
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CBC cbc_report_c.html CBCNative-avx.csv CBCJava-java.csv
fi
