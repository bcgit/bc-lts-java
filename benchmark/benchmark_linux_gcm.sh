#!/bin/bash
# usage: benchmark_linux_gcm.sh <version>
# where <version> is one the versions in the bc-lts-java-jars repository


export ltsLib="../../bc-lts-java-jars/$1/bcprov-lts8on-$1.jar"

java -version

java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose

vaesf=`java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose | fgrep VAESF | fgrep supported`
vaes=`java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose | fgrep "VAES " | fgrep supported`

../gradlew clean build

if [ -n "$vaesf" ]
then
    echo "GCM-NI (VAESF)"
    java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm
fi

if [ -n "$vaes" ]
then
    echo "GCM-NI (VAES)"
    java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm
fi

echo "GCM-NI (if available)"
 java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm

echo "GCM-java (if available)"
 java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm


if [ -n "$vaesf" ]
then
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport GCM gcm_report_c.html  GCMNative-avx.csv GCMNative-vaesf.csv GCMNative-vaes.csv GCMJava-java.csv
elif [ -n "$vaes" ]
then
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport GCM gcm_report_c.html  GCMNative-avx.csv GCMNative-vaes.csv GCMJava-java.csv
else
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport GCM gcm_report_c.html  GCMNative-avx.csv GCMJava-java.csv
fi
