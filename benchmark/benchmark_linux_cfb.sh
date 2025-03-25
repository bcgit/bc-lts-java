#!/bin/bash
# usage: benchmark_linux_cfb.sh <version>
# where <version> is one the versions in the bc-lts-java-jars repository

export ltsLib="../../bc-lts-java-jars/$1/bcprov-lts8on-$1.jar"

java -version

java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose

vaesf=`java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose | fgrep VAESF | fgrep supported`
vaes=`java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose | fgrep "VAES " | fgrep supported`

../gradlew clean build


if [ -n "$vaesf" ]
then
    echo "CFB-NI (JCE VAESF)"
    java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cfb
fi

if [ -n "$vaes" ]
then
    echo "CFB-NI (VAES)"
    java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cfb
fi

echo "CFB-NI (avx)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cfb

echo "CFB-NI (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cfb

if [ -n "$vaesf" ]
then
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CFB cfb_report_c.html CFBNative_JCE-vaesf.csv CFBNative_JCE-vaes.csv CFBNative_JCE-avx.csv CFBJava_JCE-java.csv
elif [ -n "$vaes" ]
then
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CFB cfb_report_c.html CFBNative_JCE-vaes.csv CFBNative_JCE-avx.csv CFBJava_JCE-java.csv
else
    java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CFB cfb_report_c.html CFBNative_JCE-avx.csv CFBJava_JCE-java.csv
fi
