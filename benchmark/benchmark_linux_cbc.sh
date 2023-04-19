#!/bin/bash


export ltsLib="../jars/bcprov-lts8on-2.73.0-SNAPSHOT.jar"

java -version

java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose

../gradlew clean build


echo "CBC-NI (JCE VAESF)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cbc

echo "CBC-NI (VAES)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cbc

echo "CBC-NI (avx)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cbc

echo "CBC-NI (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cbc

java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CBC cbc_report_c.html CBCNative-vaesf.csv CBCNative-vaes.csv CBCNative-avx.csv CBCJava-java.csv
