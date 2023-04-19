#!/bin/bash


export ltsLib="../jars/bcprov-lts8on-2.73.0-SNAPSHOT.jar"


java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose

../gradlew clean build



echo "ECB-NI (JCE VAESF)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb_jce

echo "ECB-NI (VAESF)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb


echo "ECB-NI (JCE VAES)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb_jce

echo "ECB-NI (VAES)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb


echo "ECB-NI (JCE avx)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb_jce

echo "ECB-NI (avx)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb


echo "ECB-NI (JCE java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb_jce

echo "ECB-NI (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb

java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport ECB ecb_report_c.html ECBNative_JCE-vaesf.csv ECBNative-vaesf.csv  ECBNative_JCE-vaes.csv ECBNative-vaes.csv ECBNative-avx.csv  ECBNative_JCE-avx.csv ECBJava-java.csv
