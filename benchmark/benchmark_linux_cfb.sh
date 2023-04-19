#!/bin/bash


export ltsLib="../jars/bcprov-lts8on-2.73.0-SNAPSHOT.jar"

#exit;


java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose

../gradlew clean build



echo "CFB-NI (JCE VAESF)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cfb

echo "CFB-NI (VAES)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cfb

echo "CFB-NI (avx)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cfb

echo "CFB-NI (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark cfb

java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CFB cfb_report_c.html CFBNative_JCE-vaesf.csv CFBNative_JCE-vaes.csv CFBNative_JCE-avx.csv CFBJava_JCE-java.csv
