#!/bin/bash


export fipsLib="../jars/bcprov-lts8on-2.73.0-SNAPSHOT.jar"

#exit;


java  -cp "$fipsLib" org.bouncycastle.util.DumpInfo -verbose

../gradlew clean build


echo "CTR-NI (JCE VAESF)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ctr

echo "CTR-NI (VAES)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ctr

echo "CTR-NI (avx)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ctr

echo "CTR-NI (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ctr

java -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport CTR ctr_report_c.html CTRNative_JCE-vaesf.csv CTRNative_JCE-vaes.csv CTRNative_JCE-avx.csv CTRJava_JCE-java.csv
