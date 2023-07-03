#!/bin/bash

export fipsLib="../../bc-lts-java-jars/2.73.2/bcprov-lts8on-2.73.2.jar"

../gradlew clean build

java  -cp "$fipsLib" org.bouncycastle.util.DumpInfo -verbose

echo "GCM-NI (VAESF)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm

echo "GCM-NI (VAES)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm

echo "GCM-NI (if available)"
 java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=avx -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm

echo "GCM-java (if available)"
 java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm



java -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport GCM gcm_report_c.html  GCMNative-avx.csv GCMNative-vaesf.csv GCMNative-vaes.csv GCMJava-java.csv
