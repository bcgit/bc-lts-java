#!/bin/bash

java -version

export fipsLib="../jars/bcprov-lts8on-2.73.0-SNAPSHOT.jar"

../gradlew clean build

java  -cp "$fipsLib" org.bouncycastle.util.DumpInfo -verbose




echo ""
java -Dorg.bouncycastle.native.cpu_variant=java -cp "$fipsLib" org.bouncycastle.util.DumpInfo

echo "nSHA java"
java -Dorg.bouncycastle.native.cpu_variant=java -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha
echo "SHA avx"
java -Dorg.bouncycastle.native.cpu_variant=avx -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha
echo "SHA vaes"
java -Dorg.bouncycastle.native.cpu_variant=vaes -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha
echo "SHA vaesf"
java -Dorg.bouncycastle.native.cpu_variant=vaesf -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark sha


java -cp "$fipsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport SHA sha_report.html SHAJava-java.csv SHANative-vaesf.csv SHANative-vaes.csv SHANative-avx.csv
