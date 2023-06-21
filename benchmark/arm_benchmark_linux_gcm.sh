#!/bin/bash

export version="2.73.2-SNAPSHOT";

export ltsLib="../../bc-lts-java-jars/$version/bcprov-lts8on-${version}.jar"


../gradlew clean build

java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose

echo "GCM-NI (NEON-LE)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=neon-le -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm

#echo "GCM-java (if available)"
# java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark gcm



java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport GCM arm_gcm_report_c.html  GCMNative-neon-le.csv GCMJava-java.csv
