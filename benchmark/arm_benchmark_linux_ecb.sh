#!/bin/bash


export version="2.73.2-SNAPSHOT";

export ltsLib="../../bc-lts-java-jars/$version/bcprov-lts8on-${version}.jar"


java  -cp "$ltsLib" org.bouncycastle.util.DumpInfo -verbose

../gradlew clean build



echo "ECB-NI (NEON)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=neon -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb_jce

echo "ECB-NI (NEON)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=neon -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb



echo "ECB-NI (JCE java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb_jce

echo "ECB-NI (java)"
java -Xmx2g -Dorg.bouncycastle.native.cpu_variant=java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.Benchmark ecb

java -cp "$ltsLib:./build/libs/bc-benchmark-java-0.1.jar" org.bouncycastle.benchmark.CreateReport ECB ecb_report_c.html ECBNative_JCE-neon.csv ECBNative-neon.csv  ECBJava-java.csv
