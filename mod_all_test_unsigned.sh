#!/usr/bin/env bash

version=`fgrep version gradle.properties | sed -e "s/version=//"`

rm -rf mtest
mkdir mtest

artifactsHome=build/libs/

tj=( $artifactsHome/*tests.jar )

testJar="${tj[0]}";

prefixes=("bcprov-lts8on" "bcpkix-lts8on" "bctls-lts8on" "bcutil-lts8on" "bcpg-lts8on" "bcmail-lts8on")

for str in "${prefixes[@]}"; do
  src="jars/${str}-${version}.jar"
  echo $src
  cp "${src}" mtest/
done


a=(`$JAVA_HOME/bin/jar -tf "$testJar" | grep -E "AllTests\.class" | sed -e 's!.class!!' | sed -e 's|/|.|g'`);

rm -rf /tmp/bc-libs
mkdir /tmp/bc-libs

export DYLIB_LIBRARY_PATH=/tmp/bc-libs
export LD_LIBRARY_PATH=/tmp/bc-libs

echo ""

java  \
  --module-path mtest \
  org.bouncycastle.util.DumpInfo

echo ""

for i in "${a[@]}"
do

  echo $i

  java  --module-path mtest \
     --add-modules org.bouncycastle.lts.mail \
     --add-modules org.bouncycastle.lts.pg \
     --add-modules org.bouncycastle.lts.pkix \
     --add-modules org.bouncycastle.lts.prov \
     --add-modules org.bouncycastle.lts.tls \
     --add-modules org.bouncycastle.lts.util \
     --add-opens org.bouncycastle.lts.prov/org.bouncycastle.jcajce.provider.symmetric=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.prov/org.bouncycastle.jcajce.provider.digest=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.util/org.bouncycastle.asn1.cmc=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.prov/org.bouncycastle.internal.asn1.cms=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.prov/org.bouncycastle.internal.asn1.bsi=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.prov/org.bouncycastle.internal.asn1.eac=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.prov/org.bouncycastle.internal.asn1.isismtt=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.util/org.bouncycastle.oer.its.etsi102941.basetypes=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.util/org.bouncycastle.oer.its.etsi102941=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.util/org.bouncycastle.oer.its.ieee1609dot2dot1=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.util/org.bouncycastle.oer.its.etsi103097.extension=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.util/org.bouncycastle.oer.its.etsi103097=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.util/org.bouncycastle.oer.its.ieee1609dot2.basetypes=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.util/org.bouncycastle.oer.its.ieee1609dot2=ALL-UNNAMED \
     --add-opens org.bouncycastle.lts.pkix/org.bouncycastle.tsp=ALL-UNNAMED \
     --add-reads org.bouncycastle.lts.mail=ALL-UNNAMED \
     --add-reads org.bouncycastle.lts.prov=ALL-UNNAMED \
     --add-reads org.bouncycastle.lts.mail=ALL-UNNAMED \
  -cp "$testJar:libs/junit.jar:libs/activation.jar:libs/mail.jar" \
  -Dbc.test.data.home=core/src/test/data \
  "$i"

    if [[ $? != 0 ]]; then
            echo ""
            echo "--------------------------------!!!"
            echo "$i failed"
            exit 1;
    fi

    echo "-------------------------------------"
    echo ""


done
