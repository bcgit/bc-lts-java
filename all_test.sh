#!/usr/bin/env bash

rm -rf mtest
mkdir mtest

artifactsHome=build/libs/

tj=( $artifactsHome/*tests.jar )

testJar="${tj[0]}";

cp jars/* mtest/

rm mtest/*-javadoc.jar
rm mtest/*-sources.jar

a=(`$JAVA_HOME/bin/jar -tf "$testJar" | grep -E "AllTests\.class" | sed -e 's!.class!!' | sed -e 's|/|.|g'`);


export DYLIB_LIBRARY_PATH=/tmp/bc-libs
export LD_LIBRARY_PATH=/tmp/bc-libs

java  \
  -cp "$testJar:mtest/*:libs/junit.jar:libs/activation.jar:libs/mail.jar" \
  org.bouncycastle.util.DumpInfo


for i in "${a[@]}"
do
  case $i in org\.bouncycaslte\.crypto\.engines\.*)
    echo "skipping $i"
    continue
    esac

  echo $i

  java  \
  -cp "$testJar:mtest/*:libs/junit.jar:libs/activation.jar:libs/mail.jar" \
  -Dbc.test.data.home=core/src/test/data \
  "$i"

done
