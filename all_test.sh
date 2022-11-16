#!/usr/bin/env bash

rm -rf mtest
mkdir mtest

artifactsHome=build/libs/

tj=( $artifactsHome/bc-lts-java-*tests.jar )

testJar="${tj[0]}";

cp jars/* mtest/

rm mtest/*-javadoc.jar
rm mtest/*-sources.jar

a=(`$JAVA_HOME/bin/jar -tf "$testJar" | grep -E "AllTests\.class" | sed -e 's!.class!!' | sed -e 's|/|.|g'`);

for i in "${a[@]}"
do
  echo $i

  java  \
  -cp "$testJar:mtest/*:libs/junit.jar:libs/activation.jar:libs/mail.jar" \
  -Dbc.test.data.home=core/src/test/data \
  "$i"

done
