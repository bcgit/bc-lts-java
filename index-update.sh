#/bin/sh

file_ext=$1

shift 

bc_java_dir="../../bc-java"

for file in $*
do
echo $file
match=`echo $file | egrep "org/bouncycastle/asn1/(cryptlib|edec|gnu|isara|iso|kisa|microsoft|misc|mozilla|nsri|ntt|oiw|rosstandart)"`
if [  -n "$match" ]
then
	loc=`echo $file | sed -e "s/core/util/"`
	current=`cd $bc_java_dir; sha256sum $loc |  sed -e "s/ .*//"`
	current=`echo $current | sed -e "s/util/core/"`
else
	current=`cd $bc_java_dir; sha256sum $file |  sed -e "s/ .*//"`
fi
ed indexes/bc-java.${file_ext}.index << %
g:$file:s:^.*$:$current  $file:
w
q
%
done
