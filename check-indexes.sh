#/bin/sh
#
# Check which files have changed in bc-java since we last looked.
#

if [ $# != 1 ]
then
    echo "usage: check-indexes.sh bc-java-repository"
    exit 1
fi

bc_java_dir=$1

while read l
do
    hash=`echo $l | sed -e "s/ .*//"`
    file=`echo $l | sed -e "s/^[^ ]* //"`
    current=`sha256sum $bc_java_dir/$file |  sed -e "s/ .*//"`
    if [ $hash != $current ]
    then
        echo $file
    fi
done < indexes/bc-java.core.index

while read l
do
    hash=`echo $l | sed -e "s/ .*//"`
    file=`echo $l | sed -e "s/^[^ ]* //"`
    current=`sha256sum $bc_java_dir/$file |  sed -e "s/ .*//"`
    if [ $hash != $current ]
    then
        echo $file
    fi
done < indexes/bc-java.util.index
