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

for mod in core util prov pkix tls pg mail 
do
    echo "checking $mod"
    while read l
    do
        hash=`echo $l | sed -e "s/ .*//"`
        file=`echo $l | sed -e "s/^[^ ]* //"`
        if [ $mod = core ]
        then
            match=`echo $file | egrep "org/bouncycastle/asn1/(cryptlib|edec|gnu|iana|isara|iso|kisa|microsoft|misc|mozilla|nsri|ntt|oiw|rosstandart)"`
            if [ -n "$match" ]
            then
                loc=`echo $file | sed -e "s/core/util/"`
        	current=`sha256sum $bc_java_dir/$loc |  sed -e "s/ .*//"`
            else
        	current=`sha256sum $bc_java_dir/$file |  sed -e "s/ .*//"`
            fi
        else
        	current=`sha256sum $bc_java_dir/$file |  sed -e "s/ .*//"`
        fi
        if [ $hash != $current ]
        then
            echo $file
        fi
    done < indexes/bc-java.$mod.index
done
