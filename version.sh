#!/bin/sh
export script_loc=$(dirname -- $(readlink -f - "$0")) | xargs

echo "Script Location: ${script_loc}"

ls -al "$script_loc"

fgrep version "$script_loc/gradle.properties" | sed -e "s/version=//"

