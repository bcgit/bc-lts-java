#!/bin/sh
export script_loc=$(dirname -- $(readlink -f - "$0"))

fgrep version "${script_loc}/gradle.properties" | sed -e "s/version=//"

