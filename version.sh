#!/bin/bash
export script_loc=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )


fgrep version "$script_loc/gradle.properties" | sed -e "s/version=//"

