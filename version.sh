#!/bin/sh

fgrep version gradle.properties | sed -e "s/version=//"

