#!/bin/sh

exec $(dirname $0)/groom-$(uname -s |tr '[:upper:]' '[:lower:]')-$(uname -m) $@
