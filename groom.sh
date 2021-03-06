#!/bin/sh

$(dirname $0)/groom-$(uname -s |tr '[:upper:]' '[:lower:]') $@
