#!/bin/bash

set -e

../src/ipset n resize-test hash:ip hashsize 64
for x in `seq 1 20`; do
   for y in `seq 1 255`; do
      ../src/ipset a resize-test 192.168.$x.$y
   done
done
../src/ipset x resize-test
