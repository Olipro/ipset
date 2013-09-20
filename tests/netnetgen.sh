#!/bin/sh

echo "n test hash:net,net hashsize 32 maxelem 87040"
for x in `seq 0 255`; do
    for y in `seq 0 3 253`; do
	z=$((y+2))
	echo "a test 10.0.0.0-10.0.2.255,10.$x.$y.0-10.$x.$z.255"
    done
done
