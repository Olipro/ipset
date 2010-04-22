#!/bin/bash

tests="init"
tests="$tests ipmap bitmap:ip macipmap portmap"
tests="$tests iphash hash:ip"
# nethash ipporthash"
# tests="$tests ipportiphash ipportnethash"
# tests="$tests iptree iptreemap"
# tests="$tests setlist"

if [ "$1" ]; then
	tests="init $@"
fi

if [ ! -x ../src/ipset ]; then
	echo "Please rune `make` first and create the ipset binary."
	exit 1
fi

for types in $tests; do
    ../src/ipset -X test >/dev/null 2>&1
    if [ -f $types ]; then
    	filename=$types
    else
    	filename=$types.t
    fi
    while read ret cmd; do
	case $ret in
	    \#)
	    	if [ "$cmd" = "eof" ]; then
	    		break
	    	fi
	    	what=$cmd
		continue
		;;
	    *)
		;;
	esac
	echo -ne "$types: $what: "
	cmd=`echo $cmd | sed 's/ipset/..\/src\/ipset 2>.foo.err/'`
	eval $cmd
	r=$?
	# echo $ret $r
	if [ "$ret" = "$r" ]; then
		echo "passed"
	else
		echo "FAILED"
		echo "Failed test: $cmd"
		cat .foo.err
		exit 1
	fi
	# sleep 1
    done < $filename
done
# Remove test sets created by setlist.t
../src/ipset -X >/dev/null 2>&1
for x in $tests; do
	case $x in
	init)
		;;
	*)
		for x in `lsmod | grep ip_set_ | awk '{print $1}'`; do
			rmmod $x >/dev/null 2>&1
		done
		;;
	esac
done
rmmod ip_set >/dev/null 2>&1
rm -f .foo.err
echo "All tests are passed"

