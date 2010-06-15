#!/bin/bash

tests="init"
tests="$tests ipmap bitmap:ip"
tests="$tests macipmap portmap"
tests="$tests iphash hash:ip hash:ip6"
tests="$tests ipporthash hash:ip,port hash:ip6,port"
tests="$tests ipportiphash hash:ip,port,ip hash:ip6,port,ip6"
tests="$tests nethash hash:net hash:net6"
tests="$tests setlist"
tests="$tests iptree iptreemap"

if [ "$1" ]; then
	tests="init $@"
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

