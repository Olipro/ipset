#!/bin/sh

tests="init"
tests+=" ipmap macipmap portmap"
tests+=" iphash nethash ipporthash"
tests+=" iptree iptreemap"

for types in $tests; do
    ipset -X test >/dev/null 2>&1
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
	eval $cmd >/dev/null 2>&1
	r=$?
	# echo $ret $r
	if [ "$ret" = "$r" ]; then
		echo "OK"
	else
		echo "FAILED"
		echo "Failed test: $cmd"
		exit 1
	fi
	# sleep 1
    done < $types.t
done
for x in $tests; do
	case $x in
	init)
		;;
	*)
		rmmod ip_set_$x >/dev/null 2>&1
		;;
	esac
done
rmmod ip_set >/dev/null 2>&1
echo "All tests are OK"

