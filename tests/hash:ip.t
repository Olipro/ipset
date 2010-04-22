# IP: Create a set with timeout
0 ipset -N test iphash --hashsize 128 timeout 5
# Range: Add zero valued element
1 ipset -A test 0.0.0.0
# Range: Test zero valued element
1 ipset -T test 0.0.0.0
# IP: Add first random value
0 ipset -A test 2.0.0.1 timeout 5
# IP: Add second random value
0 ipset -A test 192.168.68.69 timeout 0
# IP: Test first random value
0 ipset -T test 2.0.0.1
# IP: Test second random value
0 ipset -T test 192.168.68.69
# IP: Test value not added to the set
1 ipset -T test 2.0.0.2
# IP: Add third random value
0 ipset -A test 200.100.0.12
# IP: Delete the same value
0 ipset -D test 200.100.0.12
# Sleep 6s so that element can time out
0 sleep 6
# IP: List set
0 ipset -L test 2>/dev/null > .foo0 && ./sort.sh .foo0
# IP: Check listing
0 diff .foo hash:ip.t.list0 && rm .foo
# IP: Flush test set
0 ipset -F test
# IP: Delete test set
0 ipset -X test
# IP: Restore values so that rehashing is triggered
0 sed 's/hashsize 128/hashsize 128 timeout 6/' iphash.t.restore | ipset -R
# IP: Check that the values are restored
0 test `ipset -S test| grep add| wc -l` -eq 129
# Sleep 8s so that elements can time out
0 sleep 8
# IP: check that elements timed out
0 test `ipset -S test| grep add| wc -l` -eq 0
# IP: Flush test set
0 ipset -F test
# IP: Delete test set
0 ipset -X test
# Network: Create a set with timeout
0 ipset -N test iphash --hashsize 128 --netmask 24 timeout 6
# Network: Add zero valued element
1 ipset -A test 0.0.0.0
# Network: Test zero valued element
1 ipset -T test 0.0.0.0
# Network: Delete zero valued element
1 ipset -D test 0.0.0.0
# Network: Add first random network
0 ipset -A test 2.0.0.1
# Network: Add second random network
0 ipset -A test 192.168.68.69
# Network: Test first random value
0 ipset -T test 2.0.0.255
# Network: Test second random value
0 ipset -T test 192.168.68.95
# Network: Test value not added to the set
1 ipset -T test 2.0.1.0
# Network: List set
0 ipset -L test > .foo && grep '2.0.0.0 timeout' .foo >/dev/null && grep '192.168.68.0 timeout' .foo >/dev/null && rm .foo
# Network: Add third element
0 ipset -A test 200.100.10.1 timeout 0
# Network: Add third random network
0 ipset -A test 200.100.0.12
# Network: Delete the same network
0 ipset -D test 200.100.0.12
# Sleep 6s so that elements can time out
0 sleep 6
# Network: List set
0 ipset -L test > .foo
# Network: Check listing
0 diff .foo hash:ip.t.list1 && rm .foo
# Network: Flush test set
0 ipset -F test
# Network: Delete test set
0 ipset -X test
# eof
