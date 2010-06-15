# Create a set with timeout
0 ipset create test nethash hashsize 128 timeout 6
# Range: Add zero valued element
1 ipset add test 0.0.0.0/0
# Range: Test zero valued element
1 ipset test test 0.0.0.0/0
# Range: Delete zero valued element
1 ipset del test 0.0.0.0/0
# Range: Try to add /0
1 ipset add test 1.1.1.1/0
# Range: Try to add /32
0 ipset add test 1.1.1.1/32
# Range: Add almost zero valued element
0 ipset add test 0.0.0.0/1
# Range: Test almost zero valued element
0 ipset test test 0.0.0.0/1
# Range: Delete almost zero valued element
0 ipset del test 0.0.0.0/1
# Range: Test deleted element
1 ipset test test 0.0.0.0/1
# Range: Delete element not added to the set
1 ipset del test 0.0.0.0/1
# Range: Add first random network
0 ipset add test 2.0.0.1/24
# Range: Add second random network
0 ipset add test 192.168.68.69/27
# Range: Test first random value
0 ipset test test 2.0.0.255
# Range: Test second random value
0 ipset test test 192.168.68.95
# Range: Test value not added to the set
1 ipset test test 2.0.1.0
# Range: Try to add IP address
0 ipset add test 2.0.0.1
# Range: List set
0 ipset list test | sed 's/timeout ./timeout x/' > .foo0 && ./sort.sh .foo0
# Range: Check listing
0 diff -I 'Size in memory.*' .foo hash:net.t.list0 && rm .foo
# Sleep 6s so that element can time out
0 sleep 6
# IP: List set
0 ipset -L test 2>/dev/null > .foo0 && ./sort.sh .foo0
# IP: Check listing
0 diff -I 'Size in memory.*' .foo hash:net.t.list1 && rm .foo
# Flush test set
0 ipset flush test
# Delete test set
0 ipset destroy test
# eof
