# Range: Create a set with timeout
0 ipset create test hash:ip,port family inet6 timeout 5
# Range: Add partly zero valued element
0 ipset add test 2:0:0::1,0
# Range: Test partly zero valued element
0 ipset test test 2:0:0::1,0
# Range: Delete partly zero valued element
0 ipset del test 2:0:0::1,0
# Range: Add lower boundary
0 ipset add test 2:0:0::1,5
# Range: Add upper boundary
0 ipset add test 2:1:0::0,128
# Range: Test lower boundary
0 ipset test test 2:0:0::1,5
# Range: Test upper boundary
0 ipset test test 2:1:0::0,128
# Range: Test value not added to the set
1 ipset test test 2:0:0::1,4
# Range: Delete value not added to the set
1 ipset del test 2:0:0::1,6
# Range: Test value before lower boundary
1 ipset test test 2:0:0::0,5
# Range: Test value after upper boundary
1 ipset test test 2:1:0::1,128
# Range: Try to add value before lower boundary
0 ipset add test 2:0:0::0,5
# Range: Try to add value after upper boundary
0 ipset add test 2:1:0::1,128
# Range: List set
0 ipset list test | sed 's/timeout ./timeout x/' > .foo0 && ./sort.sh .foo0
# Range: Check listing
0 diff -I 'Size in memory.*' .foo hash:ip6,port.t.list0 && rm .foo
# Range: Sleep 6s so that elements can time out
0 sleep 6
# Range: List set
0 ipset list test > .foo0 && ./sort.sh .foo0
# Range: Check listing
0 diff -I 'Size in memory.*' .foo hash:ip6,port.t.list1 && rm .foo
# Range: Flush test set
0 ipset flush test
# Range: Delete test set
0 ipset destroy test
# eof
