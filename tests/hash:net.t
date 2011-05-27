# Create a set with timeout
0 ipset create test nethash hashsize 128 timeout 5
# Add zero valued element
1 ipset add test 0.0.0.0/0
# Test zero valued element
1 ipset test test 0.0.0.0/0
# Delete zero valued element
1 ipset del test 0.0.0.0/0
# Try to add /0
1 ipset add test 1.1.1.1/0
# Try to add /32
0 ipset add test 1.1.1.1/32
# Add almost zero valued element
0 ipset add test 0.0.0.0/1
# Test almost zero valued element
0 ipset test test 0.0.0.0/1
# Delete almost zero valued element
0 ipset del test 0.0.0.0/1
# Test deleted element
1 ipset test test 0.0.0.0/1
# Delete element not added to the set
1 ipset del test 0.0.0.0/1
# Add first random network
0 ipset add test 2.0.0.1/24
# Add second random network
0 ipset add test 192.168.68.69/27
# Test first random value
0 ipset test test 2.0.0.255
# Test second random value
0 ipset test test 192.168.68.95
# Test value not added to the set
1 ipset test test 2.0.1.0
# Try to add IP address
0 ipset add test 2.0.0.1
# List set
0 ipset list test | sed 's/timeout ./timeout x/' > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:net.t.list0
# Sleep 5s so that element can time out
0 sleep 5
# List set
0 ipset -L test 2>/dev/null > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:net.t.list1
# Flush test set
0 ipset flush test
# Delete test set
0 ipset destroy test
# Create test set
0 ipset new test hash:net
# Add networks in range notation
0 ipset add test 10.2.0.0-10.2.1.12
# List set
0 ipset -L test 2>/dev/null > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:net.t.list2
# Delete test set
0 ipset destroy test
# Stress test with range notation
0 ./netgen.sh | ipset restore
# List set and check the number of elements
0 n=`ipset -L test|grep '^10.'|wc -l` && test $n -eq 43520
# Delete test set
0 ipset destroy test
# eof
