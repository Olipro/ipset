# Create a set
0 ipset create test hash:net,iface hashsize 128
# Add zero valued element
1 ipset add test 0.0.0.0/0,eth0
# Test zero valued element
1 ipset test test 0.0.0.0/0,eth0
# Delete zero valued element
1 ipset del test 0.0.0.0/0,eth0
# Try to add /0
1 ipset add test 1.1.1.1/0,eth0
# Try to add /32
0 ipset add test 1.1.1.1/32,eth0
# Add almost zero valued element
0 ipset add test 0.0.0.0/1,eth0
# Test almost zero valued element
0 ipset test test 0.0.0.0/1,eth0
# Delete almost zero valued element
0 ipset del test 0.0.0.0/1,eth0
# Test deleted element
1 ipset test test 0.0.0.0/1,eth0
# Delete element not added to the set
1 ipset del test 0.0.0.0/1,eth0
# Add first random network
0 ipset add test 2.0.0.1/24,eth0
# Add second random network
0 ipset add test 192.168.68.69/27,eth1
# Test first random value
0 ipset test test 2.0.0.255,eth0
# Test second random value
0 ipset test test 192.168.68.95,eth1
# Test value not added to the set
1 ipset test test 2.0.1.0,eth0
# Test value not added to the set
1 ipset test test 2.0.0.255,eth1
# Test value not added to the set
1 ipset test test 192.168.68.95,eth0
# Try to add IP address
0 ipset add test 2.0.0.1,eth0
# List set
0 ipset list test | sed 's/timeout ./timeout x/' > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:net,iface.t.list0
# Flush test set
0 ipset flush test
# Delete test set
0 ipset destroy test
# Create test set
0 ipset new test hash:net,iface
# Add networks in range notation
0 ipset add test 10.2.0.0-10.2.1.12,eth0
# List set
0 ipset -L test 2>/dev/null > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:net,iface.t.list2
# Delete test set
0 ipset destroy test
# eof
