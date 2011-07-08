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
# Create test set
0 ipset new test hash:net,iface
# Add a /16 network with eth0
0 ipset add test 10.0.0.0/16,eth0
# Add an overlapping /24 network with eth1
0 ipset add test 10.0.0.0/24,eth1
# Add an overlapping /28 network with eth2
0 ipset add test 10.0.0.0/28,eth2
# Check matching element: from /28, with eth2
0 ipset test test 10.0.0.1,eth2
# Check non-matching element: from /28, with eth1
1 ipset test test 10.0.0.2,eth1
# Check non-matching element: from /28, with eth0
1 ipset test test 10.0.0.3,eth0
# Check matching element from: /24, with eth1
0 ipset test test 10.0.0.16,eth1
# Check non-matching element: from /24, with eth2
1 ipset test test 10.0.0.17,eth2
# Check non-matching element: from /24, with eth0
1 ipset test test 10.0.0.18,eth0
# Check matching element: from /16, with eth0
0 ipset test test 10.0.1.1,eth0
# Check non-matching element: from /16, with eth1
1 ipset test test 10.0.1.2,eth1
# Check non-matching element: from /16, with eth2
1 ipset test test 10.0.1.3,eth2
# Flush test set
0 ipset flush test
# Add overlapping networks from /4 to /30
0 (set -e; for x in `seq 4 30`; do ipset add test 192.0.0.0/$x,eth$x; done)
# List test set
0 ipset -L test 2>/dev/null > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:net,iface.t.list1
# Test matching elements in all added networks from /30 to /24
0 (set -e; y=2; for x in `seq 24 30 | tac`; do ipset test test 192.0.0.$y,eth$x; y=$((y*2)); done)
# Test non-matching elements in all added networks from /30 to /24
0 (y=2; for x in `seq 24 30 | tac`; do z=$((x-1)); ipset test test 192.0.0.$y,eth$z; ret=$?; test $ret -eq 0 && exit 1; y=$((y*2)); done)
# Delete test set
0 ipset destroy test
# Create test set with minimal hash size
0 ipset create test hash:net,iface hashsize 64
# Add clashing elements
0 (set -e; for x in `seq 0 63`; do ipset add test 10.0.0.0/16,eth$x; done)
# Check listing
0 n=`ipset list test | wc -l` && test $n -eq 70
# Delete test set
0 ipset destroy test
# eof
