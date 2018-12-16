# Create a set with timeout
0 ipset create test hash:net,port,net,port timeout 4
# Add partly zero valued element
0 ipset add test 2.0.0.1/24,0,192.168.0.0/24,0
# Test partly zero valued element
0 ipset test test 2.0.0.1/24,0,192.168.0.0/24,0
# Delete partly zero valued element
0 ipset del test 2.0.0.1/24,0,192.168.0.0/24,0
# Add first random value
0 ipset add test 2.0.0.1/24,5,192.168.0.0/24,5
# Add second random value
0 ipset add test 2.1.0.0/24,128,10.0.0.0/16,11
# Test first random value
0 ipset test test 2.0.0.1,5,192.168.0.1,5
# Test second random value
0 ipset test test 2.1.0.0,128,10.0.1.1,11
# Test value not added to the set
1 ipset test test 2.5.0.1,4,10.0.0.1,5
# Delete value not added to the set
1 ipset del test 2.0.0.1/8,6,10.0.0.0/16,6
# Test value before first random value
1 ipset test test 2.0.0.0/25,5,192.168.0.0/24,5
# Test value after second random value
1 ipset test test 2.4.0.1,128,10.0.0.100,5
# Try to add value before first random value
0 ipset add test 2.0.0.0/24,5,192.168.0.0/25,5
# Try to add value after second random value
0 ipset add test 2.1.0.1,128,10.0.0.0/17,12
# List set
0 ipset list test | grep -v Revision: | sed 's/timeout ./timeout x/' > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:net,port,net,port.t.list0
# Sleep 5s so that elements can time out
0 sleep 5
# List set
0 n=`ipset save test|wc -l` && test $n -eq 1
# Flush test set
0 ipset flush test
# Delete set
0 ipset destroy test
# Create set to add a range
0 ipset new test hash:net,port,net,port hashsize 64
# Add a range which forces a resizing
0 ipset add test 10.0.0.0/24,tcp:1-1000,192.168.0.1/24,50-55
# Check that correct number of elements are added
0 n=`ipset list test|grep '^10.0'|wc -l` && test $n -eq 6000
# Destroy set
0 ipset -X test
# Create set to add a range
0 ipset new test hash:net,port,net,port hashsize 64
# Add a range
0 ipset add test 10.0.0.0-10.0.3.255,tcp:80-82,192.168.0.1/24,tcp:80
# Check that correct number of elements are added
0 n=`ipset list test|grep '^10.0'|wc -l` && test $n -eq 3
# Destroy set
0 ipset -X test
# Create set to add a range and with range notation in the network
0 ipset new test hash:net,port,net,port hashsize 64
# Add a range which forces a resizing
0 ipset add test 10.0.0.0-10.0.3.255,tcp:80-82,192.168.0.0-192.168.2.255,8080
# Check that correct number of elements are added
0 n=`ipset list test|grep '^10.0'|wc -l` && test $n -eq 6
# Destroy set
0 ipset -X test
# Create test set with timeout support
0 ipset create test hash:net,port,net,port timeout 30
# Add a non-matching IP address entry
0 ipset -A test 2.2.2.2,80,1.1.1.1,99 nomatch
# Add an overlapping matching small net
0 ipset -A test 2.2.2.2,80,1.1.1.0/30,99
# Add an overlapping non-matching larger net
0 ipset -A test 2.2.2.2,80,1.1.1.0/28,99 nomatch
# Add an even larger matching net
0 ipset -A test 2.2.2.2,80,1.1.1.0/26,99
# Check non-matching IP
1 ipset -T test 2.2.2.2,80,1.1.1.1,99
# Check matching IP from non-matchin small net
0 ipset -T test 2.2.2.2,80,1.1.1.3,99
# Check non-matching IP from larger net
1 ipset -T test 2.2.2.2,80,1.1.1.4,99
# Check matching IP from even larger net
0 ipset -T test 2.2.2.2,80,1.1.1.16,99
# Update non-matching IP to matching one
0 ipset -! -A test 2.2.2.2,80,1.1.1.1,99
# Delete overlapping small net
0 ipset -D test 2.2.2.2,80,1.1.1.0/30,99
# Check matching IP
0 ipset -T test 2.2.2.2,80,1.1.1.1,99
# Add overlapping small net
0 ipset -A test 2.2.2.2,80,1.1.1.0/30,99
# Update matching IP as a non-matching one, with shorter timeout
0 ipset -! -A test 2.2.2.2,80,1.1.1.1,99 nomatch timeout 2
# Check non-matching IP
1 ipset -T test 2.2.2.2,80,1.1.1.1,99
# Sleep 3s so that element can time out
0 sleep 3
# Check non-matching IP
0 ipset -T test 2.2.2.2,80,1.1.1.1,99
# Check matching IP
0 ipset -T test 2.2.2.2,80,1.1.1.3,99
# Delete test set
0 ipset destroy test
# Create set
0 ipset create test hash:net,port,net,port
# Add a single element
0 ipset add test 10.0.0.1,tcp:80,2.2.2.0/24,33
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 2
# Delete the single element
0 ipset del test 10.0.0.1,tcp:80,2.2.2.0/24,33
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 1
# Add an IP range
0 ipset add test 10.0.0.1-10.0.0.10,tcp:80,2.2.2.0/24,11
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 6
# Delete the IP range
0 ipset del test 10.0.0.1-10.0.0.10,tcp:80,2.2.2.0/24,11
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 1
# Add a port range
0 ipset add test 10.0.0.1,tcp:80-89,2.2.2.0/24,22
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 11
# Delete the port range
0 ipset del test 10.0.0.1,tcp:80-89,2.2.2.0/24,22
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 1
# Add an IP and port range
0 ipset add test 10.0.0.1-10.0.0.10,tcp:80-89,2.2.2.0/24,23-24
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 101
# Delete the IP and port range
0 ipset del test 10.0.0.1-10.0.0.10,tcp:80-89,2.2.2.0/24,23-24
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 1
# Destroy set
0 ipset -X test
# Timeout: Check that resizing keeps timeout values
0 ./resizet.sh -4 netportnetport
# Nomatch: Check that resizing keeps the nomatch flag
0 ./resizen.sh -4 netportnetport
# Counters: create set
0 ipset n test hash:net,port,net,port counters
# Counters: add element with packet, byte counters
0 ipset a test 2.0.0.1,80,192.168.199.200,55 packets 5 bytes 3456
# Counters: check element
0 ipset t test 2.0.0.1,80,192.168.199.200,55
# Counters: check counters
0 ./check_counters test 2.0.0.1 5 3456
# Counters: delete element
0 ipset d test 2.0.0.1,80,192.168.199.200,55
# Counters: test deleted element
1 ipset t test 2.0.0.1,80,192.168.199.200,55
# Counters: add element with packet, byte counters
0 ipset a test 2.0.0.20,453,10.0.0.1,66 packets 12 bytes 9876
# Counters: check counters
0 ./check_counters test 2.0.0.20 12 9876
# Counters: update counters
0 ipset -! a test 2.0.0.20,453,10.0.0.1,66 packets 13 bytes 12479
# Counters: check counters
0 ./check_counters test 2.0.0.20 13 12479
# Counters: destroy set
0 ipset x test
# Counters and timeout: create set
0 ipset n test hash:net,port,net,port counters timeout 600
# Counters and timeout: add element with packet, byte counters
0 ipset a test 2.0.0.1,80,192.168.199.200,7 packets 5 bytes 3456
# Counters and timeout: check element
0 ipset t test 2.0.0.1,80,192.168.199.200,7
# Counters and timeout: check counters
0 ./check_extensions test 2.0.0.1 600 5 3456
# Counters and timeout: delete element
0 ipset d test 2.0.0.1,80,192.168.199.200,7
# Counters and timeout: test deleted element
1 ipset t test 2.0.0.1,80,192.168.199.200,7
# Counters and timeout: add element with packet, byte counters
0 ipset a test 2.0.0.20,453,10.0.0.1,7 packets 12 bytes 9876
# Counters and timeout: check counters
0 ./check_extensions test 2.0.0.20 600 12 9876
# Counters and timeout: update counters
0 ipset -! a test 2.0.0.20,453,10.0.0.1,7 packets 13 bytes 12479
# Counters and timeout: check counters
0 ./check_extensions test 2.0.0.20 600 13 12479
# Counters and timeout: update timeout
0 ipset -! a test 2.0.0.20,453,10.0.0.1,7 timeout 700
# Counters and timeout: check counters
0 ./check_extensions test 2.0.0.20 700 13 12479
# Counters and timeout: destroy set
0 ipset x test
# eof
