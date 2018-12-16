# Create a set with timeout
0 ipset create test hash:ip,port,ip,port timeout 4
# Add partly zero valued element
0 ipset add test 2.0.0.1,0,0.0.0.0,0
# Test partly zero valued element
0 ipset test test 2.0.0.1,0,0.0.0.0,0
# Delete party zero valued element
0 ipset del test 2.0.0.1,0,0.0.0.0,0
# Add almost zero valued element
0 ipset add test 2.0.0.1,0,0.0.0.1,0
# Test almost zero valued element
0 ipset test test 2.0.0.1,0,0.0.0.1,0
# Delete almost zero valued element
0 ipset del test 2.0.0.1,0,0.0.0.1,0
# Add first random value
0 ipset add test 2.0.0.1,5,1.1.1.1,10
# Add second random value
0 ipset add test 2.1.0.0,128,2.2.2.2,11
# Test first random value
0 ipset test test 2.0.0.1,5,1.1.1.1,10
# Test second random value
0 ipset test test 2.1.0.0,128,2.2.2.2,11
# Test value not added to the set
1 ipset test test 2.0.0.1,5,1.1.1.2,11
# Test value not added to the set
1 ipset test test 2.0.0.1,6,1.1.1.1,10
# Test value not added to the set
1 ipset test test 2.0.0.2,6,1.1.1.1,23
# Test value before first random value
1 ipset test test 2.0.0.0,5,1.1.1.1,10
# Test value after second random value
1 ipset test test 2.1.0.1,128,2.2.2.2,11
# Try to add value before first random value
0 ipset add test 2.0.0.0,5,1.1.1.1,10
# Try to add value after second random value
0 ipset add test 2.1.0.1,128,2.2.2.2,11
# List set
0 ipset list test | grep -v Revision: | sed 's/timeout ./timeout x/' > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:ip,port,ip,port.t.list0
# Sleep 5s so that elements can time out
0 sleep 5
# List set
0 ipset list test | grep -v Revision: > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:ip,port,ip,port.t.list1
# Flush test set
0 ipset flush test
# Add multiple elements in one step
0 ipset add test 1.1.1.1-1.1.1.4,80-84,2.2.2.2,55-56
# Delete multiple elements in one step
0 ipset del test 1.1.1.2-1.1.1.3,tcp:81-82,2.2.2.2,55-56
# Check number of elements after multi-add/multi-del
0 n=`ipset save test|wc -l` && test $n -eq 33
# Delete test set
0 ipset destroy test
# Create set to add a range
0 ipset new test hash:ip,port,ip,port hashsize 64
# Add a range which forces a resizing
0 ipset add test 10.0.0.0-10.0.3.255,tcp:80-82,192.168.0.1,99
# Check that correct number of elements are added
0 n=`ipset list test|grep '^10.0'|wc -l` && test $n -eq 3072
# Destroy set
0 ipset -X test
# Create set to add a range
0 ipset new test hash:ip,port,ip,port hashsize 64
# Add a range which forces a resizing
0 ipset add test 10.0.0.0,tcp:1-1000,192.168.0.1,51-60
# Check that correct number of elements are added
0 n=`ipset list test|grep '^10.0'|wc -l` && test $n -eq 10000
# Destroy set
0 ipset -X test
# Create set
0 ipset create test hash:ip,port,ip,port
# Add a single element
0 ipset add test 10.0.0.1,tcp:80,2.2.2.1,23
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 2
# Delete the single element
0 ipset del test 10.0.0.1,tcp:80,2.2.2.1,23
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 1
# Add an IP range
0 ipset add test 10.0.0.1-10.0.0.10,tcp:80,2.2.2.1,30-32
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 31
# Delete the IP range
0 ipset del test 10.0.0.1-10.0.0.10,tcp:80,2.2.2.1,30-32
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 1
# Add a port range
0 ipset add test 10.0.0.1,tcp:80-89,2.2.2.1,12
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 11
# Delete the port range
0 ipset del test 10.0.0.1,tcp:80-89,2.2.2.1,12
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 1
# Add an IP and port range
0 ipset add test 10.0.0.1-10.0.0.10,tcp:80-89,2.2.2.1,55
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 101
# Delete the IP and port range
0 ipset del test 10.0.0.1-10.0.0.10,tcp:80-89,2.2.2.1,55
# Check number of elements
0 n=`ipset save test|wc -l` && test $n -eq 1
# Destroy set
0 ipset -X test
# Timeout: Check that resizing keeps timeout values
0 ./resizet.sh -4 ipportipport
# Counters: create set
0 ipset n test hash:ip,port,ip,port counters
# Counters: add element with packet, byte counters
0 ipset a test 2.0.0.1,80,192.168.199.200,99 packets 5 bytes 3456
# Counters: check element
0 ipset t test 2.0.0.1,80,192.168.199.200,99
# Counters: check counters
0 ./check_counters test 2.0.0.1 5 3456
# Counters: delete element
0 ipset d test 2.0.0.1,80,192.168.199.200,99
# Counters: test deleted element
1 ipset t test 2.0.0.1,80,192.168.199.200,99
# Counters: add element with packet, byte counters
0 ipset a test 2.0.0.20,453,10.0.0.1,12 packets 12 bytes 9876
# Counters: check counters
0 ./check_counters test 2.0.0.20 12 9876
# Counters: update counters
0 ipset -! a test 2.0.0.20,453,10.0.0.1,12 packets 13 bytes 12479
# Counters: check counters
0 ./check_counters test 2.0.0.20 13 12479
# Counters: destroy set
0 ipset x test
# Counters and timeout: create set
0 ipset n test hash:ip,port,ip,port counters timeout 600
# Counters and timeout: add element with packet, byte counters
0 ipset a test 2.0.0.1,80,192.168.199.200,13 packets 5 bytes 3456
# Counters and timeout: check element
0 ipset t test 2.0.0.1,80,192.168.199.200,13
# Counters and timeout: check counters
0 ./check_extensions test 2.0.0.1 600 5 3456
# Counters and timeout: delete element
0 ipset d test 2.0.0.1,80,192.168.199.200,13
# Counters and timeout: test deleted element
1 ipset t test 2.0.0.1,80,192.168.199.200,13
# Counters and timeout: add element with packet, byte counters
0 ipset a test 2.0.0.20,453,10.0.0.1,1 packets 12 bytes 9876
# Counters and timeout: check counters
0 ./check_extensions test 2.0.0.20 600 12 9876
# Counters and timeout: update counters
0 ipset -! a test 2.0.0.20,453,10.0.0.1,1 packets 13 bytes 12479
# Counters and timeout: check counters
0 ./check_extensions test 2.0.0.20 600 13 12479
# Counters and timeout: update timeout
0 ipset -! a test 2.0.0.20,453,10.0.0.1,1 timeout 700
# Counters and timeout: check counters
0 ./check_extensions test 2.0.0.20 700 13 12479
# Counters and timeout: destroy set
0 ipset x test
# eof
