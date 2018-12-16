# Range: Create a set
0 ipset -N test netportnetporthash -6
# Range: Add zero valued element
1 ipset -A test 0::0/0,0:0,0:0:0::0/0
# Range: Test zero valued element
1 ipset -T test 0::0/0,0:0,0:0:0::0/0
# Range: Delete zero valued element
1 ipset -D test 0::0/0,0,0:0:0:0::0/0
# Range: Add almost zero valued element
0 ipset -A test 2:0:0::1/24,0,0:0:0::0/0,0
# Range: Test almost zero valued element
0 ipset -T test 2:0:0::1/24,0,0:0:0::0/0,0
# Range: Delete almost zero valued element
0 ipset -D test 2:0:0::1/24,0,0:0:0::0/0,0
# Range: Add almost zero valued element
0 ipset -A test 2:0:0::1,0,0:0:0::0/24,0
# Range: Test almost zero valued element
0 ipset -T test 2:0:0::1,0,0:0:0::0/24,0
# Range: Delete almost zero valued element
0 ipset -D test 2:0:0::1,0,0:0:0::0/24,0
# Range: Add first random value
0 ipset -A test 2:0:0::1,5,1:1:1::1/24,9
# Range: Add second random value
0 ipset -A test 2:1:0::0,128,2:2:2::2/12,10
# Range: Test first random value
0 ipset -T test 2:0:0::1,5,1:1:1::2,9
# Range: Test second random value
0 ipset -T test 2:1:0::0,128,2:2:2::0,10
# Range: Test value not added to the set
1 ipset -T test 2:0:0::1,5,2:1:1::255,10
# Range: Test value not added to the set
1 ipset -T test 2:0:0::1,6,1:1:1::1,10
# Range: Test value not added to the set
1 ipset -T test 2:0:0::2,6,1:1:1::1,10
# Range: Test value before first random value
1 ipset -T test 2:0:0::0,5,1:1:1::1,10
# Range: Test value after second random value
1 ipset -T test 2:1:0::1,128,2:2:2::2,10
# Range: Try to add value before first random value
0 ipset -A test 2:0:0::0,5,1:1:1::1/24,10
# Range: Try to add value after second random value
0 ipset -A test 2:1:0::1,128,2:2:2::2/12,10
# Range: List set
0 ipset -L test | grep -v Revision: > .foo0 && ./sort.sh .foo0
# Range: Check listing
0 diff -u -I 'Size in memory.*' .foo hash:net6,port,net6,port.t.list0
# Range: Flush test set
0 ipset -F test
# Range: Delete test set
0 ipset -X test
# Create set to add a range
0 ipset new test hash:net,port,net,port -6 hashsize 64
# Add a range which forces a resizing
0 ipset add test 1::1,tcp:80-1105,2::2/12,10
# Check that correct number of elements are added
0 n=`ipset list test|grep 1::1|wc -l` && test $n -eq 1026
# Destroy set
0 ipset -X test
# Create set to add a range
0 ipset new test hash:net,port,net,port -6 hashsize 64
# Add a range which forces a resizing
0 ipset add test 1::1/32,tcp:1-1000,5:5::5/64,50-55
# Check that correct number of elements are added
0 n=`ipset list test|grep '^1::'|wc -l` && test $n -eq 6000
# Destroy set
0 ipset -X test
# Create test set with timeout support
0 ipset create test hash:net,port,net,port family inet6 timeout 30
# Add a non-matching IP address entry
0 ipset -A test 2:2:2::2,80,1:1:1::1,8080 nomatch
# Add an overlapping matching small net
0 ipset -A test 2:2:2::2,80,1:1:1::/124,8080
# Add an overlapping non-matching larger net
0 ipset -A test 2:2:2::2,80,1:1:1::/120,8080 nomatch
# Add an even larger matching net
0 ipset -A test 2:2:2::2,80,1:1:1::/116,8080
# Check non-matching IP
1 ipset -T test 2:2:2::2,80,1:1:1::1,8080
# Check matching IP from non-matchin small net
0 ipset -T test 2:2:2::2,80,1:1:1::F,8080
# Check non-matching IP from larger net
1 ipset -T test 2:2:2::2,80,1:1:1::10,8080
# Check matching IP from even larger net
0 ipset -T test 2:2:2::2,80,1:1:1::100,8080
# Update non-matching IP to matching one
0 ipset -! -A test 2:2:2::2,80,1:1:1::1,8080
# Delete overlapping small net
0 ipset -D test 2:2:2::2,80,1:1:1::/124,8080
# Check matching IP
0 ipset -T test 2:2:2::2,80,1:1:1::1,8080
# Add overlapping small net
0 ipset -A test 2:2:2::2,80,1:1:1::/124,8080
# Update matching IP as a non-matching one, with shorter timeout
0 ipset -! -A test 2:2:2::2,80,1:1:1::1,8080 nomatch timeout 2
# Check non-matching IP
1 ipset -T test 2:2:2::2,80,1:1:1::1,8080
# Sleep 3s so that element can time out
0 sleep 3
# Check non-matching IP
0 ipset -T test 2:2:2::2,80,1:1:1::1,8080
# Check matching IP
0 ipset -T test 2:2:2::2,80,1:1:1::F,8080
# Delete test set
0 ipset destroy test
# Timeout: Check that resizing keeps timeout values
0 ./resizet.sh -6 netportnetport
# Nomatch: Check that resizing keeps the nomatch flag
0 ./resizen.sh -6 netportnetport
# Counters: create set
0 ipset n test hash:net,port,net,port -6 counters
# Counters: add element with packet, byte counters
0 ipset a test 2:0:0::1,80,2002:24:ff::1/64,12 packets 5 bytes 3456
# Counters: check element
0 ipset t test 2:0:0::1,80,2002:24:ff::1/64,12
# Counters: check counters
0 ./check_counters test 2::1 5 3456
# Counters: delete element
0 ipset d test 2:0:0::1,80,2002:24:ff::1/64,12
# Counters: test deleted element
1 ipset t test 2:0:0::1,80,2002:24:ff::1/64,12
# Counters: add element with packet, byte counters
0 ipset a test 2:0:0::20,453,2002:ff:24::ab/54,12 packets 12 bytes 9876
# Counters: check counters
0 ./check_counters test 2::20 12 9876
# Counters: update counters
0 ipset -! a test 2:0:0::20,453,2002:ff:24::ab/54,12 packets 13 bytes 12479
# Counters: check counters
0 ./check_counters test 2::20 13 12479
# Counters: destroy set
0 ipset x test
# Counters and timeout: create set
0 ipset n test hash:net,port,net,port -6 counters timeout 600
# Counters and timeout: add element with packet, byte counters
0 ipset a test 2:0:0::1,80,2002:24:ff::1/64,11 packets 5 bytes 3456
# Counters and timeout: check element
0 ipset t test 2:0:0::1,80,2002:24:ff::1/64,11
# Counters and timeout: check counters
0 ./check_extensions test 2::1 600 5 3456
# Counters and timeout: delete element
0 ipset d test 2:0:0::1,80,2002:24:ff::1/64,11
# Counters and timeout: test deleted element
1 ipset t test 2:0:0::1,80,2002:24:ff::1/64,11
# Counters and timeout: add element with packet, byte counters
0 ipset a test 2:0:0::20,453,2002:ff:24::ab/54,11 packets 12 bytes 9876
# Counters and timeout: check counters
0 ./check_extensions test 2::20 600 12 9876
# Counters and timeout: update counters
0 ipset -! a test 2:0:0::20,453,2002:ff:24::ab/54,11 packets 13 bytes 12479
# Counters and timeout: check counters
0 ./check_extensions test 2::20 600 13 12479
# Counters and timeout: update timeout
0 ipset -! a test 2:0:0::20,453,2002:ff:24::ab/54,11 timeout 700
# Counters and timeout: check counters
0 ./check_extensions test 2::20 700 13 12479
# Counters and timeout: destroy set
0 ipset x test
# eof
