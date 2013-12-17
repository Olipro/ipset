# Create a set with timeout
0 ipset create test hash:ip,mark family inet6 timeout 5
# Add partly zero valued element
0 ipset add test 2:0:0::1,0
# Test partly zero valued element
0 ipset test test 2:0:0::1,0
# Delete partly zero valued element
0 ipset del test 2:0:0::1,0
# Add first random value
0 ipset add test 2:0:0::1,5
# Add second random value
0 ipset add test 2:1:0::0,128
# Test first random value
0 ipset test test 2:0:0::1,5
# Test second random value
0 ipset test test 2:1:0::0,128
# Test value not added to the set
1 ipset test test 2:0:0::1,4
# Delete value not added to the set
1 ipset del test 2:0:0::1,6
# Test value before first random value
1 ipset test test 2:0:0::0,5
# Test value after second random value
1 ipset test test 2:1:0::1,128
# Try to add value before first random value
0 ipset add test 2:0:0::0,5
# Try to add value after second random value
0 ipset add test 2:1:0::1,128
# List set
0 ipset list test | grep -v Revision: | sed 's/timeout ./timeout x/' > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:ip6,mark.t.list0
# Sleep 5s so that elements can time out
0 sleep 5
# List set
0 ipset list test | grep -v Revision: > .foo0 && ./sort.sh .foo0
# Check listing
0 diff -u -I 'Size in memory.*' .foo hash:ip6,mark.t.list1
# Delete test set
0 ipset destroy test
# Create set to add a range
0 ipset new test hash:ip,mark -6 hashsize 64
# Add a random value 1
0 ipset add test 1::1,800000
# Add a random value 2
0 ipset add test 1::1,8900000
# Add a random value 3
0 ipset add test 1::3,8900000
# Add a random value 4
0 ipset add test 1::4,8900000
# Add a random value 5
0 ipset add test 1::5,8900000
# Add a random value 6
0 ipset add test 1::6,8900000
# Add a random value 7
0 ipset add test 1::7,8900000
# Add a random value 8
0 ipset add test 1::8,8900000
# Add a random value 9
0 ipset add test 1::9,8900000
# Add a random value 10
0 ipset add test 1::101,8900000
# Add a random value 11
0 ipset add test 1::11,8900000
# Add a random value 12
0 ipset add test 1::12,8900000
# Add a random value 13
0 ipset add test 1::13,8900000
# Add a random value 14
0 ipset add test 1::14,8900000
# Add a random value 15
0 ipset add test 1::15,8900000
# Add a random value 16
0 ipset add test 1::16,8900000
# Add a random value 17
0 ipset add test 1::17,8900000
# Add a random value 18
0 ipset add test 1::18,8900000
# Add a random value 19
0 ipset add test 1::19,8900000
# Add a random value 20
0 ipset add test 1::20,8900000
# Add a random value 21
0 ipset add test 1::21,8900000
# Add a random value 22
0 ipset add test 1::22,8900000
# Add a random value 23
0 ipset add test 1::23,8900000
# Add a random value 24
0 ipset add test 1::24,8900000
# Add a random value 25
0 ipset add test 1::25,8900000
# Add a random value 26
0 ipset add test 1::26,8900000
# Add a random value 27
0 ipset add test 1::27,8900000
# Add a random value 28
0 ipset add test 1::28,8900000
# Add a random value 29
0 ipset add test 1::29,8900000
# Add a random value 30
0 ipset add test 1::301,8900000
# Add a random value 31
0 ipset add test 1::31,8900000
# Add a random value 32
0 ipset add test 1::32,8900000
# Add a random value 33
0 ipset add test 1::33,8900000
# Add a random value 34
0 ipset add test 1::34,8900000
# Add a random value 35
0 ipset add test 1::35,8900000
# Add a random value 36
0 ipset add test 1::36,8900000
# Add a random value 37
0 ipset add test 1::37,8900000
# Add a random value 38
0 ipset add test 1::38,8900000
# Add a random value 39
0 ipset add test 1::39,8900000
# Add a random value 40
0 ipset add test 1::401,8900000
# Add a random value 41
0 ipset add test 1::41,8900000
# Add a random value 42
0 ipset add test 1::42,8900000
# Add a random value 43
0 ipset add test 1::43,8900000
# Add a random value 44
0 ipset add test 1::44,8900000
# Add a random value 45
0 ipset add test 1::45,8900000
# Add a random value 46
0 ipset add test 1::46,8900000
# Add a random value 47
0 ipset add test 1::47,8900000
# Add a random value 48
0 ipset add test 1::48,8900000
# Add a random value 49
0 ipset add test 1::49,8900000
# Add a random value 50
0 ipset add test 1::501,8900000
# Add a random value 51
0 ipset add test 1::51,8900000
# Add a random value 52
0 ipset add test 1::52,8900000
# Add a random value 53
0 ipset add test 1::53,8900000
# Add a random value 54
0 ipset add test 1::54,8900000
# Add a random value 55
0 ipset add test 1::55,8900000
# Add a random value 56
0 ipset add test 1::56,8900000
# Add a random value 57
0 ipset add test 1::57,8900000
# Add a random value 58
0 ipset add test 1::58,8900000
# Add a random value 59
0 ipset add test 1::59,8900000
# Add a random value 60
0 ipset add test 1::601,8900000
# Add a random value 61
0 ipset add test 1::61,8900000
# Add a random value 62
0 ipset add test 1::62,8900000
# Add a random value 63
0 ipset add test 1::63,8900000
# Add a random value 64
0 ipset add test 1::64,8900000
# Add a random value 65, that forces a resizing
0 ipset add test 1::65,8900000
# Check that correct number of elements are added
0 n=`ipset list test|grep 1::|wc -l` && test $n -eq 65
# Destroy set
0 ipset -X test
# Timeout: Check that resizing keeps timeout values
0 ./resizet.sh -6 ipmark
# Counters: create set
0 ipset n test hash:ip,mark -6 counters
# Counters: add element with packet, byte counters
0 ipset a test 2:0:0::1,80 packets 5 bytes 3456
# Counters: check element
0 ipset t test 2:0:0::1,80
# Counters: check counters
0 ./check_counters test 2::1 5 3456
# Counters: delete element
0 ipset d test 2:0:0::1,80
# Counters: test deleted element
1 ipset t test 2:0:0::1,80
# Counters: add element with packet, byte counters
0 ipset a test 2:0:0::20,453 packets 12 bytes 9876
# Counters: check counters
0 ./check_counters test 2::20 12 9876
# Counters: update counters
0 ipset -! a test 2:0:0::20,453 packets 13 bytes 12479
# Counters: check counters
0 ./check_counters test 2::20 13 12479
# Counters: destroy set
0 ipset x test
# Counters and timeout: create set
0 ipset n test hash:ip,mark -6 counters timeout 600
# Counters and timeout: add element with packet, byte counters
0 ipset a test 2:0:0::1,80 packets 5 bytes 3456
# Counters and timeout: check element
0 ipset t test 2:0:0::1,80
# Counters and timeout: check counters
0 ./check_extensions test 2::1 600 5 3456
# Counters and timeout: delete element
0 ipset d test 2:0:0::1,80
# Counters and timeout: test deleted element
1 ipset t test 2:0:0::1,80
# Counters and timeout: add element with packet, byte counters
0 ipset a test 2:0:0::20,453 packets 12 bytes 9876
# Counters and timeout: check counters
0 ./check_extensions test 2::20 600 12 9876
# Counters and timeout: update counters
0 ipset -! a test 2:0:0::20,453 packets 13 bytes 12479
# Counters and timeout: check counters
0 ./check_extensions test 2::20 600 13 12479
# Counters and timeout: update timeout
0 ipset -! a test 2:0:0::20,453 timeout 700
# Counters and timeout: check counters
0 ./check_extensions test 2::20 700 13 12479
# Counters and timeout: destroy set
0 ipset x test
# eof
