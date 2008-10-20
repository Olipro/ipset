# Create a set 
0 ipset -N test nethash --hashsize 128 
# Add first random network
0 ipset -A test 2.0.0.1/24
# Add second random network
0 ipset -A test 192.168.68.69/27
# Test first random value
0 ipset -T test 2.0.0.255
# Test second random value
0 ipset -T test 192.168.68.95
# Test value not added to the set
1 ipset -T test 2.0.1.0
# Try to add IP address
2 ipset -A test 2.0.0.1
# Delete test set
0 ipset -X test
# eof
