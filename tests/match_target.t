# Create sets and inet rules which call set match and SET target
0 ./iptables.sh inet start
# Send probe packet from 10.255.255.64,tcp:1025
0 sendip -p ipv4 -id 127.0.0.1 -is 10.255.255.64 -p tcp -td 80 -ts 1025 127.0.0.1
# Check that proper sets matched and target worked
0 ./check_klog.sh 10.255.255.64 tcp 1025 ipport list
# Send probe packet from 10.255.255.64,udp:1025 
0 sendip -p ipv4 -id 127.0.0.1 -is 10.255.255.64 -p udp -ud 80 -us 1025 127.0.0.1
# Check that proper sets matched and target worked
0 ./check_klog.sh 10.255.255.64 udp 1025 ipport list
# Send probe packet from 10.255.255.1,tcp:1025
0 sendip -p ipv4 -id 127.0.0.1 -is 10.255.255.1 -p tcp -td 80 -ts 1025 127.0.0.1
# Check that proper sets matched and target worked
0 ./check_klog.sh 10.255.255.1 tcp 1025 ip1 list
# Send probe packet from 10.255.255.32,tcp:1025
0 sendip -p ipv4 -id 127.0.0.1 -is 10.255.255.32 -p tcp -td 80 -ts 1025 127.0.0.1
# Check that proper sets matched and target worked
0 ./check_klog.sh 10.255.255.32 tcp 1025 ip2
# Destroy sets and rules
0 ./iptables.sh inet stop
# eof
