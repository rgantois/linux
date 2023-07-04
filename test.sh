brctl addbr br0
brctl addif br0 lan
brctl addif br0 wan
ip link set up dev lan
ip link set up dev wan
ip link set up dev br0
mount -t debugfs debug /sys/kernel/debug
cd /sys/kernel/debug/regmap


