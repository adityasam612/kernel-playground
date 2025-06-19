#!/bin/bash
echo "Loading IPv6 basic module..."
sudo insmod ipv6_counter_basic.ko

sleep 1
echo "Sending IPv6 ping..."
ping6 -c 5 ipv6.google.com

echo "Checking dmesg for packet count..."
dmesg | tail -n 20

