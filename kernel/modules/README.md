# M1 – IPv6 Packet Counter (Kernel Module)

## ✅ Project Description

This project implements an IPv6 packet counter using a Linux kernel module (Netfilter hook).  
It tracks incoming IPv6 packets, exports the counter to user space using `/proc`,  
and visualizes the result in real time with Python.

## ✅ Features

- Kernel module counts all IPv6 packets.
- Exports real-time stats via `/proc/ipv6_counter`.
- Python script polls and visualizes the count live.

## ✅ How to Build and Run

```bash
make
sudo insmod ipv6_counter_advance.ko
cat /proc/ipv6_counter  # Check the count
IPv6 Packets: 0
IPv6 Packets: 8
IPv6 Packets: 15
...


