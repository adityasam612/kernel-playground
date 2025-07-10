# visualize.py
import time

def read_count():
    try:
        with open("/proc/ipv6_counter", "r") as f:
            line = f.readline()
            return int(line.strip().split()[-1])
    except:
        return 0

print("Watching /proc/ipv6_counter...")
while True:
    print("IPv6 Packets:", read_count())
    time.sleep(1)

