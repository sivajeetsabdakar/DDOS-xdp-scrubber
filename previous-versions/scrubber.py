#!/usr/bin/env python3
import os
import sys

if os.geteuid() != 0:
    os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
from bcc import BPF

# minimal eBPF program – drops every packet
prog = """
#include <linux/bpf.h>
int xdp_drop(struct xdp_md *ctx) {
    return XDP_DROP; // Drop all packets
}
"""

# Load the program
b = BPF(text=prog)
fn = b.load_func("xdp_drop", BPF.XDP)

# Attach to interface 
DEVICE = "ens33"
b.attach_xdp(DEVICE, fn, flags=0)

print(f"XDP program loaded on {DEVICE}, dropping all packets...")

try:
    while True:
        pass
except KeyboardInterrupt:
    print("Detaching XDP program...")
    b.remove_xdp(device=DEVICE)
