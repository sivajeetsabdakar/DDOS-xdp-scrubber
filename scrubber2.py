#!/usr/bin/env python3
import os
import sys
import time
import socket
import struct

# This script needs root privileges to attach an eBPF program.
if os.geteuid() != 0:
    os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)

from bcc import BPF

# --- eBPF Program (C Code) ---
prog = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// Define the maximum number of packets allowed per second from a single IP.
#define MAX_PACKETS_PER_SEC 100

// A struct to hold the statistics for each IP address.
struct ip_stats {
    __u64 last_seen_ns; // Timestamp of the last packet in nanoseconds.
    __u32 count;        // Packet count within the current one-second window.
};

// eBPF hash map to store stats for each source IP.
BPF_HASH(ip_rates, u32, struct ip_stats);

int xdp_ratelimit(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 now = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = ip->saddr;
    struct ip_stats *stats = ip_rates.lookup(&src_ip);

    if (stats) {
        // Entry for this IP exists.
        __u64 time_diff_ns = now - stats->last_seen_ns;

        if (time_diff_ns < 1000000000) { // 1 second in nanoseconds
            stats->count++;
        } else {
            stats->count = 1;
            stats->last_seen_ns = now;
        }

        // *** LOGIC FIX ***
        // The updated stats must be written back to the map.
        ip_rates.update(&src_ip, stats);

        if (stats->count > MAX_PACKETS_PER_SEC) {
            return XDP_DROP;
        }
    } else {
        // *** VERIFIER FIX ***
        // Initialize the struct with '{}' to zero out all fields, including
        // any padding the compiler might add. This satisfies the verifier.
        struct ip_stats new_stats = {};
        new_stats.last_seen_ns = now;
        new_stats.count = 1;
        ip_rates.update(&src_ip, &new_stats);
    }

    return XDP_PASS;
}
"""

# --- Python Script Logic (unchanged) ---

# 1. Load the eBPF program
try:
    b = BPF(text=prog)
    fn = b.load_func("xdp_ratelimit", BPF.XDP)
except Exception as e:
    print(f"❌ Failed to load or compile the eBPF program: {e}")
    sys.exit(1)

# 2. Attach the program to a network interface
# !!! IMPORTANT: Replace "ens33" with your actual network interface name !!!
DEVICE = "ens33"
b.attach_xdp(DEVICE, fn, flags=0)

print(f"✅ XDP rate-limiter loaded on {DEVICE}. Dropping packets exceeding {100} pps...")

# 3. Periodically print stats from the eBPF map
ip_rates_map = b.get_table("ip_rates")
print("\nMonitoring IP packet rates... Press Ctrl+C to stop.")
try:
    while True:
        time.sleep(2)
        print("\n--- IPs observed in the last ~2 seconds ---")
        for ip, stats in ip_rates_map.items():
            ip_addr = socket.inet_ntoa(struct.pack("=I", ip.value))
            print(f"IP: {ip_addr:<16} Rate: {stats.count} pps")
        
        ip_rates_map.clear()

except KeyboardInterrupt:
    print("\nDetaching XDP program...")

finally:
    # 4. Detach the program when the script is stopped
    b.remove_xdp(device=DEVICE)
    print("✅ Program detached successfully.")
