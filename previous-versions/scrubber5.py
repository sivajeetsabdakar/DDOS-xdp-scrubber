#!/usr/bin/env python3
"""
xdp_autoban.py

XDP per-IP rate limiter with automatic temporary blacklisting (autoban).
When an IP exceeds MAX_PACKETS_PER_SEC within 1 second, it is added to a
blocked map with a timestamp. Packets from blocked IPs are dropped until
BAN_DURATION_NS elapses (automatic expiry).

Usage:
  sudo ./xdp_autoban.py [interface]
Default interface: ens33
"""
import os
import sys
import time
import socket
import struct
from bcc import BPF

# ensure we run as root (re-exec with sudo if needed)
if os.geteuid() != 0:
    os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)

DEVICE = sys.argv[1] if len(sys.argv) > 1 else "ens33"

MAX_PACKETS_PER_SEC = 100  # threshold per second
BAN_DURATION_SEC = 5       # seconds to ban an offending IP
NS_PER_SEC = 1000000000

# Convert to nanoseconds for compile-time substitution
BAN_DURATION_NS = BAN_DURATION_SEC * NS_PER_SEC

# --- eBPF Program (C) ---
prog = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>

#define MAX_PACKETS_PER_SEC %d
#define BAN_DURATION_NS %d
#define NS_PER_SEC 1000000000ULL

struct ip_stats {
    __u64 last_seen_ns;
    __u32 count;
};

struct ban_info {
    __u64 banned_since;
};

BPF_HASH(ip_rates, u32, struct ip_stats);
BPF_HASH(blocked_ips, u32, struct ban_info);

int xdp_autoban(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    // only handle IPv4 packets
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    u32 src = ip->saddr; // network order
    u64 now = bpf_ktime_get_ns();

    // Check blacklist
    struct ban_info *ban = blocked_ips.lookup(&src);
    if (ban) {
        if (now - ban->banned_since < BAN_DURATION_NS) {
            // still banned
            return XDP_DROP;
        } else {
            // expired ban: try to delete entry (best effort)
            blocked_ips.delete(&src);
        }
    }

    struct ip_stats *stats = ip_rates.lookup(&src);
    if (stats) {
        u64 diff = now - stats->last_seen_ns;
        if (diff < NS_PER_SEC) {
            // same 1-second window
            __sync_fetch_and_add(&stats->count, 1);
            if (stats->count > MAX_PACKETS_PER_SEC) {
                struct ban_info b = {};
                b.banned_since = now;
                blocked_ips.update(&src, &b);
                return XDP_DROP;
            }
        } else {
            // new window: reset
            struct ip_stats new = {};
            new.last_seen_ns = now;
            new.count = 1;
            ip_rates.update(&src, &new);
        }
    } else {
        // first time see this IP
        struct ip_stats init = {};
        init.last_seen_ns = now;
        init.count = 1;
        ip_rates.update(&src, &init);
    }

    return XDP_PASS;
}
""" % (MAX_PACKETS_PER_SEC, BAN_DURATION_NS)

def inet_ntoa_from_key(key):
    """Convert BPF map key (u32) to dotted quad string."""
    try:
        k = key.value
    except Exception:
        k = int(key)
    return socket.inet_ntoa(struct.pack("I", k))

def format_ns(ts_ns):
    """Return human-readable timestamp and relative seconds ago."""
    try:
        ts_ns = int(ts_ns)
    except Exception:
        return str(ts_ns)
    ts_s = ts_ns / 1_000_000_000
    return f"{ts_s:.3f}s (ns={ts_ns})"

def main():
    print(f"Loading XDP autoban (threshold {MAX_PACKETS_PER_SEC} pps, ban {BAN_DURATION_SEC}s) on {DEVICE} ...")
    try:
        b = BPF(text=prog)
        fn = b.load_func("xdp_autoban", BPF.XDP)
    except Exception as e:
        print(f"Failed to compile/load eBPF program: {e}")
        sys.exit(1)

    try:
        b.attach_xdp(DEVICE, fn, flags=0)
    except Exception as e:
        print(f"Failed to attach XDP program to {DEVICE}: {e}")
        sys.exit(1)

    print(f"XDP program successfully loaded on {DEVICE}. Monitoring maps...")
    ip_rates_map = b.get_table("ip_rates")
    blocked_map = b.get_table("blocked_ips")

    try:
        while True:
            time.sleep(2)
            print("\n=== ip_rates (sample) ===")
            if len(ip_rates_map) == 0:
                print("No IPs observed yet.")
            else:
                for k, v in ip_rates_map.items():
                    ip_addr = inet_ntoa_from_key(k)
                    try:
                        count = int(v.count)
                        last_ns = int(v.last_seen_ns)
                    except Exception:
                        count = int(v[1])
                        last_ns = int(v[0])
                    print(f"{ip_addr: <16}  count={count:4d}  last_seen_ns={last_ns}")

            print("\n=== blocked_ips (active bans) ===")
            if len(blocked_map) == 0:
                print("No blocked IPs.")
            else:
                for k, v in blocked_map.items():
                    ip_addr = inet_ntoa_from_key(k)
                    try:
                        banned_since = int(v.banned_since)
                    except Exception:
                        banned_since = int(v[0])
                    print(f"{ip_addr: <16}  banned_since_ns={banned_since}")

            # Optional: user-space cleanup of expired bans if needed
            # (demonstrated but not strictly required; kernel also tries to delete expired bans)
            now_ns = int(time.time() * 1_000_000_000)
            to_delete = []
            for k, v in blocked_map.items():
                try:
                    banned_since = int(v.banned_since)
                except Exception:
                    banned_since = int(v[0])
                if now_ns - banned_since > BAN_DURATION_NS:
                    to_delete.append(k)
            for k in to_delete:
                try:
                    del blocked_map[k]
                except Exception:
                    # some bcc versions require key in same ctypes form; ignore failures
                    pass

    except KeyboardInterrupt:
        print("\nUser requested stop. Detaching XDP program...")
    finally:
        try:
            b.remove_xdp(DEVICE, 0)
            print("XDP program detached successfully.")
        except Exception as e:
            print(f"Error while detaching XDP program: {e}")

if __name__ == "__main__":
    main()
