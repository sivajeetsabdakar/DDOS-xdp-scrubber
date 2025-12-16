#!/usr/bin/env python3
"""
scrubber9.py

Advanced XDP scrubber (single-file, BCC-based), verifier-safe.

Features:
- Per-IP rate limiting (1-second window)
- Automatic temporary blacklisting (autoban)
- Whitelist map (trusted IPs bypass)
- Dynamic threshold updated from user-space (ARRAY map)
- Cheap payload-fingerprint detection (FNV-1a over first bytes)
- Simple TCP SYN flood detection (per-IP SYN counters)
- Perf/ring-buffer events to user-space
- Verifier-friendly: bounds checks, no bpf_probe_read, no invalid XADD usage

Usage:
  sudo ./scrubber9.py [interface]
Default interface: ens33
"""

from bcc import BPF
import ctypes
import os
import sys
import time
import socket
import struct
import threading
import select

# re-exec as root if needed
if os.geteuid() != 0:
    os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)

DEVICE = sys.argv[1] if len(sys.argv) > 1 else "ens33"

# ---------- Tunables ----------
BASE_MAX_PPS = 100            # baseline per-IP threshold (packets/sec)
BAN_DURATION_SEC = 10         # ban duration
NS_PER_SEC = 1_000_000_000
BAN_DURATION_NS = BAN_DURATION_SEC * NS_PER_SEC
DYNAMIC_ADJUST_INTERVAL = 5   # seconds
PAYLOAD_SIG_BYTES = 8         # bytes used for cheap fingerprint
SYN_FLOOD_THRESHOLD = 200     # per-IP SYNs/sec to trigger SYN-ban
MAP_MAX_ENTRIES = 16384
# -------------------------------

# BPF program (verifier-conscious)
prog = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

#define NS_PER_SEC 1000000000ULL
#define PAYLOAD_SIG_BYTES %d

struct ip_stats {
    __u64 last_ns;
    __u32 count;
};

struct ban_info {
    __u64 since_ns;
};

struct syn_stats {
    __u64 last_ns;
    __u32 syn_count;
};

struct payload_sig {
    __u64 sig;
    __u32 count;
};

// events to user-space
struct event_t {
    u32 src_ip;
    u32 dst_ip;
    u32 reason; // 1=RATE,2=SYN,3=PAYLOAD
    u32 extra;
};

BPF_HASH(ip_rates, u32, struct ip_stats, %d);
BPF_HASH(blacklist, u32, struct ban_info, 1024);
BPF_HASH(whitelist, u32, u8, 1024);
BPF_HASH(syn_counters, u32, struct syn_stats, 4096);
BPF_HASH(payload_map, u64, struct payload_sig, 4096);
BPF_ARRAY(dynamic_threshold, u32, 1);
BPF_PERF_OUTPUT(events);

// helper: validate it's IPv4 and populate pointers
static __inline int parse_ipv4(void *data, void *data_end, struct ethhdr **eth, struct iphdr **ip) {
    *eth = data;
    if ((void*)(*eth) + sizeof(**eth) > data_end) return 0;
    if ((*eth)->h_proto != htons(ETH_P_IP)) return 0;
    *ip = (void*)(*eth) + sizeof(**eth);
    if ((void*)(*ip) + sizeof(**ip) > data_end) return 0;
    return 1;
}

int xdp_main(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr *eth;
    struct iphdr *ip;
    if (!parse_ipv4(data, data_end, &eth, &ip)) return XDP_PASS;

    u32 src = ip->saddr; // network byte order
    u32 dst = ip->daddr;
    u64 now = bpf_ktime_get_ns();

    // whitelist check
    u8 *w = whitelist.lookup(&src);
    if (w) return XDP_PASS;

    // blacklist check
    struct ban_info *bi = blacklist.lookup(&src);
    if (bi) {
        if (now - bi->since_ns < (u64)%d) {
            return XDP_DROP;
        } else {
            // expired ban: delete (best-effort)
            blacklist.delete(&src);
        }
    }

    // dynamic threshold (slot 0) fallback to BASE_MAX_PPS provided by user-space
    u32 idx = 0;
    u32 *dyn = dynamic_threshold.lookup(&idx);
    u32 threshold = %d;
    if (dyn) threshold = *dyn;

    // per-IP rate counting (1s window)
    struct ip_stats *st = ip_rates.lookup(&src);
    if (st) {
        u64 diff = now - st->last_ns;
        if (diff < NS_PER_SEC) {
            st->count++;
            if (st->count > threshold) {
                // autoban by rate
                struct ban_info nb = {};
                nb.since_ns = now;
                blacklist.update(&src, &nb);

                struct event_t ev = {};
                ev.src_ip = src; ev.dst_ip = dst; ev.reason = 1; ev.extra = st->count;
                events.perf_submit(ctx, &ev, sizeof(ev));
                return XDP_DROP;
            }
        } else {
            struct ip_stats nst = {};
            nst.last_ns = now;
            nst.count = 1;
            ip_rates.update(&src, &nst);
        }
    } else {
        struct ip_stats init = {};
        init.last_ns = now;
        init.count = 1;
        ip_rates.update(&src, &init);
    }

    // TCP SYN detection (simple)
    if (ip->protocol == IPPROTO_TCP) {
        // compute tcp header pointer with bounds checks
        u32 ip_hdr_len = ip->ihl * 4;
        if ((void*)ip + ip_hdr_len + sizeof(struct tcphdr) <= data_end) {
            struct tcphdr *tcp = (void*)ip + ip_hdr_len;
            if (tcp->syn && !tcp->ack) {
                struct syn_stats *ss = syn_counters.lookup(&src);
                if (ss) {
                    u64 diff = now - ss->last_ns;
                    if (diff < NS_PER_SEC) {
                        ss->syn_count++;
                        if (ss->syn_count > %d) {
                            struct ban_info nb = {};
                            nb.since_ns = now;
                            blacklist.update(&src, &nb);

                            struct event_t ev = {};
                            ev.src_ip = src; ev.dst_ip = dst; ev.reason = 2; ev.extra = ss->syn_count;
                            events.perf_submit(ctx, &ev, sizeof(ev));
                            return XDP_DROP;
                        }
                    } else {
                        struct syn_stats nss = {};
                        nss.last_ns = now;
                        nss.syn_count = 1;
                        syn_counters.update(&src, &nss);
                    }
                } else {
                    struct syn_stats init = {};
                    init.last_ns = now;
                    init.syn_count = 1;
                    syn_counters.update(&src, &init);
                }
            }
        }
    }

    // Payload fingerprint (cheap FNV-1a on first PAYLOAD_SIG_BYTES)
    // locate payload start: ip + ihl
    u32 ihl = ip->ihl * 4;
    void *pay = (void*)ip + ihl;

    // ensure at least 1 byte exists
    if (pay + 1 <= data_end) {
        // compute min bytes to read
        int maxb = PAYLOAD_SIG_BYTES;
        // compute available bytes
        u64 available = (u64)data_end - (u64)pay;
        int toread = available < maxb ? (int)available : maxb;
        // FNV-1a 64-bit
        u64 sig = 1469598103934665603ULL;
        #pragma unroll
        for (int i = 0; i < PAYLOAD_SIG_BYTES; i++) {
            if (i >= toread) break;
            // safe single-byte load
            unsigned char c = 0;
            c = *(unsigned char *)(pay + i);
            sig ^= (u64)c;
            sig *= 1099511628211ULL;
        }
        // key: high 32 bits src IP, low 32 bits lower(sig)
        u64 key = ((u64)src << 32) | (u64)(sig & 0xffffffff);
        struct payload_sig *ps = payload_map.lookup(&key);
        if (ps) {
            ps->count++;
            if (ps->count > threshold) {
                struct ban_info nb = {};
                nb.since_ns = now;
                blacklist.update(&src, &nb);

                struct event_t ev = {};
                ev.src_ip = src; ev.dst_ip = dst; ev.reason = 3; ev.extra = ps->count;
                events.perf_submit(ctx, &ev, sizeof(ev));
                return XDP_DROP;
            }
        } else {
            struct payload_sig newp = {};
            newp.sig = sig;
            newp.count = 1;
            payload_map.update(&key, &newp);
        }
    }

    return XDP_PASS;
}
""" % (PAYLOAD_SIG_BYTES, MAP_MAX_ENTRIES, BAN_DURATION_NS, BASE_MAX_PPS, SYN_FLOOD_THRESHOLD)

# ---------------- User-space helpers ----------------

def inet_ntoa_from_key(key):
    try:
        k = key.value
    except Exception:
        k = int(key)
    k = k & 0xffffffff
    return socket.inet_ntoa(struct.pack("I", k))

# event structure matching C struct event_t
class Event(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("reason", ctypes.c_uint32),
        ("extra", ctypes.c_uint32),
    ]

def event_printer(cpu, data, size):
    ev = ctypes.cast(data, ctypes.POINTER(Event)).contents
    src = inet_ntoa_from_key(ev.src_ip)
    dst = inet_ntoa_from_key(ev.dst_ip)
    reason = {1: "RATE", 2: "SYN", 3: "PAYLOAD"}.get(ev.reason, str(ev.reason))
    print(f"[EVENT] offender={src} -> {dst} reason={reason} extra={ev.extra}")

# ---------------- Main ----------------

def main():
    print(f"Loading scrubber9 XDP program on {DEVICE} ...")
    b = BPF(text=prog)
    fn = b.load_func("xdp_main", BPF.XDP)

    try:
        b.attach_xdp(DEVICE, fn, flags=0)
    except Exception as e:
        print("Failed to attach XDP program:", e)
        sys.exit(1)

    print("[+] XDP program attached.")
    ip_rates = b.get_table("ip_rates")
    blacklist = b.get_table("blacklist")
    whitelist = b.get_table("whitelist")
    syn_map = b.get_table("syn_counters")
    payload_map = b.get_table("payload_map")
    dyn_thr = b.get_table("dynamic_threshold")

    # initialize dynamic threshold slot 0
    try:
        k0 = dyn_thr.Key(0)
        dyn_thr[k0] = dyn_thr.Leaf(BASE_MAX_PPS)
    except Exception:
        try:
            dyn_thr[0] = BASE_MAX_PPS
        except Exception:
            pass

    # perf buffer for events
    b["events"].open_perf_buffer(event_printer)

    # thread to poll perf buffer
    def perf_loop():
        while True:
            try:
                b.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except Exception:
                pass

    t = threading.Thread(target=perf_loop, daemon=True)
    t.start()

    last_adjust = time.time()
    print("\nCommands: whitelist add <ip> | whitelist rm <ip> | show maps | set base <n> | quit\n")

    try:
        while True:
            time.sleep(2)
            # print sample ip_rates
            print("\n--- ip_rates (sample) ---")
            i = 0
            for k, v in ip_rates.items():
                try:
                    print(f"{inet_ntoa_from_key(k):<16} count={int(v.count):4d} last_ns={int(v.last_ns)}")
                except Exception:
                    pass
                i += 1
                if i >= 8: break

            # print blacklist
            print("\n--- blacklist ---")
            for k, v in blacklist.items():
                try:
                    print(f"{inet_ntoa_from_key(k):<16} since_ns={int(v.since_ns)}")
                except Exception:
                    pass

            # syn counters sample
            print("\n--- syn_counters (sample) ---")
            i = 0
            for k, v in syn_map.items():
                try:
                    print(f"{inet_ntoa_from_key(k):<16} syn_count={int(v.syn_count):4d} last_ns={int(v.last_ns)}")
                except Exception:
                    pass
                i += 1
                if i >= 8: break

            # dynamic threshold adjustment every DYNAMIC_ADJUST_INTERVAL
            now = time.time()
            if now - last_adjust >= DYNAMIC_ADJUST_INTERVAL:
                last_adjust = now
                total_pps = 0
                now_ns = int(time.time() * NS_PER_SEC)
                for k, v in ip_rates.items():
                    try:
                        if now_ns - int(v.last_ns) < NS_PER_SEC * 2:
                            total_pps += int(v.count)
                    except Exception:
                        pass
                new_thr = BASE_MAX_PPS
                if total_pps > 10000:
                    new_thr = int(BASE_MAX_PPS * 3)
                elif total_pps > 1000:
                    new_thr = int(BASE_MAX_PPS * 2)
                elif total_pps > 500:
                    new_thr = int(BASE_MAX_PPS * 1.5)
                try:
                    k0 = dyn_thr.Key(0)
                    dyn_thr[k0] = dyn_thr.Leaf(new_thr)
                except Exception:
                    try:
                        dyn_thr[0] = new_thr
                    except Exception:
                        pass
                print(f"[DYNAMIC] total_pps={total_pps} new_thr={new_thr}")

            # non-blocking user input
            rlist, _, _ = select.select([sys.stdin], [], [], 0)
            if rlist:
                line = sys.stdin.readline().strip()
                if not line:
                    continue
                parts = line.split()
                cmd = parts[0].lower()
                if cmd == "whitelist" and len(parts) >= 3:
                    sub = parts[1].lower()
                    ip = parts[2]
                    try:
                        ipn = struct.unpack("I", socket.inet_aton(ip))[0]
                    except Exception:
                        print("Invalid IP")
                        continue
                    try:
                        key = whitelist.Key(ipn)
                        if sub == "add":
                            whitelist[key] = whitelist.Leaf(1)
                            print("Added", ip, "to whitelist")
                        elif sub == "rm":
                            try:
                                del whitelist[key]
                                print("Removed", ip)
                            except Exception:
                                try:
                                    del whitelist[ipn]
                                    print("Removed", ip)
                                except Exception:
                                    print("Failed to remove", ip)
                    except Exception:
                        try:
                            if sub == "add":
                                whitelist[ipn] = 1
                                print("Added", ip)
                            elif sub == "rm":
                                del whitelist[ipn]
                                print("Removed", ip)
                        except Exception as e:
                            print("Whitelist error:", e)

                elif cmd == "show" and len(parts) > 1 and parts[1] == "maps":
                    try:
                        print("\nMap sizes:")
                        print("ip_rates:", len(ip_rates))
                        print("blacklist:", len(blacklist))
                        print("whitelist:", len(whitelist))
                        print("syn_counters:", len(syn_map))
                        print("payload_map:", len(payload_map))
                    except Exception as e:
                        print("Error reading maps:", e)

                elif cmd == "set" and len(parts) >= 3 and parts[1] == "base":
                    try:
                        val = int(parts[2])
                        # update dynamic_threshold slot 0
                        try:
                            k0 = dyn_thr.Key(0)
                            dyn_thr[k0] = dyn_thr.Leaf(val)
                        except Exception:
                            try:
                                dyn_thr[0] = val
                            except Exception:
                                pass
                        print("Set base threshold to", val)
                    except Exception:
                        print("Invalid value")

                elif cmd in ("quit", "exit"):
                    break

                else:
                    print("Unknown command")

    except KeyboardInterrupt:
        print("Interrupted by user")

    finally:
        try:
            b.remove_xdp(DEVICE, 0)
            print("Detached XDP program.")
        except Exception as e:
            print("Error detaching:", e)

if __name__ == "__main__":
    main()
