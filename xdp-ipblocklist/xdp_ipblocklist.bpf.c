/*
 * Copyright (c) 2026, LoongFire.  All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "vmlinux_local.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

// Hash map for IP blocking (only IPv4, single IPs)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);      // IPv4 address in network byte order
    __type(value, __u8);     // Action (1 = block)
} ipblocklist_map SEC(".maps");

SEC("xdp")
int xdp_ipblocklist(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    
    // Check Ethernet header bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    iph = (struct iphdr *)(eth + 1);
    // Check IP header bounds
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Check source IP
    __u8 *action = bpf_map_lookup_elem(&ipblocklist_map, &iph->saddr);
    if (action && *action == 1) {
        // Source IP is in blocklist - drop packet
        return XDP_DROP;
    }

    // Check destination IP
    action = bpf_map_lookup_elem(&ipblocklist_map, &iph->daddr);
    if (action && *action == 1) {
        // Destination IP is in blocklist - drop packet
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
