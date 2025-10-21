/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Frey Alfredsson <freysteinn@freysteinn.com> */
/* Based on code by Jesper Dangaard Brouer <brouer@redhat.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include "parsing_helpers.h"

/*
 * This example eBPF code mirrors the TC u32 rules set in the runner.sh
 * script, where the script gives different rate limits depending on if the TCP
 * traffic is for ports 8080 or 8081. It must be loaded with the direct-action
 * flag on TC to function, as this is a Qdisc classifier, not a Qdisc action. The
 * runner.sh script shows an example of how it is loaded and used.
 */

/* BPF map for TCP port to class ID mapping */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __be16);  /* TCP destination port */
    __type(value, __u32); /* Class ID */
} cls_filter_tcp_port_map SEC(".maps");

/* BPF trie map for destination IP range lookup */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct ip_key);
    __type(value, __u32); /* Class ID */
} cls_filter_ip_trie_map SEC(".maps");

/* Key structure for IP trie map */
struct ip_key {
    __u32 prefix_len;
    __u32 ip;
};

SEC("classifier")
int cls_filter(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct hdr_cursor nh;
    struct ethhdr *eth;
    int eth_type;
    int ip_type;
    int tcp_type;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    struct tcphdr *tcphdr;
    skb->tc_classid = 0x30; /* Default class */

    nh.pos = data;

    /* Parse Ethernet and IP/IPv6 headers */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type != IPPROTO_TCP)
            goto out;
        
        /* Look up destination IP in trie map */
        struct ip_key ip_key = {
            .prefix_len = 32, /* Full IP address match by default */
            .ip = iphdr->daddr
        };
        
        __u32 *ip_class = bpf_map_lookup_elem(&cls_filter_ip_trie_map, &ip_key);
        if (ip_class) {
            skb->tc_classid = *ip_class;
            goto out; /* IP match takes precedence */
        }
        
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
        if (ip_type != IPPROTO_TCP)
            goto out;
        /* IPv6 trie lookup could be added here similarly */
    } else {
        goto out;
    }

    /* Parse TCP header and look up port in map */
    tcp_type = parse_tcphdr(&nh, data_end, &tcphdr);
    if (tcp_type < 0) goto out;
    if (tcphdr + 1 > data_end) {
        goto out;
    }

    /* Look up TCP destination port in hash map */
    __u16 dest_port = bpf_ntohs(tcphdr->dest);
    __u32 *port_class = bpf_map_lookup_elem(&cls_filter_tcp_port_map, &dest_port);
    if (port_class) {
        skb->tc_classid = *port_class;
    } else {
        /* Fallback to original switch-based port classification */
        switch (tcphdr->dest) {
        case bpf_htons(8080):
            skb->tc_classid = 0x10; /* Handles are always in hex */
            break;
        case bpf_htons(8081):
            skb->tc_classid = 0x20;
            break;
        }
    }

out:
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
