/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Frey Alfredsson <freysteinn@freysteinn.com> */
/* Copyright 2025 Vincent Li <vincent.mc.li@gmail.com> */
/* Based on code by Jesper Dangaard Brouer <brouer@redhat.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include "parsing_helpers.h"

/* BPF map for TCP/UDP port to class ID mapping */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u16);  /* TCP/UDP destination port in host order */
    __type(value, __u32); /* Class ID */
} cls_filter_port_map SEC(".maps");

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
    int tcp_type, udp_type;
    struct iphdr *iphdr = NULL;
    struct ipv6hdr *ipv6hdr = NULL;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    __u16 dest_port = 0;

    skb->tc_classid = 0x30; /* Default class */

    nh.pos = data;

    /* Parse Ethernet and IP/IPv6 headers */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0)
        goto out;

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0 || !iphdr || (void *)(iphdr + 1) > data_end)
            goto out;
        
        /* Look up destination IP in trie map */
        struct ip_key ip_key = {
            .prefix_len = 32, /* Full IP address match by default */
            .ip = iphdr->daddr
        };
        
        __u32 *ip_class = bpf_map_lookup_elem(&cls_filter_ip_trie_map, &ip_key);
        if (ip_class) {
            skb->tc_classid = *ip_class;
	    bpf_printk("IP match: dest_ip=%pI4 classid=0x%x\n",
                      &iphdr->daddr, skb->tc_classid);
            goto out; /* IP match takes precedence */
        }
        
        /* Parse transport layer for port-based classification */
        if (ip_type == IPPROTO_TCP) {
            tcp_type = parse_tcphdr(&nh, data_end, &tcphdr);
            if (tcp_type >= 0 && tcphdr && (void *)(tcphdr + 1) <= data_end)
                dest_port = bpf_ntohs(tcphdr->dest);
        } else if (ip_type == IPPROTO_UDP) {
            udp_type = parse_udphdr(&nh, data_end, &udphdr);
            if (udp_type >= 0 && udphdr && (void *)(udphdr + 1) <= data_end)
                dest_port = bpf_ntohs(udphdr->dest);
        }

    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
        if (ip_type < 0 || !ipv6hdr || (void *)(ipv6hdr + 1) > data_end)
            goto out;
        /* Parse transport layer for port-based classification */
        if (ip_type == IPPROTO_TCP) {
            tcp_type = parse_tcphdr(&nh, data_end, &tcphdr);
            if (tcp_type >= 0 && tcphdr && (void *)(tcphdr + 1) <= data_end)
                dest_port = bpf_ntohs(tcphdr->dest);
        } else if (ip_type == IPPROTO_UDP) {
            udp_type = parse_udphdr(&nh, data_end, &udphdr);
            if (udp_type >= 0 && udphdr && (void *)(udphdr + 1) <= data_end)
                dest_port = bpf_ntohs(udphdr->dest);
        }
    } else {
        goto out;
    }

    /* Look up destination port in hash map for both TCP and UDP */
    if (dest_port > 0) {
        __u32 *port_class = bpf_map_lookup_elem(&cls_filter_port_map, &dest_port);
        if (port_class) {
            skb->tc_classid = *port_class;
            bpf_printk("Port match: dest_port=%d classid=0x%x\n", dest_port, skb->tc_classid);
        }
    }

out:
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
