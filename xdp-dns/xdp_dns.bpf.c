#include "vmlinux_local.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/errno.h>

#include "bpf/compiler.h"
#include "xdp_dns.h"
#include "bpf_kfuncs.h"

/* with vmlinux.h, define here to avoid the undefined error */
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN         */

#define memcpy __builtin_memcpy
#define MAX_DOMAIN_SIZE 128

struct meta_data {
	__u16 eth_proto;
	__u16 ip_pos;
	__u16 opt_pos;
	__u16 unused;
};

/* Define the LPM Trie Map for domain names */
struct domain_key {
	struct bpf_lpm_trie_key lpm_key;
	char data[MAX_DOMAIN_SIZE + 1];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct domain_key);
	__type(value, __u8);
	__uint(max_entries, 10000);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} domain_denylist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12); // 4KB buffer
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_ringbuf SEC(".maps");

struct qname_event {
	__u8 len;
	__u32 src_ip; // Store IPv4 address
	char qname[MAX_DOMAIN_SIZE + 1];
};

/*
 *  Store the VLAN header
 */
struct vlanhdr {
	__u16 tci;
	__u16 encap_proto;
};

static __always_inline void *custom_memcpy(void *dest, const void *src,
					   __u8 len)
{
	__u8 i;

	// Perform the copy byte-by-byte to satisfy the BPF verifier
	for (i = 0; i < len; i++) {
		*((char *)dest + i) = *((const char *)src + i);
	}

	return dest;
}

static __always_inline void reverse_string(char *str, __u8 len)
{
	for (int i = 0; i < (len - 1) / 2; i++) {
		char temp = str[i];
		str[i] = str[len - 1 - i];
		str[len - 1 - i] = temp;
	}
}

static __always_inline char *parse_dname_dynptr(struct bpf_dynptr *ptr, char *dname_buf, __u8 *out_len)
{
    __u8 label_len;
    __u32 offset = 0;  // Start at the beginning of the DNS query section
    __u32 total_len = 0;
    int max_len = MAX_DOMAIN_SIZE;

    // Read through the labels of the domain name
    while (total_len < max_len) {
        // Read the length of the next label
        if (bpf_dynptr_read(&label_len, sizeof(label_len), ptr, offset, 0) < 0)
            return 0;  // Error reading from packet

        // End of the domain name (null byte)
        if (label_len == 0)
            break;

        // Handle DNS name compression
        if ((label_len & 0xC0) == 0xC0) {
            // Skip 2-byte compression pointer and stop parsing
            offset += 2;
            break;
        }

        // Ensure the label length is valid and within bounds
        if (label_len > 63 || offset + label_len + 1 > max_len)
            return 0;  // Invalid label length or out of bounds

        // Copy the current label into the buffer
        if (bpf_dynptr_read(dname_buf + total_len, label_len, ptr, offset + 1, 0) < 0)
            return 0;  // Error reading from packet

        // Append the dot separator after each label except the last one
        total_len += label_len;
        if (total_len < max_len - 1) {
            dname_buf[total_len] = '.';
            total_len += 1;
        }

        // Move offset forward past the label and the length byte
        offset += label_len + 1;
    }

    // Return the parsed domain name length
    *out_len = total_len;

    return dname_buf;  // Return the fully parsed domain name
}

SEC("xdp")
int xdp_dns_denylist(struct xdp_md *ctx)
{
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct udphdr *udp;
	struct dnshdr *dns;
	struct bpf_dynptr ptr;
	char *qname;
	__u8 len = 0;
        char dname_buf[MAX_DOMAIN_SIZE];

	struct domain_key dkey = { 0 }; // LPM trie key

	// Adjust metadata
	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
		return XDP_PASS;

	// Initialize dynptr for safer memory access
	if (bpf_dynptr_from_xdp(ctx, 0, &ptr) < 0)
		return XDP_PASS;

	md = (void *)(long)ctx->data_meta;
	if ((void *)(long)(md + 1) > (void *)(long)ctx->data)
		return XDP_PASS;

	// Parse Ethernet header
	eth = (struct ethhdr *)bpf_dynptr_data(&ptr, 0, sizeof(*eth));
	if (!eth)
		return XDP_PASS;

	md->eth_proto = eth->h_proto;
	if (md->eth_proto == __bpf_htons(ETH_P_8021Q) || md->eth_proto == __bpf_htons(ETH_P_8021AD))
		return XDP_PASS;

	md->ip_pos = sizeof(*eth);

	// Parse IP header
	ipv4 = (struct iphdr *)bpf_dynptr_data(&ptr, md->ip_pos, sizeof(*ipv4));
	if (!ipv4 || ipv4->protocol != IPPROTO_UDP)
		return XDP_PASS;

	// Parse UDP header
	udp = (struct udphdr *)bpf_dynptr_data(&ptr, md->ip_pos + sizeof(*ipv4), sizeof(*udp));
	if (!udp || udp->dest != __bpf_htons(DNS_PORT))
		return XDP_PASS;

	// Parse DNS header
	dns = (struct dnshdr *)bpf_dynptr_data(&ptr, md->ip_pos + sizeof(*ipv4) + sizeof(*udp), sizeof(*dns));
	if (!dns || dns->flags.as_bits_and_pieces.qr || dns->qdcount != __bpf_htons(1))
		return XDP_PASS;

	// Parse query name (qname) using BPF dynptr
	qname = parse_dname_dynptr(&ptr, dname_buf, &len);
	if (!qname)
		return XDP_ABORTED;

	len = bpf_dynptr_size(&ptr);  // Length of the parsed qname
	bpf_printk("qname  %s len is %d from %pI4", qname, len, &ipv4->saddr);

	// Ensure safe memory bounds
	if (len > MAX_DOMAIN_SIZE)
		return XDP_ABORTED;

	// Copy qname to event and submit
	struct qname_event *event = bpf_ringbuf_reserve(&dns_ringbuf, sizeof(*event), 0);
	if (!event)
		return XDP_PASS;

	event->len = len;
	event->src_ip = ipv4->saddr;
	custom_memcpy(event->qname, qname, len);
	event->qname[len] = '\0';  // Null terminate

	bpf_ringbuf_submit(event, 0);

	// Copy qname to LPM key and reverse string
	custom_memcpy(dkey.data, qname, len);
	dkey.data[MAX_DOMAIN_SIZE] = '\0';
	reverse_string(dkey.data, len);
	dkey.lpm_key.prefixlen = len * 8;

	// Lookup in denylist
	if (bpf_map_lookup_elem(&domain_denylist, &dkey)) {
		bpf_printk("Domain %s found in denylist, dropping packet\n", dkey.data);
		return XDP_DROP;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

