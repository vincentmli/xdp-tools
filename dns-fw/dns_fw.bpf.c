/*
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
 * Copyright (c) 2024 - 2026, LoongFire.  All rights reserved.
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
#include "dns_fw.h"

/* with vmlinux.h, define here to avoid the undefined error */
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN         */

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
#define memcpy __builtin_memcpy
#define MAX_DOMAIN_NAME 127  /* Max total domain name length (reduced for verifier) */
#define MAX_DOMAIN_LABEL 63  /* Max per label length (RFC 1035) */

struct meta_data {
	__u16 eth_proto;
	__u16 ip_pos;
	__u16 opt_pos;
	__u16 unused;
};

/* Define the Hash Map for domain names */
struct domain_key {
	char data[MAX_DOMAIN_NAME + 1];  /* +1 for null terminator */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct domain_key);
	__type(value, __u8);
	__uint(max_entries, 1500000);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_fw_blocklist SEC(".maps");

/*
 * DEBUG: ringbuf was removed because bpf_ringbuf_reserve() returns NULL
 * when the buffer is full, and the original code returned XDP_PASS on
 * that failure -- silently bypassing the blocklist for all DNS queries
 * once the 4KB buffer was exhausted.  If ringbuf logging is needed in
 * future, ensure the map lookup happens BEFORE the ringbuf reserve so
 * a full buffer can never bypass firewall logic.  To restore, uncomment
 * the block below and the ringbuf code inside dns_fw().
 *
 * #define DNS_FW_RINGBUF_ENABLE
 */

/* DEBUG_RINGBUF_BEGIN -- uncomment #define above to enable
 *
 * struct {
 *	__uint(type, BPF_MAP_TYPE_RINGBUF);
 *	__uint(max_entries, 1 << 12); // 4KB buffer
 *	__uint(pinning, LIBBPF_PIN_BY_NAME);
 * } dns_fw_ringbuf SEC(".maps");
 *
 * struct qname_event {
 *	__u8 len;
 *	__u32 src_ip; // Store IPv4 address
 *	char qname[MAX_DOMAIN_NAME + 1];
 * };
 *
 * DEBUG_RINGBUF_END */

/*
 *  Store the VLAN header
 */
struct vlanhdr {
	__u16 tci;
	__u16 encap_proto;
};

/*
 *  Helper pointer to parse the incoming packets
 */
struct cursor {
	void *pos;
	void *end;
};

static __always_inline void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)                                         \
	static __always_inline struct STRUCT *parse_##STRUCT(struct cursor *c) \
	{                                                                      \
		struct STRUCT *ret = c->pos;                                   \
		if (c->pos + sizeof(struct STRUCT) > c->end)                   \
			return 0;                                              \
		c->pos += sizeof(struct STRUCT);                               \
		return ret;                                                    \
	}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)

static __always_inline struct ethhdr *parse_eth(struct cursor *c,
						__u16 *eth_proto)
{
	struct ethhdr *eth;

	if (!(eth = parse_ethhdr(c)))
		return 0;

	*eth_proto = eth->h_proto;
	if (*eth_proto == __bpf_htons(ETH_P_8021Q) ||
	    *eth_proto == __bpf_htons(ETH_P_8021AD)) {
		struct vlanhdr *vlan;

		if (!(vlan = parse_vlanhdr(c)))
			return 0;

		*eth_proto = vlan->encap_proto;
		if (*eth_proto == __bpf_htons(ETH_P_8021Q) ||
		    *eth_proto == __bpf_htons(ETH_P_8021AD)) {
			if (!(vlan = parse_vlanhdr(c)))
				return 0;

			*eth_proto = vlan->encap_proto;
		}
	}
	return eth;
}

static __always_inline char *parse_dname(struct cursor *c)
{
	__u8 *dname = c->pos;
	__u8 i;
	__u8 o;

	/* Use a conservative bound for the verifier */
	for (i = 0; i < 32; i++) {  /* Reduced from 64 to 32 for verifier */
		// Check bounds before accessing the next byte
		if (c->pos + 1 > c->end)
			return 0;

		o = *(__u8 *)c->pos;

		// Check for DNS name compression
		if ((o & 0xC0) == 0xC0) {
			// If the current label is compressed, skip the next 2 bytes
			if (c->pos + 2 > c->end)
				return 0;

			c->pos += 2;
			return (char *)dname;
		} else if (o > MAX_DOMAIN_LABEL || c->pos + o + 1 > c->end) {
			// Label is invalid or out of bounds
			return 0;
		}

		// Move the cursor by label length and its leading length byte
		c->pos += o + 1;

		// End of domain name (null label length)
		if (o == 0)
			return (char *)dname;
	}

	// If we exit the loop without finding a terminating label, return NULL
	return 0;
}

// Optimized custom_memcpy with fixed small bound
static __always_inline void *custom_memcpy(void *dest, const void *src,
					   __u8 len)
{
	/* Use a small fixed bound to help the verifier */
	/* Most domain names are much shorter than MAX_DOMAIN_NAME */
	if (len > 96)  /* Cap at 96 bytes for performance */
		len = 96;
	
	#pragma unroll
	for (int i = 0; i < 96; i++) {
		if (i >= len)
			break;
		*((__u8 *)dest + i) = *((__u8 *)src + i);
	}

	return dest;
}

// Custom strlen function for BPF
static __always_inline __u8 custom_strlen(const char *str, struct cursor *c)
{
	__u8 len = 0;
	
	/* Fixed bound loop - helps verifier */
	for (int i = 0; i < MAX_DOMAIN_NAME; i++) {
		if (str + i >= c->end)
			break;
		if (str[i] == '\0')
			break;
		len++;
	}

	return len;
}

/*
 * DEBUG: is_letsbond() -- uncomment to enable targeted bpf_printk tracing
 * for letsbond.com without flooding trace_pipe with all DNS queries.
 * Compares the first 14 bytes of dkey against the wire format of
 * "letsbond.com": \x08letsbond\x03com\x00
 * Used together with the DEBUG_PRINTK block inside dns_fw() below.
 *
 * static __always_inline int is_letsbond(const struct domain_key *dkey)
 * {
 *	const char expected[14] = {
 *		0x08,
 *		'l','e','t','s','b','o','n','d',
 *		0x03,
 *		'c','o','m',
 *		0x00
 *	};
 * #pragma unroll
 *	for (int i = 0; i < 14; i++) {
 *		if (dkey->data[i] != expected[i])
 *			return 0;
 *	}
 *	return 1;
 * }
 */

SEC("xdp")
int dns_fw(struct xdp_md *ctx)
{
	struct cursor c;
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct udphdr *udp;
	struct dnshdr *dns;
	char *qname;
	__u16 eth_proto;
	__u8 len = 0;

	struct domain_key dkey = { 0 }; // Hash map key

	cursor_init(&c, ctx);

	if (!(eth = parse_eth(&c, &eth_proto)))
		return XDP_PASS;

	if (eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c)))
			return XDP_PASS; /* Not IPv4 */
		switch (ipv4->protocol) {
		case IPPROTO_UDP:
			if (!(udp = parse_udphdr(&c)) ||
			    !(udp->dest == __bpf_htons(DNS_PORT)) ||
			    !(dns = parse_dnshdr(&c)))
				return XDP_PASS; /* Not DNS */

			if (dns->flags.as_bits_and_pieces.qr ||
			    dns->qdcount != __bpf_htons(1) || dns->ancount ||
			    dns->nscount || dns->arcount > __bpf_htons(2))
				return XDP_ABORTED; // Return FORMERR?

			qname = parse_dname(&c);
			if (!qname) {
				return XDP_ABORTED; // Return FORMERR?
			}

			len = custom_strlen(qname, &c);
			//bpf_printk("qname %s len %d ipid %d from %pI4", qname, len, ipv4->id, &ipv4->saddr);

			//avoid R2 offset is outside of the packet error
			if (qname + len > c.end)
				return XDP_ABORTED; // Return FORMERR?

			int copy_len = len < MAX_DOMAIN_NAME ? len :
							       MAX_DOMAIN_NAME;

			/* DEBUG_RINGBUF_BEGIN -- restore ringbuf logging here
			 * if needed; see map definition comments above.
			 * WARNING: always perform map lookup BEFORE ringbuf
			 * reserve to prevent a full buffer bypassing the
			 * blocklist.
			 *
			 * struct qname_event *event = bpf_ringbuf_reserve(
			 *	&dns_fw_ringbuf, sizeof(*event), 0);
			 * if (!event)
			 *	return XDP_PASS; // Drop if no space
			 * event->len = copy_len;
			 * event->src_ip = ipv4->saddr;
			 * custom_memcpy(event->qname, qname, copy_len);
			 * event->qname[copy_len] = '\0';
			 * bpf_ringbuf_submit(event, 0);
			 *
			 * DEBUG_RINGBUF_END */

			custom_memcpy(dkey.data, qname, copy_len);
			dkey.data[copy_len] = '\0'; // Ensure null-termination

			/* DEBUG_PRINTK_BEGIN -- uncomment is_letsbond() above
			 * and this block to trace letsbond.com lookups via
			 * trace_pipe without noise from other domains.
			 * Read with: cat /sys/kernel/debug/tracing/trace_pipe
			 * bpf_printk supports max 3 format args per call.
			 *
			 * if (is_letsbond(&dkey)) {
			 *	bpf_printk("DNS_FW_DEBUG letsbond.com seen len=%d",
			 *		   copy_len);
			 *	bpf_printk("DNS_FW_DEBUG key[0-2]: %02x %02x %02x",
			 *		   (unsigned char)dkey.data[0],
			 *		   (unsigned char)dkey.data[1],
			 *		   (unsigned char)dkey.data[2]);
			 *	bpf_printk("DNS_FW_DEBUG key[3-5]: %02x %02x %02x",
			 *		   (unsigned char)dkey.data[3],
			 *		   (unsigned char)dkey.data[4],
			 *		   (unsigned char)dkey.data[5]);
			 *	bpf_printk("DNS_FW_DEBUG key[6-8]: %02x %02x %02x",
			 *		   (unsigned char)dkey.data[6],
			 *		   (unsigned char)dkey.data[7],
			 *		   (unsigned char)dkey.data[8]);
			 *	bpf_printk("DNS_FW_DEBUG key[9-11]: %02x %02x %02x",
			 *		   (unsigned char)dkey.data[9],
			 *		   (unsigned char)dkey.data[10],
			 *		   (unsigned char)dkey.data[11]);
			 *	bpf_printk("DNS_FW_DEBUG key[12-13]: %02x %02x",
			 *		   (unsigned char)dkey.data[12],
			 *		   (unsigned char)dkey.data[13]);
			 *	if (bpf_map_lookup_elem(&dns_fw_blocklist, &dkey)) {
			 *		bpf_printk("DNS_FW_DEBUG letsbond.com HIT -> XDP_DROP");
			 *		return XDP_DROP;
			 *	}
			 *	bpf_printk("DNS_FW_DEBUG letsbond.com MISS -> XDP_PASS");
			 *	break;
			 * }
			 *
			 * DEBUG_PRINTK_END */

			if (bpf_map_lookup_elem(&dns_fw_blocklist, &dkey)) {
				return XDP_DROP;
			}

			break;
		}
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
