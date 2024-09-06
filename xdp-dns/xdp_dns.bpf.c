/*
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
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
#include "xdp_dns.h"

/* with vmlinux.h, define here to avoid the undefined error */
#define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD    0x88A8          /* 802.1ad Service VLAN         */

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
#define memcpy __builtin_memcpy
#define MAX_DOMAIN_SIZE 18

struct meta_data {
	__u16 eth_proto;
	__u16 ip_pos;
	__u16 opt_pos;
	__u16 unused;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_DOMAIN_SIZE + 1]);
    __type(value, __u8);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_denylist SEC(".maps");

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

static __always_inline
void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)			\
static __always_inline \
struct STRUCT *parse_ ## STRUCT (struct cursor *c)	\
{							\
	struct STRUCT *ret = c->pos;			\
	if (c->pos + sizeof(struct STRUCT) > c->end)	\
		return 0;				\
	c->pos += sizeof(struct STRUCT);		\
	return ret;					\
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)

static __always_inline
struct ethhdr *parse_eth(struct cursor *c, __u16 *eth_proto)
{
	struct ethhdr  *eth;

	if (!(eth = parse_ethhdr(c)))
		return 0;

	*eth_proto = eth->h_proto;
	if (*eth_proto == __bpf_htons(ETH_P_8021Q)
	||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
		struct vlanhdr *vlan;

		if (!(vlan = parse_vlanhdr(c)))
			return 0;

		*eth_proto = vlan->encap_proto;
		if (*eth_proto == __bpf_htons(ETH_P_8021Q)
		||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
			if (!(vlan = parse_vlanhdr(c)))
				return 0;

			*eth_proto = vlan->encap_proto;
		}
	}
	return eth;
}

static __always_inline char *parse_dname(struct cursor *c) {
    __u8 *dname = c->pos;
    __u8 i;

    for (i = 0; i < 128; i++) { /* Maximum 128 labels */
        __u8 o;

        // Check bounds before accessing the next byte
        if (c->pos + 1 > c->end)
            return 0;

        o = *(__u8 *)c->pos;

        // Check for DNS name compression
        if ((o & 0xC0) == 0xC0) {
            // If the current label is compressed, skip the next 2 bytes
            if (c->pos + 2 > c->end) // Ensure we have 2 bytes to skip
                return 0;

            c->pos += 2;
            return (char *)dname;  // Return the parsed domain name
        } else if (o > 63 || c->pos + o + 1 > c->end) {
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

static __always_inline void *custom_memcpy(void *dest, const void *src, __u8 len) {
    __u8 i;

    // Perform the copy byte-by-byte to satisfy the BPF verifier
    for (i = 0; i < len; i++) {
        *((__u8 *)dest + i) = *((__u8 *)src + i);
    }

    return dest;
}

// Custom strlen function for BPF
static __always_inline __u8 custom_strlen(const char *str, struct cursor *c) {
    __u8 len = 0;

    // Loop through the string, ensuring not to exceed MAX_STRING_LEN
    #pragma unroll
    for (int i = 0; i < MAX_DOMAIN_SIZE; i++) {
	if (str + i >= c->end)  // Check if we are at or beyond the end of the packet
		break;
        if (str[i] == '\0')
            break;
        len++;
    }

    return len;
}

SEC("xdp")
int xdp_dns(struct xdp_md *ctx)
{
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct cursor     c;
	struct ethhdr    *eth;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;
	char	*qname;
//	__u8 value = 1;
	__u8 len = 0;
	char domain_key[MAX_DOMAIN_SIZE + 1 ] = {0};  // Buffer for map lookup

	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
		return XDP_PASS;

	cursor_init(&c, ctx);
	md = (void *)(long)ctx->data_meta;
	if ((void *)(md + 1) > c.pos)
		return XDP_PASS;

	if (!(eth = parse_eth(&c, &md->eth_proto)))
		return XDP_PASS;
	md->ip_pos = c.pos - (void *)eth;

	if (md->eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c)))
			return XDP_PASS; /* Not IPv4 */
		switch (ipv4->protocol) {
		case IPPROTO_UDP:
			if (!(udp = parse_udphdr(&c))
			|| !(udp->dest == __bpf_htons(DNS_PORT))
			|| !(dns = parse_dnshdr(&c)))
				return XDP_PASS; /* Not DNS */

			if (dns->flags.as_bits_and_pieces.qr
			||  dns->qdcount != __bpf_htons(1)
			||  dns->ancount || dns->nscount
			||  dns->arcount >  __bpf_htons(2))
				return XDP_ABORTED; // Return FORMERR?

			qname = parse_dname(&c);
			if (!qname) {
				return XDP_ABORTED; // Return FORMERR?
			}

			len = custom_strlen(qname, &c);		
			bpf_printk("qname  %s len is %d from %pI4", qname, len, &ipv4->saddr);

                        //avoid R2 offset is outside of the packet error
                        if (qname + len > c.end)
				return XDP_ABORTED; // Return FORMERR?

			int copy_len = len < MAX_DOMAIN_SIZE ? len : MAX_DOMAIN_SIZE;
			custom_memcpy(domain_key, qname, copy_len);
			domain_key[MAX_DOMAIN_SIZE] = '\0'; // Ensure null-termination

/*
			bpf_printk("domain_key  %s copy_len is %d from %pI4", domain_key, copy_len, &ipv4->saddr);
			
			if (bpf_map_update_elem(&domain_denylist, &domain_key, &value, BPF_ANY) < 0) {
				bpf_printk("Domain %s not updated in denylist\n", domain_key);
			} else {
				bpf_printk("Domain %s updated in denylist\n", domain_key);
			}
				
*/
                        if (bpf_map_lookup_elem(&domain_denylist, domain_key)) {
				bpf_printk("Domain %s found in denylist, dropping packet\n", domain_key);
				return XDP_DROP;
			}
                        else {
				bpf_printk("Domain %s not found in denylist\n", domain_key);
			}

			break;
		}

	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
