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
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/errno.h>

#include "bpf/compiler.h"
//#include "bpf/builtins.h"
#include "siphash4bpf.c"
#include "xdp_dnsrrl.h"

/* with vmlinux.h, define here to avoid the undefined error */
#define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD    0x88A8          /* 802.1ad Service VLAN         */

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
#define memcpy __builtin_memcpy

struct meta_data {
	__u16 eth_proto;
	__u16 ip_pos;
	__u16 opt_pos;
	__u16 unused;
};

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
PARSE_FUNC_DECLARATION(dns_qrr)
PARSE_FUNC_DECLARATION(dns_rr)
PARSE_FUNC_DECLARATION(option)

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

static __always_inline
int cookie_verify_ipv4(struct cursor *c, struct iphdr *ipv4)
{
	__u8  input[20];
	__u64 hash;

	memcpy(input, c->pos, 16);
	memcpy(input + 16, &ipv4->saddr, 4);
	siphash_ipv4(input, (__u8 *)&hash);
	return hash == ((__u64 *)c->pos)[2];
}

SEC("xdp")
int xdp_cookie_verify_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	struct dns_rr    *opt_rr;
	__u16          rdata_len;
	__u8           i;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096)
		return XDP_ABORTED;
	c.pos += md->opt_pos;

	if (!(opt_rr = parse_dns_rr(&c))
	||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
		return XDP_ABORTED;

	rdata_len = __bpf_ntohs(opt_rr->rdata_len);
	for (i = 0; i < 10 && rdata_len >= 28; i++) {
		struct option *opt;
		__u16       opt_len;

		if (!(opt = parse_option(&c)))
			return XDP_ABORTED;

		rdata_len -= 4;
		opt_len = __bpf_ntohs(opt->len);
		if (opt->code == __bpf_htons(OPT_CODE_COOKIE)) {
			if (opt_len == 24 && c.pos + 24 <= c.end
			&&  cookie_verify_ipv4(&c, ipv4)) {
				/* Cookie match!
				 * Packet may go staight up to the DNS service
				 */
				return XDP_PASS;
			}
			/* Just a client cookie or a bad cookie
			 * break to go to rate limiting
			 */
			break;
		}
		if (opt_len > 1500 || opt_len > rdata_len
		||  c.pos + opt_len > c.end)
			return XDP_ABORTED;

		rdata_len -= opt_len;
		c.pos += opt_len;
	}
	return XDP_PASS;
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 3);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __array(values, int (void *));
} jmp_cookie_table SEC(".maps") = {
        .values = {
                [COOKIE_VERIFY_IPv4] = (void *)&xdp_cookie_verify_ipv4,
        },
};

SEC("xdp")
int xdp_dns(struct xdp_md *ctx)
{
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct cursor     c;
	struct ethhdr    *eth;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;

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
			||  dns->arcount >  __bpf_htons(2)
			||  !parse_dns_qrr(&c))
				return XDP_ABORTED; // Return FORMERR?

			if (c.pos + 1 > c.end
			||  *(__u8 *)c.pos != 0)
				return XDP_ABORTED; // Return FORMERR?

			md->opt_pos = c.pos + 1 - (void *)(ipv4 + 1);
			bpf_tail_call(ctx, &jmp_cookie_table, COOKIE_VERIFY_IPv4);

			break;
		}

	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
