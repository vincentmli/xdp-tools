#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

/* tail call index */
#define DO_DROP 0

SEC("xdp")
int xdp_drop(struct xdp_md *ctx)
{
            bpf_printk("DROP %d\n", XDP_DROP);

    return XDP_DROP;
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 2);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __array(values, int (void *));
} jmp_table SEC(".maps") = {
        .values = {
                [DO_DROP] = (void *)&xdp_drop,
        },
};

SEC("xdp")
int xdp_tailcall(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// Only IPv4 supported for this example
	struct ethhdr *ether = data;
	if (data + sizeof(*ether) <= data_end) {
		// Malformed Ethernet header
		bpf_tail_call(ctx, &jmp_table, DO_DROP);
	}
	
	return XDP_PASS;
	
}

char _license[] SEC("license") = "GPL";
