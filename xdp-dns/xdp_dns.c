#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main() {
    int map_fd;
    char *domain = "www.bpfire.net";
    __u8 value = 1;

    map_fd = bpf_obj_get("/sys/fs/bpf/xdp-dns/domain_denylist");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map: %s\n", strerror(errno));
        return 1;
    }

    if (bpf_map_update_elem(map_fd, domain, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update map: %s\n", strerror(errno));
        return 1;
    }

    printf("Domain %s added to denylist\n", domain);
    return 0;
}
