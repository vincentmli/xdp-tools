// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/wait.h>

static struct env {
    bool verbose;
    const char *iface;
    const char *bpf_obj_path;
    const char *limit;
    const char *start_rate;
    const char *default_limit;
} env;

static const struct option long_options[] = {
    { "interface", required_argument, NULL, 'i' },
    { "bpf-object", required_argument, NULL, 'b' },
    { "verbose", no_argument, NULL, 'v' },
    { "add-port", required_argument, NULL, 'p' },  // Combined: single port or range
    { "add-ip", required_argument, NULL, 'r' },
    { "delete-port", required_argument, NULL, 'd' },
    { "delete-ip", required_argument, NULL, 'x' },
    { "list-ports", no_argument, NULL, 'l' },
    { "list-ips", no_argument, NULL, 'm' },
    { "attach", no_argument, NULL, 'a' },
    { "detach", no_argument, NULL, 'D' },
    { "setup-qdisc", no_argument, NULL, 's' },
    { "limit", required_argument, NULL, 'L' },
    { "start-rate", required_argument, NULL, 'S' },
    { "default-limit", required_argument, NULL, '3' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static void print_usage(void)
{
    printf("Usage: class_filter [OPTIONS]...\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -i, --interface <iface>        Network interface to attach to\n");
    printf("  -b, --bpf-object <path>        Path to BPF object file (default: class_filter.bpf.o)\n");
    printf("  -v, --verbose                  Verbose output\n");
    printf("  -p, --add-port <spec:class:rate>       Add port mapping (e.g., 80:10:50mbit or 8000-8080:20:30mbit)\n");
    printf("  -r, --add-ip <cidr:class:rate>       Add IP range mapping with rate (e.g., 192.168.1.0/24:40:30mbit)\n");
    printf("  -d, --delete-port <port>              Delete port mapping\n");
    printf("  -x, --delete-ip <cidr>         Delete IP range mapping\n");
    printf("  -l, --list-ports               List all port mappings\n");
    printf("  -m, --list-ips                 List all IP range mappings\n");
    printf("  -a, --attach                   Attach BPF program to interface\n");
    printf("  -D, --detach                   Detach BPF program from interface\n");
    printf("  -s, --setup-qdisc              Setup TC qdisc and classes\n");
    printf("  -L, --limit <rate>             Overall limit rate (default: 100mbit)\n");
    printf("  -S, --start-rate <rate>        Start rate for classes (default: 5mbit)\n");
    printf("  -3, --default-limit <rate>     Default class ceil limit (default: 20mbit)\n");
    printf("  -h, --help                     Show this help message\n");
}

/* Get map FD from pinned path */
static int get_pinned_map(const char *map_name)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/fs/bpf/tc/globals/%s", map_name);
    int fd = bpf_obj_get(path);
    if (fd < 0 && env.verbose) {
        printf("Debug: Failed to get pinned map %s: %s\n", path, strerror(errno));
    }
    return fd;
}

static void cleanup_pinned_maps(void)
{
    unlink("/sys/fs/bpf/tc/globals/cls_filter_port_map");
    unlink("/sys/fs/bpf/tc/globals/cls_filter_ip_trie_map");
}

/* Helper function to execute system commands with proper error checking */
static int execute_system_cmd(const char *cmd, bool ignore_failure)
{
    if (env.verbose) {
        printf("Executing: %s\n", cmd);
    }
    
    int ret = system(cmd);
    if (ret == -1) {
        fprintf(stderr, "Error: system() failed for command: %s\n", cmd);
        return -EINVAL;
    }
    
    if (WIFEXITED(ret)) {
        int exit_status = WEXITSTATUS(ret);
        if (exit_status != 0) {
            if (!ignore_failure) {
                fprintf(stderr, "Error: command failed with exit code %d: %s\n", exit_status, cmd);
                return -EINVAL;
            } else if (env.verbose) {
                printf("Command failed but ignoring (may be normal): %s\n", cmd);
            }
        }
    } else {
        fprintf(stderr, "Error: command terminated abnormally: %s\n", cmd);
        return -EINVAL;
    }
    
    return 0;
}

static int add_tc_class(const char *iface, __u32 classid, const char *rate, const char *ceil)
{
    char cmd[512];
    char class_str[16];
    
    snprintf(class_str, sizeof(class_str), "1:%x", classid);
    snprintf(cmd, sizeof(cmd),
             "tc class add dev %s parent 1:1 classid %s htb rate %s ceil %s",
             iface, class_str, rate, ceil);
    
    int err = execute_system_cmd(cmd, false);
    if (err) {
        fprintf(stderr, "Error: failed to add TC class %s\n", class_str);
        return err;
    }
    
    printf("Added TC class: %s (rate: %s, ceil: %s)\n", class_str, rate, ceil);
    return 0;
}

static int delete_tc_class(const char *iface, __u32 classid)
{
    char cmd[512];
    char class_str[16];
    
    snprintf(class_str, sizeof(class_str), "1:%x", classid);
    snprintf(cmd, sizeof(cmd),
             "tc class del dev %s classid %s 2>/dev/null",
             iface, class_str);
    
    /* Ignore failure for deletion - it's OK if class doesn't exist */
    execute_system_cmd(cmd, true);
    
    if (env.verbose) {
        printf("Attempted to delete TC class: %s\n", class_str);
    }
    
    return 0;
}

/* Unified port mapping parser - detects single port vs range automatically */
static int parse_unified_port_mapping(const char *arg, __u16 *start_port, __u16 *end_port, 
                                     __u32 *classid, char **rate)
{
    char buf[256];
    char *first_colon, *second_colon, *dash;
    
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    /* Find the colons separating port(s):class:rate */
    first_colon = strchr(buf, ':');
    if (!first_colon) {
        fprintf(stderr, "Error: port mapping must be in format 'port:class:rate' or 'start-end:class:rate'\n");
        return -EINVAL;
    }
    *first_colon = '\0';
    
    second_colon = strchr(first_colon + 1, ':');
    if (!second_colon) {
        fprintf(stderr, "Error: port mapping must be in format 'port:class:rate' or 'start-end:class:rate'\n");
        return -EINVAL;
    }
    *second_colon = '\0';
    
    /* Check if it's a range (contains dash) or single port */
    dash = strchr(buf, '-');
    if (dash) {
        /* It's a port range: start-end:class:rate */
        *dash = '\0';
        
        long start = strtol(buf, NULL, 10);
        long end = strtol(dash + 1, NULL, 10);
        
        if (start <= 0 || start > 65535 || end <= 0 || end > 65535 || start > end) {
            fprintf(stderr, "Error: port range must be between 1-65535 and start <= end\n");
            return -EINVAL;
        }
        
        /* Limit range size to prevent excessive map entries */
        if ((end - start + 1) > 1000) {
            fprintf(stderr, "Error: port range too large (max 1000 ports). Use smaller ranges.\n");
            return -EINVAL;
        }
        
        *start_port = (__u16)start;
        *end_port = (__u16)end;
    } else {
        /* It's a single port: port:class:rate */
        long port = strtol(buf, NULL, 10);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Error: port must be between 1 and 65535\n");
            return -EINVAL;
        }
        *start_port = (__u16)port;
        *end_port = (__u16)port;
    }
    
    /* Parse class ID and rate (common for both single port and range) */
    long minor_num = strtol(first_colon + 1, NULL, 16);
    if (minor_num <= 0 || minor_num > 0xFFFF) {
        fprintf(stderr, "Error: class minor must be between 1 and 0xFFFF\n");
        return -EINVAL;
    }
    
    *rate = strdup(second_colon + 1);
    if (!*rate) {
        fprintf(stderr, "Error: failed to allocate memory for rate\n");
        return -ENOMEM;
    }
    
    *classid = minor_num;
    return 0;
}

static int parse_ip_mapping(const char *arg, struct in_addr *ip, __u32 *prefix_len, __u32 *classid, char **rate)
{
    char buf[256];
    char *sep1, *sep2, *slash;
    
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    slash = strchr(buf, '/');
    if (!slash) {
        fprintf(stderr, "Error: CIDR notation required (e.g., 192.168.1.0/24)\n");
        return -EINVAL;
    }
    *slash = '\0';
    
    sep1 = strchr(slash + 1, ':');
    if (!sep1) {
        fprintf(stderr, "Error: IP mapping must be in format 'cidr:class:rate'\n");
        return -EINVAL;
    }
    *sep1 = '\0';
    
    sep2 = strchr(sep1 + 1, ':');
    if (!sep2) {
        fprintf(stderr, "Error: IP mapping must be in format 'cidr:class:rate'\n");
        return -EINVAL;
    }
    *sep2 = '\0';
    
    if (inet_pton(AF_INET, buf, ip) != 1) {
        fprintf(stderr, "Error: invalid IP address: %s\n", buf);
        return -EINVAL;
    }
    
    *prefix_len = atoi(slash + 1);
    if (*prefix_len > 32) {
        fprintf(stderr, "Error: prefix length must be <= 32\n");
        return -EINVAL;
    }
    
    long minor_num = strtol(sep1 + 1, NULL, 16);
    if (minor_num <= 0 || minor_num > 0xFFFF) {
        fprintf(stderr, "Error: class minor must be between 1 and 0xFFFF\n");
        return -EINVAL;
    }
    
    *rate = strdup(sep2 + 1);
    if (!*rate) {
        fprintf(stderr, "Error: failed to allocate memory for rate\n");
        return -ENOMEM;
    }
    
    *classid = minor_num;
    return 0;
}

/* Unified port mapping function - handles both single ports and ranges */
static int add_port_mapping(const char *iface, const char *arg)
{
    __u16 start_port, end_port;
    __u32 classid;
    char *rate = NULL;
    int err, map_fd;
    
    err = parse_unified_port_mapping(arg, &start_port, &end_port, &classid, &rate);
    if (err) {
        return err;
    }
    
    map_fd = get_pinned_map("cls_filter_port_map");
    if (map_fd < 0) {
        fprintf(stderr, "Error: failed to get pinned map. Is BPF program attached?\n");
        free(rate);
        return map_fd;
    }
    
    bool is_single_port = (start_port == end_port);
    int ports_added = 0;
    int ports_failed = 0;
    
    /* Add port(s) to the map */
    for (__u16 port = start_port; port <= end_port; port++) {
        err = bpf_map_update_elem(map_fd, &port, &classid, BPF_ANY);
        if (err) {
            if (errno == E2BIG) {
                fprintf(stderr, "Error: port map full (max 4096 entries). Added %d/%d ports.\n",
                       ports_added, end_port - start_port + 1);
                break;
            }
            ports_failed++;
        } else {
            ports_added++;
        }
    }
    close(map_fd);
    
    if (ports_added == 0) {
        fprintf(stderr, "Error: failed to add any ports from specification '%s'\n", arg);
        free(rate);
        return -EINVAL;
    }
    
    if (ports_failed > 0) {
        fprintf(stderr, "Warning: failed to add %d ports from specification '%s'\n",
               ports_failed, arg);
    }
    
    /* Add TC class */
    err = add_tc_class(iface, classid, env.start_rate, rate);
    if (err) {
        /* Rollback: remove all added ports */
        map_fd = get_pinned_map("cls_filter_port_map");
        if (map_fd >= 0) {
            for (__u16 port = start_port; port <= end_port; port++) {
                bpf_map_delete_elem(map_fd, &port);
            }
            close(map_fd);
        }
        free(rate);
        return err;
    }
    
    /* Print appropriate success message */
    if (is_single_port) {
        printf("Added port mapping: %d -> 1:%x (rate: %s)\n", start_port, classid, rate);
    } else {
        printf("Added %d individual ports: %d-%d -> 1:%x (rate: %s)\n",
               ports_added, start_port, end_port, classid, rate);
    }
    
    free(rate);
    return 0;
}

static int add_ip_mapping(const char *iface, const char *arg)
{
    struct in_addr ip;
    __u32 prefix_len, classid;
    char *rate = NULL;
    int err, map_fd;
    
    err = parse_ip_mapping(arg, &ip, &prefix_len, &classid, &rate);
    if (err) return err;
    
    struct ip_key {
        __u32 prefix_len;
        __u32 ip;
    } key = {
        .prefix_len = prefix_len,
        .ip = ip.s_addr
    };
    
    map_fd = get_pinned_map("cls_filter_ip_trie_map");
    if (map_fd < 0) {
        fprintf(stderr, "Error: failed to get pinned map. Is BPF program attached?\n");
        free(rate);
        return map_fd;
    }
    
    err = bpf_map_update_elem(map_fd, &key, &classid, BPF_ANY);
    close(map_fd);
    
    if (err) {
        fprintf(stderr, "Error: failed to update IP map: %s\n", strerror(errno));
        free(rate);
        return err;
    }
    
    err = add_tc_class(iface, classid, env.start_rate, rate);
    if (err) {
        map_fd = get_pinned_map("cls_filter_ip_trie_map");
        if (map_fd >= 0) {
            bpf_map_delete_elem(map_fd, &key);
            close(map_fd);
        }
        free(rate);
        return err;
    }
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
    printf("Added IP mapping: %s/%u -> 1:%x (rate: %s)\n", ip_str, prefix_len, classid, rate);
    free(rate);
    return 0;
}

static int delete_port_mapping(const char *iface, const char *arg)
{
    __u16 port = (__u16)atoi(arg);
    int map_fd, err;
    __u32 classid;
    
    map_fd = get_pinned_map("cls_filter_port_map");
    if (map_fd < 0) {
        fprintf(stderr, "Error: failed to get pinned map. Is BPF program attached?\n");
        return map_fd;
    }
    
    err = bpf_map_lookup_elem(map_fd, &port, &classid);
    if (err) {
        if (env.verbose) {
            printf("Port %s not found in map, may already be deleted\n", arg);
        }
        close(map_fd);
        return 0;
    }
    
    err = bpf_map_delete_elem(map_fd, &port);
    close(map_fd);
    
    if (err) {
        fprintf(stderr, "Error: failed to delete port mapping: %s\n", strerror(errno));
        return err;
    }
    
    printf("Deleted port mapping: %s -> 1:%x\n", arg, classid);
    delete_tc_class(iface, classid);
    return 0;
}

static int delete_ip_mapping(const char *iface, const char *arg)
{
    struct in_addr ip;
    __u32 prefix_len;
    char buf[256];
    char *slash;
    int map_fd, err;
    __u32 classid;
    
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    slash = strchr(buf, '/');
    if (!slash) {
        fprintf(stderr, "Error: CIDR notation required (e.g., 192.168.1.0/24)\n");
        return -EINVAL;
    }
    *slash = '\0';
    
    if (inet_pton(AF_INET, buf, &ip) != 1) {
        fprintf(stderr, "Error: invalid IP address: %s\n", buf);
        return -EINVAL;
    }
    
    prefix_len = atoi(slash + 1);
    if (prefix_len > 32) {
        fprintf(stderr, "Error: prefix length must be <= 32\n");
        return -EINVAL;
    }
    
    struct ip_key {
        __u32 prefix_len;
        __u32 ip;
    } key = {
        .prefix_len = prefix_len,
        .ip = ip.s_addr
    };
    
    map_fd = get_pinned_map("cls_filter_ip_trie_map");
    if (map_fd < 0) {
        fprintf(stderr, "Error: failed to get pinned map. Is BPF program attached?\n");
        return map_fd;
    }
    
    err = bpf_map_lookup_elem(map_fd, &key, &classid);
    if (err) {
        if (env.verbose) {
            printf("IP mapping %s not found in map, may already be deleted\n", arg);
        }
        close(map_fd);
        return 0;
    }
    
    err = bpf_map_delete_elem(map_fd, &key);
    close(map_fd);
    
    if (err) {
        fprintf(stderr, "Error: failed to delete IP mapping: %s\n", strerror(errno));
        return err;
    }
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
    printf("Deleted IP mapping: %s/%u -> 1:%x\n", ip_str, prefix_len, classid);
    delete_tc_class(iface, classid);
    return 0;
}

static int list_port_mappings(void)
{
    __u16 port, next_port = 0;
    __u32 classid;
    int err, map_fd;
    
    map_fd = get_pinned_map("cls_filter_port_map");
    if (map_fd < 0) {
        fprintf(stderr, "Error: failed to get pinned map. Is BPF program attached?\n");
        return map_fd;
    }
    
    printf("Port Mappings:\n");
    printf("PORT    -> TC_CLASS  (BPF_VALUE)\n");
    printf("-------------------------------\n");
    
    int count = 0;
    while (true) {
        err = bpf_map_get_next_key(map_fd, &next_port, &port);
        if (err) {
            if (errno == ENOENT) break;
            fprintf(stderr, "Error: failed to get next key: %s\n", strerror(errno));
            close(map_fd);
            return -errno;
        }
        
        err = bpf_map_lookup_elem(map_fd, &port, &classid);
        if (err) {
            fprintf(stderr, "Error: failed to lookup element: %s\n", strerror(errno));
            close(map_fd);
            return -errno;
        }
        
        printf("%-6d -> 1:%-6x (0x%02x)\n", port, classid, classid);
        count++;
        next_port = port;
    }
    
    close(map_fd);
    printf("Total: %d port mappings\n", count);
    return 0;
}

static int list_ip_mappings(void)
{
    struct ip_key {
        __u32 prefix_len;
        __u32 ip;
    } key = {0}, next_key = {0};
    __u32 classid;
    int err, map_fd;
    
    map_fd = get_pinned_map("cls_filter_ip_trie_map");
    if (map_fd < 0) {
        fprintf(stderr, "Error: failed to get pinned map. Is BPF program attached?\n");
        return map_fd;
    }
    
    printf("IP Range Mappings:\n");
    printf("CIDR            -> TC_CLASS  (BPF_VALUE)\n");
    printf("----------------------------------------\n");
    
    int count = 0;
    while (true) {
        err = bpf_map_get_next_key(map_fd, &next_key, &key);
        if (err) {
            if (errno == ENOENT) break;
            fprintf(stderr, "Error: failed to get next key: %s\n", strerror(errno));
            close(map_fd);
            return -errno;
        }
        
        err = bpf_map_lookup_elem(map_fd, &key, &classid);
        if (err) {
            fprintf(stderr, "Error: failed to lookup element: %s\n", strerror(errno));
            close(map_fd);
            return -errno;
        }
        
        struct in_addr ip_addr = { .s_addr = key.ip };
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));
        
        printf("%s/%-2u -> 1:%-6x (0x%02x)\n", ip_str, key.prefix_len, classid, classid);
        count++;
        next_key = key;
    }
    
    close(map_fd);
    printf("Total: %d IP range mappings\n", count);
    return 0;
}

static int setup_tc_qdisc(const char *iface)
{
    char cmd[512];
    int err;
    
    printf("Setting up TC qdisc and classes on %s\n", iface);
    
    /* Delete existing qdisc - ignore failures */
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", iface);
    err = execute_system_cmd(cmd, true);
    if (err && env.verbose) {
        printf("Note: No existing qdisc to delete on %s (may be normal)\n", iface);
    }
    
    /* Add root qdisc */
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s root handle 1:0 htb default 30", iface);
    err = execute_system_cmd(cmd, false);
    if (err) {
        fprintf(stderr, "Error: failed to add root qdisc\n");
        return err;
    }
    
    /* Add main class */
    snprintf(cmd, sizeof(cmd), "tc class add dev %s parent 1:0 classid 1:1 htb rate %s", iface, env.limit);
    err = execute_system_cmd(cmd, false);
    if (err) {
        fprintf(stderr, "Error: failed to add main class\n");
        return err;
    }
    
    /* Add default class */
    snprintf(cmd, sizeof(cmd), "tc class add dev %s parent 1:1 classid 1:30 htb rate %s ceil %s", 
             iface, env.start_rate, env.default_limit);
    err = execute_system_cmd(cmd, false);
    if (err) {
        fprintf(stderr, "Error: failed to add default class 1:30\n");
        return err;
    }
    
    printf("Successfully setup TC qdisc and classes on %s\n", iface);
    
    if (env.verbose) {
        printf("\nTC qdisc configuration:\n");
        snprintf(cmd, sizeof(cmd), "tc qdisc show dev %s", iface);
        execute_system_cmd(cmd, true);
        
        printf("\nTC classes configuration:\n");
        snprintf(cmd, sizeof(cmd), "tc class show dev %s", iface);
        execute_system_cmd(cmd, true);
    }
    
    return 0;
}

static int attach_bpf_with_tc(const char *iface, const char *bpf_obj_path)
{
    char cmd[512];
    int err;
    
    cleanup_pinned_maps();
    
    /* Delete existing filter - ignore failures */
    snprintf(cmd, sizeof(cmd), "tc filter del dev %s protocol ip parent 1:0 2>/dev/null", iface);
    err = execute_system_cmd(cmd, true);
    if (err && env.verbose) {
        printf("Note: No existing filter to delete on %s (may be normal)\n", iface);
    }
    
    /* Attach BPF program */
    snprintf(cmd, sizeof(cmd),
             "tc filter add dev %s protocol ip parent 1:0 "
             "bpf obj %s classid 1: direct-action",
             iface, bpf_obj_path);
    
    err = execute_system_cmd(cmd, false);
    if (err) {
        fprintf(stderr, "Error: failed to attach BPF program via tc command\n");
        return err;
    }
    
    printf("Successfully attached BPF program to %s egress (parent 1:0)\n", iface);
    
    if (get_pinned_map("cls_filter_port_map") < 0 ||
        get_pinned_map("cls_filter_ip_trie_map") < 0) {
        fprintf(stderr, "Warning: BPF maps were not pinned. Check LIBBPF_PIN_BY_NAME in BPF program.\n");
    } else {
        printf("BPF maps automatically pinned to /sys/fs/bpf/tc/globals/\n");
    }
    
    if (env.verbose) {
        snprintf(cmd, sizeof(cmd), "tc filter show dev %s parent 1:0", iface);
        printf("Verification:\n");
        execute_system_cmd(cmd, true);
        
        printf("Pinned maps:\n");
        execute_system_cmd("ls -la /sys/fs/bpf/tc/globals/ 2>/dev/null || echo 'No pinned maps found'", true);
    }
    
    return 0;
}

static int detach_bpf_with_tc(const char *iface)
{
    char cmd[256];
    int err;
    
    printf("Cleaning up TC configuration on %s\n", iface);
    
    /* Delete filter - ignore failures */
    snprintf(cmd, sizeof(cmd), "tc filter del dev %s protocol ip parent 1:0 2>/dev/null", iface);
    err = execute_system_cmd(cmd, true);
    if (err) {
        printf("No BPF filter found on %s parent 1:0 (or error removing)\n", iface);
    } else {
        printf("Successfully detached BPF program from %s egress\n", iface);
    }
    
    cleanup_pinned_maps();
    printf("Cleaned up pinned BPF maps from /sys/fs/bpf/tc/globals/\n");
    
    /* Delete qdisc - ignore failures */
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", iface);
    err = execute_system_cmd(cmd, true);
    if (err) {
        printf("No TC qdisc found on %s (or error removing)\n", iface);
    } else {
        printf("Removed TC qdisc from %s\n", iface);
    }
    
    return 0;
}

int main(int argc, char **argv)
{
    int err, opt;
    bool map_operation = false;
    bool attach = false;
    bool detach = false;
    bool setup_qdisc = false;
    
    env.bpf_obj_path = "class_filter.bpf.o";
    env.limit = "100mbit";
    env.start_rate = "5mbit";
    env.default_limit = "20mbit";
    
    while ((opt = getopt_long(argc, argv, "i:b:vp:r:d:x:lmaDsL:S:3:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i': env.iface = optarg; break;
        case 'b': env.bpf_obj_path = optarg; break;
        case 'v': env.verbose = true; break;
        case 'p':
        case 'r':
        case 'd':
        case 'x':
        case 'l':
        case 'm': map_operation = true; break;
        case 'a': attach = true; break;
        case 'D': detach = true; break;
        case 's': setup_qdisc = true; break;
        case 'L': env.limit = optarg; break;
        case 'S': env.start_rate = optarg; break;
        case '3': env.default_limit = optarg; break;
        case 'h': print_usage(); return 0;
        default: print_usage(); return 1;
        }
    }
    
    if (detach && env.iface) {
        return detach_bpf_with_tc(env.iface);
    }
    
    if (setup_qdisc && env.iface) {
        return setup_tc_qdisc(env.iface);
    }
    
    if (map_operation) {
        optind = 1;
        while ((opt = getopt_long(argc, argv, "i:b:vp:r:d:x:lmh", long_options, NULL)) != -1) {
            switch (opt) {
            case 'p':
                if (!env.iface) {
                    fprintf(stderr, "Error: must specify interface with --add-port\n");
                    return -EINVAL;
                }
                err = add_port_mapping(env.iface, optarg);
                break;
            case 'r':
                if (!env.iface) {
                    fprintf(stderr, "Error: must specify interface with --add-ip\n");
                    return -EINVAL;
                }
                err = add_ip_mapping(env.iface, optarg);
                break;
            case 'd':
                if (!env.iface) {
                    fprintf(stderr, "Error: must specify interface with --delete-port\n");
                    return -EINVAL;
                }
                err = delete_port_mapping(env.iface, optarg);
                break;
            case 'x':
                if (!env.iface) {
                    fprintf(stderr, "Error: must specify interface with --delete-ip\n");
                    return -EINVAL;
                }
                err = delete_ip_mapping(env.iface, optarg);
                break;
            case 'l': err = list_port_mappings(); break;
            case 'm': err = list_ip_mappings(); break;
            }
            if (err) return err < 0 ? -err : err;
        }
    } else if (attach && env.iface) {
        printf("Setting up TC qdisc and classes...\n");
        err = setup_tc_qdisc(env.iface);
        if (err) return err;
        
        err = attach_bpf_with_tc(env.iface, env.bpf_obj_path);
        if (err) return err;
        
        printf("\nBPF program loaded and attached successfully to %s egress\n", env.iface);
        printf("Default class configured: 1:30 (rate: %s, ceil: %s)\n", env.start_rate, env.default_limit);
        printf("\nUse --add-port to create additional classes with rates (supports single ports and ranges).\n");
    } else {
        fprintf(stderr, "Error: must specify interface with attach/detach or map operation\n");
        print_usage();
        return 1;
    }
    
    return 0;
}
