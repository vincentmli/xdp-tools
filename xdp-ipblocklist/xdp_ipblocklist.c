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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define MAP_PATH "/sys/fs/bpf/xdp-ipblocklist/ipblocklist_map"
#define BATCH_SIZE 1000  // Number of entries per batch

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

// Structure for IP entry
struct ip_entry {
    struct ipv4_lpm_key key;
    __u8 action;
};

void add_ips_batch(int map_fd, struct ip_entry *entries, size_t count) {
    struct ipv4_lpm_key keys[BATCH_SIZE];
    __u8 actions[BATCH_SIZE];
    for (size_t i = 0; i < count; i++) {
        keys[i] = entries[i].key;
        actions[i] = entries[i].action;
    }

    __u32 num_entries = count;
    int ret = bpf_map_update_batch(map_fd, keys, actions, &num_entries, NULL);
    if (ret) {
        fprintf(stderr, "Batch update failed: %s\n", strerror(errno));
    } else {
        printf("Batch update successful\n");
    }
}

void delete_ips_batch(int map_fd, struct ip_entry *entries, size_t count) {
    struct ipv4_lpm_key keys[BATCH_SIZE];
    for (size_t i = 0; i < count; i++) {
        keys[i] = entries[i].key;
    }

    __u32 num_entries = count;
    int ret = bpf_map_delete_batch(map_fd, keys, &num_entries, NULL);
    if (ret) {
        fprintf(stderr, "Batch delete failed: %s\n", strerror(errno));
    } else {
        printf("Batch delete successful\n");
    }
}

int parse_ip_blocklist_line(const char *line, struct ipv4_lpm_key *key) {
    // Skip whitespace
    while (*line == ' ' || *line == '\t') line++;
    
    // Skip comments and empty lines
    if (*line == '#' || *line == '\n' || *line == '\0')
        return 0;
    
    // Check for "add" command - format: "add BLOCKLIST_DEv4 1.12.251.79"
    if (strncmp(line, "add ", 4) == 0) {
        char set_name[64];
        char ip_cidr[64];
        
        // Parse: add BLOCKLIST_DEv4 1.12.251.79
        int parsed = sscanf(line, "add %63s %63s", set_name, ip_cidr);
        if (parsed != 2) {
            return 0;
        }
        
        // Check if it's an IPv4 address with CIDR notation
        char *slash = strchr(ip_cidr, '/');
        char ip_str[64];
        if (slash) {
            // Has CIDR notation like 1.2.3.4/24
            size_t ip_len = slash - ip_cidr;
            strncpy(ip_str, ip_cidr, ip_len);
            ip_str[ip_len] = '\0';
            key->prefixlen = atoi(slash + 1);
        } else {
            // Single IP address, default to /32
            strcpy(ip_str, ip_cidr);
            key->prefixlen = 32;
        }
        
        // Convert IP string to network byte order
        if (inet_pton(AF_INET, ip_str, &key->addr) != 1) {
            fprintf(stderr, "Invalid IP address: %s\n", ip_str);
            return 0;
        }
        
        return 1;
    }
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s add|delete <blocklist_file>\n", argv[0]);
        printf("\n");
        printf("Processes IP blocklist files in ipset format.\n");
        printf("Files should contain lines like: add BLOCKLIST_DEv4 1.12.251.79\n");
        printf("\n");
        printf("Examples:\n");
        printf("  %s add /var/lib/ipblocklist/BLOCKLIST_DE.conf\n", argv[0]);
        printf("  %s add /var/lib/ipblocklist/BLOCKLIST_CN.conf\n", argv[0]);
        printf("  %s add /var/lib/ipblocklist/BLOCKLIST_RU.conf\n", argv[0]);
        printf("  %s delete /var/lib/ipblocklist/BLOCKLIST_DE.conf\n", argv[0]);
        printf("\n");
        printf("Note: The XDP program will drop packets where either source\n");
        printf("      OR destination IP matches any blocked IP.\n");
        return 1;
    }

    char *command = argv[1];
    char *file_path = argv[2];

    // Validate command
    if (strcmp(command, "add") != 0 && strcmp(command, "delete") != 0) {
        fprintf(stderr, "Error: Command must be 'add' or 'delete'\n");
        return 1;
    }

    // Open the BPF map
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Error opening BPF map at %s: %s\n", MAP_PATH, strerror(errno));
        fprintf(stderr, "Make sure the XDP program is loaded and the map exists.\n");
        return 1;
    }

    FILE *file = fopen(file_path, "r");
    if (!file) {
        perror("Error opening blocklist file");
        close(map_fd);
        return 1;
    }

    struct ip_entry entries[BATCH_SIZE];
    size_t count = 0;
    size_t total_processed = 0;
    size_t total_lines = 0;
    size_t skipped_lines = 0;

    printf("Processing blocklist file: %s\n", file_path);
    printf("Command: %s\n\n", command);

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        total_lines++;
        
        // Remove trailing newline
        line[strcspn(line, "\n")] = '\0';
        
        struct ipv4_lpm_key key;
        
        if (parse_ip_blocklist_line(line, &key)) {
            entries[count].key = key;
            entries[count].action = 1;  // Block action
            
            count++;
            total_processed++;

            // Process the batch if full
            if (count == BATCH_SIZE) {
                if (strcmp(command, "add") == 0) {
                    printf("  Adding batch of %zu IPs...\n", count);
                    add_ips_batch(map_fd, entries, count);
                } else if (strcmp(command, "delete") == 0) {
                    printf("  Deleting batch of %zu IPs...\n", count);
                    delete_ips_batch(map_fd, entries, count);
                }
                count = 0;
            }
        } else {
            // Only count as skipped if it's not a comment or empty line
            if (line[0] != '#' && strlen(line) > 0) {
                skipped_lines++;
            }
        }
    }

    // Process any remaining IPs in the last batch
    if (count > 0) {
        if (strcmp(command, "add") == 0) {
            printf("  Adding final batch of %zu IPs...\n", count);
            add_ips_batch(map_fd, entries, count);
        } else if (strcmp(command, "delete") == 0) {
            printf("  Deleting final batch of %zu IPs...\n", count);
            delete_ips_batch(map_fd, entries, count);
        }
    }

    fclose(file);
    close(map_fd);
    
    printf("\n");
    printf("Processing complete:\n");
    printf("  File: %s\n", file_path);
    printf("  Total lines in file: %zu\n", total_lines);
    printf("  Successfully processed: %zu IPs\n", total_processed);
    printf("  Skipped lines: %zu\n", skipped_lines);
    printf("\n");
    printf("IPs have been %sed to the blocklist.\n", command);
    printf("The XDP program will drop packets where either source\n");
    printf("or destination IP matches any blocked IP.\n");
    
    return 0;
}
