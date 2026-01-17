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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAP_PATH "/sys/fs/bpf/xdp-ipblocklist/ipblocklist_map"
#define BATCH_SIZE 1000  // Number of entries per batch

// Structure for IP entry (simple hash map version)
struct ip_entry {
    __u32 ip_addr;  // IPv4 address in network byte order
    __u8 action;
};

// Function prototypes
void add_ips_batch(int map_fd, struct ip_entry *entries, size_t count);
void delete_ips_batch(int map_fd, struct ip_entry *entries, size_t count);
void clear_entire_map(int map_fd);
int parse_ip_blocklist_line(const char *line, __u32 *ip_addr);
void print_usage(const char *program_name);
void print_ip(__u32 ip_addr);

void add_ips_batch(int map_fd, struct ip_entry *entries, size_t count) {
    if (count == 0) {
        return;  // Nothing to do
    }
    
    __u32 keys[BATCH_SIZE] = {0};
    __u8 actions[BATCH_SIZE] = {0};
    
    for (size_t i = 0; i < count; i++) {
        keys[i] = entries[i].ip_addr;
        actions[i] = entries[i].action;
    }

    __u32 num_entries = count;
    int ret = bpf_map_update_batch(map_fd, keys, actions, &num_entries, NULL);
    if (ret) {
        fprintf(stderr, "Batch update failed: %s\n", strerror(errno));
    } else {
        printf("  Added %u entries\n", num_entries);
    }
}

void delete_ips_batch(int map_fd, struct ip_entry *entries, size_t count) {
    if (count == 0) {
        return;  // Nothing to do
    }
    
    __u32 keys[BATCH_SIZE] = {0};
    
    for (size_t i = 0; i < count; i++) {
        keys[i] = entries[i].ip_addr;
    }

    __u32 num_entries = count;
    int ret = bpf_map_delete_batch(map_fd, keys, &num_entries, NULL);
    if (ret) {
        // If batch delete fails, try one by one
        fprintf(stderr, "Batch delete failed, deleting individually: %s\n", strerror(errno));
        
        size_t deleted = 0;
        for (size_t i = 0; i < count; i++) {
            ret = bpf_map_delete_elem(map_fd, &entries[i].ip_addr);
            if (ret == 0) {
                deleted++;
            } else if (errno != ENOENT) {
                fprintf(stderr, "  Failed to delete entry %zu: %s\n", i, strerror(errno));
            }
        }
        printf("  Deleted %zu entries individually\n", deleted);
    } else {
        printf("  Deleted %u entries\n", num_entries);
    }
}

void clear_entire_map(int map_fd) {
    printf("Clearing entire hash map...\n");
    
    __u32 next_key = 0;
    __u32 key = 0;
    __u32 keys[BATCH_SIZE] = {0};
    size_t batch_count = 0;
    int total_deleted = 0;
    int iteration = 0;
    int ret;
    
    // Use batch deletion for efficiency
    while (bpf_map_get_next_key(map_fd, batch_count == 0 ? NULL : &key, &next_key) == 0) {
        keys[batch_count++] = next_key;
        key = next_key;
        
        if (batch_count == BATCH_SIZE) {
            __u32 num = batch_count;
            ret = bpf_map_delete_batch(map_fd, keys, &num, NULL);
            if (ret == 0) {
                total_deleted += num;
            } else {
                // Fall back to individual deletion
                for (size_t i = 0; i < batch_count; i++) {
                    if (bpf_map_delete_elem(map_fd, &keys[i]) == 0) {
                        total_deleted++;
                    }
                }
            }
            batch_count = 0;
            
            // Progress indicator for large maps
            if (++iteration % 10 == 0) {
                printf("  Cleared %d entries so far...\n", total_deleted);
            }
        }
    }
    
    // Delete remaining entries
    if (batch_count > 0) {
        __u32 num = batch_count;
        ret = bpf_map_delete_batch(map_fd, keys, &num, NULL);
        if (ret == 0) {
            total_deleted += num;
        } else {
            // Fall back to individual deletion
            for (size_t i = 0; i < batch_count; i++) {
                if (bpf_map_delete_elem(map_fd, &keys[i]) == 0) {
                    total_deleted++;
                }
            }
        }
    }
    
    // Also try the other iteration method to catch any leftovers
    iteration = 0;
    while (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        if (bpf_map_delete_elem(map_fd, &next_key) == 0) {
            total_deleted++;
            if (++iteration % 1000 == 0) {
                printf("  Cleaning up %d more entries...\n", iteration);
            }
        }
    }
    
    printf("Successfully cleared %d entries from hash map\n", total_deleted);
}

int parse_ip_blocklist_line(const char *line, __u32 *ip_addr) {
    // Skip whitespace
    while (*line == ' ' || *line == '\t') line++;
    
    // Skip comments and empty lines
    if (*line == '#' || *line == '\n' || *line == '\0')
        return 0;
    
    // Check for "add" command - format: "add BLOCKLIST_DEv4 1.12.251.79"
    if (strncmp(line, "add ", 4) == 0) {
        char set_name[64];
        char ip_str[64];
        char ip_copy[64] = {0};  // Copy for safe manipulation
        
        // Parse: add BLOCKLIST_DEv4 1.12.251.79
        int parsed = sscanf(line, "add %63s %63s", set_name, ip_str);
        if (parsed != 2) {
            return 0;
        }
        
        // Make a copy to avoid modifying the original string if needed
        strncpy(ip_copy, ip_str, sizeof(ip_copy) - 1);
        ip_copy[sizeof(ip_copy) - 1] = '\0';
        
        // Check if it's an IPv4 address (no CIDR support in hash map)
        // If there's a CIDR notation, we'll just take the base IP
        char *slash = strchr(ip_copy, '/');
        if (slash) {
            // Has CIDR notation - truncate it
            *slash = '\0';
        }
        
        // Convert IP string to network byte order
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_copy, &addr) != 1) {
            // Don't print warning for every line to avoid spam
            return 0;
        }
        
        *ip_addr = addr.s_addr;
        return 1;
    }
    
    return 0;
}

void print_ip(__u32 ip_addr) {
    struct in_addr addr;
    addr.s_addr = ip_addr;
    printf("%s", inet_ntoa(addr));
}

void print_usage(const char *program_name) {
    printf("XDP IP Blocklist Manager - Hash Map Version\n");
    printf("===========================================\n");
    printf("Usage: %s add|delete|clear|dump|stats <blocklist_file>\n", program_name);
    printf("\n");
    printf("Commands:\n");
    printf("  add <file>    - Add IPs from blocklist file\n");
    printf("  delete <file> - Delete IPs from blocklist file\n");
    printf("  clear         - Clear entire map\n");
    printf("  dump          - Dump all entries in map\n");
    printf("  stats         - Show map statistics\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s add /var/lib/ipblocklist/BLOCKLIST_DE.conf\n", program_name);
    printf("  %s delete /var/lib/ipblocklist/BLOCKLIST_DE.conf\n", program_name);
    printf("  %s clear\n", program_name);
    printf("  %s dump\n", program_name);
    printf("  %s stats\n", program_name);
    printf("\n");
    printf("Note: Hash map implementation - only supports individual IPs (no CIDR ranges)\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    char *command = argv[1];
    
    // Handle commands that don't need map operations first
    if (strcmp(command, "help") == 0 || strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }
    
    // Open the BPF map (needed for all operations except help)
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Error opening BPF map at %s: %s\n", MAP_PATH, strerror(errno));
        fprintf(stderr, "Make sure the XDP program is loaded and the map exists.\n");
        return 1;
    }
    
    // Handle clear command
    if (strcmp(command, "clear") == 0) {
        clear_entire_map(map_fd);
        close(map_fd);
        return 0;
    }
    
    // Handle dump command
    if (strcmp(command, "dump") == 0) {
        printf("Dumping all entries in hash map:\n");
        printf("===============================\n");
        
        __u32 next_key = 0;
        __u32 key = 0;
        __u8 value;
        int count = 0;
        
        while (bpf_map_get_next_key(map_fd, count == 0 ? NULL : &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                printf("%3d. ", ++count);
                print_ip(next_key);
                printf(" -> %u\n", value);
            }
            key = next_key;
        }
        
        if (count == 0) {
            printf("Map is empty\n");
        } else {
            printf("\nTotal entries: %d\n", count);
        }
        close(map_fd);
        return 0;
    }
    
    // Handle stats command
    if (strcmp(command, "stats") == 0) {
        struct bpf_map_info info = {0};
        __u32 info_len = sizeof(info);
        
        if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) == 0) {
            printf("Map Statistics:\n");
            printf("===============\n");
            printf("Name:          %s\n", info.name);
            printf("Type:          %u (BPF_MAP_TYPE_HASH)\n", info.type);
            printf("Key size:      %u bytes\n", info.key_size);
            printf("Value size:    %u bytes\n", info.value_size);
            printf("Max entries:   %u\n", info.max_entries);
            printf("Map flags:     %u\n", info.map_flags);
            printf("Map ID:        %u\n", info.id);
            
            // Count actual entries
            __u32 next_key = 0;
            __u32 key = 0;
            int count = 0;
            
            while (bpf_map_get_next_key(map_fd, count == 0 ? NULL : &key, &next_key) == 0) {
                count++;
                key = next_key;
            }
            
            printf("Current entries: %d\n", count);
            printf("Usage:          %.1f%%\n", (float)count / info.max_entries * 100);
        } else {
            fprintf(stderr, "Failed to get map info: %s\n", strerror(errno));
        }
        
        close(map_fd);
        return 0;
    }
    
    // For add/delete commands, need a file argument
    if (argc < 3) {
        fprintf(stderr, "Error: File argument required for %s command\n", command);
        fprintf(stderr, "Usage: %s %s <blocklist_file>\n", argv[0], command);
        close(map_fd);
        return 1;
    }
    
    char *file_path = argv[2];

    // Validate command
    if (strcmp(command, "add") != 0 && strcmp(command, "delete") != 0) {
        fprintf(stderr, "Error: Command must be 'add', 'delete', 'clear', 'dump', or 'stats'\n");
        close(map_fd);
        return 1;
    }

    FILE *file = fopen(file_path, "r");
    if (!file) {
        perror("Error opening blocklist file");
        close(map_fd);
        return 1;
    }

    struct ip_entry entries[BATCH_SIZE] = {0};
    size_t count = 0;
    size_t total_processed = 0;
    size_t total_lines = 0;
    size_t skipped_lines = 0;
    size_t batch_num = 0;

    printf("Processing blocklist file: %s\n", file_path);
    printf("Command: %s\n\n", command);

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        total_lines++;
        
        // Remove trailing newline
        line[strcspn(line, "\n")] = '\0';
        
        __u32 ip_addr;
        
        if (parse_ip_blocklist_line(line, &ip_addr)) {
            entries[count].ip_addr = ip_addr;
            entries[count].action = 1;  // Block action
            
            count++;
            total_processed++;

            // Process the batch if full
            if (count == BATCH_SIZE) {
                batch_num++;
                printf("Batch %zu: ", batch_num);
                
                if (strcmp(command, "add") == 0) {
                    add_ips_batch(map_fd, entries, count);
                } else if (strcmp(command, "delete") == 0) {
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
        batch_num++;
        printf("Batch %zu: ", batch_num);
        
        if (strcmp(command, "add") == 0) {
            add_ips_batch(map_fd, entries, count);
        } else if (strcmp(command, "delete") == 0) {
            delete_ips_batch(map_fd, entries, count);
        }
    }

    fclose(file);
    close(map_fd);
    
    printf("\n");
    printf("Processing complete:\n");
    printf("====================\n");
    printf("File:               %s\n", file_path);
    printf("Command:            %s\n", command);
    printf("Total lines:        %zu\n", total_lines);
    printf("Successfully processed: %zu IPs\n", total_processed);
    printf("Skipped lines:      %zu\n", skipped_lines);
    printf("Batches processed:  %zu\n", batch_num);
    printf("\n");
    printf("Hash map updated successfully.\n");
    printf("XDP program will drop packets where either source or destination IP matches.\n");
    
    return 0;
}
