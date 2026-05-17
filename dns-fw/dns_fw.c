/*
 * Copyright (c) 2024, BPFire.  All rights reserved.
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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stddef.h>

#define MAX_DOMAIN_NAME 127    /* Max total domain name length (reduced for BPF verifier) */
#define MAX_DOMAIN_LABEL 63    /* Max per label length (RFC 1035) */
#define MAX_DOMAINS_PER_BATCH 1000
#define MAX_LINE_LENGTH 256    /* Keep at 256, sufficient for 127 + extra */

struct domain_key {
	char data[MAX_DOMAIN_NAME + 1];  /* +1 for null terminator */
};

// Function declarations
static void encode_domain(const char *domain, char *encoded, size_t max_len);
static void decode_domain(const char *encoded, char *decoded, size_t max_len);
static int batch_add_domains(int map_fd, char domains[][MAX_DOMAIN_NAME + 1], int count);
static int batch_delete_domains(int map_fd, char domains[][MAX_DOMAIN_NAME + 1], int count);
static int load_and_process_domains(const char *filename, int map_fd, int is_add);
static int list_all_domains(int map_fd);
static int manage_single_domain(int map_fd, const char *command, const char *domain);
static int validate_domain(const char *domain);
static int clear_all_domains(int map_fd);
static void print_usage(const char *prog);

// Function to validate domain name according to RFC 1035
static int validate_domain(const char *domain)
{
	const char *ptr = domain;
	size_t label_len;
	size_t total_len = 0;
	
	if (!domain || *domain == '\0')
		return 0;
	
	while (*ptr) {
		// Find the length of the current label
		label_len = strcspn(ptr, ".");
		
		// Check if label exceeds maximum length
		if (label_len > MAX_DOMAIN_LABEL) {
			fprintf(stderr, "Warning: Label '%.*s' exceeds max length (%d chars)\n",
			        (int)label_len, ptr, MAX_DOMAIN_LABEL);
			return 0;
		}
		
		// Check if label is empty
		if (label_len == 0) {
			fprintf(stderr, "Warning: Empty label in domain %s\n", domain);
			return 0;
		}
		
		total_len += label_len + 1; // +1 for the dot or null terminator
		
		// Move to the next label
		ptr += label_len;
		if (*ptr == '.') {
			ptr++; // Skip the dot
		}
	}
	
	// Check total length (subtract 1 because we don't count the final null)
	if (total_len - 1 > MAX_DOMAIN_NAME) {
		fprintf(stderr, "Warning: Domain %s exceeds max total length (%d chars, max %d)\n",
		        domain, (int)(total_len - 1), MAX_DOMAIN_NAME);
		return 0;
	}
	
	return 1;
}

// Function to encode a domain name with label lengths (DNS wire format)
static void encode_domain(const char *domain, char *encoded, size_t max_len)
{
	const char *ptr = domain;
	char *enc_ptr = encoded;
	size_t label_len;
	size_t total_len = 0;

	memset(encoded, 0, max_len);
	
	while (*ptr && total_len < max_len - 1) {
		// Find the length of the current label
		label_len = strcspn(ptr, ".");
		if (label_len > 0 && (total_len + label_len + 1) < max_len) {
			// Set the length of the label
			*enc_ptr++ = (char)label_len;
			total_len++;
			// Copy the label itself
			memcpy(enc_ptr, ptr, label_len);
			enc_ptr += label_len;
			total_len += label_len;
		}
		// Move to the next label
		ptr += label_len;
		if (*ptr == '.') {
			ptr++; // Skip the dot
		}
	}
	// Append a zero-length label to mark the end of the domain name
	if (total_len < max_len - 1) {
		*enc_ptr++ = 0;
	}
}

// Function to convert domain from DNS wire format to readable string
static void decode_domain(const char *encoded, char *decoded, size_t max_len)
{
	const unsigned char *ptr = (const unsigned char *)encoded;
	char *out_ptr = decoded;
	unsigned char label_len;
	int first = 1;
	size_t remaining;

	memset(decoded, 0, max_len);
	
	while (*ptr) {
		remaining = max_len - (out_ptr - decoded);
		if (remaining <= 1)
			break;
			
		label_len = *ptr++;
		
		if (!first && remaining > 1) {
			*out_ptr++ = '.';
		}
		first = 0;
		
		if (label_len > 0 && (size_t)label_len < remaining) {
			memcpy(out_ptr, ptr, label_len);
			out_ptr += label_len;
			ptr += label_len;
		}
	}
}

// Batch add domains to the map
static int batch_add_domains(int map_fd, char domains[][MAX_DOMAIN_NAME + 1], int count)
{
	if (count == 0)
		return 0;
	
	struct domain_key *keys = calloc(count, sizeof(struct domain_key));
	__u8 *values = calloc(count, sizeof(__u8));
	
	if (!keys || !values) {
		fprintf(stderr, "Failed to allocate memory for batch operation\n");
		free(keys);
		free(values);
		return -1;
	}
	
	// Prepare keys and values
	for (int i = 0; i < count; i++) {
		encode_domain(domains[i], keys[i].data, MAX_DOMAIN_NAME + 1);
		values[i] = 1;
	}
	
	// Use BPF batch API to add all domains
	__u32 batch_count = count;
	int err = bpf_map_update_batch(map_fd, keys, values, &batch_count, BPF_ANY);
	
	if (err) {
		fprintf(stderr, "Failed to add domains in batch: %s (errno: %d)\n", 
			strerror(errno), errno);
		free(keys);
		free(values);
		return -1;
	}
	
	// Check if all domains were added
	if (batch_count != (__u32)count) {
		fprintf(stderr, "Warning: Only added %u out of %d domains\n", batch_count, count);
	}
	
	free(keys);
	free(values);
	return 0;
}

// Batch delete domains from the map - FIXED to handle ENOENT by falling back to per-key deletion
static int batch_delete_domains(int map_fd, char domains[][MAX_DOMAIN_NAME + 1], int count)
{
	if (count == 0)
		return 0;
	
	struct domain_key *keys = calloc(count, sizeof(struct domain_key));
	
	if (!keys) {
		fprintf(stderr, "Failed to allocate memory for batch operation\n");
		return -1;
	}
	
	// Prepare keys
	for (int i = 0; i < count; i++) {
		encode_domain(domains[i], keys[i].data, MAX_DOMAIN_NAME + 1);
	}
	
	// Use BPF batch API to delete all domains
	__u32 batch_count = count;
	int err = bpf_map_delete_batch(map_fd, keys, &batch_count, NULL);
	
	// If successful or only ENOENT, we need to handle remaining keys
	if (err && errno != ENOENT) {
		fprintf(stderr, "Failed to delete domains in batch: %s (errno: %d)\n", 
			strerror(errno), errno);
		free(keys);
		return -1;
	}
	
	// If we got ENOENT, batch_count indicates how many were deleted before the error
	// We need to delete the remaining keys one by one
	if (err && errno == ENOENT) {
		if (batch_count < (__u32)count) {
			fprintf(stderr, "Warning: Batch delete stopped at %u out of %d domains, falling back to per-key deletion\n", 
				batch_count, count);
			
			// Delete remaining keys one by one
			int failed_count = 0;
			for (__u32 i = batch_count; i < (__u32)count; i++) {
				if (bpf_map_delete_elem(map_fd, &keys[i]) != 0) {
					if (errno != ENOENT) {
						fprintf(stderr, "Warning: Failed to delete domain %s: %s\n", 
							domains[i], strerror(errno));
						failed_count++;
					}
					// ENOENT is ignored - domain already not in map
				}
			}
			
			if (failed_count > 0) {
				fprintf(stderr, "Warning: %d domains failed to delete\n", failed_count);
			}
		}
	} else if (!err) {
		// Check if all domains were deleted (only when no error occurred)
		if (batch_count != (__u32)count) {
			fprintf(stderr, "Warning: Only deleted %u out of %d domains\n", batch_count, count);
			
			// Delete remaining keys one by one
			for (__u32 i = batch_count; i < (__u32)count; i++) {
				if (bpf_map_delete_elem(map_fd, &keys[i]) != 0 && errno != ENOENT) {
					fprintf(stderr, "Warning: Failed to delete domain %s: %s\n", 
						domains[i], strerror(errno));
				}
			}
		}
	}
	
	free(keys);
	return 0;
}

// Clear all domains from the map using batch operations
static int clear_all_domains(int map_fd)
{
    printf("Clearing all domains from denylist...\n");
    
    struct domain_key *keys = calloc(MAX_DOMAINS_PER_BATCH, sizeof(struct domain_key));
    if (!keys) {
        fprintf(stderr, "Failed to allocate memory for batch clear\n");
        return -1;
    }
    
    struct domain_key next_key = {0};
    struct domain_key key_ptr = {0};
    int batch_count = 0;
    int total_deleted = 0;
    int iteration = 0;
    int first = 1;
    
    // First pass: collect keys in batches and delete
    while (bpf_map_get_next_key(map_fd, first ? NULL : &key_ptr, &next_key) == 0) {
        // Store the current key
        memcpy(&keys[batch_count], &next_key, sizeof(struct domain_key));
        memcpy(&key_ptr, &next_key, sizeof(struct domain_key));
        batch_count++;
        first = 0;
        
        // If batch is full, delete it
        if (batch_count >= MAX_DOMAINS_PER_BATCH) {
            __u32 num_to_delete = batch_count;
            int ret = bpf_map_delete_batch(map_fd, keys, &num_to_delete, NULL);
            
            if (ret == 0) {
                total_deleted += num_to_delete;
            } else {
                // Fall back to individual deletion for this batch
                fprintf(stderr, "Batch delete failed for batch %d, falling back to individual deletion\n", iteration);
                for (int i = 0; i < batch_count; i++) {
                    if (bpf_map_delete_elem(map_fd, &keys[i]) == 0) {
                        total_deleted++;
                    }
                }
            }
            
            batch_count = 0;
            iteration++;
            
            // Progress indicator for large maps
            if (iteration % 10 == 0 && iteration > 0) {
                printf("  Cleared %d domains so far...\n", total_deleted);
            }
        }
    }
    
    // Delete any remaining keys in the last partial batch
    if (batch_count > 0) {
        __u32 num_to_delete = batch_count;
        int ret = bpf_map_delete_batch(map_fd, keys, &num_to_delete, NULL);
        
        if (ret == 0) {
            total_deleted += num_to_delete;
        } else {
            // Fall back to individual deletion for remaining keys
            for (int i = 0; i < batch_count; i++) {
                if (bpf_map_delete_elem(map_fd, &keys[i]) == 0) {
                    total_deleted++;
                }
            }
        }
    }
    
    // Second pass: catch any leftovers (safety measure)
    iteration = 0;
    first = 1;
    memset(&next_key, 0, sizeof(next_key));
    while (bpf_map_get_next_key(map_fd, first ? NULL : &key_ptr, &next_key) == 0) {
        struct domain_key key_to_delete;
        memcpy(&key_to_delete, &next_key, sizeof(struct domain_key));
        memcpy(&key_ptr, &next_key, sizeof(struct domain_key));
        first = 0;
        
        if (bpf_map_delete_elem(map_fd, &key_to_delete) == 0) {
            total_deleted++;
            if (++iteration % 1000 == 0) {
                printf("  Cleaning up %d more domains...\n", iteration);
            }
        }
    }
    
    free(keys);
    printf("Successfully cleared %d domains from denylist\n", total_deleted);
    return 0;
}

// Safe string copy function that ensures null termination
static void safe_strcpy(char *dest, const char *src, size_t dest_size)
{
	size_t src_len = strlen(src);
	size_t copy_len = (src_len < dest_size - 1) ? src_len : dest_size - 1;
	
	memcpy(dest, src, copy_len);
	dest[copy_len] = '\0';
}

// Function to load domains from a text file and process in batches
static int load_and_process_domains(const char *filename, int map_fd, int is_add)
{
	FILE *file = fopen(filename, "r");
	if (!file) {
		fprintf(stderr, "Failed to open file %s: %s\n", filename, strerror(errno));
		return -1;
	}
	
	char line[MAX_LINE_LENGTH];
	char domains[MAX_DOMAINS_PER_BATCH][MAX_DOMAIN_NAME + 1];
	int batch_count = 0;
	int total_processed = 0;
	int batch_num = 0;
	
	while (fgets(line, sizeof(line), file)) {
		// Remove newline character
		line[strcspn(line, "\n")] = 0;
		
		// Skip empty lines and comments
		if (line[0] == '\0' || line[0] == '#')
			continue;
		
		// Trim whitespace
		char *start = line;
		while (*start == ' ' || *start == '\t') start++;
		
		if (*start == '\0')
			continue;
		
		// Check if domain is too long before validation
		if (strlen(start) > MAX_DOMAIN_NAME) {
			fprintf(stderr, "Warning: Domain %s exceeds max length (%d), skipping\n", 
			        start, MAX_DOMAIN_NAME);
			continue;
		}
		
		// Validate domain name according to RFC 1035
		if (!validate_domain(start)) {
			fprintf(stderr, "Warning: Domain %s validation failed, skipping\n", start);
			continue;
		}
		
		// Use safe string copy instead of strncpy
		safe_strcpy(domains[batch_count], start, MAX_DOMAIN_NAME + 1);
		batch_count++;
		
		// If we've reached the batch size, process this batch
		if (batch_count >= MAX_DOMAINS_PER_BATCH) {
			int ret;
			if (is_add) {
				ret = batch_add_domains(map_fd, domains, batch_count);
			} else {
				ret = batch_delete_domains(map_fd, domains, batch_count);
			}
			
			if (ret < 0) {
				fprintf(stderr, "Failed to process batch %d\n", batch_num);
				fclose(file);
				return -1;
			}
			
			total_processed += batch_count;
			batch_num++;
			batch_count = 0;
			
			// Optional: Print progress every 10 batches
			if (batch_num % 10 == 0) {
				printf("Processed %d domains so far...\n", total_processed);
			}
		}
	}
	
	// Process any remaining domains in the last batch
	if (batch_count > 0) {
		int ret;
		if (is_add) {
			ret = batch_add_domains(map_fd, domains, batch_count);
		} else {
			ret = batch_delete_domains(map_fd, domains, batch_count);
		}
		
		if (ret < 0) {
			fprintf(stderr, "Failed to process final batch %d\n", batch_num);
			fclose(file);
			return -1;
		}
		
		total_processed += batch_count;
	}
	
	fclose(file);
	printf("Total processed: %d domains from %s\n", total_processed, filename);
	return total_processed;
}

// List all domains in the map using batch lookup
static int list_all_domains(int map_fd)
{
	struct domain_key *keys = calloc(MAX_DOMAINS_PER_BATCH, sizeof(struct domain_key));
	__u8 *values = calloc(MAX_DOMAINS_PER_BATCH, sizeof(__u8));
	
	if (!keys || !values) {
		fprintf(stderr, "Failed to allocate memory for batch lookup\n");
		free(keys);
		free(values);
		return -1;
	}
	
	__u32 batch_size = MAX_DOMAINS_PER_BATCH;
	__u32 start_key = 0;
	int total_count = 0;
	
	printf("Domains in denylist:\n");
	printf("--------------------\n");
	
	while (1) {
		__u32 count = batch_size;
		int err = bpf_map_lookup_batch(map_fd, &start_key, &start_key, 
						keys, values, &count, NULL);
		
		if (err && errno != ENOENT) {
			fprintf(stderr, "Batch lookup failed: %s\n", strerror(errno));
			break;
		}
		
		if (count == 0)
			break;
		
		for (__u32 i = 0; i < count; i++) {
			char decoded[MAX_DOMAIN_NAME + 1];
			decode_domain(keys[i].data, decoded, sizeof(decoded));
			printf("%s\n", decoded);
			total_count++;
		}
		
		if (err && errno == ENOENT)
			break;
	}
	
	printf("--------------------\n");
	printf("Total: %d domains\n", total_count);
	
	free(keys);
	free(values);
	return 0;
}

// Add or delete a single domain
static int manage_single_domain(int map_fd, const char *command, const char *domain)
{
	struct domain_key dkey = { 0 };
	__u8 value = 1;
	
	// Check domain length
	if (strlen(domain) > MAX_DOMAIN_NAME) {
		fprintf(stderr, "Domain exceeds max length (%d)\n", MAX_DOMAIN_NAME);
		return -1;
	}
	
	// Validate domain name
	if (!validate_domain(domain)) {
		fprintf(stderr, "Domain validation failed\n");
		return -1;
	}
	
	// Encode the domain name with label lengths (no reverse needed for hash map)
	encode_domain(domain, dkey.data, MAX_DOMAIN_NAME + 1);
	
	if (strcmp(command, "add") == 0) {
		if (bpf_map_update_elem(map_fd, &dkey, &value, BPF_ANY) != 0) {
			fprintf(stderr, "Failed to add domain to map: %s\n", strerror(errno));
			return -1;
		}
		printf("Domain %s added to denylist\n", domain);
	} else if (strcmp(command, "delete") == 0) {
		if (bpf_map_delete_elem(map_fd, &dkey) != 0) {
			fprintf(stderr, "Failed to remove domain from map: %s\n", strerror(errno));
			return -1;
		}
		printf("Domain %s removed from denylist\n", domain);
	} else {
		fprintf(stderr, "Invalid command: %s\n", command);
		return -1;
	}
	
	return 0;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  Single domain operations:\n");
	fprintf(stderr, "    %s <map_path> add <domain>\n", prog);
	fprintf(stderr, "    %s <map_path> delete <domain>\n", prog);
	fprintf(stderr, "\n  Batch operations from file:\n");
	fprintf(stderr, "    %s <map_path> batch-add <file>\n", prog);
	fprintf(stderr, "    %s <map_path> batch-delete <file>\n", prog);
	fprintf(stderr, "\n  List all domains:\n");
	fprintf(stderr, "    %s <map_path> list\n", prog);
	fprintf(stderr, "\n  Clear all domains:\n");
	fprintf(stderr, "    %s <map_path> clear\n", prog);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  <map_path> - BPF map path (e.g., /sys/fs/bpf/dns_fw_denylist)\n");
	fprintf(stderr, "  <domain>   - Domain name to add/delete (max %d chars total, labels max %d chars)\n", 
		MAX_DOMAIN_NAME, MAX_DOMAIN_LABEL);
	fprintf(stderr, "  <file>     - Text file with one domain per line\n");
	fprintf(stderr, "\nFile format example:\n");
	fprintf(stderr, "  example.com\n");
	fprintf(stderr, "  google.com\n");
	fprintf(stderr, "  # This is a comment\n");
	fprintf(stderr, "  facebook.com\n");
	fprintf(stderr, "\nNote: For large files, the program processes domains in\n");
	fprintf(stderr, "      batches of %d domains at a time.\n", MAX_DOMAINS_PER_BATCH);
	fprintf(stderr, "\nRFC 1035 Limits:\n");
	fprintf(stderr, "  - Maximum total domain name length: %d characters\n", MAX_DOMAIN_NAME);
	fprintf(stderr, "  - Maximum label length: %d characters\n", MAX_DOMAIN_LABEL);
}

int main(int argc, char *argv[])
{
	int map_fd;
	
	// Check for proper number of arguments
	if (argc < 3) {
		print_usage(argv[0]);
		return 1;
	}
	
	const char *map_path = argv[1];
	const char *command = argv[2];
	
	// Open the BPF map
	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to open map at %s: %s\n", map_path, strerror(errno));
		return 1;
	}
	
	int ret = 0;
	
	if (strcmp(command, "add") == 0 && argc == 4) {
		ret = manage_single_domain(map_fd, "add", argv[3]);
	} else if (strcmp(command, "delete") == 0 && argc == 4) {
		ret = manage_single_domain(map_fd, "delete", argv[3]);
	} else if (strcmp(command, "batch-add") == 0 && argc == 4) {
		int total = load_and_process_domains(argv[3], map_fd, 1);
		if (total < 0) {
			ret = -1;
		} else {
			printf("Successfully processed %d domains from file\n", total);
		}
	} else if (strcmp(command, "batch-delete") == 0 && argc == 4) {
		int total = load_and_process_domains(argv[3], map_fd, 0);
		if (total < 0) {
			ret = -1;
		} else {
			printf("Successfully processed %d domains from file\n", total);
		}
	} else if (strcmp(command, "list") == 0 && argc == 3) {
		ret = list_all_domains(map_fd);
	} else if (strcmp(command, "clear") == 0 && argc == 3) {
		ret = clear_all_domains(map_fd);
	} else {
		fprintf(stderr, "Invalid command or arguments\n");
		print_usage(argv[0]);
		ret = 1;
	}
	
	close(map_fd);
	return ret;
}
