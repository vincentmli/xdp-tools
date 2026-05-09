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

#define MAX_DOMAIN_SIZE 63
#define MAX_DOMAINS_PER_BATCH 1000
#define MAX_LINE_LENGTH 256

struct domain_key {
	char data[MAX_DOMAIN_SIZE + 1];
};

// Function declarations
static void encode_domain(const char *domain, char *encoded, size_t max_len);
static void decode_domain(const char *encoded, char *decoded, size_t max_len);
static int batch_add_domains(int map_fd, char domains[][MAX_DOMAIN_SIZE + 1], int count);
static int batch_delete_domains(int map_fd, char domains[][MAX_DOMAIN_SIZE + 1], int count);
static int load_and_process_domains(const char *filename, int map_fd, int is_add);
static int list_all_domains(int map_fd);
static int manage_single_domain(int map_fd, const char *command, const char *domain);
static void print_usage(const char *prog);

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
static int batch_add_domains(int map_fd, char domains[][MAX_DOMAIN_SIZE + 1], int count)
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
		encode_domain(domains[i], keys[i].data, MAX_DOMAIN_SIZE + 1);
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

// Batch delete domains from the map
static int batch_delete_domains(int map_fd, char domains[][MAX_DOMAIN_SIZE + 1], int count)
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
		encode_domain(domains[i], keys[i].data, MAX_DOMAIN_SIZE + 1);
	}
	
	// Use BPF batch API to delete all domains
	__u32 batch_count = count;
	int err = bpf_map_delete_batch(map_fd, keys, &batch_count, NULL);
	
	if (err) {
		fprintf(stderr, "Failed to delete domains in batch: %s (errno: %d)\n", 
			strerror(errno), errno);
		free(keys);
		return -1;
	}
	
	// Check if all domains were deleted
	if (batch_count != (__u32)count) {
		fprintf(stderr, "Warning: Only deleted %u out of %d domains\n", batch_count, count);
	}
	
	free(keys);
	return 0;
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
	char domains[MAX_DOMAINS_PER_BATCH][MAX_DOMAIN_SIZE + 1];
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
		
		// Check domain length
		if (strlen(start) > MAX_DOMAIN_SIZE) {
			fprintf(stderr, "Warning: Domain %s exceeds max length, skipping\n", start);
			continue;
		}
		
		strncpy(domains[batch_count], start, MAX_DOMAIN_SIZE);
		domains[batch_count][MAX_DOMAIN_SIZE] = '\0';
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
			char decoded[MAX_DOMAIN_SIZE + 1];
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
	
	// Encode the domain name with label lengths (no reverse needed for hash map)
	encode_domain(domain, dkey.data, MAX_DOMAIN_SIZE + 1);
	
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
	fprintf(stderr, "  <domain>   - Domain name to add/delete (max %d chars)\n", MAX_DOMAIN_SIZE);
	fprintf(stderr, "  <file>     - Text file with one domain per line\n");
	fprintf(stderr, "\nFile format example:\n");
	fprintf(stderr, "  example.com\n");
	fprintf(stderr, "  google.com\n");
	fprintf(stderr, "  # This is a comment\n");
	fprintf(stderr, "  facebook.com\n");
	fprintf(stderr, "\nNote: For large files, the program processes domains in\n");
	fprintf(stderr, "      batches of %d domains at a time.\n", MAX_DOMAINS_PER_BATCH);
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
		// Implement clear by walking and deleting all entries
		struct domain_key key = { 0 };
		__u32 next_key = 0;
		int count = 0;
		
		while (bpf_map_get_next_key(map_fd, &next_key, &key) == 0) {
			next_key = *(int *)&key;
			if (bpf_map_delete_elem(map_fd, &key) == 0) {
				count++;
			}
		}
		printf("Cleared %d domains from denylist\n", count);
		ret = 0;
	} else {
		fprintf(stderr, "Invalid command or arguments\n");
		print_usage(argv[0]);
		ret = 1;
	}
	
	close(map_fd);
	return ret;
}
