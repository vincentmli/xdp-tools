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
#include <getopt.h>
#include <unistd.h>  // Added for close()

#define MAX_DOMAIN_SIZE 63

struct domain_key {
	struct bpf_lpm_trie_key lpm_key;
	char data[MAX_DOMAIN_SIZE + 1];
};

// Function to encode a domain name with label lengths
static void encode_domain(const char *domain, char *encoded)
{
	const char *ptr = domain;
	char *enc_ptr = encoded;
	size_t label_len;

	while (*ptr) {
		// Find the length of the current label
		label_len = strcspn(ptr, ".");
		if (label_len > 0) {
			// Set the length of the label
			*enc_ptr++ = (char)label_len;
			// Copy the label itself
			memcpy(enc_ptr, ptr, label_len);
			enc_ptr += label_len;
		}
		// Move to the next label
		ptr += label_len;
		if (*ptr == '.') {
			ptr++; // Skip the dot
		}
	}
	// Append a zero-length label to mark the end of the domain name
	*enc_ptr++ = 0;
}

static void reverse_string(char *str)
{
	int len = strlen(str);
	for (int i = 0; i < len / 2; i++) {
		char temp = str[i];
		str[i] = str[len - i - 1];
		str[len - i - 1] = temp;
	}
}

static void print_usage(const char *prog_name)
{
	fprintf(stderr, "Usage: %s [OPTIONS] <command> <domain>\n", prog_name);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -m, --map PATH    Path to the BPF map (required)\n");
	fprintf(stderr, "  -d, --denylist    Operate on denylist (default)\n");
	fprintf(stderr, "  -a, --allowlist   Operate on allowlist\n");
	fprintf(stderr, "  -h, --help        Show this help message\n");
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  add    Add domain to the specified list\n");
	fprintf(stderr, "  delete Remove domain from the specified list\n");
	fprintf(stderr, "  list   List all domains in the specified list\n");
	fprintf(stderr, "\nExamples:\n");
	fprintf(stderr, "  %s -m /sys/fs/bpf/domain_denylist add google.com\n", prog_name);
	fprintf(stderr, "  %s -m /sys/fs/bpf/domain_allowlist add trusted.com\n", prog_name);
	fprintf(stderr, "  %s -m /sys/fs/bpf/domain_denylist delete bad.com\n", prog_name);
	fprintf(stderr, "  %s -m /sys/fs/bpf/domain_allowlist list\n", prog_name);
}

int main(int argc, char *argv[])
{
	int map_fd;
	struct domain_key dkey = { 0 };
	__u8 value = 1;
	int opt;
	const char *map_path = NULL;
	const char *command = NULL;
	const char *domain = NULL;

	// Parse command line options
	static struct option long_options[] = {
		{"map", required_argument, 0, 'm'},
		{"denylist", no_argument, 0, 'd'},
		{"allowlist", no_argument, 0, 'a'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "m:dah", long_options, NULL)) != -1) {
		switch (opt) {
		case 'm':
			map_path = optarg;
			break;
		case 'd':
			// Denylist (for display purposes only - the map path determines the actual map)
			break;
		case 'a':
			// Allowlist (for display purposes only - the map path determines the actual map)
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	// Check if map path was provided
	if (map_path == NULL) {
		fprintf(stderr, "Error: Map path is required. Use -m or --map option.\n");
		print_usage(argv[0]);
		return 1;
	}

	// Check for required arguments (command and domain for add/delete)
	if (optind >= argc) {
		fprintf(stderr, "Error: Missing command argument\n");
		print_usage(argv[0]);
		return 1;
	}

	command = argv[optind];

	// For add/delete commands, we need a domain
	if (strcmp(command, "add") == 0 || strcmp(command, "delete") == 0) {
		if (optind + 1 >= argc) {
			fprintf(stderr, "Error: Missing domain argument for '%s' command\n", command);
			print_usage(argv[0]);
			return 1;
		}
		domain = argv[optind + 1];
		
		// Encode the domain name with label lengths
		encode_domain(domain, dkey.data);
		reverse_string(dkey.data);

		// Set the LPM trie key prefix length
		dkey.lpm_key.prefixlen = strlen(dkey.data) * 8;
	} else if (strcmp(command, "list") != 0) {
		fprintf(stderr, "Error: Unknown command '%s'. Use 'add', 'delete', or 'list'.\n",
			command);
		print_usage(argv[0]);
		return 1;
	}

	// Open the BPF map
	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to open map at '%s': %s\n", map_path, strerror(errno));
		fprintf(stderr, "Make sure the XDP program is loaded and the map is pinned\n");
		return 1;
	}

	// Execute the command
	if (strcmp(command, "add") == 0) {
		// Update the map with the encoded domain name
		if (bpf_map_update_elem(map_fd, &dkey, &value, BPF_ANY) != 0) {
			fprintf(stderr, "Failed to add domain '%s' to map '%s': %s\n",
				domain, map_path, strerror(errno));
			close(map_fd);
			return 1;
		}
		printf("Domain '%s' added to %s\n", domain, map_path);
	} else if (strcmp(command, "delete") == 0) {
		// Remove the domain from the map
		if (bpf_map_delete_elem(map_fd, &dkey) != 0) {
			fprintf(stderr,
				"Failed to remove domain '%s' from map '%s': %s\n",
				domain, map_path, strerror(errno));
			close(map_fd);
			return 1;
		}
		printf("Domain '%s' removed from %s\n", domain, map_path);
	} else if (strcmp(command, "list") == 0) {
		// List all domains in the map
		struct domain_key next_key = { 0 };
		char decoded_domain[MAX_DOMAIN_SIZE + 1];
		int found = 0;
		int err;

		printf("Domains in map '%s':\n", map_path);
		
		while ((err = bpf_map_get_next_key(map_fd, &next_key, &next_key)) == 0) {
			// Decode the domain for display
			char *src = next_key.data;
			char *dst = decoded_domain;
			int first = 1;
			
			while (*src) {
				int len = *src++;
				if (!first) *dst++ = '.';
				memcpy(dst, src, len);
				dst += len;
				src += len;
				first = 0;
			}
			*dst = '\0';
			
			printf("  %s\n", decoded_domain);
			found = 1;
		}
		
		if (!found) {
			printf("  (empty)\n");
		}
	}

	close(map_fd);
	return 0;
}
