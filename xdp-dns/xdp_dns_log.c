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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <syslog.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>

#define MAX_DOMAIN_SIZE 63

// Structure must match exactly with BPF program
struct qname_event {
	uint8_t len;
	uint32_t src_ip;
	uint8_t blocked;
	uint8_t allowed;
	char qname[MAX_DOMAIN_SIZE + 1];
};

static volatile int running = 1;

// Signal handler for graceful shutdown
void signal_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {
		running = 0;
	}
}

// Helper function to convert DNS label format to dot notation
void dns_label_to_dot_notation(char *dns_name, char *output, size_t len)
{
	size_t pos = 0, out_pos = 0;

	while (pos < len) {
		uint8_t label_len = dns_name[pos];
		
		if (label_len == 0) {
			break; // End of domain name
		}
		
		if (pos + label_len + 1 > len) {
			break; // Buffer overflow protection
		}
		
		if (out_pos != 0) {
			output[out_pos++] = '.';
		}
		
		// Copy the label
		for (size_t i = 1; i <= label_len; i++) {
			if (out_pos >= MAX_DOMAIN_SIZE) {
				break;
			}
			output[out_pos++] = dns_name[pos + i];
		}
		
		pos += label_len + 1;
	}

	output[out_pos] = '\0';
}

// Handle event from ring buffer
int handle_event(void *ctx __attribute__((unused)), void *data,
		 size_t data_sz)
{
	if (data_sz < sizeof(struct qname_event)) {
		syslog(LOG_ERR, "Unexpected data size: %zu (expected at least %zu)", 
		       data_sz, sizeof(struct qname_event));
		return -1;
	}

	struct qname_event *event = (struct qname_event *)data;

	if (event->len > MAX_DOMAIN_SIZE) {
		syslog(LOG_ERR, "Invalid qname length: %u", event->len);
		return -1;
	}

	char src_ip_str[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &event->src_ip, src_ip_str, sizeof(src_ip_str))) {
		syslog(LOG_ERR, "Failed to convert source IP");
		return -1;
	}

	char domain_str[MAX_DOMAIN_SIZE + 1] = { 0 };
	
	if (event->len > 0) {
		dns_label_to_dot_notation(event->qname, domain_str, event->len);
	} else {
		strcpy(domain_str, "(empty)");
	}

	// Determine status
	const char *status;
	if (event->allowed) {
		status = "ALLOWED (bypass chain)";
	} else if (event->blocked) {
		status = "BLOCKED";
	} else {
		status = "PASS (continuing chain)";
	}

	syslog(LOG_INFO, "DNS: %s | Source: %s | Status: %s", 
	       domain_str, src_ip_str, status);

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <path_to_ringbuf>\n", argv[0]);
		fprintf(stderr, "Example: %s /sys/fs/bpf/xdp-dns-denylist/dns_ringbuf\n", argv[0]);
		return 1;
	}

	const char *ringbuf_path = argv[1];
	struct ring_buffer *rb;
	int ringbuf_fd;

	// Set up signal handlers
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// Open syslog
	openlog("xdp_dns_log", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	// Open the ring buffer
	ringbuf_fd = bpf_obj_get(ringbuf_path);
	if (ringbuf_fd < 0) {
		syslog(LOG_ERR, "Failed to open ring buffer at %s: %m", ringbuf_path);
		closelog();
		return 1;
	}

	// Set up ring buffer polling
	rb = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
	if (!rb) {
		syslog(LOG_ERR, "Failed to create ring buffer: %m");
		close(ringbuf_fd);
		closelog();
		return 1;
	}

	syslog(LOG_INFO, "XDP DNS logger started, monitoring %s", ringbuf_path);

	// Main polling loop
	while (running) {
		int err = ring_buffer__poll(rb, 1000); // Poll with 1 second timeout
		if (err < 0) {
			if (errno == EINTR) {
				// Interrupted by signal, continue
				continue;
			}
			syslog(LOG_ERR, "Ring buffer poll error: %d", err);
			break;
		}
	}

	syslog(LOG_INFO, "XDP DNS logger stopped");

	ring_buffer__free(rb);
	close(ringbuf_fd);
	closelog();
	return 0;
}
