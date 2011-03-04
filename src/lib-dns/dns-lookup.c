/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "write-full.h"
#include "time-util.h"
#include "dns-lookup.h"

#include <stdio.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 512

struct dns_lookup {
	int fd;
	char *path;

	struct istream *input;
	struct io *io;
	struct timeout *to;

	struct timeval start_time;
	unsigned int warn_msecs;

	struct dns_lookup_result result;
	struct ip_addr *ips;
	unsigned int ip_idx;

	dns_lookup_callback_t *callback;
	void *context;
};

static void dns_lookup_free(struct dns_lookup **_lookup);

static int dns_lookup_input_line(struct dns_lookup *lookup, const char *line)
{
	struct dns_lookup_result *result = &lookup->result;

	if (result->ips_count == 0) {
		/* first line: <ret> <ip count> */
		if (sscanf(line, "%d %u", &result->ret,
			   &result->ips_count) == 0)
			return -1;
		if (result->ret != 0) {
			result->error = net_gethosterror(result->ret);
			return 1;
		}
		if (result->ips_count == 0)
			return -1;

		result->ips = lookup->ips =
			i_new(struct ip_addr, result->ips_count);
	} else {
		if (net_addr2ip(line, &lookup->ips[lookup->ip_idx]) < 0)
			return -1;
		if (++lookup->ip_idx == result->ips_count) {
			result->ret = 0;
			return 1;
		}
	}
	return 0;
}

static void dns_lookup_save_msecs(struct dns_lookup *lookup)
{
	struct timeval now;
	int diff;

	if (gettimeofday(&now, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");

	diff = timeval_diff_msecs(&now, &lookup->start_time);
	if (diff > 0)
		lookup->result.msecs = diff;
}

static void dns_lookup_input(struct dns_lookup *lookup)
{
	const char *line;
	struct dns_lookup_result *result = &lookup->result;
	int ret = 0;

	while ((line = i_stream_read_next_line(lookup->input)) != NULL) {
		ret = dns_lookup_input_line(lookup, line);
		if (ret > 0)
			break;
		if (ret < 0) {
			result->error = t_strdup_printf(
				"Invalid input from %s", lookup->path);
			break;
		}
	}

	if (result->error != NULL) {
		/* already got the error */
	} else if (lookup->input->stream_errno != 0) {
		result->error = t_strdup_printf("read(%s) failed: %m",
						lookup->path);
		ret = -1;
	} else if (lookup->input->eof) {
		result->error = t_strdup_printf("Unexpected EOF from %s",
						lookup->path);
		ret = -1;
	}
	if (ret != 0) {
		dns_lookup_save_msecs(lookup);
		lookup->callback(result, lookup->context);
		dns_lookup_free(&lookup);
	}
}

static void dns_lookup_timeout(struct dns_lookup *lookup)
{
	lookup->result.error = "DNS lookup timed out";

	lookup->callback(&lookup->result, lookup->context);
	dns_lookup_free(&lookup);
}

#undef dns_lookup
int dns_lookup(const char *host, const struct dns_lookup_settings *set,
	       dns_lookup_callback_t *callback, void *context)
{
	struct dns_lookup *lookup;
	struct dns_lookup_result result;
	const char *cmd;
	int fd;

	memset(&result, 0, sizeof(result));
	result.ret = NO_RECOVERY;

	fd = net_connect_unix(set->dns_client_socket_path);
	if (fd == -1) {
		result.error = t_strdup_printf("connect(%s) failed: %m",
					       set->dns_client_socket_path);
		callback(&result, context);
		return -1;
	}

	cmd = t_strconcat("IP\t", host, "\n", NULL);
	if (write_full(fd, cmd, strlen(cmd)) < 0) {
		result.error = t_strdup_printf("write(%s) failed: %m",
					       set->dns_client_socket_path);
		(void)close(fd);
		callback(&result, context);
		return -1;
	}

	lookup = i_new(struct dns_lookup, 1);
	lookup->fd = fd;
	lookup->path = i_strdup(set->dns_client_socket_path);
	lookup->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	lookup->io = io_add(fd, IO_READ, dns_lookup_input, lookup);
	if (set->timeout_msecs != 0) {
		lookup->to = timeout_add(set->timeout_msecs,
					 dns_lookup_timeout, lookup);
	}
	lookup->result.ret = NO_RECOVERY;
	lookup->callback = callback;
	lookup->context = context;
	if (gettimeofday(&lookup->start_time, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");
	return 0;
}

static void dns_lookup_free(struct dns_lookup **_lookup)
{
	struct dns_lookup *lookup = *_lookup;

	*_lookup = NULL;

	if (lookup->to != NULL)
		timeout_remove(&lookup->to);
	io_remove(&lookup->io);
	i_stream_destroy(&lookup->input);
	if (close(lookup->fd) < 0)
		i_error("close(%s) failed: %m", lookup->path);

	i_free(lookup->ips);
	i_free(lookup->path);
	i_free(lookup);
}
