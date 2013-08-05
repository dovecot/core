/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
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
	bool ptr_lookup;

	struct istream *input;
	struct io *io;
	struct timeout *to;

	struct timeval start_time;
	unsigned int warn_msecs;

	struct dns_lookup_result result;
	struct ip_addr *ips;
	unsigned int ip_idx;
	char *name;

	dns_lookup_callback_t *callback;
	void *context;
};

static void dns_lookup_free(struct dns_lookup **_lookup);

static int dns_lookup_input_line(struct dns_lookup *lookup, const char *line)
{
	struct dns_lookup_result *result = &lookup->result;

	if (result->ips_count == 0) {
		if (lookup->ptr_lookup) {
			/* <ret> [<name>] */
			if (strncmp(line, "0 ", 2) == 0) {
				result->name = lookup->name =
					i_strdup(line + 2);
				result->ret = 0;
			} else {
				if (str_to_int(line, &result->ret) < 0) {
					return -1;
				}
				result->error = net_gethosterror(result->ret);
			}
			return 1;
		}
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

static int
dns_lookup_common(const char *cmd, bool ptr_lookup,
		  const struct dns_lookup_settings *set,
		  dns_lookup_callback_t *callback, void *context,
		  struct dns_lookup **lookup_r)
{
	struct dns_lookup *lookup;
	struct dns_lookup_result result;
	int fd;

	memset(&result, 0, sizeof(result));
	result.ret = EAI_FAIL;

	fd = net_connect_unix(set->dns_client_socket_path);
	if (fd == -1) {
		result.error = t_strdup_printf("connect(%s) failed: %m",
					       set->dns_client_socket_path);
		callback(&result, context);
		return -1;
	}

	if (write_full(fd, cmd, strlen(cmd)) < 0) {
		result.error = t_strdup_printf("write(%s) failed: %m",
					       set->dns_client_socket_path);
		i_close_fd(&fd);
		callback(&result, context);
		return -1;
	}

	lookup = i_new(struct dns_lookup, 1);
	lookup->ptr_lookup = ptr_lookup;
	lookup->fd = fd;
	lookup->path = i_strdup(set->dns_client_socket_path);
	lookup->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	lookup->io = io_add(fd, IO_READ, dns_lookup_input, lookup);
	if (set->timeout_msecs != 0) {
		lookup->to = timeout_add(set->timeout_msecs,
					 dns_lookup_timeout, lookup);
	}
	lookup->result.ret = EAI_FAIL;
	lookup->callback = callback;
	lookup->context = context;
	if (gettimeofday(&lookup->start_time, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");

	*lookup_r = lookup;
	return 0;
}

#undef dns_lookup
int dns_lookup(const char *host, const struct dns_lookup_settings *set,
	       dns_lookup_callback_t *callback, void *context,
	       struct dns_lookup **lookup_r)
{
	return dns_lookup_common(t_strconcat("IP\t", host, "\n", NULL), FALSE,
				 set, callback, context, lookup_r);
}

#undef dns_lookup_ptr
int dns_lookup_ptr(const struct ip_addr *ip,
		   const struct dns_lookup_settings *set,
		   dns_lookup_callback_t *callback, void *context,
		   struct dns_lookup **lookup_r)
{
	const char *cmd = t_strconcat("NAME\t", net_ip2addr(ip), "\n", NULL);
	return dns_lookup_common(cmd, TRUE, set, callback, context, lookup_r);
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

	i_free(lookup->name);
	i_free(lookup->ips);
	i_free(lookup->path);
	i_free(lookup);
}

void dns_lookup_abort(struct dns_lookup **lookup)
{
	dns_lookup_free(lookup);
}

void dns_lookup_switch_ioloop(struct dns_lookup *lookup)
{
	if (lookup->to != NULL)
		lookup->to = io_loop_move_timeout(&lookup->to);
	lookup->io = io_loop_move_io(&lookup->io);
}
