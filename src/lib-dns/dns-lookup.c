/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "llist.h"
#include "istream.h"
#include "write-full.h"
#include "time-util.h"
#include "dns-lookup.h"

#include <stdio.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 512

struct dns_lookup {
	struct dns_lookup *prev, *next;
	struct dns_client *client;
	bool ptr_lookup;

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

struct dns_client {
	int fd;
	char *path;

	unsigned int timeout_msecs, idle_timeout_msecs;

	struct istream *input;
	struct io *io;
	struct timeout *to_idle;

	struct dns_lookup *head, *tail;
	bool deinit_client_at_free;
};

#undef dns_lookup
#undef dns_lookup_ptr
#undef dns_client_lookup
#undef dns_client_lookup_ptr

static void dns_lookup_free(struct dns_lookup **_lookup);

static void dns_client_disconnect(struct dns_client *client, const char *error)
{
	struct dns_lookup *lookup, *next;
	struct dns_lookup_result result;

	if (client->to_idle != NULL)
		timeout_remove(&client->to_idle);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->input != NULL)
		i_stream_destroy(&client->input);
	if (client->fd != -1) {
		if (close(client->fd) < 0)
			i_error("close(%s) failed: %m", client->path);
		client->fd = -1;
	}

	i_zero(&result);
	result.ret = EAI_FAIL;
	result.error = error;

	lookup = client->head;
	client->head = NULL;
	while (lookup != NULL) {
		next = lookup->next;
		lookup->callback(&result, lookup->context);
		dns_lookup_free(&lookup);
		lookup = next;
	}
}

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
		/* first line: <ret> [<ip count>] */
		if (sscanf(line, "%d %u", &result->ret,
			   &result->ips_count) < 1)
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

static void dns_client_input(struct dns_client *client)
{
	const char *line;
	struct dns_lookup *lookup = client->head;
	bool retry = FALSE;
	int ret = 0;

	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		if (lookup == NULL) {
			dns_client_disconnect(client, t_strdup_printf(
				"Unexpected input from %s", client->path));
			return;
		}
		ret = dns_lookup_input_line(lookup, line);
		if (ret > 0)
			break;
		if (ret < 0) {
			dns_client_disconnect(client, t_strdup_printf(
				"Invalid input from %s", client->path));
			return;
		}
	}

	if (ret != 0 && lookup->result.error != NULL) {
		/* already got the error */
	} else if (client->input->stream_errno != 0) {
		dns_client_disconnect(client, t_strdup_printf(
			"read(%s) failed: %s", client->path,
			i_stream_get_error(client->input)));
		return;
	} else if (client->input->eof) {
		dns_client_disconnect(client, t_strdup_printf(
			"Unexpected EOF from %s", client->path));
		return;
	}
	if (ret > 0) {
		dns_lookup_save_msecs(lookup);
		lookup->callback(&lookup->result, lookup->context);
		retry = !lookup->client->deinit_client_at_free;
		dns_lookup_free(&lookup);
	}
	if (retry)
		dns_client_input(client);
}

static void dns_lookup_timeout(struct dns_lookup *lookup)
{
	lookup->result.error = "DNS lookup timed out";

	lookup->callback(&lookup->result, lookup->context);
	dns_lookup_free(&lookup);
}

int dns_lookup(const char *host, const struct dns_lookup_settings *set,
	       dns_lookup_callback_t *callback, void *context,
	       struct dns_lookup **lookup_r)
{
	struct dns_client *client;

	client = dns_client_init(set);
	client->deinit_client_at_free = TRUE;
	if (dns_client_lookup(client, host, callback, context, lookup_r) < 0) {
		dns_client_deinit(&client);
		return -1;
	}
	return 0;
}

int dns_lookup_ptr(const struct ip_addr *ip,
		   const struct dns_lookup_settings *set,
		   dns_lookup_callback_t *callback, void *context,
		   struct dns_lookup **lookup_r)
{
	struct dns_client *client;

	client = dns_client_init(set);
	client->deinit_client_at_free = TRUE;
	if (dns_client_lookup_ptr(client, ip, callback, context, lookup_r) < 0) {
		dns_client_deinit(&client);
		return -1;
	}
	return 0;
}

static void dns_client_idle_timeout(struct dns_client *client)
{
	i_assert(client->head == NULL);

	dns_client_disconnect(client, "Idle timeout");
}

static void dns_lookup_free(struct dns_lookup **_lookup)
{
	struct dns_lookup *lookup = *_lookup;
	struct dns_client *client = lookup->client;

	*_lookup = NULL;

	DLLIST2_REMOVE(&client->head, &client->tail, lookup);
	if (lookup->to != NULL)
		timeout_remove(&lookup->to);
	i_free(lookup->name);
	i_free(lookup->ips);
	if (client->deinit_client_at_free)
		dns_client_deinit(&client);
	else if (client->head == NULL && client->fd != -1) {
		client->to_idle = timeout_add(client->idle_timeout_msecs,
					      dns_client_idle_timeout, client);
	}
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
	if (lookup->client->deinit_client_at_free)
		lookup->client->io = io_loop_move_io(&lookup->client->io);
}

struct dns_client *dns_client_init(const struct dns_lookup_settings *set)
{
	struct dns_client *client;

	client = i_new(struct dns_client, 1);
	client->path = i_strdup(set->dns_client_socket_path);
	client->timeout_msecs = set->timeout_msecs;
	client->idle_timeout_msecs = set->idle_timeout_msecs;
	client->fd = -1;
	return client;
}

void dns_client_deinit(struct dns_client **_client)
{
	struct dns_client *client = *_client;

	*_client = NULL;

	i_assert(client->head == NULL);

	dns_client_disconnect(client, "deinit");
	i_free(client->path);
	i_free(client);
}

int dns_client_connect(struct dns_client *client, const char **error_r)
{
	if (client->fd != -1)
		return 0;

	client->fd = net_connect_unix(client->path);
	if (client->fd == -1) {
		*error_r = t_strdup_printf("connect(%s) failed: %m",
					   client->path);
		return -1;
	}
	client->input = i_stream_create_fd(client->fd, MAX_INBUF_SIZE, FALSE);
	client->io = io_add(client->fd, IO_READ, dns_client_input, client);
	return 0;
}

static int
dns_client_send_request(struct dns_client *client, const char *cmd,
			const char **error_r)
{
	int ret;

	if (client->fd == -1) {
		if (dns_client_connect(client, error_r) < 0)
			return -1;
		ret = -1;
	} else {
		/* already connected. if write() fails, retry connecting */
		ret = 0;
	}

	if (write_full(client->fd, cmd, strlen(cmd)) < 0) {
		*error_r = t_strdup_printf("write(%s) failed: %m", client->path);
		return ret;
	}
	return 1;
}

static int
dns_client_lookup_common(struct dns_client *client,
			 const char *cmd, bool ptr_lookup,
			 dns_lookup_callback_t *callback, void *context,
			 struct dns_lookup **lookup_r)
{
	struct dns_lookup *lookup;
	struct dns_lookup_result result;
	int ret;

	i_zero(&result);
	result.ret = EAI_FAIL;

	if ((ret = dns_client_send_request(client, cmd, &result.error)) <= 0) {
		if (ret == 0) {
			/* retry once */
			ret = dns_client_send_request(client, cmd, &result.error);
		}
		if (ret <= 0) {
			callback(&result, context);
			return -1;
		}
	}

	lookup = i_new(struct dns_lookup, 1);
	lookup->client = client;
	lookup->ptr_lookup = ptr_lookup;
	if (client->timeout_msecs != 0) {
		lookup->to = timeout_add(client->timeout_msecs,
					 dns_lookup_timeout, lookup);
	}
	lookup->result.ret = EAI_FAIL;
	lookup->callback = callback;
	lookup->context = context;
	if (gettimeofday(&lookup->start_time, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");

	if (client->to_idle != NULL)
		timeout_remove(&client->to_idle);
	DLLIST2_APPEND(&client->head, &client->tail, lookup);
	*lookup_r = lookup;
	return 0;
}

int dns_client_lookup(struct dns_client *client, const char *host,
		      dns_lookup_callback_t *callback, void *context,
		      struct dns_lookup **lookup_r)
{
	const char *cmd = t_strconcat("IP\t", host, "\n", NULL);
	return dns_client_lookup_common(client, cmd, FALSE,
					callback, context, lookup_r);
}

int dns_client_lookup_ptr(struct dns_client *client, const struct ip_addr *ip,
			  dns_lookup_callback_t *callback, void *context,
			  struct dns_lookup **lookup_r)
{
	const char *cmd = t_strconcat("NAME\t", net_ip2addr(ip), "\n", NULL);
	return dns_client_lookup_common(client, cmd, TRUE,
					callback, context, lookup_r);
}

void dns_client_switch_ioloop(struct dns_client *client)
{
	struct dns_lookup *lookup;
	
	if (client->io != NULL)
		client->io = io_loop_move_io(&client->io);
	if (client->to_idle != NULL)
		client->to_idle = io_loop_move_timeout(&client->to_idle);
	for (lookup = client->head; lookup != NULL; lookup = lookup->next)
		dns_lookup_switch_ioloop(lookup);
}
