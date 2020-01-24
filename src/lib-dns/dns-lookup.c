/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "array.h"
#include "ostream.h"
#include "connection.h"
#include "lib-event.h"
#include "llist.h"
#include "istream.h"
#include "write-full.h"
#include "time-util.h"
#include "dns-lookup.h"

#include <stdio.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 512

static struct event_category event_category_dns = {
	.name = "dns"
};

struct dns_lookup {
	struct dns_lookup *prev, *next;
	struct dns_client *client;
	pool_t pool;
	bool ptr_lookup;

	struct timeout *to;

	struct timeval start_time;
	unsigned int warn_msecs;

	struct dns_lookup_result result;
	struct event *event;

	dns_lookup_callback_t *callback;
	void *context;
};

struct dns_client {
	struct connection conn;
	struct connection_list *clist;
	struct dns_lookup *head, *tail;
	struct timeout *to_idle;
	struct ioloop *ioloop;
	char *path;

	struct event *event;
	unsigned int timeout_msecs;
	unsigned int idle_timeout_msecs;

	bool connected:1;
	bool deinit_client_at_free:1;
};

#undef dns_lookup
#undef dns_lookup_ptr
#undef dns_client_lookup
#undef dns_client_lookup_ptr

static void dns_lookup_free(struct dns_lookup **_lookup);

static void dns_lookup_save_msecs(struct dns_lookup *lookup);

static void dns_lookup_callback(struct dns_lookup *lookup)
{
	struct event_passthrough *e =
		event_create_passthrough(lookup->event)->
		set_name("dns_request_finished");

	dns_lookup_save_msecs(lookup);

	if (lookup->result.ret != 0) {
		e->add_int("error_code", lookup->result.ret);
		e->add_str("error", lookup->result.error);
		e_debug(e->event(), "Lookup failed after %u msecs: %s",
			lookup->result.msecs, lookup->result.error);
	} else {
		e_debug(e->event(), "Lookup successful after %u msecs",
			lookup->result.msecs);
	}
	lookup->callback(&lookup->result, lookup->context);
}

static void dns_client_disconnect(struct dns_client *client, const char *error)
{
	struct dns_lookup *lookup, *next;
	struct dns_lookup_result result;

	timeout_remove(&client->to_idle);

	if (client->connected)
		connection_disconnect(&client->conn);
	client->connected = FALSE;

	i_zero(&result);
	result.ret = EAI_FAIL;
	result.error = error;
	e_debug(client->conn.event, "Disconnect: %s", error);

	lookup = client->head;
	client->head = NULL;
	while (lookup != NULL) {
		next = lookup->next;
		dns_lookup_callback(lookup);
		dns_lookup_free(&lookup);
		lookup = next;
	}
}

static void dns_client_destroy(struct connection *conn)
{
	struct dns_client *client = container_of(conn, struct dns_client, conn);
	client->connected = FALSE;
	connection_deinit(conn);
}

static int dns_lookup_input_args(struct dns_lookup *lookup, const char *const *args)
{
	struct dns_lookup_result *result = &lookup->result;

	if (str_to_int(args[0], &result->ret) < 0)
		return -1;
	if (result->ret != 0) {
		result->error = args[1];
		return 1;
	}

	if (lookup->ptr_lookup) {
		result->name = p_strdup(lookup->pool, args[1]);
		return 1;
	}

	ARRAY(struct ip_addr) ips;
	p_array_init(&ips, lookup->pool, 2);
	for(unsigned int i = 1; args[i] != NULL; i++) {
		struct ip_addr *ip = array_append_space(&ips);
		if (net_addr2ip(args[i], ip) < 0)
			return -1;
	}
	result->ips = array_get(&ips, &result->ips_count);

	return 1;
}

static void dns_lookup_save_msecs(struct dns_lookup *lookup)
{
	struct timeval now;
	int diff;

	i_gettimeofday(&now);

	diff = timeval_diff_msecs(&now, &lookup->start_time);
	if (diff > 0)
		lookup->result.msecs = diff;
}

static int dns_client_input_args(struct connection *conn, const char *const *args)
{
	struct dns_client *client = container_of(conn, struct dns_client, conn);
	struct dns_lookup *lookup = client->head;
	bool retry = FALSE;
	int ret = 0;

	if (lookup == NULL) {
		dns_client_disconnect(client, t_strdup_printf(
			"Unexpected input from %s", conn->name));
		return -1;
	}

	if ((ret = dns_lookup_input_args(lookup, args)) == 0) {
		return 1; /* keep on reading */
	} else if (ret < 0) {
		dns_client_disconnect(client, t_strdup_printf(
			"Invalid input from %s", conn->name));
		return -1;
	} else if (ret > 0) {
		dns_lookup_callback(lookup);
		retry = !lookup->client->deinit_client_at_free;
		dns_lookup_free(&lookup);
	}

	return retry ? 1 : -1;
}

static void dns_lookup_timeout(struct dns_lookup *lookup)
{
	lookup->result.error = "Lookup timed out";

	dns_lookup_callback(lookup);
	dns_lookup_free(&lookup);
}

int dns_lookup(const char *host, const struct dns_lookup_settings *set,
	       dns_lookup_callback_t *callback, void *context,
	       struct dns_lookup **lookup_r)
{
	struct dns_client *client;

	client = dns_client_init(set);
	client->deinit_client_at_free = TRUE;
	return dns_client_lookup(client, host, callback, context, lookup_r);
}

int dns_lookup_ptr(const struct ip_addr *ip,
		   const struct dns_lookup_settings *set,
		   dns_lookup_callback_t *callback, void *context,
		   struct dns_lookup **lookup_r)
{
	struct dns_client *client;

	client = dns_client_init(set);
	client->deinit_client_at_free = TRUE;
	return dns_client_lookup_ptr(client, ip, callback, context, lookup_r);
}

static void dns_client_idle_timeout(struct dns_client *client)
{
	i_assert(client->head == NULL);

	/* send QUIT */
	o_stream_nsend_str(client->conn.output, "QUIT\n");
	dns_client_disconnect(client, "Idle timeout");
}

static void dns_lookup_free(struct dns_lookup **_lookup)
{
	struct dns_lookup *lookup = *_lookup;
	struct dns_client *client = lookup->client;

	*_lookup = NULL;

	DLLIST2_REMOVE(&client->head, &client->tail, lookup);
	timeout_remove(&lookup->to);
	if (client->deinit_client_at_free)
		dns_client_deinit(&client);
	else if (client->head == NULL && client->connected) {
		client->to_idle = timeout_add_to(client->ioloop,
						 client->idle_timeout_msecs,
						 dns_client_idle_timeout, client);
	}
	event_unref(&lookup->event);
	pool_unref(&lookup->pool);
}

void dns_lookup_abort(struct dns_lookup **lookup)
{
	dns_lookup_free(lookup);
}

static void dns_lookup_switch_ioloop_real(struct dns_lookup *lookup)
{
	if (lookup->to != NULL)
		lookup->to = io_loop_move_timeout(&lookup->to);
}

void dns_lookup_switch_ioloop(struct dns_lookup *lookup)
{
	/* dns client ioloop switch switches all lookups too */
	if (lookup->client->deinit_client_at_free)
		dns_client_switch_ioloop(lookup->client);
	else
		dns_lookup_switch_ioloop_real(lookup);
}

static void dns_client_connected(struct connection *conn, bool success)
{
	struct dns_client *client = container_of(conn, struct dns_client, conn);
	if (!success)
		return;
	client->connected = TRUE;
}

static const struct connection_vfuncs dns_client_vfuncs = {
	.destroy = dns_client_destroy,
	.input_args = dns_client_input_args,
	.client_connected = dns_client_connected,
};

static const struct connection_settings dns_client_set = {
	.service_name_in = "dns",
	.service_name_out = "dns-client",
	.major_version = 1,
	.minor_version = 0,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE,
};

struct dns_client *dns_client_init(const struct dns_lookup_settings *set)
{
	struct dns_client *client;

	client = i_new(struct dns_client, 1);
	client->timeout_msecs = set->timeout_msecs;
	client->idle_timeout_msecs = set->idle_timeout_msecs;
	client->clist = connection_list_init(&dns_client_set, &dns_client_vfuncs);
	client->ioloop = set->ioloop == NULL ? current_ioloop : set->ioloop;
	client->path = i_strdup(set->dns_client_socket_path);

	client->event = event_create(set->event_parent);
	event_add_category(client->event, &event_category_dns);

	client->conn.event_parent = client->event;
	connection_init_client_unix(client->clist, &client->conn, client->path);
	return client;
}

void dns_client_deinit(struct dns_client **_client)
{
	struct dns_client *client = *_client;
	struct connection_list *clist = client->clist;
	*_client = NULL;

	i_assert(client->head == NULL);

	dns_client_disconnect(client, "deinit");
	connection_list_deinit(&clist);
	i_free(client->path);
	event_unref(&client->event);
	i_free(client);
}

int dns_client_connect(struct dns_client *client, const char **error_r)
{
	if (client->connected)
		return 0;
	if (client->ioloop != NULL)
		connection_switch_ioloop_to(&client->conn, client->ioloop);
	int ret = connection_client_connect(&client->conn);
	if (ret < 0)
		*error_r = t_strdup_printf("Failed to connect to %s: %m",
					   client->path);
	return ret;
}

static int
dns_client_send_request(struct dns_client *client, const char *cmd,
			const char **error_r)
{
	int ret;

	if (!client->connected) {
		if (dns_client_connect(client, error_r) < 0)
			return -1;
	}

	if ((ret = o_stream_send(client->conn.output, cmd, strlen(cmd))) < 0) {
		*error_r = t_strdup_printf("write(%s) failed: %s",
					   client->conn.name,
					   o_stream_get_error(client->conn.output));
		dns_client_disconnect(client, "Cannot send data");
	}

	return ret;
}

static int
dns_client_lookup_common(struct dns_client *client,
			 const char *cmd, const char *param, bool ptr_lookup,
			 dns_lookup_callback_t *callback, void *context,
			 struct dns_lookup **lookup_r)
{
	struct dns_lookup *lookup;
	int ret;

	i_assert(param != NULL && *param != '\0');
	cmd = t_strdup_printf("%s\t%s\n", cmd, param);

	pool_t pool = pool_alloconly_create("dns lookup", 512);
	lookup = p_new(pool, struct dns_lookup, 1);
	lookup->pool = pool;

	i_gettimeofday(&lookup->start_time);

	lookup->client = client;
	lookup->callback = callback;
	lookup->context = context;
	lookup->ptr_lookup = ptr_lookup;
	lookup->result.ret = EAI_FAIL;
	lookup->event = event_create(client->event);
	event_set_append_log_prefix(lookup->event, t_strconcat("dns(", param, "): ", NULL));
	struct event_passthrough *e =
		event_create_passthrough(lookup->event)->
		set_name("dns_request_started");
	e_debug(e->event(), "Lookup started");

	if ((ret = dns_client_send_request(client, cmd, &lookup->result.error)) <= 0) {
		if (ret == 0) {
			/* retry once */
			ret = dns_client_send_request(client, cmd,
						      &lookup->result.error);
		}
		if (ret <= 0) {
			dns_lookup_callback(lookup);
			dns_lookup_free(&lookup);
			return -1;
		}
	}

	if (client->timeout_msecs != 0) {
		lookup->to = timeout_add_to(client->ioloop,
					    client->timeout_msecs,
					    dns_lookup_timeout, lookup);
	}
	timeout_remove(&client->to_idle);
	DLLIST2_APPEND(&client->head, &client->tail, lookup);
	*lookup_r = lookup;
	return 0;
}

int dns_client_lookup(struct dns_client *client, const char *host,
		      dns_lookup_callback_t *callback, void *context,
		      struct dns_lookup **lookup_r)
{
	return dns_client_lookup_common(client, "IP", host, FALSE,
					callback, context, lookup_r);
}

int dns_client_lookup_ptr(struct dns_client *client, const struct ip_addr *ip,
			  dns_lookup_callback_t *callback, void *context,
			  struct dns_lookup **lookup_r)
{
	return dns_client_lookup_common(client, "NAME", net_ip2addr(ip), TRUE,
					callback, context, lookup_r);
}

void dns_client_switch_ioloop(struct dns_client *client)
{
	struct dns_lookup *lookup;

	connection_switch_ioloop(&client->conn);
	client->to_idle = io_loop_move_timeout(&client->to_idle);
	client->ioloop = current_ioloop;

	for (lookup = client->head; lookup != NULL; lookup = lookup->next)
		dns_lookup_switch_ioloop_real(lookup);
}
