/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "ostream.h"
#include "connection.h"
#include "llist.h"
#include "time-util.h"
#include "dns-client-cache.h"
#include "dns-lookup.h"

static struct event_category event_category_dns = {
	.name = "dns"
};

struct dns_cache_lookup {
	struct dns_client *client;
	char *key;
};

struct dns_lookup {
	struct dns_lookup *prev, *next;
	struct dns_client *client;
	pool_t pool;
	bool ptr_lookup;
	bool cached;

	struct timeout *to;

	struct timeval start_time;
	unsigned int warn_msecs;

	struct dns_lookup_result result;
	struct event *event;
	const char *cache_key; /* cache lookup key */

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
	struct dns_client_cache *cache;

	unsigned int timeout_msecs;
	unsigned int idle_timeout_msecs;

	bool connected:1;
	bool deinit_client_at_free:1;
};

static void dns_cache_lookup_free(struct dns_cache_lookup **_ctx)
{
	struct dns_cache_lookup *ctx = *_ctx;
	*_ctx = NULL;

	i_free(ctx->key);
	i_free(ctx);
}

static void dns_client_cache_callback(const struct dns_lookup_result *result,
				      struct dns_cache_lookup *ctx)
{
	if (result->ret < 0)
		e_debug(ctx->client->conn.event,
			"Background entry refresh failed for %s '%s': %s",
			*ctx->key == 'I' ? "IP" : "name",
			ctx->key + 1, result->error);
	dns_cache_lookup_free(&ctx);
}

static void dns_client_cache_refresh(const char *cache_key,
				     struct dns_client *client)
{
	struct dns_lookup *lookup;
	struct dns_cache_lookup *ctx;

	if (*cache_key == 'I') {
		struct ip_addr ip;
		if (net_addr2ip(cache_key + 1, &ip) < 0)
			i_unreached();
		ctx = i_new(struct dns_cache_lookup, 1);
		ctx->key = i_strdup(cache_key);
		ctx->client = client;
		if (dns_client_lookup_ptr(client, &ip, client->conn.event,
					  dns_client_cache_callback,
					  ctx, &lookup) < 0) {
			e_debug(client->conn.event,
				"Cannot refresh IP '%s' (trying again later)",
				cache_key + 1);
			dns_cache_lookup_free(&ctx);
		}
	} else if (*cache_key == 'N') {
		ctx = i_new(struct dns_cache_lookup, 1);
		ctx->key = i_strdup(cache_key);
		ctx->client = client;
		if (dns_client_lookup(client, cache_key + 1, client->conn.event,
				      dns_client_cache_callback,
				      ctx, &lookup) < 0) {
			e_debug(client->conn.event,
				"Cannot refresh name '%s' (trying again later)",
				cache_key + 1);
			dns_cache_lookup_free(&ctx);
		}
	} else {
		i_unreached();
	}
}

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

	if (!lookup->cached) {
		dns_client_cache_entry(lookup->client->cache, lookup->cache_key,
				       &lookup->result);
	}
	dns_lookup_save_msecs(lookup);

	if (lookup->result.ret != 0) {
		i_assert(lookup->result.error != NULL);
		e->add_int("error_code", lookup->result.ret);
		e->add_str("error", lookup->result.error);
		e_debug(e->event(), "Lookup failed after %u msecs: %s",
			lookup->result.msecs, lookup->result.error);
	} else {
		e->add_str("cached", lookup->cached ? "yes" : "no");
		e_debug(e->event(), "Lookup successful after %u msecs",
			lookup->result.msecs);
		i_assert(lookup->ptr_lookup || lookup->result.ips_count > 0);
	}
	if (lookup->callback != NULL)
		lookup->callback(&lookup->result, lookup->context);
}

static void dns_lookup_callback_cached(struct dns_lookup *lookup)
{
	timeout_remove(&lookup->to);
	dns_lookup_callback(lookup);
	dns_lookup_free(&lookup);
}

static void dns_client_disconnect(struct dns_client *client, const char *error)
{
	struct dns_lookup *lookup, *next;

	if (client->connected) {
		timeout_remove(&client->to_idle);
		connection_disconnect(&client->conn);
		client->connected = FALSE;

		e_debug(client->conn.event, "Disconnect: %s", error);
	}

	lookup = client->head;
	client->head = NULL;
	client->tail = NULL;
	while (lookup != NULL) {
		next = lookup->next;

		i_zero(&lookup->result);
		lookup->result.ret = EAI_FAIL;
		lookup->result.error = error;

		dns_lookup_callback(lookup);
		dns_lookup_free(&lookup);
		lookup = next;
	}
}

static void dns_client_destroy(struct connection *conn)
{
	struct dns_client *client = container_of(conn, struct dns_client, conn);
	client->connected = FALSE;
	timeout_remove(&client->to_idle);
	connection_deinit(conn);
}

static int dns_lookup_input_args(struct dns_lookup *lookup, const char *const *args)
{
	struct dns_lookup_result *result = &lookup->result;

	if (str_to_int(args[0], &result->ret) < 0)
		return -1;
	if (result->ret != 0) {
		result->error = args[1];
		return 0;
	}

	if (lookup->ptr_lookup) {
		result->name = p_strdup(lookup->pool, args[1]);
		return 0;
	}

	ARRAY(struct ip_addr) ips;
	p_array_init(&ips, lookup->pool, 2);
	for(unsigned int i = 1; args[i] != NULL; i++) {
		struct ip_addr *ip = array_append_space(&ips);
		if (net_addr2ip(args[i], ip) < 0)
			return -1;
	}
	result->ips = array_get(&ips, &result->ips_count);

	return 0;
}

static void dns_lookup_save_msecs(struct dns_lookup *lookup)
{
	struct timeval now;
	long long diff;

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

	if (lookup == NULL) {
		dns_client_disconnect(client, t_strdup_printf(
			"Unexpected input from %s", conn->name));
		return -1;
	}

	if (dns_lookup_input_args(lookup, args) < 0) {
		dns_client_disconnect(client, t_strdup_printf(
			"Invalid input from %s", conn->name));
		return -1;
	}
	DLLIST2_REMOVE(&client->head, &client->tail, lookup);

	dns_lookup_callback(lookup);
	retry = !lookup->client->deinit_client_at_free;
	dns_lookup_free(&lookup);

	return retry ? 1 : -1;
}

static void dns_lookup_timeout(struct dns_lookup *lookup)
{
	long long duration_msecs = timeval_diff_msecs(&ioloop_timeval,
						      &lookup->start_time);
	/* Disconnection aborts all requests with this same log message.
	   It's not exactly right for all requests, but it shouldn't be too
	   far off. */
	dns_client_disconnect(lookup->client, t_strdup_printf(
		"Lookup timed out in %lld.%03lld secs",
		duration_msecs / 1000, duration_msecs % 1000));
}

int dns_lookup(const char *host, const struct dns_lookup_settings *set,
	       dns_lookup_callback_t *callback, void *context,
	       struct dns_lookup **lookup_r)
{
	struct dns_client *client;

	i_assert(set->cache_ttl_secs == 0);
	client = dns_client_init(set);
	client->deinit_client_at_free = TRUE;
	return dns_client_lookup(client, host, client->conn.event, callback,
				 context, lookup_r);
}

int dns_lookup_ptr(const struct ip_addr *ip,
		   const struct dns_lookup_settings *set,
		   dns_lookup_callback_t *callback, void *context,
		   struct dns_lookup **lookup_r)
{
	struct dns_client *client;

	i_assert(set->cache_ttl_secs == 0);
	client = dns_client_init(set);
	client->deinit_client_at_free = TRUE;
	return dns_client_lookup_ptr(client, ip, client->conn.event,
				     callback, context, lookup_r);
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

	timeout_remove(&lookup->to);
	if (client->deinit_client_at_free)
		dns_client_deinit(&client);
	else if (client->head == NULL && client->connected &&
		 client->to_idle == NULL) {
		client->to_idle = timeout_add_to(client->ioloop,
						 client->idle_timeout_msecs,
						 dns_client_idle_timeout, client);
	}
	event_unref(&lookup->event);
	pool_unref(&lookup->pool);
}

void dns_lookup_abort(struct dns_lookup **_lookup)
{
	struct dns_lookup *lookup = *_lookup;

	if (lookup == NULL)
		return;
	*_lookup = NULL;

	struct dns_client *client = lookup->client;
	if (client->deinit_client_at_free)
		dns_client_deinit(&client);
	else if (lookup->callback != NULL) {
		dns_lookup_save_msecs(lookup);
		lookup->result.ret = EAI_CANCELED,
		lookup->result.error = "Lookup canceled";
		lookup->callback(&lookup->result, lookup->context);
		lookup->callback = NULL;
	}
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
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = TRUE,
};

struct dns_client *dns_client_init(const struct dns_lookup_settings *set)
{
	struct dns_client *client;

	i_assert(set->dns_client_socket_path[0] != '\0');

	client = i_new(struct dns_client, 1);
	client->timeout_msecs = set->timeout_msecs;
	client->idle_timeout_msecs = set->idle_timeout_msecs;
	client->clist = connection_list_init(&dns_client_set, &dns_client_vfuncs);
	client->ioloop = set->ioloop == NULL ? current_ioloop : set->ioloop;
	client->path = i_strdup(set->dns_client_socket_path);
	client->conn.event_parent=set->event_parent;
	connection_init_client_unix(client->clist, &client->conn, client->path);
	event_add_category(client->conn.event, &event_category_dns);
	if (set->cache_ttl_secs > 0) {
		client->cache = dns_client_cache_init(set->cache_ttl_secs,
			dns_client_cache_refresh, client);
	}
	return client;
}

void dns_client_deinit(struct dns_client **_client)
{
	struct dns_client *client = *_client;
	struct connection_list *clist = client->clist;
	*_client = NULL;

	client->deinit_client_at_free = FALSE; /* avoid recursion here */
	dns_client_disconnect(client, "deinit");

	/* dns_client_disconnect() is supposed to clear out all queries */
	i_assert(client->head == NULL);
	connection_list_deinit(&clist);

	dns_client_cache_deinit(&client->cache);

	i_free(client->path);
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
			 struct event *event,
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
	if (event == NULL)
		lookup->event = event_create(client->conn.event);
	else {
		lookup->event = event_create(event);
		event_add_category(lookup->event, &event_category_dns);
	}
	lookup->cache_key = p_strdup_printf(lookup->pool, "%c%s",
				      ptr_lookup ? 'I' : 'N', param);
	event_set_append_log_prefix(lookup->event, t_strconcat("dns(", param, "): ", NULL));
	struct event_passthrough *e =
		event_create_passthrough(lookup->event)->
		set_name("dns_request_started");
	e_debug(e->event(), "Lookup started");

	if (dns_client_cache_lookup(client->cache, lookup->cache_key, pool,
				    &lookup->result)) {
		lookup->cached = TRUE;
		lookup->to = timeout_add_short(0, dns_lookup_callback_cached,
					       lookup);
		return 0;
	}

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
		      struct event *event,
		      dns_lookup_callback_t *callback, void *context,
		      struct dns_lookup **lookup_r)
{
	int ret;
	T_BEGIN {
		ret = dns_client_lookup_common(client, "IP", host, FALSE, event,
					       callback, context, lookup_r);
	} T_END;
	return ret;
}

int dns_client_lookup_ptr(struct dns_client *client, const struct ip_addr *ip,
			  struct event *event,
			  dns_lookup_callback_t *callback, void *context,
			  struct dns_lookup **lookup_r)
{
	int ret;
	T_BEGIN {
		ret = dns_client_lookup_common(client, "NAME", net_ip2addr(ip),
					       TRUE, event, callback, context,
					       lookup_r);
	} T_END;
	return ret;
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

bool dns_client_has_pending_queries(struct dns_client *client)
{
	return client->head != NULL;
}
