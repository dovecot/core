/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "time-util.h"
#include "lib-event-private.h"
#include "event-filter.h"
#include "connection.h"
#include "stats-client.h"

#define STATS_CLIENT_TIMEOUT_MSECS (5*1000)
#define STATS_CLIENT_RECONNECT_INTERVAL_MSECS (10*1000)

struct stats_client {
	struct connection conn;
	struct event_filter *filter;
	struct ioloop *ioloop;
	struct timeout *to_reconnect;
	bool handshaked;
	bool handshake_received_at_least_once;
	bool silent_notfound_errors;
};

static struct connection_list *stats_clients;

static void stats_client_connect(struct stats_client *client);

static int
client_handshake_filter(const char *const *args, struct event_filter **filter_r,
			const char **error_r)
{
	if (strcmp(args[0], "FILTER") != 0) {
		*error_r = "Expected FILTER";
		return -1;
	}
	if (args[1] == NULL || args[1][0] == '\0') {
		*filter_r = NULL;
		return 0;
	}

	*filter_r = event_filter_create();
	if (!event_filter_import(*filter_r, t_str_tabunescape(args[1]), error_r)) {
		event_filter_unref(filter_r);
		return -1;
	}
	return 0;
}

static int
stats_client_handshake(struct stats_client *client, const char *const *args)
{
	struct event_filter *filter;
	const char *error;

	if (client_handshake_filter(args, &filter, &error) < 0) {
		i_error("stats: Received invalid handshake: %s (input: %s)",
			error, t_strarray_join(args, "\t"));
		return -1;
	}
	client->handshaked = TRUE;
	client->handshake_received_at_least_once = TRUE;
	if (client->ioloop != NULL)
		io_loop_stop(client->ioloop);

	if (filter == NULL)
		filter = event_filter_create();

	event_filter_unref(&client->filter);
	client->filter = filter;
	event_set_global_debug_send_filter(client->filter);
	return 1;
}

static int
stats_client_input_args(struct connection *conn, const char *const *args)
{
	struct stats_client *client = (struct stats_client *)conn;

	return stats_client_handshake(client, args);

}

static void stats_client_reconnect(struct stats_client *client)
{
	timeout_remove(&client->to_reconnect);
	stats_client_connect(client);
}

static void stats_client_destroy(struct connection *conn)
{
	struct stats_client *client = (struct stats_client *)conn;
	struct event *event;
	unsigned int reconnect_msecs = STATS_CLIENT_RECONNECT_INTERVAL_MSECS;

	/* after reconnection the IDs need to be re-sent */
	for (event = events_get_head(); event != NULL; event = event->next)
		event->sent_to_stats_id = 0;

	client->handshaked = FALSE;
	connection_disconnect(conn);
	if (client->ioloop != NULL) {
		/* waiting for stats handshake to finish */
		io_loop_stop(client->ioloop);
	} else if (conn->connect_finished.tv_sec != 0) {
		int msecs_since_connected =
			timeval_diff_msecs(&ioloop_timeval,
					   &conn->connect_finished);
		if (msecs_since_connected >= STATS_CLIENT_RECONNECT_INTERVAL_MSECS) {
			/* reconnect immdiately */
			reconnect_msecs = 0;
		} else {
			/* wait for reconnect interval since we last
			   were connected. */
			reconnect_msecs = STATS_CLIENT_RECONNECT_INTERVAL_MSECS -
				msecs_since_connected;
		}
	}
	if (client->to_reconnect == NULL) {
		client->to_reconnect =
			timeout_add(reconnect_msecs,
				    stats_client_reconnect, client);
	}
}

static const struct connection_settings stats_client_set = {
	.service_name_in = "stats-server",
	.service_name_out = "stats-client",
	.major_version = 4,
	.minor_version = 0,

	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = TRUE
};

static const struct connection_vfuncs stats_client_vfuncs = {
	.destroy = stats_client_destroy,
	.input_args = stats_client_input_args,
};

static void
stats_event_write(struct stats_client *client,
		  struct event *event, struct event *global_event,
		  const struct failure_context *ctx, string_t *str, bool begin)
{
	struct event *merged_event;
	struct event *parent_event;
	bool update = FALSE, flush_output = FALSE;

	merged_event = begin ? event_ref(event) : event_minimize(event);
	parent_event = merged_event->parent;

	if (parent_event != NULL) {
		if (parent_event->sent_to_stats_id !=
		    parent_event->change_id) {
			stats_event_write(client, parent_event, NULL,
					  ctx, str, TRUE);
		}
		i_assert(parent_event->sent_to_stats_id != 0);
	}
	if (begin) {
		i_assert(event == merged_event);
		update = (event->sent_to_stats_id != 0);
		const char *cmd = !update ? "BEGIN" : "UPDATE";
		str_printfa(str, "%s\t%"PRIu64"\t", cmd, event->id);
		event->sent_to_stats_id = event->change_id;
		/* Flush the BEGINs early on, because the stats event writing
		   may trigger more events recursively (e.g. data_stack_grow),
		   which may use the BEGIN events as parents. */
		flush_output = !update;
	} else {
		str_printfa(str, "EVENT\t%"PRIu64"\t",
			    global_event == NULL ? 0 : global_event->id);
	}
	str_printfa(str, "%"PRIu64"\t",
		    parent_event == NULL ? 0 : parent_event->id);
	if (!update)
		str_printfa(str, "%u\t", ctx->type);
	event_export(merged_event, str);
	str_append_c(str, '\n');
	event_unref(&merged_event);
	if (flush_output) {
		o_stream_nsend(client->conn.output, str_data(str), str_len(str));
		str_truncate(str, 0);
	}
}

static void
stats_client_send_event(struct stats_client *client, struct event *event,
			const struct failure_context *ctx)
{
	static int recursion = 0;

	if (!client->handshaked)
		return;

	if (!event_filter_match(client->filter, event, ctx))
		return;

	/* Need to send the event for stats and/or export */
	string_t *str = t_str_new(256);

	if (++recursion == 0)
		o_stream_cork(client->conn.output);
	struct event *global_event = event_get_global();
	if (global_event != NULL)
		stats_event_write(client, global_event, NULL, ctx, str, TRUE);

	stats_event_write(client, event, global_event, ctx, str, FALSE);
	o_stream_nsend(client->conn.output, str_data(str), str_len(str));

	i_assert(recursion > 0);
	if (--recursion == 0)
		o_stream_uncork(client->conn.output);
}

static void
stats_client_free_event(struct stats_client *client, struct event *event)
{
	if (event->sent_to_stats_id == 0)
		return;
	o_stream_nsend_str(client->conn.output,
			   t_strdup_printf("END\t%"PRIu64"\n", event->id));
}

static bool
stats_event_callback(struct event *event, enum event_callback_type type,
		     struct failure_context *ctx,
		     const char *fmt ATTR_UNUSED, va_list args ATTR_UNUSED)
{
	if (stats_clients->connections == NULL)
		return TRUE;
	struct stats_client *client =
		(struct stats_client *)stats_clients->connections;
	if (client->conn.output == NULL)
		return TRUE;

	switch (type) {
	case EVENT_CALLBACK_TYPE_CREATE:
		break;
	case EVENT_CALLBACK_TYPE_SEND:
		stats_client_send_event(client, event, ctx);
		break;
	case EVENT_CALLBACK_TYPE_FREE:
		stats_client_free_event(client, event);
		break;
	}
	return TRUE;
}

static void
stats_category_append(string_t *str, const struct event_category *category)
{
	str_append(str, "CATEGORY\t");
	str_append_tabescaped(str, category->name);
	if (category->parent != NULL) {
		str_append_c(str, '\t');
		str_append_tabescaped(str, category->parent->name);
	}
	str_append_c(str, '\n');
}

static void stats_category_registered(struct event_category *category)
{
	if (stats_clients->connections == NULL)
		return;
	struct stats_client *client =
		(struct stats_client *)stats_clients->connections;
	if (client->conn.output == NULL)
		return;

	string_t *str = t_str_new(64);
	stats_category_append(str, category);
	o_stream_nsend(client->conn.output, str_data(str), str_len(str));
}

static void stats_global_init(void)
{
	stats_clients = connection_list_init(&stats_client_set,
					     &stats_client_vfuncs);
	event_register_callback(stats_event_callback);
	event_category_register_callback(stats_category_registered);
}

static void stats_global_deinit(void)
{
	event_unregister_callback(stats_event_callback);
	event_category_unregister_callback(stats_category_registered);
	connection_list_deinit(&stats_clients);
}

static void stats_client_timeout(struct stats_client *client)
{
	e_error(client->conn.event, "Timeout waiting for handshake response");
	io_loop_stop(client->ioloop);
}

static void stats_client_wait_handshake(struct stats_client *client)
{
	struct ioloop *prev_ioloop = current_ioloop;
	struct timeout *to;

	i_assert(client->to_reconnect == NULL);

	client->ioloop = io_loop_create();
	to = timeout_add(STATS_CLIENT_TIMEOUT_MSECS, stats_client_timeout, client);
	connection_switch_ioloop(&client->conn);
	io_loop_run(client->ioloop);
	io_loop_set_current(prev_ioloop);
	connection_switch_ioloop(&client->conn);
	if (client->to_reconnect != NULL)
		client->to_reconnect = io_loop_move_timeout(&client->to_reconnect);
	io_loop_set_current(client->ioloop);
	timeout_remove(&to);
	io_loop_destroy(&client->ioloop);
}

static void stats_client_send_registered_categories(struct stats_client *client)
{
	struct event_category *const *categories;
	unsigned int i, count;

	string_t *str = t_str_new(64);
	categories = event_get_registered_categories(&count);
	for (i = 0; i < count; i++)
		stats_category_append(str, categories[i]);
	o_stream_nsend(client->conn.output, str_data(str), str_len(str));
}

static void stats_client_connect(struct stats_client *client)
{
	if (connection_client_connect(&client->conn) == 0) {
		/* read the handshake so the global debug filter is updated */
		stats_client_send_registered_categories(client);
		if (!client->handshake_received_at_least_once)
			stats_client_wait_handshake(client);
	} else if (!client->silent_notfound_errors ||
		   (errno != ENOENT && errno != ECONNREFUSED)) {
		i_error("net_connect_unix(%s) failed: %m", client->conn.name);
	}
}

struct stats_client *
stats_client_init(const char *path, bool silent_notfound_errors)
{
	struct stats_client *client;

	if (stats_clients == NULL)
		stats_global_init();

	client = i_new(struct stats_client, 1);
	client->silent_notfound_errors = silent_notfound_errors;
	connection_init_client_unix(stats_clients, &client->conn, path);
	stats_client_connect(client);
	return client;
}

void stats_client_deinit(struct stats_client **_client)
{
	struct stats_client *client = *_client;

	*_client = NULL;

	event_filter_unref(&client->filter);
	connection_deinit(&client->conn);
	timeout_remove(&client->to_reconnect);
	i_free(client);

	if (stats_clients->connections == NULL)
		stats_global_deinit();
}
