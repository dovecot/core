/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "array.h"
#include "llist.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "lib-event-private.h"
#include "event-filter.h"
#include "ostream.h"
#include "connection.h"
#include "master-service.h"
#include "stats-event-category.h"
#include "stats-metrics.h"
#include "stats-settings.h"
#include "client-writer.h"

struct stats_event {
	struct stats_event *prev, *next;

	uint64_t id;
	struct event *event;
};

struct writer_client {
	struct connection conn;

	struct stats_event *events;
	HASH_TABLE(struct stats_event *, struct stats_event *) events_hash;
};

static struct connection_list *writer_clients = NULL;

static void client_writer_send_handshake(struct writer_client *client)
{
	string_t *filter = t_str_new(128);
	string_t *str = t_str_new(128);

	event_filter_export(stats_metrics_get_event_filter(stats_metrics), filter);

	str_append(str, "FILTER\t");
	str_append_tabescaped(str, str_c(filter));
	str_append_c(str, '\n');
	o_stream_nsend(client->conn.output, str_data(str), str_len(str));
}

static unsigned int stats_event_hash(const struct stats_event *event)
{
	return (unsigned int)event->id;
}

static int stats_event_cmp(const struct stats_event *event1,
			   const struct stats_event *event2)
{
	return event1->id == event2->id ? 0 : 1;
}

void client_writer_create(int fd)
{
	struct writer_client *client;

	client = i_new(struct writer_client, 1);
	hash_table_create(&client->events_hash, default_pool, 0,
			  stats_event_hash, stats_event_cmp);

	connection_init_server(writer_clients, &client->conn,
			       "stats", fd, fd);
	client_writer_send_handshake(client);
}

static void writer_client_destroy(struct connection *conn)
{
	struct writer_client *client = (struct writer_client *)conn;
	struct stats_event *event, *next;

	for (event = client->events; event != NULL; event = next) {
		next = event->next;
		event_unref(&event->event);
		i_free(event);
	}
	hash_table_destroy(&client->events_hash);

	connection_deinit(conn);
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
}

static struct stats_event *
writer_client_find_event(struct writer_client *client, uint64_t event_id)
{
	struct stats_event lookup_event = { .id = event_id };
	return hash_table_lookup(client->events_hash, &lookup_event);
}

static bool
writer_client_run_event(struct writer_client *client,
			uint64_t parent_event_id, const char *const *args,
			struct event **event_r, const char **error_r)
{
	struct event *parent_event;
	unsigned int log_type;

	if (parent_event_id == 0)
		parent_event = NULL;
	else {
		struct stats_event *stats_parent_event =
			writer_client_find_event(client, parent_event_id);
		if (stats_parent_event == NULL) {
			*error_r = "Unknown parent event ID";
			return FALSE;
		}
		parent_event = stats_parent_event->event;
	}
	if (args[0] == NULL || str_to_uint(args[0], &log_type) < 0 ||
	    log_type >= LOG_TYPE_COUNT) {
		*error_r = "Invalid log type";
		return FALSE;
	}
	const struct failure_context ctx = {
		.type = (enum log_type)log_type
	};
	args++;

	struct event *event = event_create(parent_event);
	if (!event_import_unescaped(event, args, error_r)) {
		event_unref(&event);
		return FALSE;
	}
	stats_metrics_event(stats_metrics, event, &ctx);
	*event_r = event;
	return TRUE;
}

static bool
writer_client_input_event(struct writer_client *client,
			  const char *const *args, const char **error_r)
{
	struct event *event;
	uint64_t parent_event_id;

	if (args[0] == NULL || str_to_uint64(args[0], &parent_event_id) < 0) {
		*error_r = "Invalid parent ID";
		return FALSE;
	}
	if (!writer_client_run_event(client, parent_event_id, args+1, &event, error_r))
		return FALSE;
	event_unref(&event);
	return TRUE;
}

static bool
writer_client_input_event_begin(struct writer_client *client,
				const char *const *args, const char **error_r)
{
	struct event *event;
	struct stats_event *stats_event;
	uint64_t event_id, parent_event_id;

	if (args[0] == NULL || args[1] == NULL ||
	    str_to_uint64(args[0], &event_id) < 0 ||
	    str_to_uint64(args[1], &parent_event_id) < 0) {
		*error_r = "Invalid event IDs";
		return FALSE;
	}
	if (writer_client_find_event(client, event_id) != NULL) {
		*error_r = "Duplicate event ID";
		return FALSE;
	}
	if (!writer_client_run_event(client, parent_event_id, args+2, &event, error_r))
		return FALSE;

	stats_event = i_new(struct stats_event, 1);
	stats_event->id = event_id;
	stats_event->event = event;
	DLLIST_PREPEND(&client->events, stats_event);
	hash_table_insert(client->events_hash, stats_event, stats_event);
	return TRUE;
}

static bool
writer_client_input_event_update(struct writer_client *client,
				 const char *const *args, const char **error_r)
{
	struct stats_event *stats_event, *parent_stats_event;
	struct event *parent_event;
	uint64_t event_id, parent_event_id;

	if (args[0] == NULL || args[1] == NULL ||
	    str_to_uint64(args[0], &event_id) < 0 ||
	    str_to_uint64(args[1], &parent_event_id) < 0) {
		*error_r = "Invalid event IDs";
		return FALSE;
	}
	stats_event = writer_client_find_event(client, event_id);
	if (stats_event == NULL) {
		*error_r = "Unknown event ID";
		return FALSE;
	}
	parent_stats_event = parent_event_id == 0 ? NULL :
		writer_client_find_event(client, parent_event_id);
	parent_event = parent_stats_event == NULL ? NULL :
		parent_stats_event->event;
	if (stats_event->event->parent != parent_event) {
		*error_r = "Event unexpectedly changed parent";
		return FALSE;
	}
	return event_import_unescaped(stats_event->event, args, error_r);
}

static bool
writer_client_input_event_end(struct writer_client *client,
			      const char *const *args, const char **error_r)
{
	struct stats_event *stats_event;
	uint64_t event_id;

	if (args[0] == NULL || str_to_uint64(args[0], &event_id) < 0) {
		*error_r = "Invalid event ID";
		return FALSE;
	}
	stats_event = writer_client_find_event(client, event_id);
	if (stats_event == NULL) {
		*error_r = "Unknown event ID";
		return FALSE;
	}

	DLLIST_REMOVE(&client->events, stats_event);
	hash_table_remove(client->events_hash, stats_event);
	event_unref(&stats_event->event);
	i_free(stats_event);
	return TRUE;
}

static bool
writer_client_input_category(struct writer_client *client ATTR_UNUSED,
			     const char *const *args, const char **error_r)
{
	struct event_category *category, *parent;

	if (args[0] == NULL) {
		*error_r = "Missing category name";
		return FALSE;
	}
	if (args[1] == NULL)
		parent = NULL;
	else if ((parent = event_category_find_registered(args[1])) == NULL) {
		*error_r = "Unknown parent category";
		return FALSE;
	}

	category = event_category_find_registered(args[0]);
	if (category == NULL) {
		/* new category - create */
		stats_event_category_register(args[0], parent);
	} else if (category->parent != parent) {
		*error_r = t_strdup_printf(
			"Category parent '%s' changed to '%s'",
			category->parent == NULL ? "" : category->parent->name,
			parent == NULL ? "" : parent->name);
		return FALSE;
	} else {
		/* duplicate - ignore */
		return TRUE;
	}
	return TRUE;
}

static int
writer_client_input_args(struct connection *conn, const char *const *args)
{
	struct writer_client *client = (struct writer_client *)conn;
	const char *error, *cmd = args[0];
	bool ret;

	if (cmd == NULL) {
		i_error("Client sent empty line");
		return 1;
	}
	if (strcmp(cmd, "EVENT") == 0)
		ret = writer_client_input_event(client, args+1, &error);
	else if (strcmp(cmd, "BEGIN") == 0)
		ret = writer_client_input_event_begin(client, args+1, &error);
	else if (strcmp(cmd, "UPDATE") == 0)
		ret = writer_client_input_event_update(client, args+1, &error);
	else if (strcmp(cmd, "END") == 0)
		ret = writer_client_input_event_end(client, args+1, &error);
	else if (strcmp(cmd, "CATEGORY") == 0)
		ret = writer_client_input_category(client, args+1, &error);
	else {
		error = "Unknown command";
		ret = FALSE;
	}
	if (!ret) {
		i_error("Client sent invalid input for %s: %s (input: %s)",
			cmd, error, t_strarray_join(args, "\t"));
		return -1;
	}
	return 1;
}

static struct connection_settings client_set = {
	.service_name_in = "stats-client",
	.service_name_out = "stats-server",
	.major_version = 3,
	.minor_version = 0,

	.input_max_size = 1024*128, /* "big enough" */
	.output_max_size = (size_t)-1,
	.client = FALSE,
};

static const struct connection_vfuncs client_vfuncs = {
	.destroy = writer_client_destroy,
	.input_args = writer_client_input_args,
};

void client_writers_init(void)
{
	writer_clients = connection_list_init(&client_set, &client_vfuncs);
}

void client_writers_deinit(void)
{
	connection_list_deinit(&writer_clients);
}
