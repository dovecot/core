/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "array.h"
#include "str.h"
#include "stats-dist.h"
#include "strescape.h"
#include "connection.h"
#include "ostream.h"
#include "master-service.h"
#include "stats-metrics.h"
#include "stats-settings.h"
#include "client-reader.h"
#include "client-writer.h"

struct reader_client {
	struct connection conn;
};

static struct connection_list *reader_clients = NULL;

void client_reader_create(int fd)
{
	struct reader_client *client;

	client = i_new(struct reader_client, 1);
	connection_init_server(reader_clients, &client->conn,
			       "stats-reader", fd, fd);
}

static void reader_client_destroy(struct connection *conn)
{
	connection_deinit(conn);
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
}

static void reader_client_dump_stats(string_t *str, struct stats_dist *stats,
				     const char *const *fields)
{
	for (unsigned int i = 0; fields[i] != NULL; i++) {
		const char *field = fields[i];

		str_append_c(str, '\t');
		if (strcmp(field, "count") == 0)
			str_printfa(str, "%u", stats_dist_get_count(stats));
		else if (strcmp(field, "sum") == 0)
			str_printfa(str, "%"PRIu64, stats_dist_get_sum(stats));
		else if (strcmp(field, "min") == 0)
			str_printfa(str, "%"PRIu64, stats_dist_get_min(stats));
		else if (strcmp(field, "max") == 0)
			str_printfa(str, "%"PRIu64, stats_dist_get_max(stats));
		else if (strcmp(field, "avg") == 0)
			str_printfa(str, "%.02f", stats_dist_get_avg(stats));
		else if (strcmp(field, "median") == 0)
			str_printfa(str, "%"PRIu64, stats_dist_get_median(stats));
		else if (strcmp(field, "variance") == 0)
			str_printfa(str, "%.02f", stats_dist_get_variance(stats));
		else if (field[0] == '%') {
			str_printfa(str, "%"PRIu64,
				    stats_dist_get_percentile(stats, strtod(field+1, NULL)/100.0));
		} else {
			/* return unknown fields as empty */
		}
	}
}

static void reader_client_dump_metric(string_t *str, const struct metric *metric,
				      const char *const *fields)
{
	reader_client_dump_stats(str, metric->duration_stats, fields);
	for (unsigned int i = 0; i < metric->fields_count; i++) {
		str_append_c(str, '\t');
		str_append_tabescaped(str, metric->fields[i].field_key);
		reader_client_dump_stats(str, metric->fields[i].stats, fields);
	}
	str_append_c(str, '\n');
}

static void
reader_client_append_sub_name(string_t *str, const char *sub_name)
{
	for (; *sub_name != '\0'; sub_name++) {
		switch (*sub_name) {
		case '\t':
		case '\n':
		case '\r':
		case ' ':
			str_append_c(str, '_');
			break;
		default:
			str_append_c(str, *sub_name);
		}
	}
}

static void
reader_client_dump_sub_metrics(struct ostream *output, const struct metric *metric,
			       const char *sub_name, const char *const *fields)
{
	size_t root_pos, name_pos;
	struct metric *const *sub_metrics;
	if (!array_is_created(&metric->sub_metrics))
		return;
	string_t *str = t_str_new(128);
	reader_client_append_sub_name(str, sub_name);
	str_append_c(str, '_');
	root_pos = str->used;

	array_foreach(&metric->sub_metrics, sub_metrics) {
		str_truncate(str, root_pos);
		reader_client_append_sub_name(str, (*sub_metrics)->sub_name);
		name_pos = str->used;
		reader_client_dump_metric(str, *sub_metrics, fields);
		o_stream_nsend(output, str_data(str), str_len(str));
		str_truncate(str, name_pos);
		reader_client_dump_sub_metrics(output, *sub_metrics,
					       str_c(str), fields);
	}
}

static int
reader_client_input_dump(struct reader_client *client, const char *const *args)
{
	struct stats_metrics_iter *iter;
	const struct metric *metric;

	o_stream_cork(client->conn.output);
	iter = stats_metrics_iterate_init(stats_metrics);
	while ((metric = stats_metrics_iterate(iter)) != NULL) T_BEGIN {
		string_t *str = t_str_new(128);
		str_append_tabescaped(str, metric->name);
		reader_client_dump_metric(str, metric, args);
		o_stream_nsend(client->conn.output, str_data(str), str_len(str));
		reader_client_dump_sub_metrics(client->conn.output, metric,
					       metric->name, args);
	} T_END;
	o_stream_nsend(client->conn.output, "\n", 1);
	stats_metrics_iterate_deinit(&iter);
	o_stream_uncork(client->conn.output);
	return 1;
}

static int
reader_client_input_dump_reset(struct reader_client *client,
			       const char *const *args)
{
	(void)reader_client_input_dump(client, args);
	stats_metrics_reset(stats_metrics);
	return 1;
}

static int
reader_client_input_metrics_add(struct reader_client *client,
				const char *const *args)
{
	const char *error;

	if (str_array_length(args) < 7) {
		e_error(client->conn.event, "METRICS-ADD: Not enough parameters");
		return -1;
	}

	struct stats_metric_settings set = {
		.metric_name = args[0],
		.description = args[1],
		.fields = args[2],
		.group_by = args[3],
		.filter = args[4],
		.exporter = args[5],
		.exporter_include = args[6],
	};
	o_stream_cork(client->conn.output);
	if (stats_metrics_add_dynamic(stats_metrics, &set, &error)) {
		client_writer_update_connections();
		o_stream_nsend(client->conn.output, "+", 1);
	} else {
		o_stream_nsend(client->conn.output, "-", 1);
		o_stream_nsend_str(client->conn.output, "METRICS-ADD: ");
		o_stream_nsend_str(client->conn.output, error);
	}
	o_stream_nsend(client->conn.output, "\n", 1);
	o_stream_uncork(client->conn.output);
	return 1;
}

static int
reader_client_input_metrics_remove(struct reader_client *client,
				   const char *const *args)
{
	if (str_array_length(args) < 1) {
		e_error(client->conn.event, "METRICS-REMOVE: Not enough parameters");
		return -1;
	}

	if (stats_metrics_remove_dynamic(stats_metrics, args[0])) {
		client_writer_update_connections();
		o_stream_nsend(client->conn.output, "+\n", 2);
	} else {
		o_stream_nsend_str(client->conn.output,
				   t_strdup_printf("-metrics '%s' not found\n", args[0]));
	}
	return 1;
}

static int
reader_client_input_args(struct connection *conn, const char *const *args)
{
	struct reader_client *client = (struct reader_client *)conn;
	const char *cmd = args[0];

	if (cmd == NULL) {
		i_error("Client sent empty line");
		return 1;
	}
	args++;
	if (strcmp(cmd, "DUMP") == 0)
		return reader_client_input_dump(client, args);
	else if (strcmp(cmd, "METRICS-ADD") == 0)
		return reader_client_input_metrics_add(client, args);
	else if (strcmp(cmd, "METRICS-REMOVE") == 0)
		return reader_client_input_metrics_remove(client, args);
	else if (strcmp(cmd, "DUMP-RESET") == 0)
		return reader_client_input_dump_reset(client, args);
	return 1;
}

static struct connection_settings client_set = {
	.service_name_in = "stats-reader-client",
	.service_name_out = "stats-reader-server",
	.major_version = 2,
	.minor_version = 0,

	.input_max_size = 1024,
	.output_max_size = SIZE_MAX,
	.client = FALSE,
};

static const struct connection_vfuncs client_vfuncs = {
	.destroy = reader_client_destroy,
	.input_args = reader_client_input_args,
};

void client_readers_init(void)
{
	reader_clients = connection_list_init(&client_set, &client_vfuncs);
}

void client_readers_deinit(void)
{
	connection_list_deinit(&reader_clients);
}
