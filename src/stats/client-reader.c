/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "stats-dist.h"
#include "strescape.h"
#include "connection.h"
#include "ostream.h"
#include "master-service.h"
#include "stats-metrics.h"
#include "client-reader.h"

struct reader_client {
	struct connection conn;
	struct stats_metrics *metrics;
};

static struct connection_list *reader_clients = NULL;

void client_reader_create(int fd, struct stats_metrics *metrics)
{
	struct reader_client *client;

	client = i_new(struct reader_client, 1);
	client->metrics = metrics;
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

static int
reader_client_input_dump(struct reader_client *client, const char *const *args)
{
	struct stats_metrics_iter *iter;
	const struct metric *metric;
	string_t *str = t_str_new(128);

	o_stream_cork(client->conn.output);
	iter = stats_metrics_iterate_init(client->metrics);
	while ((metric = stats_metrics_iterate(iter)) != NULL) {
		str_truncate(str, 0);
		str_append_tabescaped(str, metric->name);
		reader_client_dump_stats(str, metric->duration_stats, args);
		for (unsigned int i = 0; i < metric->fields_count; i++) {
			str_append_c(str, '\t');
			str_append_tabescaped(str, metric->fields[i].field_key);
			reader_client_dump_stats(str, metric->fields[i].stats, args);
		}
		str_append_c(str, '\n');
		o_stream_nsend(client->conn.output, str_data(str), str_len(str));
	}
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
	stats_metrics_reset(client->metrics);
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
	.output_max_size = (size_t)-1,
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
