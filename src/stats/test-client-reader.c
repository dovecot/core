/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-stats-common.h"
#include "master-service-private.h"
#include "client-reader.h"
#include "connection.h"
#include "ostream.h"

static struct connection_list *conn_list;

struct test_connection {
	struct connection conn;

	unsigned int row_count;
};

static void test_reader_server_destroy(struct connection *conn)
{
	io_loop_stop(conn->ioloop);
}

static struct connection_settings client_set = {
	.service_name_in = "stats-reader-server",
	.service_name_out = "stats-reader-client",
	.major_version = 2,
	.minor_version = 0,
	.allow_empty_args_input = TRUE,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE,
};

bool test_stats_callback(struct event *event,
			 enum event_callback_type type ATTR_UNUSED,
			 struct failure_context *ctx, const char *fmt ATTR_UNUSED,
			 va_list args ATTR_UNUSED)
{
	if (stats_metrics != NULL) {
		stats_metrics_event(stats_metrics, event, ctx);
		struct event_filter *filter =
			stats_metrics_get_event_filter(stats_metrics);
		return !event_filter_match(filter, event, ctx);
	}
	return TRUE;
}

static const char *settings_blob_1 =
"metric=test\n"
"metric/test/metric_name=test\n"
"metric/test/filter=event:test\n"
"\n";

static int test_reader_server_input_args(struct connection *conn ATTR_UNUSED,
					 const char *const *args)
{
	if (args[0] == NULL)
		return -1;

	test_assert_strcmp(args[0], "test");
	test_assert_strcmp(args[1], "1");

	return 1;
}

static void test_dump_metrics(void)
{
	int fds[2];

	test_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	struct connection *conn = i_new(struct connection, 1);

	struct ioloop *loop = io_loop_create();

	client_reader_create(fds[1]);
	connection_init_client_fd(conn_list, conn, "stats", fds[0], fds[0]);
	o_stream_nsend_str(conn->output, "DUMP\tcount\n");

	io_loop_run(loop);
	connection_deinit(conn);
	i_free(conn);

	/* allow client-reader to finish up */
	io_loop_set_running(loop);
	io_loop_handler_run(loop);

	io_loop_destroy(&loop);
}

static void test_client_reader(void)
{
	const struct connection_vfuncs client_vfuncs = {
		.input_args = test_reader_server_input_args,
		.destroy = test_reader_server_destroy,
	};

	test_begin("client reader");

	/* register some stats */
	test_init(settings_blob_1);

	client_readers_init();
	conn_list = connection_list_init(&client_set, &client_vfuncs);

	/* push event in */
	struct event *event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	test_event_send(event);
	event_unref(&event);

	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == 1);
	test_assert(get_stats_dist_field("test", STATS_DIST_SUM) > 0);

	/* check output from reader */
	test_dump_metrics();

	test_deinit();

	client_readers_deinit();
	connection_list_deinit(&conn_list);

	test_end();
}

static const char *settings_blob_2 =
"metric=test\n"
"metric/test/metric_name=test\n"
"metric/test/filter=event:test\n"
"metric/test/group_by=test_name\n"
"\n";

static int
test_reader_server_input_args_group_by(struct connection *conn,
				       const char *const *args)
{
	struct test_connection *tconn =
		container_of(conn, struct test_connection, conn);

	if (args[0] == NULL)
		return -1;

	tconn->row_count++;

	if (tconn->row_count == 1) {
		test_assert_strcmp(args[0], "test");
		test_assert_strcmp(args[1], "1");
	} else if (tconn->row_count == 2) {
		test_assert_strcmp(args[0], "test_alpha");
		test_assert_strcmp(args[1], "1");
	}
	return 1;
}

static void test_dump_metrics_group_by(void)
{
	int fds[2];

	test_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	struct test_connection *conn = i_new(struct test_connection, 1);

	struct ioloop *loop = io_loop_create();

	client_reader_create(fds[1]);
	connection_init_client_fd(conn_list, &conn->conn, "stats", fds[0], fds[0]);
	o_stream_nsend_str(conn->conn.output, "DUMP\tcount\n");

	io_loop_run(loop);
	connection_deinit(&conn->conn);
	i_free(conn);

	io_loop_set_running(loop);
	io_loop_handler_run(loop);

	io_loop_destroy(&loop);
}

static void test_client_reader_group_by(void)
{
	const struct connection_vfuncs client_vfuncs = {
		.input_args = test_reader_server_input_args_group_by,
		.destroy = test_reader_server_destroy,
	};

	test_begin("client reader (group by)");

	/* register some stats */
	test_init(settings_blob_2);

	client_readers_init();
	conn_list = connection_list_init(&client_set, &client_vfuncs);

	/* push event in */
	struct event *event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	event_add_str(event, "event_name", "alpha");
	test_event_send(event);
	event_unref(&event);

	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == 1);
	test_assert(get_stats_dist_field("test", STATS_DIST_SUM) > 0);

	/* check output from reader */
	test_dump_metrics_group_by();

	test_deinit();

	client_readers_deinit();
	connection_list_deinit(&conn_list);

	test_end();
}

int main(void) {
	/* fake master service to pretend destroying
	   connections. */
	struct master_service local_master_service = {
		.stopping = TRUE,
		.total_available_count = 100,
		.service_count_left = 100,
	};
	void (*const test_functions[])(void) = {
		test_client_reader,
		test_client_reader_group_by,
		NULL
	};

	master_service = &local_master_service;

	int ret = test_run(test_functions);

	return ret;
}
