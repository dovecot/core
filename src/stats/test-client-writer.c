/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-stats-common.h"
#include "master-service-private.h"
#include "client-writer.h"
#include "connection.h"
#include "ostream.h"

static struct event *last_sent_event = NULL;
static bool recurse_back = FALSE;
static struct connection_list *conn_list;

static void test_writer_server_destroy(struct connection *conn)
{
	io_loop_stop(conn->ioloop);
}

static int test_writer_server_input_args(struct connection *conn,
					 const char *const *args ATTR_UNUSED)
{
	/* check filter */
	test_assert_strcmp(args[0], "FILTER");
	test_assert_strcmp(args[1], "ntest");
	/* send commands now */
	string_t *send_buf = t_str_new(128);
	o_stream_nsend_str(conn->output, "CATEGORY\ttest\n");
	str_printfa(send_buf, "BEGIN\t%"PRIu64"\t0\t0\t", last_sent_event->id);
	event_export(last_sent_event, send_buf);
	str_append_c(send_buf, '\n');
	o_stream_nsend(conn->output, str_data(send_buf), str_len(send_buf));
	str_truncate(send_buf, 0);
	str_printfa(send_buf, "END\t%"PRIu64"\n", last_sent_event->id);
	o_stream_nsend(conn->output, str_data(send_buf), str_len(send_buf));
	/* disconnect immediately */
	return -1;
}

static struct connection_settings client_set = {
	.service_name_in = "stats-server",
	.service_name_out = "stats-client",
	.major_version = 3,
	.minor_version = 0,

	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE,
};

static const struct connection_vfuncs client_vfuncs = {
	.input_args = test_writer_server_input_args,
	.destroy = test_writer_server_destroy,
};

static void test_write_one(struct event *event ATTR_UNUSED)
{
	int fds[2];

	test_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	struct connection *conn = i_new(struct connection, 1);

	struct ioloop *loop = io_loop_create();

	client_writer_create(fds[1]);
	connection_init_client_fd(conn_list, conn, "stats", fds[0], fds[0]);

	last_sent_event = event;
	io_loop_run(loop);
	last_sent_event = NULL;
	connection_deinit(conn);
	i_free(conn);

	/* client-writer needs two loops to deinit */
	io_loop_set_running(loop);
	io_loop_handler_run(loop);
	io_loop_set_running(loop);
	io_loop_handler_run(loop);

	io_loop_destroy(&loop);
}

bool test_stats_callback(struct event *event,
			 enum event_callback_type type ATTR_UNUSED,
			 struct failure_context *ctx ATTR_UNUSED,
			 const char *fmt ATTR_UNUSED,
			 va_list args ATTR_UNUSED)
{
	if (recurse_back)
		return TRUE;

	recurse_back = TRUE;
	if (stats_metrics != NULL) {
		test_write_one(event);
	}
	recurse_back = FALSE;

	return TRUE;
}

static const char *settings_blob_1 =
"metric=test\n"
"metric/test/name=test\n"
"metric/test/event_name=test\n"
"\n";

static void test_client_writer(void)
{
	test_begin("client writer");

	/* register some stats */
	test_init(settings_blob_1);

	client_writers_init();
	conn_list = connection_list_init(&client_set, &client_vfuncs);

	/* push event in */
	struct event *event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	test_event_send(event);
	event_unref(&event);

	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == 1);
	test_assert(get_stats_dist_field("test", STATS_DIST_SUM) > 0);

	test_deinit();

	client_writers_deinit();
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
		test_client_writer,
		NULL
	};

	master_service = &local_master_service;

	int ret = test_run(test_functions);

	return ret;
}
