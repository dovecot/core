/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "llist.h"
#include "array.h"
#include "path-util.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "istream-base64.h"
#include "istream-crlf.h"
#include "iostream-temp.h"
#include "iostream-ssl.h"
#include "iostream-ssl-test.h"
#ifdef HAVE_OPENSSL
#include "iostream-openssl.h"
#endif
#include "connection.h"
#include "test-common.h"
#include "smtp-server.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#define CLIENT_PROGRESS_TIMEOUT     30
#define MAX_PARALLEL_PENDING        200

static bool debug = FALSE;
static bool small_socket_buffers = FALSE;
static const char *failure = NULL;

enum test_ssl_mode {
	TEST_SSL_MODE_NONE = 0,
	TEST_SSL_MODE_IMMEDIATE,
	TEST_SSL_MODE_STARTTLS
};

static unsigned int test_max_pending = 1;
static bool test_unknown_size = FALSE;
static enum test_ssl_mode test_ssl_mode = TEST_SSL_MODE_NONE;

static struct ip_addr bind_ip;
static in_port_t bind_port = 0;
static int fd_listen = -1;
static pid_t server_pid = (pid_t)-1;

/*
 * Test files
 */

static ARRAY_TYPE(const_string) files;
static pool_t files_pool;

static void test_files_read_dir(const char *path)
{
	DIR *dirp;

	/* open the directory */
	if ((dirp = opendir(path)) == NULL) {
		if (errno == ENOENT || errno == EACCES)
			return;
		i_fatal("test files: "
			"failed to open directory %s: %m", path);
	}

	/* read entries */
	for (;;) {
		const char *file;
		struct dirent *dp;
		struct stat st;
#if 0
		if (array_count(&files) > 10)
			break;
#endif
		errno = 0;
		if ((dp=readdir(dirp)) == NULL)
			break;
		if (*dp->d_name == '.')
			continue;

		file = t_abspath_to(dp->d_name, path);
		if (stat(file, &st) == 0) {
			if (S_ISREG(st.st_mode)) {
				file += 2; /* skip "./" */
				file = p_strdup(files_pool, file);
				array_push_back(&files, &file);
			} else {
				test_files_read_dir(file);
			}
		}
	}

	if (errno != 0)
		i_fatal("test files: "
			"failed to read directory %s: %m", path);

	/* Close the directory */
	if (closedir(dirp) < 0)
		i_error("test files: "
			"failed to close directory %s: %m", path);
}

static void test_files_init(void)
{
	/* initialize file array */
	files_pool = pool_alloconly_create
		(MEMPOOL_GROWING"smtp_server_request", 4096);
	p_array_init(&files, files_pool, 512);

	/* obtain all filenames */
	test_files_read_dir(".");
}

static void test_files_deinit(void)
{
	pool_unref(&files_pool);
}

static struct istream *
test_file_open(const char *path)
{
	struct istream *file;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT && errno != EACCES) {
			i_fatal("test files: "
				"open(%s) failed: %m", path);
		}
		if (debug) {
			i_debug("test files: "
				"open(%s) failed: %m", path);
		}
		return NULL;
	}

	file = i_stream_create_fd_autoclose(&fd, 40960);
	i_stream_set_name(file, path);
	return file;
}

/*
 * Test server
 */

struct client {
	pool_t pool;
	struct client *prev, *next;

	struct smtp_server_connection *smtp_conn;
};

struct client_transaction {
	struct client *client;
	struct smtp_server_cmd_ctx *data_cmd;
	struct smtp_server_transaction *trans;

	const char *path;

	struct istream *payload, *file;
};

static struct smtp_server *smtp_server;

static struct io *io_listen;
static struct client *clients;

static int
client_transaction_read_more(struct client_transaction *ctrans)
{
	struct istream *payload = ctrans->payload;
	const unsigned char *pdata, *fdata;
	size_t psize, fsize, pleft;
	off_t ret;

	if (debug) {
		i_debug("test server: read more payload for [%s]",
			ctrans->path);
	}

	/* read payload */
	while ((ret=i_stream_read_more(payload, &pdata, &psize)) > 0) {
		if (debug) {
			i_debug("test server: "
				"got data for [%s] (size=%d)",
				ctrans->path, (int)psize);
		}
		/* compare with file on disk */
		pleft = psize;
		while ((ret=i_stream_read_more
			(ctrans->file, &fdata, &fsize)) > 0 && pleft > 0) {
			fsize = (fsize > pleft ? pleft : fsize);
			if (memcmp(pdata, fdata, fsize) != 0) {
				i_fatal("test server: "
					"received data does not match file [%s] "
					"(%"PRIuUOFF_T":%"PRIuUOFF_T")",
					ctrans->path, payload->v_offset,
					ctrans->file->v_offset);
			}
			i_stream_skip(ctrans->file, fsize);
			pleft -= fsize;
			pdata += fsize;
		}
		if (ret < 0 && ctrans->file->stream_errno != 0) {
			i_fatal("test server: "
				"failed to read file: %s",
				i_stream_get_error(ctrans->file));
		}
		i_stream_skip(payload, psize);
	}

	if (ret == 0) {
		if (debug) {
			i_debug("test server: "
				"need more data for [%s]",
				ctrans->path);
		}
		/* we will be called again for this request */
		return 0;
	}

	(void)i_stream_read(ctrans->file);
	if (payload->stream_errno != 0) {
		i_fatal("test server: "
			"failed to read transaction payload: %s",
			i_stream_get_error(payload));
	} if (i_stream_have_bytes_left(ctrans->file)) {
		if (i_stream_read_more(ctrans->file, &fdata, &fsize) <= 0)
			fsize = 0;
		i_fatal("test server: "
			"payload ended prematurely "
			"(at least %"PRIuSIZE_T" bytes left)", fsize);
	}

	if (debug) {
		i_debug("test server: "
			"finished transaction for [%s]",
			ctrans->path);
	}

	/* dereference payload stream; finishes the request */
	i_stream_unref(&payload);
	ctrans->payload = NULL;
	i_stream_unref(&ctrans->file);

	/* finished */
	smtp_server_reply_all(ctrans->data_cmd, 250, "2.0.0", "OK");
	return 1;
}

static void
client_transaction_handle_payload(struct client_transaction *ctrans,
	const char *path, struct istream *data_input)
{
	struct smtp_server_transaction *trans = ctrans->trans;
	struct istream *fstream;

	ctrans->path = p_strdup(trans->pool, path);

	if (debug) {
		i_debug("test server: got transaction for: %s",
			path);
	}

	fstream = test_file_open(path);
	if (fstream == NULL)
		i_fatal("test server: failed to open: %s", path);

	i_stream_ref(data_input);
	ctrans->payload = data_input;
	i_assert(ctrans->payload != NULL);

	ctrans->file = i_stream_create_base64_encoder(fstream, 80, TRUE),
	i_stream_unref(&fstream);

	(void)client_transaction_read_more(ctrans);
}

/* transaction */

static struct client_transaction *
client_transaction_init(struct client *client,
	struct smtp_server_cmd_ctx *data_cmd,
	struct smtp_server_transaction *trans)
{
	struct client_transaction *ctrans;
	pool_t pool = trans->pool;

	ctrans = p_new(pool, struct client_transaction, 1);
	ctrans->client = client;
	ctrans->trans = trans;
	ctrans->data_cmd = data_cmd;

	return ctrans;
}

static void
client_transaction_deinit(struct client_transaction **_ctrans)
{
	struct client_transaction *ctrans = *_ctrans;

	*_ctrans = NULL;

	i_stream_unref(&ctrans->payload);
	i_stream_unref(&ctrans->file);
}

static void
test_server_conn_trans_free(void *context ATTR_UNUSED,
	struct smtp_server_transaction *trans)
{
	struct client_transaction *ctrans =
		(struct client_transaction *)trans->context;
	client_transaction_deinit(&ctrans);
}

static int
test_server_conn_cmd_rcpt(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct smtp_server_recipient *rcpt)
{
	if (debug) {
		i_debug("test server: RCPT TO:%s",
			smtp_address_encode(rcpt->path));
	}

	return 1;
}

static int
test_server_conn_cmd_data_begin(void *conn_ctx,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_transaction *trans,
	struct istream *data_input)
{
	struct client *client = (struct client *)conn_ctx;
	const char *fpath = trans->params.envid;
	struct client_transaction *ctrans;

	i_assert(fpath != NULL);

	if (debug) {
		i_debug("test server: DATA (file path = %s)", fpath);
	}

	ctrans = client_transaction_init(client, cmd, trans);
	client_transaction_handle_payload
		(ctrans, fpath, data_input);
	trans->context = ctrans;
	return 0;
}

static int
test_server_conn_cmd_data_continue(void *conn_ctx ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd,
	struct smtp_server_transaction *trans)
{
	struct client_transaction *ctrans =
		(	struct client_transaction *)trans->context;

	if (debug)
		i_debug("test server: DATA continue");

	ctrans->data_cmd = cmd;

	return client_transaction_read_more(ctrans);
}

/* client connection */

static void
test_server_connection_destroy(void *context);

static const struct smtp_server_callbacks server_callbacks =
{
	.conn_cmd_rcpt = test_server_conn_cmd_rcpt,
	.conn_cmd_data_begin = test_server_conn_cmd_data_begin,
	.conn_cmd_data_continue = test_server_conn_cmd_data_continue,

	.conn_trans_free = test_server_conn_trans_free,

	.conn_destroy = test_server_connection_destroy
};

static void client_init(int fd)
{
	struct client *client;
	pool_t pool;

	net_set_nonblock(fd, TRUE);

	pool = pool_alloconly_create("client", 256);
	client = p_new(pool, struct client, 1);
	client->pool = pool;

	client->smtp_conn = smtp_server_connection_create(smtp_server,
		fd, fd, NULL, 0, (test_ssl_mode == TEST_SSL_MODE_IMMEDIATE),
		NULL, &server_callbacks, client);
	smtp_server_connection_start(client->smtp_conn);
	DLLIST_PREPEND(&clients, client);
}

static void client_deinit(struct client **_client)
{
	struct client *client = *_client;

	*_client = NULL;

	DLLIST_REMOVE(&clients, client);

	if (client->smtp_conn != NULL)
		smtp_server_connection_terminate(&client->smtp_conn, NULL, "deinit");
	pool_unref(&client->pool);
}

static void
test_server_connection_destroy(void *context)
{
	struct client *client = context;

	client->smtp_conn = NULL;
	client_deinit(&client);
}

static void client_accept(void *context ATTR_UNUSED)
{
	int fd;

	for (;;) {
		/* accept new client */
		if ((fd=net_accept(fd_listen, NULL, NULL)) < 0) {
			if (errno == EAGAIN)
				break;
			if (errno == ECONNABORTED)
				continue;
			i_fatal("test server: accept() failed: %m");
		}

		client_init(fd);
	}
}

/* */

static void
test_server_init(const struct smtp_server_settings *server_set)
{
	/* open server socket */
	io_listen = io_add(fd_listen,
		IO_READ, client_accept, (void *)NULL);

	smtp_server = smtp_server_init(server_set);
}

static void test_server_deinit(void)
{
	/* close server socket */
	io_remove(&io_listen);

	/* deinitialize */
	smtp_server_deinit(&smtp_server);
}

/*
 * Test client
 */

struct test_client_transaction {
	struct test_client_transaction *prev, *next;
	struct smtp_client_connection *conn;
	struct smtp_client_transaction *trans;

	struct io *io;
	struct istream *file;
	unsigned int files_idx;
};

static struct smtp_client *smtp_client;
static enum smtp_protocol client_protocol;
static struct test_client_transaction *client_requests;
static unsigned int client_files_first, client_files_last;
static struct timeout *client_to = NULL;
struct timeout *to_client_progress = NULL;

static struct test_client_transaction *
test_client_transaction_new(void)
{
	struct test_client_transaction *tctrans;

	tctrans = i_new(struct test_client_transaction, 1);
	DLLIST_PREPEND(&client_requests, tctrans);

	return tctrans;
}

static void
test_client_transaction_destroy(struct test_client_transaction *tctrans)
{
	if (tctrans->trans != NULL)
		smtp_client_transaction_destroy(&tctrans->trans);
	io_remove(&tctrans->io);
	i_stream_unref(&tctrans->file);

	DLLIST_REMOVE(&client_requests, tctrans);
	i_free(tctrans);
}

static void test_client_continue(void *dummy);

static void
test_client_finished(unsigned int files_idx)
{
	const char **paths;
	unsigned int count;

	if (debug) {
		i_debug("test client: "
			"finished [%u]", files_idx);
	}

	paths = array_get_modifiable(&files, &count);
	i_assert(files_idx < count);
	i_assert(client_files_first < count);
	i_assert(paths[files_idx] != NULL);

	paths[files_idx] = NULL;
	if (client_to == NULL)
		client_to = timeout_add_short(0, test_client_continue, NULL);
}

static void
test_client_transaction_finish(struct test_client_transaction *tctrans)
{
	tctrans->trans = NULL;
	test_client_transaction_destroy(tctrans);
}

static void
test_client_transaction_rcpt(const struct smtp_reply *reply,
				      struct test_client_transaction *tctrans)
{
	const char **paths;
	const char *path;
	unsigned int count;

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	paths = array_get_modifiable(&files, &count);
	i_assert(tctrans->files_idx < count);
	i_assert(client_files_first < count);
	path = paths[tctrans->files_idx];
	i_assert(path != NULL);

	if (reply->status / 100 != 2) {
		i_fatal("test client: "
			"SMTP RCPT for %s failed: %s",
			path, smtp_reply_log(reply));
	}
}

static void
test_client_transaction_rcpt_data(const struct smtp_reply *reply ATTR_UNUSED,
				      struct test_client_transaction *tctrans)
{
	const char **paths;
	const char *path;
	unsigned int count;

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	paths = array_get_modifiable(&files, &count);
	i_assert(tctrans->files_idx < count);
	i_assert(client_files_first < count);
	path = paths[tctrans->files_idx];
	i_assert(path != NULL);

	if (reply->status / 100 != 2) {
		i_fatal("test client: "
			"SMTP DATA for %s failed: %s",
			path, smtp_reply_log(reply));
	}
}

static void
test_client_transaction_data(const struct smtp_reply *reply,
				      struct test_client_transaction *tctrans)
{
	const char **paths;
	const char *path;
	unsigned int count;

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	if (debug) {
		i_debug("test client: "
			"got response for DATA [%u]",
			tctrans->files_idx);
	}

	paths = array_get_modifiable(&files, &count);
	i_assert(tctrans->files_idx < count);
	i_assert(client_files_first < count);
	path = paths[tctrans->files_idx];
	i_assert(path != NULL);

	if (debug) {
		i_debug("test client: "
			"path for [%u]: %s",
			tctrans->files_idx, path);
	}

	if (reply->status / 100 != 2) {
		i_fatal("test client: "
			"SMTP transaction for %s failed: %s",
			path, smtp_reply_log(reply));
	}

	test_client_finished(tctrans->files_idx);
}

static void test_client_continue(void *dummy ATTR_UNUSED)
{
	struct test_client_transaction *tctrans;
	struct smtp_params_mail mail_params;
	const char **paths;
	unsigned int count, pending_count, i;

	if (debug)
		i_debug("test client: continue");

	timeout_remove(&client_to);
	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	paths = array_get_modifiable(&files, &count);

	i_assert(client_files_first <= count);
	i_assert(client_files_last <= count);

	i_assert(client_files_first <= client_files_last);
	for (; client_files_first < client_files_last &&
		paths[client_files_first] == NULL; client_files_first++);

	pending_count = 0;
	for (i = client_files_first; i < client_files_last; i++) {
		if (paths[i] != NULL)
			pending_count++;
	}

	if (debug) {
		i_debug("test client: finished until [%u/%u]; "
			"sending until [%u/%u] (%u pending)",
			client_files_first-1, count,
			client_files_last, count, pending_count);
	}

	if (debug && client_files_first < count) {
		const char *path = paths[client_files_first];
		i_debug("test client: "
			"next blocking: %s [%d]",
			(path == NULL ? "none" : path),
			client_files_first);
	}

	if (client_files_first >= count) {
		io_loop_stop(current_ioloop);
		return;
	}

	for (; client_files_last < count && pending_count < test_max_pending;
	     client_files_last++, pending_count++) {
		struct istream *fstream, *payload;
		const char *path = paths[client_files_last];
		unsigned int r, rcpts;
		enum smtp_client_connection_ssl_mode ssl_mode;

		fstream = test_file_open(path);
		if (fstream == NULL) {
			paths[client_files_last] = NULL;
			if (debug) {
				i_debug("test client: "
					"skipping %s [%u]",
					path, client_files_last);
			}
			if (client_to == NULL)
				client_to = timeout_add_short(0, test_client_continue, NULL);
			continue;
		}

		if (debug) {
			i_debug("test client: "
				"retrieving %s [%u]",
				path, client_files_last);
		}

		tctrans = test_client_transaction_new();
		tctrans->files_idx = client_files_last;

		switch (test_ssl_mode) {
		case TEST_SSL_MODE_NONE:
		default:		
			ssl_mode = SMTP_CLIENT_SSL_MODE_NONE;
			break;
		case TEST_SSL_MODE_IMMEDIATE:
			ssl_mode = SMTP_CLIENT_SSL_MODE_IMMEDIATE;
			break;
		case TEST_SSL_MODE_STARTTLS:
			ssl_mode = SMTP_CLIENT_SSL_MODE_STARTTLS;
			break;
		}

		tctrans->conn = smtp_client_connection_create(smtp_client,
			client_protocol, net_ip2addr(&bind_ip), bind_port,
			ssl_mode, NULL);

		i_zero(&mail_params);
		mail_params.envid = path;

		tctrans->trans = smtp_client_transaction_create(tctrans->conn,
			SMTP_ADDRESS_LITERAL("user", "example.com"),
			&mail_params, 0,
			test_client_transaction_finish, tctrans);
		smtp_client_connection_unref(&tctrans->conn);

		rcpts = tctrans->files_idx % 10 + 1;
		for (r = 1; r <= rcpts; r++) {
			smtp_client_transaction_add_rcpt(tctrans->trans,
				smtp_address_create_temp(
					t_strdup_printf("rcpt%u", r), "example.com"), NULL,
				test_client_transaction_rcpt,
				test_client_transaction_rcpt_data, tctrans);
		}

		if (!test_unknown_size)
			payload = i_stream_create_base64_encoder(fstream, 80, TRUE);
		else {
			struct istream *b64_stream =
				i_stream_create_base64_encoder(fstream, 80, FALSE);
			payload = i_stream_create_crlf(b64_stream);
			i_stream_unref(&b64_stream);
		}

		if (debug) {
			uoff_t raw_size = (uoff_t)-1, b64_size = (uoff_t)-1;

			(void)i_stream_get_size(fstream, TRUE, &raw_size);
			(void)i_stream_get_size(payload, TRUE, &b64_size);
			i_debug("test client: "
				"sending %"PRIuUOFF_T"/%"PRIuUOFF_T" bytes payload %s [%u]",
				raw_size, b64_size, path, client_files_last);
		}

		smtp_client_transaction_send(tctrans->trans, payload,
			test_client_transaction_data, tctrans);

		i_stream_unref(&payload);
		i_stream_unref(&fstream);
	}
}

static void
test_client_progress_timeout(void *context ATTR_UNUSED)
{
	/* Terminate test due to lack of progress */
	failure = "Test is hanging";
	timeout_remove(&to_client_progress);
	io_loop_stop(current_ioloop);
}

static void
test_client(enum smtp_protocol protocol,
	const struct smtp_client_settings *client_set)
{
	client_protocol = protocol;

	if (!small_socket_buffers) {
		to_client_progress = timeout_add(CLIENT_PROGRESS_TIMEOUT*1000,
			test_client_progress_timeout, NULL);
	}

	/* create client */
	smtp_client = smtp_client_init(client_set);

	/* start querying server */
	client_files_first = client_files_last = 0;
	test_client_continue(NULL);
}

/* cleanup */

static void test_client_deinit(void)
{
	timeout_remove(&client_to);
	timeout_remove(&to_client_progress);
	smtp_client_deinit(&smtp_client);
}

/*
 * Tests
 */

static void test_open_server_fd(void)
{
	if (fd_listen != -1)
		i_close_fd(&fd_listen);
	fd_listen = net_listen(&bind_ip, &bind_port, 128);
	if (fd_listen == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), bind_port);
	}
	net_set_nonblock(fd_listen, TRUE);
}

static void test_server_kill(void)
{
	if (server_pid != (pid_t)-1) {
		(void)kill(server_pid, SIGKILL);
		(void)waitpid(server_pid, NULL, 0);
	}
	server_pid = (pid_t)-1;
}

static void test_run_client_server(
	enum smtp_protocol protocol,
	struct smtp_client_settings *client_set,
	struct smtp_server_settings *server_set,
	void (*client_init)(enum smtp_protocol protocol,
		const struct smtp_client_settings *client_set))
{
	struct ioloop *ioloop;

	if (test_ssl_mode == TEST_SSL_MODE_STARTTLS)
		server_set->capabilities |= SMTP_CAPABILITY_STARTTLS;

	failure = NULL;
	test_open_server_fd();

	if ((server_pid = fork()) == (pid_t)-1)
		i_fatal("fork() failed: %m");
	if (server_pid == 0) {
		server_pid = (pid_t)-1;
		hostpid_init();
		if (debug)
			i_debug("server: PID=%s", my_pid);
		i_set_failure_prefix("SERVER: ");
		/* child: server */
		ioloop = io_loop_create();
		test_server_init(server_set);
		io_loop_run(ioloop);
		test_server_deinit();
		io_loop_destroy(&ioloop);
		i_close_fd(&fd_listen);
	} else {
		if (debug)
			i_debug("client: PID=%s", my_pid);
		i_set_failure_prefix("CLIENT: ");
		i_close_fd(&fd_listen);
		/* parent: client */
		ioloop = io_loop_create();
		client_init(protocol, client_set);
		io_loop_run(ioloop);
		test_client_deinit();
		io_loop_destroy(&ioloop);
		bind_port = 0;
		test_server_kill();
	}
}

static void test_run_scenarios(enum smtp_protocol protocol,
	enum smtp_capability capabilities,
	void (*client_init)(enum smtp_protocol protocol,
		const struct smtp_client_settings *client_set))
{
	struct smtp_server_settings smtp_server_set;
	struct smtp_client_settings smtp_client_set;
	struct ssl_iostream_settings ssl_server_set, ssl_client_set;

	/* ssl settings */
	ssl_iostream_test_settings_server(&ssl_server_set);
	ssl_server_set.verbose = debug;
	ssl_iostream_test_settings_client(&ssl_client_set);
	ssl_client_set.verbose = debug;

	/* server settings */
	i_zero(&smtp_server_set);
	smtp_server_set.protocol = protocol;
	smtp_server_set.capabilities = capabilities;
	smtp_server_set.hostname = "localhost";
	smtp_server_set.max_client_idle_time_msecs = 10*000;
	smtp_server_set.max_pipelined_commands = 1;
	smtp_server_set.auth_optional = TRUE;
	smtp_server_set.ssl = &ssl_server_set;
	smtp_server_set.debug = debug;

	/* client settings */
	i_zero(&smtp_client_set);
	smtp_client_set.my_hostname = "localhost";
	smtp_client_set.temp_path_prefix = "/tmp";
	smtp_client_set.ssl = &ssl_client_set;
	smtp_client_set.debug = debug;

	if (small_socket_buffers) {
		smtp_client_set.socket_send_buffer_size = 4096;
		smtp_client_set.socket_recv_buffer_size = 4096;
		smtp_client_set.command_timeout_msecs = 20*60*1000;
		smtp_client_set.connect_timeout_msecs = 20*60*1000;
		smtp_server_set.socket_send_buffer_size = 4096;
		smtp_server_set.socket_recv_buffer_size = 4096;
	}

	test_max_pending = 1;
	test_unknown_size = FALSE;
	test_ssl_mode = TEST_SSL_MODE_NONE;
	test_files_init();
	test_run_client_server(protocol,
		&smtp_client_set, &smtp_server_set,
		client_init);
	test_files_deinit();

	test_out_reason("sequential", (failure == NULL), failure);

	test_max_pending = MAX_PARALLEL_PENDING;
	test_unknown_size = FALSE;
	test_ssl_mode = TEST_SSL_MODE_NONE;
	test_files_init();
	test_run_client_server(protocol,
		&smtp_client_set, &smtp_server_set,
		client_init);
	test_files_deinit();

	test_out_reason("parallel", (failure == NULL), failure);

	smtp_server_set.max_pipelined_commands = 5;
	smtp_server_set.capabilities |= SMTP_CAPABILITY_PIPELINING;
	test_max_pending = MAX_PARALLEL_PENDING;
	test_unknown_size = FALSE;
	test_ssl_mode = TEST_SSL_MODE_NONE;
	test_files_init();
	test_run_client_server(protocol,
		&smtp_client_set, &smtp_server_set,
		client_init);
	test_files_deinit();

	test_out_reason("parallel pipelining", (failure == NULL), failure);

	smtp_server_set.max_pipelined_commands = 5;
	smtp_server_set.capabilities |= SMTP_CAPABILITY_PIPELINING;
	test_max_pending = MAX_PARALLEL_PENDING;
	test_unknown_size = TRUE;
	test_ssl_mode = TEST_SSL_MODE_NONE;
	test_files_init();
	test_run_client_server(protocol,
		&smtp_client_set, &smtp_server_set,
		client_init);
	test_files_deinit();

	test_out_reason("unknown payload size", (failure == NULL), failure);

	smtp_server_set.max_pipelined_commands = 5;
	smtp_server_set.capabilities |= SMTP_CAPABILITY_PIPELINING;
	test_max_pending = MAX_PARALLEL_PENDING;
	test_unknown_size = FALSE;
	test_ssl_mode = TEST_SSL_MODE_IMMEDIATE;
	test_files_init();
	test_run_client_server(protocol,
		&smtp_client_set, &smtp_server_set,
		client_init);
	test_files_deinit();

	test_out_reason("parallel pipelining ssl",
			(failure == NULL), failure);

	smtp_server_set.max_pipelined_commands = 5;
	smtp_server_set.capabilities |= SMTP_CAPABILITY_PIPELINING;
	test_max_pending = MAX_PARALLEL_PENDING;
	test_unknown_size = FALSE;
	test_ssl_mode = TEST_SSL_MODE_STARTTLS;
	test_files_init();
	test_run_client_server(protocol,
		&smtp_client_set, &smtp_server_set,
		client_init);
	test_files_deinit();

	test_out_reason("parallel pipelining startls",
			(failure == NULL), failure);
}

static void test_smtp_normal(void)
{
	test_begin("smtp payload - normal");
	test_run_scenarios(SMTP_PROTOCOL_SMTP,
		SMTP_CAPABILITY_DSN, test_client);
	test_end();
}

static void test_smtp_chunking(void)
{
	test_begin("smtp payload - chunking");
	test_run_scenarios(SMTP_PROTOCOL_SMTP,
		SMTP_CAPABILITY_DSN | SMTP_CAPABILITY_CHUNKING,
		test_client);
	test_end();
}

static void test_lmtp_normal(void)
{
	test_begin("lmtp payload - normal");
	test_run_scenarios(SMTP_PROTOCOL_LMTP,
		SMTP_CAPABILITY_DSN, test_client);
	test_end();
}

static void test_lmtp_chunking(void)
{
	test_begin("lmtp payload - chunking");
	test_run_scenarios(SMTP_PROTOCOL_LMTP,
		SMTP_CAPABILITY_DSN | SMTP_CAPABILITY_CHUNKING,
		test_client);
	test_end();
}

static void (*const test_functions[])(void) = {
	test_smtp_normal,
	test_smtp_chunking,
	test_lmtp_normal,
	test_lmtp_chunking,
	NULL
};

/*
 * Main
 */

volatile sig_atomic_t terminating = 0;

static void
test_signal_handler(int signo)
{
	if (terminating != 0)
		raise(signo);
	terminating = 1;

	/* make sure we don't leave any pesky children alive */
	test_server_kill();

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void test_atexit(void)
{
	test_server_kill();
}

int main(int argc, char *argv[])
{
	int c;
	int ret;

	lib_init();
#ifdef HAVE_OPENSSL
	ssl_iostream_openssl_init();
#endif

	atexit(test_atexit);
	(void)signal(SIGCHLD, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGTERM, test_signal_handler);
	(void)signal(SIGQUIT, test_signal_handler);
	(void)signal(SIGINT, test_signal_handler);
	(void)signal(SIGSEGV, test_signal_handler);
	(void)signal(SIGABRT, test_signal_handler);

	while ((c = getopt(argc, argv, "DS")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		case 'S':
			small_socket_buffers = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D][-S]", argv[0]);
		}
	}

	/* listen on localhost */
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);

	ret = test_run(test_functions);

	ssl_iostream_context_cache_free();
#ifdef HAVE_OPENSSL
	ssl_iostream_openssl_deinit();
#endif
	lib_deinit();

	return ret;
}
