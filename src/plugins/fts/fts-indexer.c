/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "connection.h"
#include "write-full.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "time-util.h"
#include "settings-parser.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "fts-api.h"
#include "fts-storage.h"
#include "fts-indexer.h"

#define INDEXER_NOTIFY_INTERVAL_SECS 10
#define INDEXER_SOCKET_NAME "indexer"
#define INDEXER_WAIT_MSECS 250

struct fts_indexer_context {
	struct connection conn;

	struct mailbox *box;
	struct ioloop *ioloop;

	struct timeval search_start_time, last_notify;
	unsigned int percentage;
	struct connection_list *connection_list;

	bool notified:1;
	bool failed:1;
	bool completed:1;
};

static void fts_indexer_notify(struct fts_indexer_context *ctx)
{
	unsigned long long elapsed_msecs, est_total_msecs;
	unsigned int eta_secs;

	if (ioloop_time - ctx->last_notify.tv_sec < INDEXER_NOTIFY_INTERVAL_SECS)
		return;
	ctx->last_notify = ioloop_timeval;

	if (ctx->box->storage->callbacks.notify_ok == NULL ||
	    ctx->percentage == 0)
		return;

	elapsed_msecs = timeval_diff_msecs(&ioloop_timeval,
					   &ctx->search_start_time);
	est_total_msecs = elapsed_msecs * 100 / ctx->percentage;
	eta_secs = (est_total_msecs - elapsed_msecs) / 1000;

	T_BEGIN {
		const char *text;

		text = t_strdup_printf("Indexed %d%% of the mailbox, "
				       "ETA %d:%02d", ctx->percentage,
				       eta_secs/60, eta_secs%60);
		ctx->box->storage->callbacks.
			notify_ok(ctx->box, text,
				  ctx->box->storage->callback_context);
		ctx->notified = TRUE;
	} T_END;
}

static int fts_indexer_more_int(struct fts_indexer_context *ctx)
{
	struct ioloop *prev_ioloop = current_ioloop;
	struct timeout *to;

	if (ctx->failed)
		return -1;
	if (ctx->completed)
		return 1;

	/* wait for a while for the reply. FIXME: once search API supports
	   asynchronous waits, get rid of this wait and use the mail IO loop */
	io_loop_set_current(ctx->ioloop);
	to = timeout_add_short(INDEXER_WAIT_MSECS, io_loop_stop, ctx->ioloop);
	io_loop_run(ctx->ioloop);
	timeout_remove(&to);
	io_loop_set_current(prev_ioloop);

	if (ctx->failed)
		return -1;
	if (ctx->completed)
		return 1;
	return 0;
}

int fts_indexer_more(struct fts_indexer_context *ctx)
{
	int ret;

	if ((ret = fts_indexer_more_int(ctx)) < 0) {
		/* If failed is already set, the code has had a chance to
		 * set an internal error already, i.e. MAIL_ERROR_INUSE. */
		if (!ctx->failed)
			mail_storage_set_internal_error(ctx->box->storage);
		ctx->failed = TRUE;
		return -1;
	}

	if (ret == 0)
		fts_indexer_notify(ctx);

	return ret;
}

static void fts_indexer_destroy(struct connection *conn)
{
	struct fts_indexer_context *ctx =
		container_of(conn, struct fts_indexer_context, conn);
	connection_deinit(conn);
	if (!ctx->completed)
		ctx->failed = TRUE;
	ctx->completed = TRUE;
}

int fts_indexer_deinit(struct fts_indexer_context **_ctx)
{
	struct fts_indexer_context *ctx = *_ctx;
	i_assert(ctx != NULL);
	*_ctx = NULL;
	if (!ctx->completed)
		ctx->failed = TRUE;
	int ret = ctx->failed ? -1 : 0;
	if (ctx->notified) {
		/* we notified at least once */
		ctx->box->storage->callbacks.
			notify_ok(ctx->box, "Mailbox indexing finished",
				  ctx->box->storage->callback_context);
	}
	connection_list_deinit(&ctx->connection_list);
	io_loop_set_current(ctx->ioloop);
	io_loop_destroy(&ctx->ioloop);
	i_free(ctx);
	return ret;
}

static int
fts_indexer_input_args(struct connection *conn, const char *const *args)
{
	struct fts_indexer_context *ctx =
		container_of(conn, struct fts_indexer_context, conn);
	int percentage;
	if (args[1] == NULL) {
		e_error(conn->event, "indexer sent invalid reply");
		return -1;
	}
	if (strcmp(args[0], "1") != 0) {
		e_error(conn->event, "indexer sent invalid reply");
		return -1;
	}
	if (strcmp(args[1], "OK") == 0)
		return 1;
	if (str_to_int(args[1], &percentage) < 0) {
		e_error(conn->event, "indexer sent invalid progress: %s", args[1]);
		ctx->failed = TRUE;
		return -1;
	}
	if (percentage < 0) {
		e_error(ctx->box->event, "indexer failed to index mailbox");
		ctx->failed = TRUE;
		return -1;
	}
	ctx->percentage = percentage;
	if (ctx->percentage == 100)
		ctx->completed = TRUE;
	return 1;
}

static void fts_indexer_client_connected(struct connection *conn, bool success)
{
	struct fts_indexer_context *ctx =
		container_of(conn, struct fts_indexer_context, conn);
	if (!success) {
		ctx->completed = TRUE;
		ctx->failed = TRUE;
		return;
	}
	ctx->failed = ctx->completed = FALSE;
	const char *cmd = t_strdup_printf("PREPEND\t1\t%s\t%s\t0\t%s\n",
			      str_tabescape(ctx->box->storage->user->username),
			      str_tabescape(ctx->box->vname),
			      str_tabescape(ctx->box->storage->user->session_id));
	o_stream_nsend_str(conn->output, cmd);
}

static void fts_indexer_idle_timeout(struct connection *conn)
{
	struct fts_indexer_context *ctx =
		container_of(conn, struct fts_indexer_context, conn);
	mail_storage_set_error(ctx->box->storage, MAIL_ERROR_INUSE,
			       "Timeout while waiting for indexing to finish");
	ctx->failed = TRUE;
	connection_disconnect(conn);
}

static const struct connection_settings indexer_client_set =
{
	.service_name_in = "indexer-server",
	.service_name_out = "indexer-client",
	.major_version = 1,
	.minor_version = 0,
	.client_connect_timeout_msecs = 2000,
	.input_max_size = SIZE_MAX,
	.output_max_size = IO_BLOCK_SIZE,
	.client = TRUE,
};

static const struct connection_vfuncs indexer_client_vfuncs =
{
	.destroy = fts_indexer_destroy,
	.client_connected = fts_indexer_client_connected,
	.input_args = fts_indexer_input_args,
	.idle_timeout = fts_indexer_idle_timeout,
};

int fts_indexer_init(struct fts_backend *backend, struct mailbox *box,
		     struct fts_indexer_context **ctx_r)
{
	struct ioloop *prev_ioloop = current_ioloop;
	struct fts_indexer_context *ctx;
	uint32_t last_uid, seq1, seq2;
	const char *path, *value, *error;
	unsigned int timeout_secs = 0;
	int ret;

	value = mail_user_plugin_getenv(box->storage->user, "fts_index_timeout");
	if (value != NULL) {
		if (settings_get_time(value, &timeout_secs, &error) < 0) {
			e_error(box->storage->user->event,
				"Invalid fts_index_timeout setting: %s",
				error);
			return -1;
		}
	}

	ret = fts_search_get_first_missing_uid(backend, box, &last_uid);
	if (ret < 0)
		return -1;
	if (ret > 0) {
		/* everything is already indexed */
		return 0;
	}

	mailbox_get_seq_range(box, last_uid+1, (uint32_t)-1, &seq1, &seq2);
	if (seq1 == 0) {
		/* no new messages (last messages in mailbox were expunged) */
		return 0;
	}

	path = t_strconcat(box->storage->user->set->base_dir,
			   "/"INDEXER_SOCKET_NAME, NULL);

	ctx = i_new(struct fts_indexer_context, 1);
	ctx->box = box;
	ctx->search_start_time = ioloop_timeval;
	ctx->conn.event_parent = box->event;
	ctx->ioloop = io_loop_create();
	ctx->connection_list = connection_list_init(&indexer_client_set,
						    &indexer_client_vfuncs);
	ctx->conn.input_idle_timeout_secs = timeout_secs;
	connection_init_client_unix(ctx->connection_list, &ctx->conn,
				    path);
	ret = connection_client_connect(&ctx->conn);
	io_loop_set_current(prev_ioloop);
	*ctx_r = ctx;
	return ctx->failed || ret < 0 ? -1 : 1;
}

#define INDEXER_HANDSHAKE "VERSION\tindexer-client\t1\t0\n"

int fts_indexer_cmd(struct mail_user *user, const char *cmd,
	            const char **path_r)
{
	const char *path;
	int fd;

	path = t_strconcat(user->set->base_dir,
	                   "/"INDEXER_SOCKET_NAME, NULL);
	fd = net_connect_unix_with_retries(path, 1000);
	if (fd == -1) {
	        i_error("net_connect_unix(%s) failed: %m", path);
	        return -1;
	}

	cmd = t_strconcat(INDEXER_HANDSHAKE, cmd, NULL);
	if (write_full(fd, cmd, strlen(cmd)) < 0) {
	        i_error("write(%s) failed: %m", path);
	        i_close_fd(&fd);
	        return -1;
	}
	*path_r = path;
	return fd;
}
