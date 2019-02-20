/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "write-full.h"
#include "strescape.h"
#include "time-util.h"
#include "settings-parser.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "fts-api.h"
#include "fts-indexer.h"

#define INDEXER_NOTIFY_INTERVAL_SECS 10

#define INDEXER_SOCKET_NAME "indexer"
#define INDEXER_WAIT_MSECS 250
#define INDEXER_HANDSHAKE "VERSION\tindexer\t1\t0\n"

struct fts_indexer_context {
	struct mailbox *box;

	struct timeval search_start_time, last_notify;
	unsigned int percentage;
	unsigned int timeout_secs;

	char *path;
	int fd;
	struct istream *input;

	bool notified:1;
	bool failed:1;
};

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

int fts_indexer_init(struct fts_backend *backend, struct mailbox *box,
		     struct fts_indexer_context **ctx_r)
{
	struct fts_indexer_context *ctx;
	struct mailbox_status status;
	uint32_t last_uid, seq1, seq2;
	const char *path, *cmd, *value, *error;
	int fd;

	if (fts_backend_get_last_uid(backend, box, &last_uid) < 0)
		return -1;

	mailbox_get_open_status(box, STATUS_UIDNEXT, &status);
	if (status.uidnext == last_uid+1) {
		/* everything is already indexed */
		return 0;
	}

	mailbox_get_seq_range(box, last_uid+1, (uint32_t)-1, &seq1, &seq2);
	if (seq1 == 0) {
		/* no new messages (last messages in mailbox were expunged) */
		return 0;
	}

	cmd = t_strdup_printf("PREPEND\t1\t%s\t%s\t0\t%s\n",
			      str_tabescape(box->storage->user->username),
			      str_tabescape(box->vname),
			      str_tabescape(box->storage->user->session_id));
	fd = fts_indexer_cmd(box->storage->user, cmd, &path);
	if (fd == -1)
		return -1;

	/* connect to indexer and request immediate indexing of the mailbox */
	ctx = i_new(struct fts_indexer_context, 1);
	ctx->box = box;
	ctx->path = i_strdup(path);
	ctx->fd = fd;
	ctx->input = i_stream_create_fd(fd, 128);
	ctx->search_start_time = ioloop_timeval;

	value = mail_user_plugin_getenv(box->storage->user, "fts_index_timeout");
	if (value != NULL) {
		if (settings_get_time(value, &ctx->timeout_secs, &error) < 0)
			i_error("Invalid fts_index_timeout setting: %s", error);
	}


	*ctx_r = ctx;
	return 1;
}

int fts_indexer_deinit(struct fts_indexer_context **_ctx)
{
	struct fts_indexer_context *ctx = *_ctx;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;

	i_stream_destroy(&ctx->input);
	if (close(ctx->fd) < 0)
		i_error("close(%s) failed: %m", ctx->path);
	if (ctx->notified) {
		/* we notified at least once */
		ctx->box->storage->callbacks.
			notify_ok(ctx->box, "Mailbox indexing finished",
				  ctx->box->storage->callback_context);
	}
	i_free(ctx->path);
	i_free(ctx);
	return ret;
}

static int fts_indexer_input(struct fts_indexer_context *ctx)
{
	const char *line;
	int percentage;

	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		/* initial reply: <tag> \t OK
		   following: <tag> \t <percentage> */
		if (!str_begins(line, "1\t")) {
			i_error("indexer sent invalid reply: %s", line);
			return -1;
		}
		line += 2;
		if (strcmp(line, "OK") == 0)
			continue;
		if (str_to_int(line, &percentage) < 0 || percentage > 100) {
			i_error("indexer sent invalid percentage: %s", line);
			return -1;
		}
		if (percentage < 0) {
			/* indexing failed */
			i_error("indexer failed to index mailbox %s",
				ctx->box->vname);
			return -1;
		}
		ctx->percentage = percentage;
		if (percentage == 100) {
			/* finished */
			return 1;
		}
	}
	if (ctx->input->stream_errno != 0) {
		i_error("indexer read(%s) failed: %s",
			i_stream_get_name(ctx->input),
			i_stream_get_error(ctx->input));
		return -1;
	}
	if (ctx->input->eof) {
		i_error("indexer disconnected unexpectedly");
		return -1;
	}
	return 0;
}

static int fts_indexer_more_int(struct fts_indexer_context *ctx)
{
	struct ioloop *ioloop;
	struct io *io;
	struct timeout *to;
	int ret;

	if ((ret = fts_indexer_input(ctx)) != 0)
		return ret;

	/* wait for a while for the reply. FIXME: once search API supports
	   asynchronous waits, get rid of this wait and use the mail IO loop */
	ioloop = io_loop_create();
	io = io_add(ctx->fd, IO_READ, io_loop_stop, ioloop);
	to = timeout_add_short(INDEXER_WAIT_MSECS, io_loop_stop, ioloop);
	io_loop_run(ioloop);
	io_remove(&io);
	timeout_remove(&to);
	io_loop_destroy(&ioloop);

	return fts_indexer_input(ctx);
}

int fts_indexer_more(struct fts_indexer_context *ctx)
{
	int ret, diff;

	if ((ret = fts_indexer_more_int(ctx)) < 0) {
		mail_storage_set_internal_error(ctx->box->storage);
		ctx->failed = TRUE;
		return -1;
	}

	if (ctx->timeout_secs > 0) {
		diff = ioloop_time - ctx->search_start_time.tv_sec;
		if (diff > (int)ctx->timeout_secs) {
			mail_storage_set_error(ctx->box->storage,
				MAIL_ERROR_INUSE,
				"Timeout while waiting for indexing to finish");
			ctx->failed = TRUE;
			return -1;
		}
	}
	if (ret == 0)
		fts_indexer_notify(ctx);
	return ret;
}
