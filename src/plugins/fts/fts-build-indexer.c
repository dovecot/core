/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "write-full.h"
#include "strescape.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "fts-api-private.h"
#include "fts-build-private.h"

#define INDEXER_SOCKET_NAME "indexer"
#define INDEXER_WAIT_MSECS 250
#define INDEXER_HANDSHAKE "VERSION\tindexer\t1\t0\n"

struct indexer_fts_storage_build_context {
	struct fts_storage_build_context ctx;

	char *path;
	int fd;
	struct istream *input;
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
		(void)close(fd);
		return -1;
	}
	*path_r = path;
	return fd;
}

static int
fts_build_indexer_init(struct fts_backend *backend, struct mailbox *box,
		       struct fts_storage_build_context **build_ctx_r)
{
	struct indexer_fts_storage_build_context *ctx;
	struct mailbox_status status;
	uint32_t last_uid, seq1, seq2;
	const char *path, *cmd;
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

	cmd = t_strdup_printf("PREPEND\t1\t%s\t%s\n",
			      str_tabescape(box->storage->user->username),
			      str_tabescape(box->vname));
	fd = fts_indexer_cmd(box->storage->user, cmd, &path);
	if (fd == -1)
		return -1;

	/* connect to indexer and request immediate indexing of the mailbox */
	ctx = i_new(struct indexer_fts_storage_build_context, 1);
	ctx->ctx.mail_count = 100;
	ctx->path = i_strdup(path);
	ctx->fd = fd;
	ctx->input = i_stream_create_fd(fd, 128, FALSE);

	*build_ctx_r = &ctx->ctx;
	return 1;
}

static int
fts_build_indexer_deinit(struct fts_storage_build_context *_ctx)
{
	struct indexer_fts_storage_build_context *ctx =
		(struct indexer_fts_storage_build_context *)_ctx;

	i_stream_destroy(&ctx->input);
	if (close(ctx->fd) < 0)
		i_error("close(%s) failed: %m", ctx->path);
	i_free(ctx->path);
	return 0;
}

static int
fts_build_indexer_input(struct indexer_fts_storage_build_context *ctx)
{
	const char *line;
	int percentage;

	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		/* initial reply: <tag> \t OK
		   following: <tag> \t <percentage> */
		if (strncmp(line, "1\t", 2) != 0) {
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
				ctx->ctx.box->vname);
			return -1;
		}
		ctx->ctx.mail_idx = percentage;
		if (percentage == 100) {
			/* finished */
			return 1;
		}
	}
	if (ctx->input->eof || ctx->input->stream_errno != 0) {
		i_error("indexer disconnected unexpectedly");
		return -1;
	}
	return 0;
}

static int fts_build_indexer_more(struct fts_storage_build_context *_ctx)
{
	struct indexer_fts_storage_build_context *ctx =
		(struct indexer_fts_storage_build_context *)_ctx;
	struct ioloop *ioloop;
	struct io *io;
	struct timeout *to;
	int ret;

	if ((ret = fts_build_indexer_input(ctx)) != 0)
		return ret;

	/* wait for a while for the reply. FIXME: once search API supports
	   asynchronous waits, get rid of this wait and use the mail IO loop */
	ioloop = io_loop_create();
	io = io_add(ctx->fd, IO_READ, io_loop_stop, ioloop);
	to = timeout_add(INDEXER_WAIT_MSECS, io_loop_stop, ioloop);
	io_loop_run(ioloop);
	io_remove(&io);
	timeout_remove(&to);
	io_loop_destroy(&ioloop);

	return fts_build_indexer_input(ctx);
}

const struct fts_storage_build_vfuncs fts_storage_build_indexer_vfuncs = {
	fts_build_indexer_init,
	fts_build_indexer_deinit,
	fts_build_indexer_more
};
