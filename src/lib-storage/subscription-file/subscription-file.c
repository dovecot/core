/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "file-lock.h"
#include "write-full.h"
#include "mail-storage.h"
#include "subscription-file.h"

#include <unistd.h>
#include <fcntl.h>

#define SUBSCRIPTION_FILE_NAME ".subscriptions"
#define MAX_MAILBOX_LENGTH PATH_MAX

struct subsfile_list_context {
	pool_t pool;

	struct mail_storage *storage;
	struct istream *input;
	const char *path;

	int failed;
};

static int subsfile_set_syscall_error(struct mail_storage *storage,
				      const char *path, const char *function)
{
	i_assert(function != NULL);

	if (errno == EACCES) {
		mail_storage_set_error(storage, "Permission denied");
		return FALSE;
	}

	mail_storage_set_critical(storage,
				  "%s failed with subscription file %s: %m",
				  function, path);
	return FALSE;
}

static int subscription_open(struct mail_storage *storage, int update,
			     const char **path)
{
	int fd;

	*path = t_strconcat(storage->dir, "/" SUBSCRIPTION_FILE_NAME, NULL);

	fd = update ? open(*path, O_RDWR | O_CREAT, 0660) :
		open(*path, O_RDONLY);
	if (fd == -1) {
		if (update || errno != ENOENT) {
                        subsfile_set_syscall_error(storage, "open()", *path);
			return -1;
		}

		return -1;
	}

	/* FIXME: we should work without locking, rename() would be easiest
	   but .lock would work too */
	if (file_wait_lock(fd, update ? F_WRLCK : F_RDLCK) <= 0) {
		subsfile_set_syscall_error(storage, "file_wait_lock()", *path);
		(void)close(fd);
		return -1;
	}
	return fd;
}

static const char *next_line(struct mail_storage *storage, const char *path,
			     struct istream *input, int *failed)
{
	const char *line;

	while ((line = i_stream_next_line(input)) == NULL) {
		switch (i_stream_read(input)) {
		case -1:
			*failed = FALSE;
			return NULL;
		case -2:
			/* mailbox name too large */
			mail_storage_set_critical(storage,
				"Subscription file %s contains lines longer "
				"than %u characters", path,
				MAX_MAILBOX_LENGTH);
			*failed = TRUE;
			return NULL;
		}
	}

	*failed = FALSE;
	return line;
}

static int stream_cut(struct mail_storage *storage, const char *path,
		      struct istream *input, uoff_t count)
{
	struct ostream *output;
	int fd, failed;

	fd = i_stream_get_fd(input);
	i_assert(fd != -1);

	output = o_stream_create_file(fd, default_pool, 4096, FALSE);
	if (o_stream_seek(output, input->start_offset + input->v_offset) < 0) {
		failed = TRUE;
		errno = output->stream_errno;
		subsfile_set_syscall_error(storage, "o_stream_seek()", path);
	} else {
		i_stream_skip(input, count);
		failed = o_stream_send_istream(output, input) < 0;
		if (failed) {
			errno = output->stream_errno;
			subsfile_set_syscall_error(storage,
						   "o_stream_send_istream()",
						   path);
		}
	}

	if (!failed) {
		if (ftruncate(fd, output->offset) < 0) {
			subsfile_set_syscall_error(storage, "ftruncate()",
						   path);
			failed = TRUE;
		}
	}

	o_stream_unref(output);
	return !failed;
}

int subsfile_set_subscribed(struct mail_storage *storage,
			    const char *name, int set)
{
	const char *path, *line;
	struct istream *input;
	uoff_t offset;
	int fd, failed;

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	fd = subscription_open(storage, TRUE, &path);
	if (fd == -1)
		return FALSE;

	input = i_stream_create_file(fd, default_pool,
				     MAX_MAILBOX_LENGTH, FALSE);
	do {
		offset = input->v_offset;
                line = next_line(storage, path, input, &failed);
	} while (line != NULL && strcmp(line, name) != 0);

	if (!failed) {
		if (set && line == NULL) {
			/* add subscription. we're at EOF so just write it */
			write_full(fd, t_strconcat(name, "\n", NULL),
				   strlen(name)+1);
		} else if (!set && line != NULL) {
			/* remove subcription. */
			uoff_t size = input->v_offset - offset;
			i_stream_seek(input, offset);
			if (!stream_cut(storage, path, input, size))
				failed = TRUE;
		}
	}

	i_stream_unref(input);

	if (close(fd) < 0) {
		subsfile_set_syscall_error(storage, "close()", path);
		failed = TRUE;
	}
	return !failed;
}

struct subsfile_list_context *
subsfile_list_init(struct mail_storage *storage)
{
	struct subsfile_list_context *ctx;
	pool_t pool;
	const char *path;
	int fd;

	fd = subscription_open(storage, FALSE, &path);
	if (fd == -1 && errno != ENOENT)
		return NULL;

	pool = pool_alloconly_create("subsfile_list", MAX_MAILBOX_LENGTH+1024);

	ctx = p_new(pool, struct subsfile_list_context, 1);
	ctx->pool = pool;
	ctx->storage = storage;
	ctx->input = fd == -1 ? NULL :
		i_stream_create_file(fd, pool, MAX_MAILBOX_LENGTH, TRUE);
	ctx->path = p_strdup(pool, path);
	return ctx;
}

int subsfile_list_deinit(struct subsfile_list_context *ctx)
{
	int failed;

	failed = ctx->failed;
	if (ctx->input != NULL)
		i_stream_unref(ctx->input);
	pool_unref(ctx->pool);

	return !failed;
}

const char *subsfile_list_next(struct subsfile_list_context *ctx)
{
	if (ctx->failed || ctx->input == NULL)
		return NULL;

	return next_line(ctx->storage, ctx->path, ctx->input, &ctx->failed);
}
