/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "file-dotlock.h"
#include "mail-storage-private.h"
#include "subscription-file.h"

#include <unistd.h>
#include <fcntl.h>

#define MAX_MAILBOX_LENGTH PATH_MAX

#define SUBSCRIPTION_FILE_LOCK_TIMEOUT 120
#define SUBSCRIPTION_FILE_CHANGE_TIMEOUT 30
#define SUBSCRIPTION_FILE_IMMEDIATE_TIMEOUT (5*60)

struct subsfile_list_context {
	pool_t pool;

	struct mail_storage *storage;
	struct istream *input;
	const char *path;

	int failed;
};

static void subsfile_set_syscall_error(struct mail_storage *storage,
				       const char *function, const char *path)
{
	i_assert(function != NULL);

	if (errno == EACCES)
		mail_storage_set_error(storage, "Permission denied");
	else {
		mail_storage_set_critical(storage,
			"%s failed with subscription file %s: %m",
			function, path);
	}
}

static const char *next_line(struct mail_storage *storage, const char *path,
			     struct istream *input, int *failed)
{
	const char *line;

	*failed = FALSE;
	if (input == NULL)
		return NULL;

	while ((line = i_stream_next_line(input)) == NULL) {
		switch (i_stream_read(input)) {
		case -1:
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

	return line;
}

int subsfile_set_subscribed(struct mail_storage *storage, const char *path,
			    const char *temp_prefix, const char *name, int set)
{
	const char *line;
	struct istream *input;
	struct ostream *output;
	int fd_in, fd_out, found, failed = FALSE;

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	/* FIXME: set lock notification callback */
	fd_out = file_dotlock_open(path, temp_prefix, NULL,
				   SUBSCRIPTION_FILE_LOCK_TIMEOUT,
				   SUBSCRIPTION_FILE_CHANGE_TIMEOUT,
				   SUBSCRIPTION_FILE_IMMEDIATE_TIMEOUT,
				   NULL, NULL);
	if (fd_out == -1) {
		if (errno == EAGAIN) {
			mail_storage_set_error(storage,
				"Timeout waiting for subscription file lock");
		} else {
			subsfile_set_syscall_error(storage,
						   "file_dotlock_open()", path);
		}
		return -1;
	}

	fd_in = open(path, O_RDONLY);
	if (fd_in == -1 && errno != ENOENT) {
		subsfile_set_syscall_error(storage, "open()", path);
		file_dotlock_delete(path, NULL, fd_out);
		return -1;
	}

	input = fd_in == -1 ? NULL :
		i_stream_create_file(fd_in, default_pool,
				     MAX_MAILBOX_LENGTH, TRUE);
	output = o_stream_create_file(fd_out, default_pool,
				      MAX_MAILBOX_LENGTH, FALSE);
	found = FALSE;
	while ((line = next_line(storage, path, input, &failed)) != NULL) {
		if (strcmp(line, name) == 0) {
			found = TRUE;
			if (!set)
				continue;
		}

		if (o_stream_send_str(output, line) < 0 ||
		    o_stream_send(output, "\n", 1) < 0) {
			subsfile_set_syscall_error(storage, "write()",
						   path);
			failed = TRUE;
			break;
		}
	}

	if (!failed && set && !found) {
		/* append subscription */
		line = t_strconcat(name, "\n", NULL);
		if (o_stream_send_str(output, line) < 0) {
			subsfile_set_syscall_error(storage, "write()", path);
			failed = TRUE;
		}
	}

	if (input != NULL)
		i_stream_unref(input);
	o_stream_unref(output);

	if (failed || (set && found) || (!set && !found)) {
		if (file_dotlock_delete(path, NULL, fd_out) < 0) {
			subsfile_set_syscall_error(storage,
				"file_dotlock_delete()", path);
			failed = TRUE;
		}
	} else {
		if (file_dotlock_replace(path, NULL, fd_out, TRUE) < 0) {
			subsfile_set_syscall_error(storage,
				"file_dotlock_replace()", path);
			failed = TRUE;
		}
	}
	return failed ? -1 : 0;
}

struct subsfile_list_context *
subsfile_list_init(struct mail_storage *storage, const char *path)
{
	struct subsfile_list_context *ctx;
	pool_t pool;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1 && errno != ENOENT) {
		subsfile_set_syscall_error(storage, "open()", path);
		return NULL;
	}

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

	return failed ? -1 : 0;
}

const char *subsfile_list_next(struct subsfile_list_context *ctx)
{
	if (ctx->failed || ctx->input == NULL)
		return NULL;

	return next_line(ctx->storage, ctx->path, ctx->input, &ctx->failed);
}
