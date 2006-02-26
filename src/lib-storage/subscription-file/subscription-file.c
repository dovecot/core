/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "nfs-workarounds.h"
#include "file-dotlock.h"
#include "mail-storage-private.h"
#include "subscription-file.h"

#include <unistd.h>
#include <fcntl.h>

#define MAX_MAILBOX_LENGTH PATH_MAX

#define SUBSCRIPTION_FILE_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT
#define SUBSCRIPTION_FILE_LOCK_TIMEOUT 120
#define SUBSCRIPTION_FILE_CHANGE_TIMEOUT 30

struct subsfile_list_context {
	pool_t pool;

	struct mail_storage *storage;
	struct istream *input;
	const char *path;

	bool failed;
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
			     struct istream *input, bool *failed_r)
{
	const char *line;

	*failed_r = FALSE;
	if (input == NULL)
		return NULL;

	while ((line = i_stream_next_line(input)) == NULL) {
                switch (i_stream_read(input)) {
		case -1:
                        if (input->stream_errno != 0 &&
                            input->stream_errno != ESTALE) {
                                subsfile_set_syscall_error(storage,
                                                           "read()", path);
                                *failed_r = TRUE;
                        }
			return NULL;
		case -2:
			/* mailbox name too large */
			mail_storage_set_critical(storage,
				"Subscription file %s contains lines longer "
				"than %u characters", path,
				MAX_MAILBOX_LENGTH);
			*failed_r = TRUE;
			return NULL;
		}
	}

	return line;
}

int subsfile_set_subscribed(struct mail_storage *storage, const char *path,
			    const char *temp_prefix, const char *name, bool set)
{
	struct dotlock_settings dotlock_set;
	struct dotlock *dotlock;
	const char *line;
	struct istream *input;
	struct ostream *output;
	int fd_in, fd_out;
	bool found, failed = FALSE;

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	memset(&dotlock_set, 0, sizeof(dotlock_set));
	dotlock_set.temp_prefix = temp_prefix;
	dotlock_set.timeout = SUBSCRIPTION_FILE_LOCK_TIMEOUT;
	dotlock_set.stale_timeout = SUBSCRIPTION_FILE_CHANGE_TIMEOUT;

	fd_out = file_dotlock_open(&dotlock_set, path, 0, &dotlock);
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

	fd_in = nfs_safe_open(path, O_RDONLY);
	if (fd_in == -1 && errno != ENOENT) {
		subsfile_set_syscall_error(storage, "open()", path);
		(void)file_dotlock_delete(&dotlock);
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
		i_stream_destroy(&input);
	o_stream_destroy(&output);

	if (failed || (set && found) || (!set && !found)) {
		if (file_dotlock_delete(&dotlock) < 0) {
			subsfile_set_syscall_error(storage,
				"file_dotlock_delete()", path);
			failed = TRUE;
		}
	} else {
		enum dotlock_replace_flags flags =
			DOTLOCK_REPLACE_FLAG_VERIFY_OWNER;
		if (file_dotlock_replace(&dotlock, flags) < 0) {
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

	fd = nfs_safe_open(path, O_RDONLY);
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
	bool failed;

	failed = ctx->failed;
	if (ctx->input != NULL)
		i_stream_destroy(&ctx->input);
	pool_unref(ctx->pool);

	return failed ? -1 : 0;
}

const char *subsfile_list_next(struct subsfile_list_context *ctx)
{
        const char *line;
        unsigned int i;
        int fd;

        if (ctx->failed || ctx->input == NULL)
		return NULL;

        for (i = 0;; i++) {
                line = next_line(ctx->storage, ctx->path, ctx->input,
                                 &ctx->failed);
                if (ctx->input->stream_errno != ESTALE ||
                    i == SUBSCRIPTION_FILE_ESTALE_RETRY_COUNT)
                        break;

                /* Reopen the subscription file and re-send everything.
                   this isn't the optimal behavior, but it's allowed by
                   IMAP and this way we don't have to read everything into
                   memory or try to play any guessing games. */
                i_stream_destroy(&ctx->input);

                fd = nfs_safe_open(ctx->path, O_RDONLY);
                if (fd == -1) {
                        /* In case of ENOENT all the subscriptions got lost.
                           Just return end of subscriptions list in that
                           case. */
                        if (errno != ENOENT) {
                                subsfile_set_syscall_error(ctx->storage,
                                                           "open()",
                                                           ctx->path);
                                ctx->failed = TRUE;
                        }
                        return NULL;
                }

                ctx->input = i_stream_create_file(fd, ctx->pool,
                                                  MAX_MAILBOX_LENGTH, TRUE);
        }
        return line;
}
