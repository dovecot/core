/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "nfs-workarounds.h"
#include "mkdir-parents.h"
#include "file-dotlock.h"
#include "mailbox-list-private.h"
#include "subscription-file.h"

#include <unistd.h>
#include <fcntl.h>

#define SUBSCRIPTION_FILE_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT
#define SUBSCRIPTION_FILE_LOCK_TIMEOUT 120
#define SUBSCRIPTION_FILE_CHANGE_TIMEOUT 30

struct subsfile_list_context {
	struct mailbox_list *list;
	struct istream *input;
	char *path;

	bool failed;
};

static void subsread_set_syscall_error(struct mailbox_list *list,
				       const char *function, const char *path)
{
	if (errno == EACCES && !list->mail_set->mail_debug) {
		mailbox_list_set_error(list, MAIL_ERROR_PERM,
				       "No permission to read subscriptions");
	} else {
		mailbox_list_set_critical(list,
			"%s failed with subscription file %s: %m",
			function, path);
	}
}

static void subswrite_set_syscall_error(struct mailbox_list *list,
					const char *function, const char *path)
{
	if (errno == EACCES && !list->mail_set->mail_debug) {
		mailbox_list_set_error(list, MAIL_ERROR_PERM,
				       "No permission to modify subscriptions");
	} else {
		mailbox_list_set_critical(list,
			"%s failed with subscription file %s: %m",
			function, path);
	}
}

static const char *next_line(struct mailbox_list *list, const char *path,
			     struct istream *input, bool *failed_r,
			     bool ignore_estale)
{
	const char *line;

	*failed_r = FALSE;

	while ((line = i_stream_next_line(input)) == NULL) {
                switch (i_stream_read(input)) {
		case -1:
                        if (input->stream_errno != 0 &&
                            (input->stream_errno != ESTALE || !ignore_estale)) {
                                subswrite_set_syscall_error(list,
							    "read()", path);
                                *failed_r = TRUE;
                        }
			return NULL;
		case -2:
			/* mailbox name too large */
			mailbox_list_set_critical(list,
				"Subscription file %s contains lines longer "
				"than %u characters", path,
				(unsigned int)list->mailbox_name_max_length);
			*failed_r = TRUE;
			return NULL;
		}
	}

	return line;
}

int subsfile_set_subscribed(struct mailbox_list *list, const char *path,
			    const char *temp_prefix, const char *name, bool set)
{
	const struct mail_storage_settings *mail_set = list->mail_set;
	struct dotlock_settings dotlock_set;
	struct dotlock *dotlock;
	struct mailbox_permissions perm;
	const char *line, *dir, *fname;
	struct istream *input;
	struct ostream *output;
	int fd_in, fd_out;
	enum mailbox_list_path_type type;
	bool found, changed = FALSE, failed = FALSE;

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	memset(&dotlock_set, 0, sizeof(dotlock_set));
	dotlock_set.use_excl_lock = mail_set->dotlock_use_excl;
	dotlock_set.nfs_flush = mail_set->mail_nfs_storage;
	dotlock_set.temp_prefix = temp_prefix;
	dotlock_set.timeout = SUBSCRIPTION_FILE_LOCK_TIMEOUT;
	dotlock_set.stale_timeout = SUBSCRIPTION_FILE_CHANGE_TIMEOUT;

	mailbox_list_get_root_permissions(list, &perm);
	fd_out = file_dotlock_open_group(&dotlock_set, path, 0,
					 perm.file_create_mode,
					 perm.file_create_gid,
					 perm.file_create_gid_origin, &dotlock);
	if (fd_out == -1 && errno == ENOENT) {
		/* directory hasn't been created yet. */
		type = list->set.control_dir != NULL ?
			MAILBOX_LIST_PATH_TYPE_CONTROL :
			MAILBOX_LIST_PATH_TYPE_DIR;
		fname = strrchr(path, '/');
		if (fname != NULL) {
			dir = t_strdup_until(path, fname);
			if (mailbox_list_mkdir_root(list, dir, type) < 0)
				return -1;
		}
		fd_out = file_dotlock_open_group(&dotlock_set, path, 0,
						 perm.file_create_mode,
						 perm.file_create_gid,
						 perm.file_create_gid_origin,
						 &dotlock);
	}
	if (fd_out == -1) {
		if (errno == EAGAIN) {
			mailbox_list_set_error(list, MAIL_ERROR_TEMP,
				"Timeout waiting for subscription file lock");
		} else {
			subswrite_set_syscall_error(list, "file_dotlock_open()",
						    path);
		}
		return -1;
	}

	fd_in = nfs_safe_open(path, O_RDONLY);
	if (fd_in == -1 && errno != ENOENT) {
		subswrite_set_syscall_error(list, "open()", path);
		file_dotlock_delete(&dotlock);
		return -1;
	}

	found = FALSE;
	output = o_stream_create_fd_file(fd_out, 0, FALSE);
	o_stream_cork(output);
	if (fd_in != -1) {
		input = i_stream_create_fd(fd_in, list->mailbox_name_max_length+1,
					   TRUE);
		while ((line = next_line(list, path, input,
					 &failed, FALSE)) != NULL) {
			if (strcmp(line, name) == 0) {
				found = TRUE;
				if (!set) {
					changed = TRUE;
					continue;
				}
			}

			o_stream_nsend_str(output, line);
			o_stream_nsend(output, "\n", 1);
		}
		i_stream_destroy(&input);
	}

	if (!failed && set && !found) {
		/* append subscription */
		line = t_strconcat(name, "\n", NULL);
		o_stream_nsend_str(output, line);
		changed = TRUE;
	}

	if (changed && !failed) {
		if (o_stream_nfinish(output) < 0) {
			subswrite_set_syscall_error(list, "write()", path);
			failed = TRUE;
		} else if (mail_set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
			if (fsync(fd_out) < 0) {
				subswrite_set_syscall_error(list, "fsync()",
							    path);
				failed = TRUE;
			}
		}
	} else {
		o_stream_ignore_last_errors(output);
	}
	o_stream_destroy(&output);

	if (failed || !changed) {
		if (file_dotlock_delete(&dotlock) < 0) {
			subswrite_set_syscall_error(list,
				"file_dotlock_delete()", path);
			failed = TRUE;
		}
	} else {
		enum dotlock_replace_flags flags =
			DOTLOCK_REPLACE_FLAG_VERIFY_OWNER;
		if (file_dotlock_replace(&dotlock, flags) < 0) {
			subswrite_set_syscall_error(list,
				"file_dotlock_replace()", path);
			failed = TRUE;
		}
	}
	return failed ? -1 : (changed ? 1 : 0);
}

struct subsfile_list_context *
subsfile_list_init(struct mailbox_list *list, const char *path)
{
	struct subsfile_list_context *ctx;
	int fd;

	ctx = i_new(struct subsfile_list_context, 1);
	ctx->list = list;

	fd = nfs_safe_open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT) {
			subsread_set_syscall_error(list, "open()", path);
			ctx->failed = TRUE;
		}
	} else {
		ctx->input = i_stream_create_fd(fd,
					list->mailbox_name_max_length+1, TRUE);
		i_stream_set_return_partial_line(ctx->input, TRUE);
	}
	ctx->path = i_strdup(path);
	return ctx;
}

int subsfile_list_deinit(struct subsfile_list_context **_ctx)
{
	struct subsfile_list_context *ctx = *_ctx;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;

	if (ctx->input != NULL)
		i_stream_destroy(&ctx->input);
	i_free(ctx->path);
	i_free(ctx);
	return ret;
}

int subsfile_list_fstat(struct subsfile_list_context *ctx, struct stat *st_r)
{
	const struct stat *st;

	if (ctx->failed)
		return -1;

	if (i_stream_stat(ctx->input, FALSE, &st) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	*st_r = *st;
	return 0;
}

const char *subsfile_list_next(struct subsfile_list_context *ctx)
{
        const char *line;
        unsigned int i;
        int fd;

        if (ctx->failed || ctx->input == NULL)
		return NULL;

        for (i = 0;; i++) {
                line = next_line(ctx->list, ctx->path, ctx->input, &ctx->failed,
				 i < SUBSCRIPTION_FILE_ESTALE_RETRY_COUNT);
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
                                subsread_set_syscall_error(ctx->list, "open()",
							   ctx->path);
                                ctx->failed = TRUE;
                        }
                        return NULL;
                }

		ctx->input = i_stream_create_fd(fd,
					ctx->list->mailbox_name_max_length+1,
					TRUE);
		i_stream_set_return_partial_line(ctx->input, TRUE);
        }
        return line;
}
