/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "ostream.h"
#include "write-full.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mbox-storage.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netdb.h>

struct mail_save_context {
	struct index_mailbox *ibox;
	int transaction;

	struct ostream *output;
	uoff_t sync_offset;
};

static char my_hostdomain[256] = "";

static int write_error(struct mail_save_context *ctx)
{
	if (errno == ENOSPC) {
		mail_storage_set_error(ctx->ibox->box.storage,
				       "Not enough disk space");
	} else {
		mail_storage_set_critical(ctx->ibox->box.storage,
			"Error writing to mbox file %s: %m",
			ctx->ibox->index->mailbox_path);
	}

	return FALSE;
}

static int mbox_seek_to_end(struct mail_save_context *ctx, off_t *offset)
{
	struct stat st;
	char ch;
	int fd;

	fd = ctx->ibox->index->mbox_fd;
	if (fstat(fd, &st) < 0) {
		mail_storage_set_critical(ctx->ibox->box.storage,
					  "fstat() failed for mbox file %s: %m",
					  ctx->ibox->index->mailbox_path);
		return FALSE;
	}

	*offset = st.st_size;
	if (st.st_size == 0)
		return TRUE;

	if (lseek(fd, st.st_size-1, SEEK_SET) < 0) {
		mail_storage_set_critical(ctx->ibox->box.storage,
					  "lseek() failed for mbox file %s: %m",
					 ctx->ibox->index->mailbox_path);
		return FALSE;
	}

	if (read(fd, &ch, 1) != 1) {
		mail_storage_set_critical(ctx->ibox->box.storage,
					  "read() failed for mbox file %s: %m",
					  ctx->ibox->index->mailbox_path);
		return FALSE;
	}

	if (ch != '\n') {
		if (write_full(fd, "\n", 1) < 0)
			return write_error(ctx);
		*offset += 1;
	}

	return TRUE;
}

static int mbox_append_lf(struct mail_save_context *ctx)
{
	if (o_stream_send(ctx->output, "\n", 1) < 0)
		return write_error(ctx);

	return TRUE;
}

static int write_from_line(struct mail_save_context *ctx, time_t received_date)
{
	const char *sender, *line, *name;

	if (*my_hostdomain == '\0') {
		struct hostent *hent;

		hostpid_init();
		hent = gethostbyname(my_hostname);

		name = hent != NULL ? hent->h_name : NULL;
		if (name == NULL) {
			/* failed, use just the hostname */
			name = my_hostname;
		}

		strocpy(my_hostdomain, name, sizeof(my_hostdomain));
	}

	sender = t_strconcat(ctx->ibox->box.storage->user, "@",
			     my_hostdomain, NULL);

	/* save in local timezone, no matter what it was given with */
	line = mbox_from_create(sender, received_date);

	if (o_stream_send_str(ctx->output, line) < 0)
		return write_error(ctx);

	return TRUE;
}

static int write_flags(struct mail_save_context *ctx,
		       const struct mail_full_flags *full_flags)
{
	enum mail_flags flags = full_flags->flags;
	const char *str;
	unsigned int field;
	unsigned int i;

	if (flags == 0)
		return TRUE;

	if (flags & MAIL_SEEN) {
		if (o_stream_send_str(ctx->output, "Status: R\n") < 0)
			return write_error(ctx);
	}

	if (flags & (MAIL_ANSWERED|MAIL_DRAFT|MAIL_FLAGGED|MAIL_DELETED)) {
		str = t_strconcat("X-Status: ",
				  (flags & MAIL_ANSWERED) ? "A" : "",
				  (flags & MAIL_DRAFT) ? "D" : "",
				  (flags & MAIL_FLAGGED) ? "F" : "",
				  (flags & MAIL_DELETED) ? "T" : "",
				  "\n", NULL);

		if (o_stream_send_str(ctx->output, str) < 0)
			return write_error(ctx);
	}

	if (flags & MAIL_CUSTOM_FLAGS_MASK) {
		if (o_stream_send_str(ctx->output, "X-Keywords:") < 0)
			return write_error(ctx);

		field = 1 << MAIL_CUSTOM_FLAG_1_BIT;
		for (i = 0; i < full_flags->custom_flags_count; i++) {
			const char *custom_flag = full_flags->custom_flags[i];

			if ((flags & field) && custom_flag != NULL) {
				if (o_stream_send(ctx->output, " ", 1) < 0)
					return write_error(ctx);

				if (o_stream_send_str(ctx->output,
						      custom_flag) < 0)
					return write_error(ctx);
			}

                        field <<= 1;
		}

		if (o_stream_send(ctx->output, "\n", 1) < 0)
			return write_error(ctx);
	}

	return TRUE;
}

int mbox_storage_save_next(struct mail_save_context *ctx,
			   const struct mail_full_flags *flags,
			   time_t received_date,
			   int timezone_offset __attr_unused__,
			   struct istream *data)
{
	enum mail_flags real_flags;
	int failed;

	/* we don't need the real flag positions, easier to keep using our own.
	   they need to be checked/added though. */
	real_flags = flags->flags;
	if (!index_mailbox_fix_custom_flags(ctx->ibox, &real_flags,
					    flags->custom_flags,
					    flags->custom_flags_count))
		return FALSE;

	t_push();
	if (!write_from_line(ctx, received_date) ||
	    !write_flags(ctx, flags) ||
	    !index_storage_save(ctx->ibox->box.storage,
				ctx->ibox->index->mailbox_path,
				data, ctx->output) ||
	    !mbox_append_lf(ctx)) {
		/* failed, truncate file back to original size.
		   output stream needs to be flushed before truncating
		   so unref() won't write anything. */
		o_stream_flush(ctx->output);
		if (ctx->sync_offset != (uoff_t)-1) {
			(void)ftruncate(ctx->ibox->index->mbox_fd,
					ctx->sync_offset);
			ctx->sync_offset = (uoff_t)-1;
		}
		failed = TRUE;
	} else {
		if (!ctx->transaction)
			ctx->sync_offset = ctx->output->offset;
		failed = FALSE;
	}
	t_pop();

	return !failed;
}

struct mail_save_context *
mbox_storage_save_init(struct mailbox *box, int transaction)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mail_save_context *ctx;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return NULL;
	}

	if (!index_storage_sync_and_lock(ibox, FALSE, MAIL_LOCK_EXCLUSIVE))
		return NULL;

	ctx = i_new(struct mail_save_context, 1);
	ctx->ibox = ibox;
	ctx->transaction = transaction;

	if (!mbox_seek_to_end(ctx, &ctx->sync_offset)) {
		i_free(ctx);
		return NULL;
	}

	ctx->output = o_stream_create_file(ibox->index->mbox_fd,
					   default_pool, 4096, 0, FALSE);
	o_stream_set_blocking(ctx->output, 60000, NULL, NULL);
	return ctx;
}

int mbox_storage_save_deinit(struct mail_save_context *ctx, int rollback)
{
	int failed = FALSE;

	if (!index_storage_lock(ctx->ibox, MAIL_LOCK_UNLOCK))
		failed = TRUE;

	if (o_stream_flush(ctx->output) < 0)
		failed = TRUE;
	o_stream_unref(ctx->output);

	if (rollback && ctx->sync_offset != (uoff_t)-1) {
		if (ftruncate(ctx->ibox->index->mbox_fd,
			      ctx->sync_offset) < 0) {
			mail_storage_set_critical(ctx->ibox->box.storage,
				"ftruncate(%s) failed: %m",
				ctx->ibox->index->mailbox_path);
			failed = TRUE;
		}
	}

	i_free(ctx);
	return !failed;
}
