/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "ostream.h"
#include "str.h"
#include "write-full.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mbox-storage.h"
#include "mail-save.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netdb.h>

struct mail_save_context {
	struct index_mailbox *ibox;
	int transaction;

	struct ostream *output;
	uoff_t sync_offset, content_length_offset, eoh_offset;

	const struct mail_full_flags *flags;
};

static char my_hostdomain[256] = "";

static int syscall_error(struct mail_save_context *ctx, const char *function)
{
	mail_storage_set_critical(ctx->ibox->box.storage,
				  "%s failed for mbox file %s: %m",
				  function, ctx->ibox->index->mailbox_path);
	return FALSE;
}

static int write_error(struct mail_save_context *ctx)
{
	if (ENOSPACE(errno)) {
		mail_storage_set_error(ctx->ibox->box.storage,
				       "Not enough disk space");
	} else {
                syscall_error(ctx, "write()");
	}

	return FALSE;
}

static int mbox_seek_to_end(struct mail_save_context *ctx, uoff_t *offset)
{
	struct stat st;
	char ch;
	int fd;

	fd = ctx->ibox->index->mbox_fd;
	if (fstat(fd, &st) < 0)
                return syscall_error(ctx, "fstat()");

	*offset = (uoff_t)st.st_size;
	if (st.st_size == 0)
		return TRUE;

	if (lseek(fd, st.st_size-1, SEEK_SET) < 0)
                return syscall_error(ctx, "lseek()");

	if (read(fd, &ch, 1) != 1)
		return syscall_error(ctx, "read()");

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

static const char *get_system_flags(enum mail_flags flags)
{
	string_t *str;

	if (flags == 0)
		return "";

	str = t_str_new(32);
	if (flags & MAIL_SEEN)
		str_append(str, "Status: R\n");

	if (flags & (MAIL_ANSWERED|MAIL_DRAFT|MAIL_FLAGGED|MAIL_DELETED)) {
		str_append(str, "X-Status: ");

		if ((flags & MAIL_ANSWERED) != 0)
			str_append_c(str, 'A');
		if ((flags & MAIL_DRAFT) != 0)
			str_append_c(str, 'D');
		if ((flags & MAIL_FLAGGED) != 0)
			str_append_c(str, 'F');
		if ((flags & MAIL_DELETED) != 0)
			str_append_c(str, 'T');
		str_append_c(str, '\n');
	}

	return str_c(str);
}

static const char *get_custom_flags(const struct mail_full_flags *flags)
{
	string_t *str;
	unsigned int field;
	unsigned int i;

	if ((flags->flags & MAIL_CUSTOM_FLAGS_MASK) == 0)
		return "";

	str = t_str_new(256);
	field = 1 << MAIL_CUSTOM_FLAG_1_BIT;
	for (i = 0; i < flags->custom_flags_count; i++) {
		const char *custom_flag = flags->custom_flags[i];

		if ((flags->flags & field) && custom_flag != NULL) {
			str_append_c(str, ' ');
			str_append(str, custom_flag);
		}

		field <<= 1;
	}

	return str_c(str);
}

static int save_header_callback(const char *name, write_func_t *write_func,
				void *context)
{
	static const char *content_length = "Content-Length: ";
	struct mail_save_context *ctx = context;
	const char *str;
	char *buf;
	size_t space;

	if (name == NULL) {
		/* write system flags */
		str = get_system_flags(ctx->flags->flags);
		if (write_func(ctx->output, str, strlen(str)) < 0)
			return -1;

		/* write beginning of content-length header */
		if (write_func(ctx->output, content_length,
			       strlen(content_length)) < 0) {
			write_error(ctx);
			return -1;
		}
		ctx->content_length_offset = ctx->output->offset;

		/* calculate how much space custom flags and content-length
		   value needs, then write that amount of spaces. */
		space = strlen(get_custom_flags(ctx->flags));
		space += sizeof("X-Keywords: ");
		space += MBOX_HEADER_EXTRA_SPACE + MAX_INT_STRLEN + 1;

		/* @UNSAFE */
		buf = t_malloc(space);
		memset(buf, ' ', space-1);
		buf[space-1] = '\n';

		if (write_func(ctx->output, buf, space) < 0) {
			write_error(ctx);
			return -1;
		}
		ctx->eoh_offset = ctx->output->offset;
		return 1;
	}

	switch (*name) {
	case 'C':
	case 'c':
		if (strcasecmp(name, "Content-Length") == 0)
			return 0;
		break;
	case 'S':
	case 's':
		if (strcasecmp(name, "Status") == 0)
			return 0;
		break;
	case 'X':
	case 'x':
		if (strcasecmp(name, "X-UID") == 0)
			return 0;
		if (strcasecmp(name, "X-Status") == 0)
			return 0;
		if (strcasecmp(name, "X-Keywords") == 0)
			return 0;
		if (strcasecmp(name, "X-IMAPbase") == 0)
			return 0;
		break;
	}

	return 1;
}

static int mbox_fix_header(struct mail_save_context *ctx)
{
	uoff_t old_offset;
	const char *str;
	int crlf = getenv("MAIL_SAVE_CRLF") != NULL;

	old_offset = ctx->output->offset;
	if (o_stream_seek(ctx->output, ctx->content_length_offset) < 0)
                return syscall_error(ctx, "o_stream_seek()");

	/* write value for Content-Length */
	str = dec2str(old_offset - (ctx->eoh_offset + 1 + crlf));
	if (o_stream_send_str(ctx->output, str) < 0)
		return write_error(ctx);

	/* [CR]LF X-Keywords: */
	str = crlf ? "\r\nX-Keywords:" : "\nX-Keywords:";
	if (o_stream_send_str(ctx->output, str) < 0)
		return write_error(ctx);

	/* write custom flags into X-Keywords */
	str = get_custom_flags(ctx->flags);
	if (o_stream_send_str(ctx->output, str) < 0)
		return write_error(ctx);

	if (o_stream_seek(ctx->output, old_offset) < 0)
		return syscall_error(ctx, "o_stream_seek()");
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
	ctx->flags = flags;
	real_flags = flags->flags;
	if (!index_mailbox_fix_custom_flags(ctx->ibox, &real_flags,
					    flags->custom_flags,
					    flags->custom_flags_count))
		return FALSE;

	t_push();
	if (!write_from_line(ctx, received_date) ||
	    !mail_storage_save(ctx->ibox->box.storage,
			       ctx->ibox->index->mailbox_path,
			       data, ctx->output,
			       getenv("MAIL_SAVE_CRLF") != NULL,
			       save_header_callback, ctx) ||
	    !mbox_fix_header(ctx) ||
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
					   default_pool, 4096, FALSE);
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
			syscall_error(ctx, "ftruncate()");
			failed = TRUE;
		}
	} else {
		if (fdatasync(ctx->ibox->index->mbox_fd) < 0) {
			syscall_error(ctx, "fsync()");
			failed = TRUE;
		}
	}

	i_free(ctx);
	return !failed;
}
