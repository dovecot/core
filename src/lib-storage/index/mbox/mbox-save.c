/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "ostream.h"
#include "str.h"
#include "write-full.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "mbox-from.h"
#include "mbox-lock.h"
#include "mail-save.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netdb.h>

struct mbox_save_context {
	struct index_mailbox *ibox;
	uoff_t append_offset;

	struct ostream *output;
	uoff_t sync_offset, content_length_offset, eoh_offset;

	const struct mail_full_flags *flags;
};

static char my_hostdomain[256] = "";

static int write_error(struct mbox_save_context *ctx)
{
	if (ENOSPACE(errno)) {
		mail_storage_set_error(ctx->ibox->box.storage,
				       "Not enough disk space");
	} else {
                mbox_set_syscall_error(ctx->ibox, "write()");
	}

	return -1;
}

static int mbox_seek_to_end(struct mbox_save_context *ctx, uoff_t *offset)
{
	struct stat st;
	char ch;
	int fd;

	fd = ctx->ibox->mbox_fd;
	if (fstat(fd, &st) < 0)
                return mbox_set_syscall_error(ctx->ibox, "fstat()");

	*offset = (uoff_t)st.st_size;
	if (st.st_size == 0)
		return 0;

	if (lseek(fd, st.st_size-1, SEEK_SET) < 0)
                return mbox_set_syscall_error(ctx->ibox, "lseek()");

	if (read(fd, &ch, 1) != 1)
		return mbox_set_syscall_error(ctx->ibox, "read()");

	if (ch != '\n') {
		if (write_full(fd, "\n", 1) < 0)
			return write_error(ctx);
		*offset += 1;
	}

	return 0;
}

static int mbox_append_lf(struct mbox_save_context *ctx)
{
	if (o_stream_send(ctx->output, "\n", 1) < 0)
		return write_error(ctx);

	return TRUE;
}

static int write_from_line(struct mbox_save_context *ctx, time_t received_date,
			   const char *from_envelope)
{
	const char *line, *name;

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

	if (from_envelope == NULL) {
		from_envelope = t_strconcat(ctx->ibox->storage->user, "@",
					    my_hostdomain, NULL);
	}

	/* save in local timezone, no matter what it was given with */
	line = mbox_from_create(from_envelope, received_date);

	if (o_stream_send_str(ctx->output, line) < 0)
		return write_error(ctx);

	return 0;
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
		if ((flags & MAIL_DELETED) != 0)
			str_append_c(str, 'D');
		if ((flags & MAIL_FLAGGED) != 0)
			str_append_c(str, 'F');
		if ((flags & MAIL_DRAFT) != 0)
			str_append_c(str, 'T');
		str_append_c(str, '\n');
	}

	return str_c(str);
}

static const char *get_keywords(const struct mail_full_flags *flags)
{
	string_t *str;
	unsigned int i;

	if (flags->keywords_count == 0)
		return "";

	str = t_str_new(256);
	for (i = 0; i < flags->keywords_count; i++) {
		if (str_len(str) > 0)
			str_append_c(str, ' ');
		str_append(str, flags->keywords[i]);
	}
	return str_c(str);
}

static int save_header_callback(const char *name, write_func_t *write_func,
				void *context)
{
	static const char *content_length = "Content-Length: ";
	struct mbox_save_context *ctx = context;
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

		/* calculate how much space keywords and content-length
		   value needs, then write that amount of spaces. */
		space = strlen(get_keywords(ctx->flags));
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

static int mbox_fix_header(struct mbox_save_context *ctx)
{
	uoff_t old_offset;
	const char *str;
	int crlf = getenv("MAIL_SAVE_CRLF") != NULL;

	old_offset = ctx->output->offset;
	if (o_stream_seek(ctx->output, ctx->content_length_offset) < 0)
                return mbox_set_syscall_error(ctx->ibox, "o_stream_seek()");

	/* write value for Content-Length */
	str = dec2str(old_offset - (ctx->eoh_offset + 1 + crlf));
	if (o_stream_send_str(ctx->output, str) < 0)
		return write_error(ctx);

	/* [CR]LF X-Keywords: */
	str = crlf ? "\r\nX-Keywords:" : "\nX-Keywords:";
	if (o_stream_send_str(ctx->output, str) < 0)
		return write_error(ctx);

	/* write keywords into X-Keywords */
	str = get_keywords(ctx->flags);
	if (o_stream_send_str(ctx->output, str) < 0)
		return write_error(ctx);

	if (o_stream_seek(ctx->output, old_offset) < 0)
		return mbox_set_syscall_error(ctx->ibox, "o_stream_seek()");
	return 0;
}

int mbox_save(struct mailbox_transaction_context *_t,
	      const struct mail_full_flags *flags,
	      time_t received_date, int timezone_offset __attr_unused__,
	      const char *from_envelope, struct istream *data)
{
	struct mbox_transaction_context *t =
		(struct mbox_transaction_context *)_t;
	struct index_mailbox *ibox = t->ictx.ibox;
	struct mbox_save_context *ctx = t->save_ctx;
	int ret;

	if (ctx == NULL) {
		ctx = t->save_ctx = i_new(struct mbox_save_context, 1);
		ctx->ibox = ibox;
		ctx->append_offset = (uoff_t)-1;
	}
	ctx->flags = flags;

	if (ctx->append_offset == (uoff_t)-1) {
		if (ibox->mbox_lock_type != F_WRLCK) {
			if (mbox_lock(ibox, F_WRLCK, &t->mbox_lock_id) <= 0)
				return -1;
		}

		if (ibox->mbox_fd == -1) {
			if (mbox_file_open(ibox) < 0)
				return -1;
		}

		if (mbox_seek_to_end(ctx, &ctx->append_offset) < 0)
			return -1;

		ctx->output = o_stream_create_file(ibox->mbox_fd, default_pool,
						   4096, FALSE);
		o_stream_set_blocking(ctx->output, 60000, NULL, NULL);
	}

	i_assert(ibox->mbox_lock_type == F_WRLCK);

	t_push();
	if (write_from_line(ctx, received_date, from_envelope) < 0 ||
	    mail_storage_save(ibox->box.storage, ibox->path, data, ctx->output,
			      getenv("MAIL_SAVE_CRLF") != NULL,
			      save_header_callback, ctx) < 0 ||
	    mbox_fix_header(ctx) < 0 ||
	    mbox_append_lf(ctx) < 0) {
		ret = -1;
	} else {
		ret = 0;
	}
	t_pop();
	return ret;
}

static void mbox_save_deinit(struct mbox_save_context *ctx)
{
	if (ctx->output != NULL)
		o_stream_unref(ctx->output);
	i_free(ctx);
}

int mbox_save_commit(struct mbox_save_context *ctx)
{
	int ret = 0;

	if (ctx->ibox->mbox_fd != -1) {
		if (fdatasync(ctx->ibox->mbox_fd) < 0) {
			mbox_set_syscall_error(ctx->ibox, "fsync()");
			ret = -1;
		}
	}

	mbox_save_deinit(ctx);
	return ret;
}

void mbox_save_rollback(struct mbox_save_context *ctx)
{
	struct index_mailbox *ibox = ctx->ibox;

	if (ctx->append_offset != (uoff_t)-1 && ibox->mbox_fd != -1) {
		i_assert(ibox->mbox_lock_type == F_WRLCK);

		/* failed, truncate file back to original size.
		   output stream needs to be flushed before truncating
		   so unref() won't write anything. */
		o_stream_flush(ctx->output);

		if (ftruncate(ibox->mbox_fd, (off_t)ctx->append_offset) < 0)
			mbox_set_syscall_error(ibox, "ftruncate()");
	}

	mbox_save_deinit(ctx);
}
