/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "temp-string.h"
#include "write-full.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"
#include "mail-custom-flags.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

typedef struct {
	IOBuffer *outbuf;
	int failed;

	unsigned int seq;
	unsigned int msg_flags;
        const char **custom_flags;

	unsigned int uid_validity;
	unsigned int uid_last;

	unsigned int ximapbase_found:1;
	unsigned int xkeywords_found:1;
	unsigned int status_found:1;
	unsigned int xstatus_found:1;
} MboxRewriteContext;

/* Remove dirty flag from all messages */
static void reset_dirty_flags(MailIndex *index)
{
	MailIndexRecord *rec;

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		rec->index_flags &= ~INDEX_MAIL_FLAG_DIRTY;
		rec = index->next(index, rec);
	}

	index->header->flags &= ~(MAIL_INDEX_FLAG_DIRTY_MESSAGES |
				  MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS);
}

static int mbox_write(MailIndex *index, IOBuffer *inbuf, IOBuffer *outbuf,
		      uoff_t end_offset)
{
	i_assert(inbuf->offset <= end_offset);

	if (io_buffer_send_iobuffer(outbuf, inbuf,
				    end_offset - inbuf->offset) < 0)
		return FALSE;

	if (inbuf->offset < end_offset) {
		/* fsck should have noticed it.. */
		index_set_error(index, "Error rewriting mbox file %s: "
				"Unexpected end of file", index->mbox_path);
		return FALSE;
	}

	return TRUE;
}

static int mbox_write_ximapbase(MboxRewriteContext *ctx)
{
	const char *str;
	int i;

	str = t_strdup_printf("X-IMAPbase: %u %u",
			      ctx->uid_validity, ctx->uid_last);
	if (io_buffer_send(ctx->outbuf, str, strlen(str)) < 0)
		return FALSE;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (ctx->custom_flags[i] != NULL) {
			if (io_buffer_send(ctx->outbuf, " ", 1) < 0)
				return FALSE;

			if (io_buffer_send(ctx->outbuf, ctx->custom_flags[i],
					   strlen(ctx->custom_flags[i])) < 0)
				return FALSE;
		}
	}

	if (io_buffer_send(ctx->outbuf, "\n", 1) < 0)
		return FALSE;

	return TRUE;
}

static int mbox_write_xkeywords(MboxRewriteContext *ctx, const char *x_keywords)
{
	unsigned int field;
	int i;

	if ((ctx->msg_flags & MAIL_CUSTOM_FLAGS_MASK) == 0 &&
	    x_keywords == NULL)
		return TRUE;

	if (io_buffer_send(ctx->outbuf, "X-Keywords:", 11) < 0)
		return FALSE;

	field = 1 << MAIL_CUSTOM_FLAG_1_BIT;
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++, field <<= 1) {
		if ((ctx->msg_flags & field) && ctx->custom_flags[i] != NULL) {
			if (io_buffer_send(ctx->outbuf, " ", 1) < 0)
				return FALSE;

			if (io_buffer_send(ctx->outbuf, ctx->custom_flags[i],
					   strlen(ctx->custom_flags[i])) < 0)
				return FALSE;
		}
	}

	if (x_keywords != NULL) {
		/* X-Keywords that aren't custom flags */
		if (io_buffer_send(ctx->outbuf, " ", 1) < 0)
			return FALSE;

		if (io_buffer_send(ctx->outbuf, x_keywords,
				   strlen(x_keywords)) < 0)
			return FALSE;
	}

	if (io_buffer_send(ctx->outbuf, "\n", 1) < 0)
		return FALSE;

	return TRUE;
}

static int mbox_write_status(MboxRewriteContext *ctx, const char *status)
{
	const char *str;

	str = (ctx->msg_flags & MAIL_SEEN) ? "Status: RO" : "Status: O";
	if (status != NULL)
		str = t_strconcat(str, status, NULL);

	if (io_buffer_send(ctx->outbuf, str, strlen(str)) < 0)
		return FALSE;
	if (io_buffer_send(ctx->outbuf, "\n", 1) < 0)
		return FALSE;

	return TRUE;
}

static int mbox_write_xstatus(MboxRewriteContext *ctx, const char *x_status)
{
	const char *str;

	/* X-Status field */
	if ((ctx->msg_flags & (MAIL_SYSTEM_FLAGS_MASK^MAIL_SEEN)) == 0 &&
	    x_status == NULL)
		return TRUE;

	str = t_strconcat("X-Status: ",
			  (ctx->msg_flags & MAIL_ANSWERED) ? "A" : "",
			  (ctx->msg_flags & MAIL_DRAFT) ? "D" : "",
			  (ctx->msg_flags & MAIL_FLAGGED) ? "F" : "",
			  (ctx->msg_flags & MAIL_DELETED) ? "T" : "",
			  x_status, NULL);

	if (io_buffer_send(ctx->outbuf, str, strlen(str)) < 0)
		return FALSE;
	if (io_buffer_send(ctx->outbuf, "\n", 1) < 0)
		return FALSE;

	return TRUE;
}

static const char *strip_chars(const char *value, size_t value_len,
			       const char *list)
{
	/* leave only unknown flags, very likely none */
	char *ret, *p;
	unsigned int i;

	ret = p = t_buffer_get(value_len+1);
	for (i = 0; i < value_len; i++) {
		if (strchr(list, value[i]) == NULL)
			*p++ = value[i];
	}

	if (ret == p)
		return NULL;
	*p = '\0';
        t_buffer_alloc((size_t) (p-ret)+1);
	return ret;
}

static void update_stripped_custom_flags(const char *value, size_t len,
					 int index, void *context)
{
	TempString *str = context;

	if (index < 0) {
		/* not found, keep it */
		if (str->len != 0)
			t_string_append_c(str, ' ');
		t_string_append_n(str, value, len);
	}
}

static const char *strip_custom_flags(const char *value, size_t len,
				      MboxRewriteContext *ctx)
{
	TempString *str;

	str = t_string_new(len+1);
	mbox_keywords_parse(value, len, ctx->custom_flags,
			    update_stripped_custom_flags, str);
	return str->len == 0 ? NULL : str->str;
}

static void header_func(MessagePart *part __attr_unused__,
			const char *name, size_t name_len,
			const char *value, size_t value_len,
			void *context)
{
	MboxRewriteContext *ctx = context;
	const char *str;
	char *end;

	if (ctx->failed)
		return;

	if (name_len == 6 && strncasecmp(name, "Status", 6) == 0) {
		ctx->status_found = TRUE;
		str = strip_chars(value, value_len, "RO");
		(void)mbox_write_status(ctx, str);
	} else if (name_len == 8 && strncasecmp(name, "X-Status", 8) == 0) {
		ctx->xstatus_found = TRUE;
		str = strip_chars(value, value_len, "ADFT");
		(void)mbox_write_xstatus(ctx, str);
	} else if (name_len == 10 && strncasecmp(name, "X-Keywords", 10) == 0) {
		ctx->ximapbase_found = TRUE;
		str = strip_custom_flags(value, value_len, ctx);
		(void)mbox_write_xkeywords(ctx, str);
	} else if (name_len == 10 && strncasecmp(name, "X-IMAPbase", 10) == 0) {
		if (ctx->seq == 1) {
			/* temporarily copy the value to make sure we
			   don't overflow it */
			t_push();
			value = t_strndup(value, value_len);
			ctx->uid_validity = strtoul(value, &end, 10);
			while (*end == ' ') end++;
			ctx->uid_last = strtoul(end, &end, 10);
			t_pop();

			ctx->ximapbase_found = TRUE;
			(void)mbox_write_ximapbase(ctx);
		}
	} else {
		/* save this header */
		(void)io_buffer_send(ctx->outbuf, name, name_len);
		(void)io_buffer_send(ctx->outbuf, ": ", 2);
		(void)io_buffer_send(ctx->outbuf, value, value_len);
		(void)io_buffer_send(ctx->outbuf, "\n", 1);
	}

	if (ctx->outbuf->closed)
		ctx->failed = TRUE;
}

static int mbox_write_header(MailIndex *index,
			     MailIndexRecord *rec, unsigned int seq,
			     IOBuffer *inbuf, IOBuffer *outbuf,
			     uoff_t end_offset)
{
	/* We need to update fields that define message flags. Standard fields
	   are stored in Status and X-Status. For custom flags we use
	   uw-imapd compatible format, by first listing them in first message's
	   X-IMAPbase field and actually defining them in X-Keywords field.

	   Format of X-IMAPbase is: <UID validity> <last used UID> <flag names>

	   We don't want to sync our UIDs with the mbox file, so the UID
	   validity is always kept different from our internal UID validity.
	   Last used UID is also not updated, and set to 0 initially.
	*/
	MboxRewriteContext ctx;
	MessageSize hdr_size;

	if (inbuf->offset >= end_offset) {
		/* fsck should have noticed it.. */
		index_set_error(index, "Error rewriting mbox file %s: "
				"Unexpected end of file", index->mbox_path);
		return FALSE;
	}

	t_push();

	/* parse the header, write the fields we don't want to change */
	memset(&ctx, 0, sizeof(ctx));
	ctx.outbuf = outbuf;
	ctx.seq = seq;
	ctx.msg_flags = rec->msg_flags;
	ctx.uid_validity = index->header->uid_validity-1;
	ctx.custom_flags = mail_custom_flags_list_get(index->custom_flags);

	io_buffer_set_read_limit(inbuf, inbuf->offset + rec->header_size);
	message_parse_header(NULL, inbuf, &hdr_size, header_func, &ctx);
	io_buffer_set_read_limit(inbuf, 0);

	i_assert(hdr_size.physical_size == rec->header_size);

	/* append the flag fields */
	if (seq == 1 && !ctx.ximapbase_found) {
		/* write X-IMAPbase header to first message */
		(void)mbox_write_ximapbase(&ctx);
	}

	if (!ctx.xkeywords_found)
		(void)mbox_write_xkeywords(&ctx, NULL);
	if (!ctx.status_found)
		(void)mbox_write_status(&ctx, NULL);
	if (!ctx.xstatus_found)
		(void)mbox_write_xstatus(&ctx, NULL);

	t_pop();

	mail_custom_flags_list_unref(index->custom_flags);

	/* empty line ends headers */
	(void)io_buffer_send(outbuf, "\n", 1);

	return TRUE;
}

static int fd_copy(int in_fd, int out_fd, uoff_t out_offset)
{
	IOBuffer *inbuf, *outbuf;
	int ret;

	i_assert(out_offset <= OFF_T_MAX);

	if (lseek(in_fd, 0, SEEK_SET) < 0)
		return -1;
	if (lseek(out_fd, (off_t)out_offset, SEEK_SET) < 0)
		return -1;

	inbuf = io_buffer_create_mmap(in_fd, default_pool, 65536, 0);
	outbuf = io_buffer_create_file(out_fd, default_pool, 1024);

	ret = io_buffer_send_iobuffer(outbuf, inbuf, inbuf->size);
	if (ret < 0)
		errno = outbuf->buf_errno;
	else {
		/* we may have shrinked the file */
		i_assert(out_offset + inbuf->size <= OFF_T_MAX);
		ret = ftruncate(out_fd, (off_t) (out_offset + inbuf->size));
	}

	io_buffer_destroy(outbuf);
	io_buffer_destroy(inbuf);

	return ret;
}

int mbox_index_rewrite(MailIndex *index)
{
	/* Write messages beginning from the first dirty one to temp file,
	   then copy it over the mbox file. This may create data loss if
	   interrupted (see below). This rewriting relies quite a lot on
	   valid header/body sizes which fsck() should have ensured. */
	MailIndexRecord *rec;
	IOBuffer *inbuf, *outbuf;
	uoff_t offset, dirty_offset;
	const char *path;
	unsigned int seq;
	int mbox_fd, tmp_fd, failed, dirty_found, locked, rewrite;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if ((index->header->flags & MAIL_INDEX_FLAG_DIRTY_MESSAGES) == 0) {
		/* no need to rewrite */
		return TRUE;
	}

	mbox_fd = tmp_fd = -1; locked = FALSE;
	failed = TRUE; rewrite = FALSE;
	do {
		/* lock before fscking to prevent race conditions between
		   fsck's unlock and our lock. */
		mbox_fd = open(index->mbox_path, O_RDWR);
		if (mbox_fd == -1) {
			mbox_set_syscall_error(index, "open()");
			break;
		}

		if (!mbox_lock(index, index->mbox_path, mbox_fd, TRUE))
			break;
		locked = TRUE;

		if (!mbox_index_fsck(index))
			break;

		if ((index->header->flags &
		     MAIL_INDEX_FLAG_DIRTY_MESSAGES) == 0) {
			/* fsck() figured out there's no dirty messages
			   after all */
			failed = FALSE; rewrite = FALSE;
			break;
		}

		tmp_fd = mail_index_create_temp_file(index, &path);
		if (tmp_fd == -1)
			break;

		failed = FALSE; rewrite = TRUE;
	} while (0);

	if (!rewrite) {
		if (locked)
			(void)mbox_unlock(index, index->mbox_path, mbox_fd);
		if (mbox_fd != -1 && close(mbox_fd) < 0)
			mbox_set_syscall_error(index, "close()");
		return !failed;
	}

	if (index->header->flags & MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS) {
		/* need to update X-IMAPbase in first message */
		dirty_found = TRUE;
	} else {
		dirty_found = FALSE;
	}
	dirty_offset = 0;

	inbuf = io_buffer_create_mmap(mbox_fd, default_pool,
				      MAIL_MMAP_BLOCK_SIZE, 0);
	outbuf = io_buffer_create_file(tmp_fd, default_pool, 8192);

	failed = FALSE; seq = 1;
	rec = index->lookup(index, 1);
	while (rec != NULL) {
		/* get offset to beginning of mail headers */
		if (!mbox_mail_get_start_offset(index, rec, &offset)) {
			/* fsck should have fixed it */
			failed = TRUE;
			break;
		}

		if (offset + rec->header_size + rec->body_size > inbuf->size) {
			index_set_corrupted(index, "Invalid message size");
			failed = TRUE;
			break;
		}

		if (!dirty_found &&
		    (rec->index_flags & INDEX_MAIL_FLAG_DIRTY)) {
			/* first dirty message */
			dirty_found = TRUE;
			dirty_offset = offset;

			io_buffer_seek(inbuf, dirty_offset);
		}

		if (dirty_found) {
			/* write the From-line */
			if (!mbox_write(index, inbuf, outbuf, offset)) {
				failed = TRUE;
				break;
			}

			/* write header, updating flag fields */
			offset += rec->header_size;
			if (!mbox_write_header(index, rec, seq, inbuf, outbuf,
					       offset)) {
				failed = TRUE;
				break;
			}

			/* write body */
			offset += rec->body_size;
			if (!mbox_write(index, inbuf, outbuf, offset)) {
				failed = TRUE;
				break;
			}
		}

		seq++;
		rec = index->next(index, rec);
	}

	if (!dirty_found) {
		index_set_error(index, "Expected dirty messages not found "
				"from mbox file %s", index->mbox_path);
		failed = TRUE;
	}

	/* always end with a \n */
	(void)io_buffer_send(outbuf, "\n", 1);
	if (outbuf->closed) {
		errno = outbuf->buf_errno;
		mbox_set_syscall_error(index, "write()");
		failed = TRUE;
	}

	io_buffer_destroy(outbuf);
	io_buffer_destroy(inbuf);

	if (!failed) {
		/* POSSIBLE DATA LOSS HERE. We're writing to the mbox file,
		   so if we get killed here before finished, we'll lose some
		   bytes. I can't really think of any way to fix this,
		   rename() is problematic too especially because of file
		   locking issues (new mail could be lost).

		   Usually we're moving the data by just a few bytes, so
		   the data loss should never be more than those few bytes..
		   If we moved more, we could have written the file from end
		   to beginning in blocks (it'd be a bit slow to do it in
		   blocks of ~1-10 bytes which is the usual case, so we don't
		   bother).

		   Also, we might as well be shrinking the file, in which
		   case we can't lose data. */
		if (fd_copy(tmp_fd, mbox_fd, dirty_offset) == 0) {
			/* all ok, we need to fsck the index next time.
			   use set_flags because set_lock() would remove it
			   if we modified it directly */
			index->set_flags |= MAIL_INDEX_FLAG_FSCK;
			reset_dirty_flags(index);
		} else {
			mbox_set_syscall_error(index, "fd_copy()");
			failed = TRUE;
		}
	}

	(void)mbox_unlock(index, index->mbox_path, mbox_fd);
	(void)unlink(path);

	if (close(mbox_fd) < 0)
		mbox_set_syscall_error(index, "close()");
	if (close(tmp_fd) < 0)
		index_file_set_syscall_error(index, path, "close()");
	return failed;
}
