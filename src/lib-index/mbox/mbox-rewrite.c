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

	const char *status, *x_status, *x_keywords;
	unsigned int uid_validity;
	unsigned int uid_last;
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

	index->header->flags &= ~MAIL_INDEX_FLAG_DIRTY_MESSAGES;
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
	return str->str;
}

static void header_func(MessagePart *part __attr_unused__,
			const char *name, size_t name_len,
			const char *value, size_t value_len,
			void *context)
{
	MboxRewriteContext *ctx = context;
	char *end;

	if (ctx->failed)
		return;

	if (name_len == 6 && strncasecmp(name, "Status", 6) == 0)
		ctx->status = strip_chars(value, value_len, "RO");
	else if (name_len == 8 && strncasecmp(name, "X-Status", 8) == 0)
		ctx->x_status = strip_chars(value, value_len, "ADFT");
	else if (name_len == 10 && strncasecmp(name, "X-Keywords", 10) == 0)
		ctx->x_keywords = strip_custom_flags(value, value_len, ctx);
	else if (name_len == 10 && strncasecmp(name, "X-IMAPbase", 10) == 0) {
		if (ctx->seq == 1) {
			/* temporarily copy the value to make sure we
			   don't overflow it */
			t_push();
			value = t_strndup(value, value_len);
			ctx->uid_validity = strtoul(value, &end, 10);
			while (*end == ' ') end++;
			ctx->uid_last = strtoul(end, &end, 10);
			t_pop();
		}
	} else {
		/* save this header */
		(void)io_buffer_send(ctx->outbuf, name, name_len);
		(void)io_buffer_send(ctx->outbuf, ": ", 2);
		(void)io_buffer_send(ctx->outbuf, value, value_len);
		(void)io_buffer_send(ctx->outbuf, "\n", 1);

		if (ctx->outbuf->closed)
			ctx->failed = TRUE;
	}
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
	const char *str, *flags, **custom_flags;
	unsigned int field;
	int i;

	if (inbuf->offset >= end_offset) {
		/* fsck should have noticed it.. */
		index_set_error(index, "Error rewriting mbox file %s: "
				"Unexpected end of file", index->mbox_path);
		return FALSE;
	}

	t_push();

	custom_flags = mail_custom_flags_list_get(index->custom_flags);

	/* parse the header, write the fields we don't want to change */
	memset(&ctx, 0, sizeof(ctx));
	ctx.outbuf = outbuf;
	ctx.seq = seq;
	ctx.msg_flags = rec->msg_flags;
	ctx.custom_flags = custom_flags;

	io_buffer_set_read_limit(inbuf, inbuf->offset + rec->header_size);
	message_parse_header(NULL, inbuf, &hdr_size, header_func, &ctx);
	io_buffer_set_read_limit(inbuf, 0);

	i_assert(hdr_size.physical_size == rec->header_size);

	/* append the flag fields */
	if (seq == 1) {
		/* write X-IMAPbase header to first message */
		if (ctx.uid_validity == 0)
			ctx.uid_validity = index->header->uid_validity-1;

		str = t_strdup_printf("X-IMAPbase: %u %u",
				      ctx.uid_validity, ctx.uid_last);
		(void)io_buffer_send(outbuf, str, strlen(str));

		for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
			if (custom_flags[i] != NULL) {
				(void)io_buffer_send(outbuf, " ", 1);
				(void)io_buffer_send(outbuf, custom_flags[i],
						     strlen(custom_flags[i]));
			}
		}
		(void)io_buffer_send(outbuf, "\n", 1);
	}

	if ((rec->msg_flags & MAIL_CUSTOM_FLAGS_MASK) ||
	    ctx.x_keywords != NULL) {
		/* write X-Keywords header containing custom flags */
		(void)io_buffer_send(outbuf, "X-Keywords:", 11);

		field = 1 << MAIL_CUSTOM_FLAG_1_BIT;
		for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++, field <<= 1) {
			if ((rec->msg_flags & field) &&
			    custom_flags[i] != NULL) {
				(void)io_buffer_send(outbuf, " ", 1);
				(void)io_buffer_send(outbuf, custom_flags[i],
						     strlen(custom_flags[i]));
			}
		}

		if (ctx.x_keywords != NULL && ctx.x_keywords[0] != '\0') {
			/* X-Keywords that aren't custom flags */
			(void)io_buffer_send(outbuf, " ", 1);
			(void)io_buffer_send(outbuf, ctx.x_keywords,
					     strlen(ctx.x_keywords));
		}
		(void)io_buffer_send(outbuf, "\n", 1);
	}

	/* Status field */
	flags = (rec->msg_flags & MAIL_SEEN) ? "Status: RO" : "Status: O";
	flags = t_strconcat(flags, ctx.status, NULL);
	(void)io_buffer_send(outbuf, flags, strlen(flags));
	(void)io_buffer_send(outbuf, "\n", 1);

	/* X-Status field */
	if ((rec->msg_flags & (MAIL_SYSTEM_FLAGS_MASK^MAIL_SEEN)) != 0 ||
	    ctx.x_status != NULL) {
		flags = t_strconcat("X-Status: ",
				    (rec->msg_flags & MAIL_ANSWERED) ? "A" : "",
				    (rec->msg_flags & MAIL_DRAFT) ? "D" : "",
				    (rec->msg_flags & MAIL_FLAGGED) ? "F" : "",
				    (rec->msg_flags & MAIL_DELETED) ? "T" : "",
				    ctx.x_status, NULL);
		(void)io_buffer_send(outbuf, flags, strlen(flags));
		(void)io_buffer_send(outbuf, "\n", 1);
	}
	t_pop();

	mail_custom_flags_list_unref(index->custom_flags);

	/* empty line ends headers */
	(void)io_buffer_send(outbuf, "\n", 1);

	return TRUE;
}

int mbox_index_rewrite(MailIndex *index)
{
	/* Write it to temp file and then rename() to real file.
	   easier and much safer than moving data inside the file.
	   This rewriting relies quite a lot on valid header/body sizes
	   which fsck() should have ensured. */
	MailIndexRecord *rec;
	IOBuffer *inbuf, *outbuf;
	uoff_t offset;
	const char *path;
	unsigned int seq;
	int in_fd, out_fd, failed;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if ((index->header->flags & MAIL_INDEX_FLAG_DIRTY_MESSAGES) == 0) {
		/* no need to rewrite */
		return TRUE;
	}

	if (!mbox_index_fsck(index))
		return FALSE;

	in_fd = open(index->mbox_path, O_RDWR);
	if (in_fd == -1)
		return mbox_set_syscall_error(index, "open()");

	out_fd = mail_index_create_temp_file(index, &path);
	if (out_fd == -1) {
		if (close(in_fd) < 0)
			mbox_set_syscall_error(index, "close()");
		return FALSE;
	}

	if (!mbox_lock(index, index->mbox_path, in_fd, TRUE)) {
		if (close(in_fd) < 0)
			mbox_set_syscall_error(index, "close()");
		if (close(out_fd) < 0)
			index_file_set_syscall_error(index, path, "close()");
		return FALSE;
	}

	inbuf = io_buffer_create_mmap(in_fd, default_pool,
				      MAIL_MMAP_BLOCK_SIZE, 0);
	outbuf = io_buffer_create_file(out_fd, default_pool, 8192);

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

		seq++;
		rec = index->next(index, rec);
	}

	/* always end with a \n */
	(void)io_buffer_send(outbuf, "\n", 1);
	if (outbuf->closed) {
		errno = outbuf->buf_errno;
		mbox_set_syscall_error(index, "write()");
		failed = TRUE;
	}

	if (!failed) {
		if (rename(path, index->mbox_path) == 0) {
			/* all ok, we need to fsck the index next time.
			   use set_flags because set_lock() would remove it
			   if we modified it directly */
			index->set_flags |= MAIL_INDEX_FLAG_FSCK;
			reset_dirty_flags(index);
		} else {
			index_set_error(index, "rename(%s, %s) failed: %m",
					path, index->mbox_path);
			failed = TRUE;
		}
	}

	(void)mbox_unlock(index, index->mbox_path, in_fd);
	(void)unlink(path);

	if (close(in_fd) < 0)
		mbox_set_syscall_error(index, "close()");
	if (close(out_fd) < 0)
		index_file_set_syscall_error(index, path, "close()");
	io_buffer_destroy(outbuf);
	io_buffer_destroy(inbuf);
	return failed;
}
