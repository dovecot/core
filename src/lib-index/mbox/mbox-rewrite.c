/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
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
	OStream *output;
	int failed;

	uoff_t content_length;
	unsigned int seq;
	unsigned int msg_flags;
        const char **custom_flags;

	unsigned int uid_validity;
	unsigned int uid_last;

	unsigned int ximapbase_found:1;
	unsigned int xkeywords_found:1;
	unsigned int status_found:1;
	unsigned int xstatus_found:1;
	unsigned int content_length_found:1;
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

static int mbox_write(MailIndex *index, IStream *input, OStream *output,
		      uoff_t end_offset)
{
	uoff_t old_limit;
	int failed;

	i_assert(input->v_offset <= end_offset);

	old_limit = input->v_limit;
	i_stream_set_read_limit(input, end_offset);
	if (o_stream_send_istream(output, input) < 0) {
		index_set_error(index, "Error rewriting mbox file %s: %s",
				index->mailbox_path,
				strerror(output->stream_errno));
		failed = TRUE;
	} else if (input->v_offset < end_offset) {
		/* fsck should have noticed it.. */
		index_set_error(index, "Error rewriting mbox file %s: "
				"Unexpected end of file", index->mailbox_path);
		failed = TRUE;
	} else {
		failed = FALSE;
	}

	i_stream_set_read_limit(input, old_limit);
	return !failed;
}

static int mbox_write_ximapbase(MboxRewriteContext *ctx)
{
	const char *str;
	int i;

	str = t_strdup_printf("X-IMAPbase: %u %u",
			      ctx->uid_validity, ctx->uid_last);
	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (ctx->custom_flags[i] != NULL) {
			if (o_stream_send(ctx->output, " ", 1) < 0)
				return FALSE;

			if (o_stream_send_str(ctx->output,
					      ctx->custom_flags[i]) < 0)
				return FALSE;
		}
	}

	if (o_stream_send(ctx->output, "\n", 1) < 0)
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

	if (o_stream_send_str(ctx->output, "X-Keywords:") < 0)
		return FALSE;

	field = 1 << MAIL_CUSTOM_FLAG_1_BIT;
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++, field <<= 1) {
		if ((ctx->msg_flags & field) && ctx->custom_flags[i] != NULL) {
			if (o_stream_send(ctx->output, " ", 1) < 0)
				return FALSE;

			if (o_stream_send_str(ctx->output,
					      ctx->custom_flags[i]) < 0)
				return FALSE;
		}
	}

	if (x_keywords != NULL) {
		/* X-Keywords that aren't custom flags */
		if (o_stream_send(ctx->output, " ", 1) < 0)
			return FALSE;

		if (o_stream_send_str(ctx->output, x_keywords) < 0)
			return FALSE;
	}

	if (o_stream_send(ctx->output, "\n", 1) < 0)
		return FALSE;

	return TRUE;
}

static int mbox_write_status(MboxRewriteContext *ctx, const char *status)
{
	const char *str;

	str = (ctx->msg_flags & MAIL_SEEN) ? "Status: RO" : "Status: O";
	if (status != NULL)
		str = t_strconcat(str, status, NULL);

	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;
	if (o_stream_send(ctx->output, "\n", 1) < 0)
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

	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;
	if (o_stream_send(ctx->output, "\n", 1) < 0)
		return FALSE;

	return TRUE;
}

static int mbox_write_content_length(MboxRewriteContext *ctx)
{
	char str[MAX_INT_STRLEN+30];

	i_snprintf(str, sizeof(str), "Content-Length: %"PRIuUOFF_T"\n",
		   ctx->content_length);

	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;
	return TRUE;
}

static const char *strip_chars(const char *value, size_t value_len,
			       const char *list)
{
	/* @UNSAFE: leave only unknown flags, very likely none */
	char *ret, *p;
	size_t i;

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
	} else if (name_len == 14 &&
		   strncasecmp(name, "Content-Length", 14) == 0) {
		ctx->content_length_found = TRUE;
		(void)mbox_write_content_length(ctx);
	} else if (name_len > 0) {
		/* save this header */
		(void)o_stream_send(ctx->output, name, name_len);
		(void)o_stream_send(ctx->output, ": ", 2);
		(void)o_stream_send(ctx->output, value, value_len);
		(void)o_stream_send(ctx->output, "\n", 1);
	}

	if (ctx->output->closed)
		ctx->failed = TRUE;
}

static int mbox_write_header(MailIndex *index,
			     MailIndexRecord *rec, unsigned int seq,
			     IStream *input, OStream *output, uoff_t end_offset,
			     uoff_t hdr_size, uoff_t body_size)
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
	MessageSize hdr_parsed_size;

	if (input->v_offset >= end_offset) {
		/* fsck should have noticed it.. */
		index_set_error(index, "Error rewriting mbox file %s: "
				"Unexpected end of file", index->mailbox_path);
		return FALSE;
	}

	t_push();

	/* parse the header, write the fields we don't want to change */
	memset(&ctx, 0, sizeof(ctx));
	ctx.output = output;
	ctx.seq = seq;
	ctx.content_length = body_size;
	ctx.msg_flags = rec->msg_flags;
	ctx.uid_validity = index->header->uid_validity-1;
	ctx.custom_flags = mail_custom_flags_list_get(index->custom_flags);

	i_stream_set_read_limit(input, input->v_offset + hdr_size);
	message_parse_header(NULL, input, &hdr_parsed_size, header_func, &ctx);
	i_stream_set_read_limit(input, 0);

	i_assert(hdr_parsed_size.physical_size == hdr_size);

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
	if (!ctx.content_length_found)
		(void)mbox_write_content_length(&ctx);

	t_pop();

	/* empty line ends headers */
	(void)o_stream_send(output, "\n", 1);

	return TRUE;
}

static int fd_copy(int in_fd, int out_fd, uoff_t out_offset)
{
	IStream *input;
	OStream *output;
	int ret;

	i_assert(out_offset <= OFF_T_MAX);

	if (lseek(out_fd, (off_t)out_offset, SEEK_SET) < 0)
		return -1;

	t_push();

	input = i_stream_create_mmap(in_fd, data_stack_pool,
				     1024*256, 0, 0, FALSE);
	output = o_stream_create_file(out_fd, data_stack_pool, 1024, 0, FALSE);
	o_stream_set_blocking(output, 60000, NULL, NULL);

	ret = o_stream_send_istream(output, input);
	if (ret < 0)
		errno = output->stream_errno;
	else {
		/* we may have shrinked the file */
		i_assert(out_offset + input->v_size <= OFF_T_MAX);
		ret = ftruncate(out_fd, (off_t) (out_offset + input->v_size));
	}

	o_stream_unref(output);
	i_stream_unref(input);
	t_pop();

	return ret;
}

#define INDEX_DIRTY_FLAGS \
        (MAIL_INDEX_FLAG_DIRTY_MESSAGES | MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS)

int mbox_index_rewrite(MailIndex *index)
{
	/* Write messages beginning from the first dirty one to temp file,
	   then copy it over the mbox file. This may create data loss if
	   interrupted (see below). This rewriting relies quite a lot on
	   valid header/body sizes which fsck() should have ensured. */
	MailIndexRecord *rec;
	IStream *input;
	OStream *output;
	uoff_t offset, hdr_size, body_size, dirty_offset;
	const char *path;
	unsigned int seq;
	int tmp_fd, failed, dirty_found, rewrite;

	i_assert(index->lock_type == MAIL_LOCK_UNLOCK);

	if (!index->set_lock(index, MAIL_LOCK_SHARED))
		return FALSE;

	rewrite = (index->header->flags & INDEX_DIRTY_FLAGS) &&
		index->header->messages_count > 0;

	if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
		return FALSE;

	if (!rewrite) {
		/* no need to rewrite */
		return TRUE;
	}

	tmp_fd = -1; input = NULL;
	failed = TRUE; rewrite = FALSE;
	do {
		if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
			break;

		if (!index->sync_and_lock(index, MAIL_LOCK_EXCLUSIVE, NULL))
			break;

		input = mbox_get_stream(index, 0, MAIL_LOCK_EXCLUSIVE);
		if (input == NULL)
			break;

		if ((index->header->flags & INDEX_DIRTY_FLAGS) == 0) {
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
		if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
			failed = TRUE;
		if (input != NULL)
			i_stream_unref(input);
		return !failed;
	}

	if (index->header->flags & MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS) {
		/* need to update X-IMAPbase in first message */
		dirty_found = TRUE;
	} else {
		dirty_found = FALSE;
	}
	dirty_offset = 0;

	/* note: we can't use data_stack_pool with output stream because it's
	   being written to inside t_push() .. t_pop() calls */
	output = o_stream_create_file(tmp_fd, system_pool, 8192, 0, FALSE);
	o_stream_set_blocking(output, 60000, NULL, NULL);

	failed = FALSE; seq = 1;
	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if (dirty_found || (rec->index_flags & INDEX_MAIL_FLAG_DIRTY)) {
			/* get offset to beginning of mail headers */
			if (!mbox_mail_get_location(index, rec, &offset,
						    &hdr_size, &body_size)) {
				/* fsck should have fixed it */
				failed = TRUE;
				break;
			}

			if (offset < input->v_offset) {
				index_set_corrupted(index,
						    "Invalid message offset");
				failed = TRUE;
				break;
			}

			if (offset + hdr_size + body_size > input->v_size) {
				index_set_corrupted(index,
						    "Invalid message size");
				failed = TRUE;
				break;
			}
		}

		if (!dirty_found &&
		    (rec->index_flags & INDEX_MAIL_FLAG_DIRTY)) {
			/* first dirty message */
			dirty_found = TRUE;
			dirty_offset = offset;

			i_stream_seek(input, dirty_offset);
		}

		if (dirty_found) {
			/* write the From-line */
			if (!mbox_write(index, input, output, offset)) {
				failed = TRUE;
				break;
			}

			/* write header, updating flag fields */
			offset += hdr_size;
			if (!mbox_write_header(index, rec, seq, input, output,
					       offset, hdr_size, body_size)) {
				failed = TRUE;
				break;
			}

			/* write body */
			offset += body_size;
			if (!mbox_write(index, input, output, offset)) {
				failed = TRUE;
				break;
			}
		}

		seq++;
		rec = index->next(index, rec);
	}

	if (!dirty_found) {
		index_set_error(index, "Expected dirty messages not found "
				"from mbox file %s", index->mailbox_path);
		failed = TRUE;
	}

	if (!failed) {
		/* always end with a \n */
		(void)o_stream_send(output, "\n", 1);
	}

	if (output->closed) {
		errno = output->stream_errno;
		mbox_set_syscall_error(index, "write()");
		failed = TRUE;
	}

	i_stream_unref(input);
	o_stream_unref(output);

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
		if (fd_copy(tmp_fd, index->mbox_fd, dirty_offset) == 0) {
			/* All ok. Just make sure the timestamps of index and
			   mbox differ, so index will be updated at next sync */
			index->file_sync_stamp = ioloop_time-61;
			reset_dirty_flags(index);
		} else {
			mbox_set_syscall_error(index, "fd_copy()");
			failed = TRUE;
		}
	}

	if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
		failed = TRUE;

	(void)unlink(path);

	if (close(tmp_fd) < 0)
		index_file_set_syscall_error(index, path, "close()");
	return !failed;
}
