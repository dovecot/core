/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "file-set-size.h"
#include "str.h"
#include "write-full.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"
#include "mail-custom-flags.h"
#include "mail-cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

struct mbox_rewrite_context {
	struct ostream *output;

	uoff_t content_length;
	unsigned int seq, uid;
	unsigned int msg_flags;
	const char **custom_flags;

	unsigned int uid_validity;
	unsigned int uid_last;
	char *x_keywords;

	unsigned int ximapbase_found:1;
	unsigned int xuid_found:1;
	unsigned int status_found:1;
	unsigned int xstatus_found:1;
	unsigned int content_length_found:1;
};

/* Remove dirty flag from all messages */
static int reset_dirty_flags(struct mail_index *index)
{
	struct mail_index_record *rec;
	enum mail_index_record_flag index_flags;

	if (mail_cache_lock(index->cache, FALSE) <= 0)
		return FALSE;
	mail_cache_unlock_later(index->cache);

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		index_flags = mail_cache_get_index_flags(index->cache, rec);
		if ((index_flags & MAIL_INDEX_FLAG_DIRTY) != 0) {
			index_flags &= ~MAIL_INDEX_FLAG_DIRTY;
			if (!mail_cache_update_index_flags(index->cache,
							   rec, index_flags))
				return FALSE;
		}

		rec = index->next(index, rec);
	}

	index->header->flags &= ~(MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES |
				  MAIL_INDEX_HDR_FLAG_DIRTY_CUSTOMFLAGS);
	return TRUE;
}

static int mbox_write(struct mail_index *index, struct istream *input,
		      struct ostream *output, uoff_t end_offset)
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
		/* sync should have noticed it.. */
		index_set_error(index, "Error rewriting mbox file %s: "
				"Unexpected end of file", index->mailbox_path);
		failed = TRUE;
	} else {
		failed = FALSE;
	}

	i_stream_set_read_limit(input, old_limit);
	return !failed;
}

static int mbox_write_ximapbase(struct mbox_rewrite_context *ctx)
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

static int mbox_write_xuid(struct mbox_rewrite_context *ctx)
{
	const char *str;

	str = t_strdup_printf("X-UID: %u\n", ctx->uid);

	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;

	return TRUE;
}

static int mbox_write_xkeywords(struct mbox_rewrite_context *ctx,
				const char *x_keywords, uoff_t wanted_offset,
				int force_filler)
{
	unsigned int field;
	int i;

	if ((ctx->msg_flags & MAIL_CUSTOM_FLAGS_MASK) == 0 &&
	    x_keywords == NULL && !force_filler &&
	    ctx->output->offset + sizeof("X-Keywords:")+1 >= wanted_offset) {
		/* nothing to do, and not enough extra space to write the
		   filler. Do it only if there's space for "X-Keywords: \n" */
		return TRUE;
	}

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

	/* fill the rest with spaces. -1 for \n */
	if (ctx->output->offset < wanted_offset-1 || force_filler) {
		char buf[1024];
		uoff_t fill_left;

		fill_left = force_filler ? MBOX_HEADER_EXTRA_SPACE :
			wanted_offset-1 - ctx->output->offset;
		memset(buf, ' ', sizeof(buf));
		while (fill_left > sizeof(buf)) {
			if (o_stream_send(ctx->output, buf, sizeof(buf)) < 0)
				return FALSE;
			fill_left -= sizeof(buf);
		}
		if (o_stream_send(ctx->output, buf, fill_left) < 0)
			return FALSE;
	}

	if (o_stream_send(ctx->output, "\n", 1) < 0)
		return FALSE;

	return TRUE;
}

static int mbox_write_status(struct mbox_rewrite_context *ctx,
			     const char *status)
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

static int mbox_write_xstatus(struct mbox_rewrite_context *ctx,
			      const char *x_status)
{
	const char *str;

	/* X-Status field */
	if ((ctx->msg_flags & (MAIL_SYSTEM_FLAGS_MASK^MAIL_SEEN)) == 0 &&
	    x_status == NULL)
		return TRUE;

	str = t_strconcat("X-Status: ",
			  (ctx->msg_flags & MAIL_ANSWERED) ? "A" : "",
			  (ctx->msg_flags & MAIL_DELETED) ? "D" : "",
			  (ctx->msg_flags & MAIL_FLAGGED) ? "F" : "",
			  (ctx->msg_flags & MAIL_DRAFT) ? "T" : "",
			  x_status, NULL);

	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;
	if (o_stream_send(ctx->output, "\n", 1) < 0)
		return FALSE;

	return TRUE;
}

static int mbox_write_content_length(struct mbox_rewrite_context *ctx)
{
	char str[MAX_INT_STRLEN+30];

	i_snprintf(str, sizeof(str), "Content-Length: %"PRIuUOFF_T"\n",
		   ctx->content_length);

	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;
	return TRUE;
}

static const char *strip_chars(const unsigned char *value, size_t value_len,
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

static void update_stripped_custom_flags(const unsigned char *value, size_t len,
					 int index, void *context)
{
	string_t *str = context;

	if (index < 0) {
		/* not found, keep it */
		if (str_len(str) != 0)
			str_append_c(str, ' ');
		str_append_n(str, value, len);
	}
}

static const char *strip_custom_flags(const unsigned char *value, size_t len,
				      struct mbox_rewrite_context *ctx)
{
	string_t *str;

	str = t_str_new(len+1);
	mbox_keywords_parse(value, len, ctx->custom_flags,
			    update_stripped_custom_flags, str);
	return str_len(str) == 0 ? NULL : str_c(str);
}

static int write_header(struct mbox_rewrite_context *ctx,
			struct message_header_line *hdr)
{
	const char *str;

	switch (hdr->name_len) {
	case 5:
		if (strcasecmp(hdr->name, "X-UID") == 0) {
			if (ctx->xuid_found)
				return TRUE;

			ctx->xuid_found = TRUE;
			return mbox_write_xuid(ctx);
		}
		break;
	case 6:
		if (strcasecmp(hdr->name, "Status") == 0) {
			if (ctx->status_found)
				return TRUE;
			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				return TRUE;
			}

			ctx->status_found = TRUE;
			str = strip_chars(hdr->full_value,
					  hdr->full_value_len, "RO");
			return mbox_write_status(ctx, str);
		}
		break;
	case 8:
		if (strcasecmp(hdr->name, "X-Status") == 0) {
			if (ctx->xstatus_found)
				return TRUE;
			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				return TRUE;
			}

			ctx->xstatus_found = TRUE;
			str = strip_chars(hdr->full_value,
					  hdr->full_value_len, "ADFT");
			return mbox_write_xstatus(ctx, str);
		}
		break;
	case 10:
		if (strcasecmp(hdr->name, "X-Keywords") == 0) {
			if (ctx->x_keywords != NULL)
				return TRUE;
			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				return TRUE;
			}

			str = strip_custom_flags(hdr->full_value,
						 hdr->full_value_len, ctx);
			ctx->x_keywords = i_strdup(str);
			return TRUE;
		} else if (strcasecmp(hdr->name, "X-IMAPbase") == 0) {
			if (ctx->seq != 1 || ctx->ximapbase_found)
				return TRUE;

			ctx->ximapbase_found = TRUE;
			return mbox_write_ximapbase(ctx);
		}
		break;
	case 14:
		if (strcasecmp(hdr->name, "Content-Length") == 0) {
			if (ctx->content_length_found)
				return TRUE;

			ctx->content_length_found = TRUE;
			return mbox_write_content_length(ctx);
		}
		break;
	}

	if (!hdr->eoh) {
		/* save this header */
		if (!hdr->continued) {
			(void)o_stream_send(ctx->output, hdr->name,
					    hdr->name_len);
			(void)o_stream_send(ctx->output, ": ", 2);
		}
		(void)o_stream_send(ctx->output, hdr->value, hdr->value_len);
		if (!hdr->no_newline)
			(void)o_stream_send(ctx->output, "\n", 1);
	}

	return !ctx->output->closed;
}

static int mbox_write_header(struct mail_index *index,
			     struct mail_index_record *rec, unsigned int seq,
			     struct istream *input, struct ostream *output,
			     uoff_t dirty_offset,
			     uoff_t *hdr_input_size, uoff_t body_size)
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
	struct mbox_rewrite_context ctx;
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;
	struct message_size hdr_size;
	uoff_t offset;
	int force_filler;

	t_push();

	/* parse the header, write the fields we don't want to change */
	memset(&ctx, 0, sizeof(ctx));
	ctx.output = output;
	ctx.content_length = body_size;
	ctx.seq = seq;
	ctx.uid = rec->uid;
	ctx.msg_flags = rec->msg_flags;
	ctx.uid_validity = index->header->uid_validity;
	ctx.uid_last = index->header->next_uid-1;
	ctx.custom_flags = mail_custom_flags_list_get(index->custom_flags);

	if (body_size == 0) {
		/* possibly broken message, find the next From-line
		   and make sure header parser won't pass it. */
		offset = input->v_offset;
		mbox_skip_header(input);
		i_stream_set_read_limit(input, input->v_offset);
		i_stream_seek(input, offset);
	}

	hdr_ctx = message_parse_header_init(input, &hdr_size);
	while ((hdr = message_parse_header_next(hdr_ctx)) != NULL) {
		t_push();
		write_header(&ctx, hdr);
		t_pop();
	}
	message_parse_header_deinit(hdr_ctx);
	*hdr_input_size = hdr_size.physical_size;

	i_stream_set_read_limit(input, 0);

	/* append the flag fields */
	if (seq == 1 && !ctx.ximapbase_found) {
		/* write X-IMAPbase header to first message */
		(void)mbox_write_ximapbase(&ctx);
	}

	force_filler = !ctx.xuid_found;
	if (!ctx.status_found)
		(void)mbox_write_status(&ctx, NULL);
	if (!ctx.xstatus_found)
		(void)mbox_write_xstatus(&ctx, NULL);
	if (!ctx.xuid_found)
		(void)mbox_write_xuid(&ctx);
	if (!ctx.content_length_found)
		(void)mbox_write_content_length(&ctx);

	/* write the x-keywords header last so it can fill the extra space
	   with spaces. -1 is for ending \n. */
	(void)mbox_write_xkeywords(&ctx, ctx.x_keywords,
				   input->v_offset - dirty_offset - 1,
				   force_filler);
	i_free(ctx.x_keywords);

	t_pop();

	/* empty line ends headers */
	(void)o_stream_send(output, "\n", 1);

	return TRUE;
}

static int fd_copy(struct mail_index *index, int in_fd, int out_fd,
		   uoff_t out_offset, uoff_t size)
{
	struct istream *input;
	struct ostream *output;
	struct stat st;
	int ret;

	i_assert(out_offset <= OFF_T_MAX);

	/* first grow the file to wanted size, to make sure we don't run out
	   of disk space */
	if (fstat(out_fd, &st) < 0) {
		mbox_set_syscall_error(index, "fstat()");
		return -1;
	}

	if ((uoff_t)st.st_size < out_offset + size) {
		if (file_set_size(out_fd, (off_t)(out_offset + size)) < 0) {
			mbox_set_syscall_error(index, "file_set_size()");
			(void)ftruncate(out_fd, st.st_size);
			return -1;
		}
	}

	if (lseek(out_fd, (off_t)out_offset, SEEK_SET) < 0) {
		mbox_set_syscall_error(index, "lseek()");
		(void)ftruncate(out_fd, st.st_size);
		return -1;
	}

	t_push();

	input = i_stream_create_mmap(in_fd, pool_datastack_create(),
				     1024*256, 0, 0, FALSE);
	i_stream_set_read_limit(input, size);

	output = o_stream_create_file(out_fd, pool_datastack_create(),
				      1024, FALSE);
	o_stream_set_blocking(output, 60000, NULL, NULL);

	ret = o_stream_send_istream(output, input);
	if (ret < 0) {
		errno = output->stream_errno;
		mbox_set_syscall_error(index, "o_stream_send_istream()");
	}

	o_stream_unref(output);
	i_stream_unref(input);
	t_pop();

	return ret;
}

static int dirty_flush(struct mail_index *index, uoff_t dirty_offset,
		       struct ostream *output, int output_fd)
{
	if (output->offset == 0)
		return TRUE;

	if (o_stream_flush(output) < 0) {
		mbox_set_syscall_error(index, "o_stream_flush()");
		return FALSE;
	}

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
	if (fd_copy(index, output_fd, index->mbox_fd,
		    dirty_offset, output->offset) < 0)
		return FALSE;

	/* All ok. Just make sure the timestamps of index and
	   mbox differ, so index will be updated at next sync */
	index->sync_stamp = 0;

	if (o_stream_seek(output, 0) < 0) {
		mbox_set_syscall_error(index, "o_stream_seek()");
		return FALSE;
	}
	return TRUE;
}

#define INDEX_DIRTY_FLAGS \
	(MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES | \
	 MAIL_INDEX_HDR_FLAG_DIRTY_CUSTOMFLAGS)

int mbox_index_rewrite(struct mail_index *index)
{
	/* Write messages beginning from the first dirty one to temp file,
	   then copy it over the mbox file. This may create data loss if
	   interrupted (see below). This rewriting relies quite a lot on
	   valid header/body sizes which fsck() should have ensured. */
	struct mail_index_record *rec;
	struct istream *input;
	struct ostream *output;
	uoff_t offset, hdr_size, body_size, dirty_offset;
	const char *path;
	unsigned int seq;
	int tmp_fd, failed, dirty, dirty_found, rewrite, no_locking;

	i_assert(!index->mailbox_readonly);
	i_assert(index->lock_type == MAIL_LOCK_UNLOCK ||
		 (index->lock_type == MAIL_LOCK_EXCLUSIVE &&
		  index->mbox_lock_type == MAIL_LOCK_EXCLUSIVE));

	no_locking = index->mbox_lock_type == MAIL_LOCK_EXCLUSIVE;
	if (!no_locking) {
		if (!index->set_lock(index, MAIL_LOCK_SHARED))
			return FALSE;
	}

	rewrite = (index->header->flags & INDEX_DIRTY_FLAGS) &&
		index->header->messages_count > 0;

	if (!no_locking) {
		if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
			return FALSE;
	}

	if (!rewrite) {
		/* no need to rewrite */
		return TRUE;
	}

	/* kludgy .. but we need to force resyncing */
	index->mbox_rewritten = TRUE;

	tmp_fd = -1; input = NULL;
	failed = TRUE; rewrite = FALSE;
	do {
		if (!no_locking) {
			if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
				break;

			if (!index->sync_and_lock(index, FALSE,
						  MAIL_LOCK_EXCLUSIVE, NULL))
				break;
		}

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
		if (!no_locking) {
			if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
				failed = TRUE;
		}
		if (input != NULL)
			i_stream_unref(input);
		return !failed;
	}

	if (index->header->flags & MAIL_INDEX_HDR_FLAG_DIRTY_CUSTOMFLAGS) {
		/* need to update X-IMAPbase in first message */
		dirty_found = TRUE;
	} else {
		dirty_found = FALSE;
	}
	dirty_offset = 0;

	/* note: we can't use data_stack_pool with output stream because it's
	   being written to inside t_push() .. t_pop() calls */
	output = o_stream_create_file(tmp_fd, system_pool, 8192, FALSE);
	o_stream_set_blocking(output, 60000, NULL, NULL);

	failed = FALSE; seq = 1;
	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if (dirty_found)
			dirty = FALSE;
		else {
			dirty = (mail_cache_get_index_flags(index->cache, rec) &
				 MAIL_INDEX_FLAG_DIRTY) != 0;
		}

		if (dirty_found || dirty) {
			/* get offset to beginning of mail headers */
			if (!mbox_mail_get_location(index, rec, &offset,
						    &body_size)) {
				/* fsck should have fixed it */
				failed = TRUE;
				break;
			}

			if (offset < input->v_offset) {
				mail_cache_set_corrupted(index->cache,
					"Invalid message offset");
				failed = TRUE;
				break;
			}

			if (!dirty_found) {
				/* first dirty message */
				dirty_found = TRUE;
				dirty_offset = offset;

				i_stream_seek(input, dirty_offset);
			}

			/* write the From-line */
			if (!mbox_write(index, input, output, offset)) {
				failed = TRUE;
				break;
			}

			/* write header, updating flag fields */
			if (!mbox_write_header(index, rec, seq, input, output,
					       dirty_offset,
					       &hdr_size, body_size)) {
				failed = TRUE;
				break;
			}
			offset += hdr_size;

			if (dirty_found &&
			    offset - dirty_offset == output->offset) {
				/* no need to write more, flush */
				if (!dirty_flush(index, dirty_offset,
						 output, tmp_fd)) {
					failed = TRUE;
					break;
				}
				dirty_found = FALSE;
			} else {
				/* write body */
				offset += body_size;
				if (!mbox_write(index, input, output, offset)) {
					failed = TRUE;
					break;
				}
			}
		}

		seq++;
		rec = index->next(index, rec);
	}

	if (!failed && dirty_found) {
		/* end with \n */
		(void)o_stream_send(output, "\n", 1);
	}

	if (output->closed) {
		errno = output->stream_errno;
		mbox_set_syscall_error(index, "write()");
		failed = TRUE;
	}

	if (!failed && dirty_found) {
		uoff_t dirty_size = output->offset;

		if (!dirty_flush(index, dirty_offset, output, tmp_fd))
			failed = TRUE;
		else {
			/* we may have shrinked the file */
			i_assert(dirty_offset + dirty_size <= OFF_T_MAX);
			if (ftruncate(index->mbox_fd,
				      (off_t)(dirty_offset + dirty_size)) < 0) {
				mbox_set_syscall_error(index, "ftruncate()");
				failed = TRUE;
			}
		}
	}

	if (!failed) {
		if (!reset_dirty_flags(index))
			failed = TRUE;
	}

	i_stream_unref(input);
	o_stream_unref(output);

	if (!no_locking) {
		if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
			failed = TRUE;
	}

	(void)unlink(path);

	if (close(tmp_fd) < 0)
		index_file_set_syscall_error(index, path, "close()");
	return !failed;
}
