/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "rfc822-tokenize.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"
#include "mail-index-data.h"
#include "mail-custom-flags.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

extern MailIndex mbox_index;

int mbox_set_syscall_error(MailIndex *index, const char *function)
{
	i_assert(function != NULL);

	index_set_error(index, "%s failed with mbox file %s: %m",
			function, index->mbox_path);
	return FALSE;
}

int mbox_file_open(MailIndex *index)
{
	struct stat st;
	int fd;

	i_assert(index->mbox_fd == -1);

	fd = open(index->mbox_path, O_RDWR);
	if (fd == -1) {
		mbox_set_syscall_error(index, "open()");
		return FALSE;
	}

	if (fstat(fd, &st) < 0) {
		mbox_set_syscall_error(index, "fstat()");
		(void)close(fd);
		return FALSE;
	}

	index->mbox_fd = fd;
	index->mbox_dev = st.st_dev;
	index->mbox_ino = st.st_ino;
	return TRUE;
}

IBuffer *mbox_get_inbuf(MailIndex *index, uoff_t offset, MailLockType lock_type)
{
	i_assert(offset < OFF_T_MAX);

	switch (lock_type) {
	case MAIL_LOCK_SHARED:
	case MAIL_LOCK_EXCLUSIVE:
		/* don't drop exclusive lock, it may be there for a reason */
		if (index->mbox_lock_type != MAIL_LOCK_EXCLUSIVE) {
			if (!mbox_lock(index, lock_type))
				return NULL;
		}
		break;
	default:
		if (index->mbox_fd == -1) {
			if (!mbox_file_open(index))
				return NULL;
		}
		break;
	}

	if (index->mbox_inbuf == NULL) {
		index->mbox_inbuf =
			i_buffer_create_mmap(index->mbox_fd, default_pool,
					     MAIL_MMAP_BLOCK_SIZE, 0, 0, FALSE);
	}

	i_buffer_set_read_limit(index->mbox_inbuf, 0);
	i_buffer_set_start_offset(index->mbox_inbuf, (uoff_t)offset);
	i_buffer_seek(index->mbox_inbuf, 0);

	i_buffer_ref(index->mbox_inbuf);
	return index->mbox_inbuf;
}

void mbox_file_close_inbuf(MailIndex *index)
{
	if (index->mbox_inbuf != NULL) {
		i_buffer_close(index->mbox_inbuf);
		i_buffer_unref(index->mbox_inbuf);
		index->mbox_inbuf = NULL;
	}
}

void mbox_file_close_fd(MailIndex *index)
{
	mbox_file_close_inbuf(index);

	if (index->mbox_fd != -1) {
		close(index->mbox_fd);
		index->mbox_fd = -1;
	}
}

void mbox_header_init_context(MboxHeaderContext *ctx, MailIndex *index,
			      IBuffer *inbuf)
{
	memset(ctx, 0, sizeof(MboxHeaderContext));
	md5_init(&ctx->md5);

	ctx->index = index;
	ctx->inbuf = inbuf;
	ctx->custom_flags = mail_custom_flags_list_get(index->custom_flags);
}

void mbox_header_free_context(MboxHeaderContext *ctx __attr_unused__)
{
}

static MailFlags mbox_get_status_flags(const char *value, size_t len)
{
	MailFlags flags;
	size_t i;

	flags = 0;
	for (i = 0; i < len; i++) {
		switch (value[i]) {
		case 'A':
			flags |= MAIL_ANSWERED;
			break;
		case 'F':
			flags |= MAIL_FLAGGED;
			break;
		case 'D':
			flags |= MAIL_DRAFT;
			break;
		case 'R':
			flags |= MAIL_SEEN;
			break;
		case 'T':
			flags |= MAIL_DELETED;
			break;
		}
	}

	return flags;
}

static void mbox_update_custom_flags(const char *value __attr_unused__,
				     size_t len __attr_unused__,
				     int index, void *context)
{
	MailFlags *flags = context;

	if (index >= 0)
		*flags |= 1 << (index + MAIL_CUSTOM_FLAG_1_BIT);
}

static MailFlags
mbox_get_keyword_flags(const char *value, size_t len,
		       const char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT])
{
	MailFlags flags;

	flags = 0;
	mbox_keywords_parse(value, len, custom_flags,
			    mbox_update_custom_flags, &flags);
	return flags;
}

static int mbox_parse_imapbase(const char *value, size_t len,
			       MboxHeaderContext *ctx)
{
	const char **custom_flags, **old_flags;
	size_t pos, start;
	MailFlags flags;
	int idx, ret, spaces, max;

	/* skip <uid validity> and <last uid> fields */
	spaces = 0;
	for (pos = 0; pos < len; pos++) {
		if (value[pos] == ' ' && (pos == 0 || value[pos-1] != ' ')) {
			if (++spaces == 2)
				break;
		}
	}

	while (pos < len && value[pos] == ' ') pos++;

	if (pos == len)
		return TRUE;

	t_push();

	/* we're at the 3rd field now, which begins the list of custom flags */
	max = MAIL_CUSTOM_FLAGS_COUNT;
	custom_flags = t_new(const char *, max);
	for (idx = 0, start = pos; ; pos++) {
		if (pos == len || value[pos] == ' ' || value[pos] == '\t') {
			if (start != pos) {
				if (idx == max) {
					/* need more memory */
					old_flags = custom_flags;
					max *= 2;
					custom_flags = t_new(const char *, max);
					memcpy(custom_flags, old_flags,
					       sizeof(const char *) * idx);
				}

				custom_flags[idx++] =
					t_strdup_until(value+start, value+pos);
			}
			start = pos+1;

			if (pos == len)
				break;
		}
	}

	flags = MAIL_CUSTOM_FLAGS_MASK;
	ret = mail_custom_flags_fix_list(ctx->index->custom_flags, &flags,
					 custom_flags, idx);

	t_pop();

	return ret > 0;
}

void mbox_header_func(MessagePart *part __attr_unused__,
		      const char *name, size_t name_len,
		      const char *value, size_t value_len,
		      void *context)
{
	MboxHeaderContext *ctx = context;
	uoff_t start_offset, end_offset;
	size_t i;
	int fixed = FALSE;

	/* Pretty much copy&pasted from popa3d by Solar Designer */
	switch (*name) {
	case '\0':
		/* End of headers */
		if (!ctx->set_read_limit)
			break;

		/* a) use Content-Length, b) search for "From "-line */
		start_offset = ctx->inbuf->v_offset;
		i_buffer_set_read_limit(ctx->inbuf, 0);

		end_offset = start_offset + ctx->content_length;
		if (ctx->content_length == 0 ||
		    !mbox_verify_end_of_body(ctx->inbuf, end_offset)) {
			if (ctx->content_length != 0)
				i_buffer_seek(ctx->inbuf, start_offset);
			mbox_skip_message(ctx->inbuf);
			end_offset = ctx->inbuf->v_offset;
			ctx->content_length = end_offset - start_offset;
		}

		i_buffer_seek(ctx->inbuf, start_offset);
		i_buffer_set_read_limit(ctx->inbuf, end_offset);
		break;

	case 'R':
	case 'r':
		if (!ctx->received && name_len == 8 &&
		    strncasecmp(name, "Received", 8) == 0) {
			ctx->received = TRUE;
			fixed = TRUE;
		}
		break;

	case 'C':
	case 'c':
		if (name_len == 14 && ctx->set_read_limit &&
		    strncasecmp(name, "Content-Length", 14) == 0) {
			/* manual parsing, so we can deal with uoff_t */
			ctx->content_length = 0;
			for (i = 0; i < value_len; i++) {
				if (value[i] < '0' || value[i] > '9') {
					/* invalid */
					ctx->content_length = 0;
					break;
				}

				ctx->content_length = ctx->content_length * 10 +
					(value[i] - '0');
			}
		}
		break;

	case 'D':
	case 'd':
		if (name_len == 12)
			fixed = strncasecmp(name, "Delivered-To", 12) == 0;
		else if (name_len == 4) {
			/* Received-header contains date too,
			   and more trusted one */
			fixed = !ctx->received &&
				strncasecmp(name, "Date", 4) == 0;
		}
		break;

	case 'M':
	case 'm':
		if (name_len == 10) {
			/* Received-header contains unique ID too,
			   and more trusted one */
			fixed = !ctx->received &&
				strncasecmp(name, "Message-ID", 10) == 0;
		}
		break;

	case 'S':
	case 's':
		if (name_len == 6 && strncasecmp(name, "Status", 6) == 0) {
			/* update message flags */
			ctx->flags |= mbox_get_status_flags(value, value_len);
		}
		break;

	case 'X':
	case 'x':
		if (name_len == 13) {
			/* Let the local delivery agent help generate unique
			   ID's but don't blindly trust this header alone as
			   it could just as easily come from the remote. */
			fixed = strncasecmp(name, "X-Delivery-ID:", 13) == 0;
		} else if (name_len == 8 &&
			 strncasecmp(name, "X-Status", 8) == 0) {
			/* update message flags */
			ctx->flags |= mbox_get_status_flags(value, value_len);
		} else if (name_len == 10 &&
			   strncasecmp(name, "X-Keywords", 10) == 0) {
			/* update custom message flags */
			ctx->flags |= mbox_get_keyword_flags(value, value_len,
							     ctx->custom_flags);
		} else if (name_len == 10 &&
			   strncasecmp(name, "X-IMAPbase", 10) == 0) {
			/* update list of custom message flags */
			(void)mbox_parse_imapbase(value, value_len, ctx);
		}
		break;
	}

	if (fixed)
		md5_update(&ctx->md5, value, value_len);
}

void mbox_keywords_parse(const char *value, size_t len,
			 const char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT],
			 void (*func)(const char *, size_t, int, void *),
			 void *context)
{
	size_t custom_len[MAIL_CUSTOM_FLAGS_COUNT];
	size_t item_len;
	int i;

	/* the value is often empty, so check that first */
	while (len > 0 && IS_LWSP(*value)) {
		value++;
		len--;
	}

	if (len == 0)
		return;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		custom_len[i] = custom_flags[i] != NULL ?
			strlen(custom_flags[i]) : 0;
	}

	for (;;) {
		/* skip whitespace */
		while (len > 0 && IS_LWSP(*value)) {
			value++;
			len--;
		}

		if (len == 0)
			break;

		/* find the length of the item */
		for (item_len = 0; item_len < len; item_len++) {
			if (IS_LWSP(value[item_len]))
				break;
		}

		/* check if it's found */
		for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
			if (custom_len[i] == item_len &&
			    strncasecmp(custom_flags[i], value, item_len) == 0)
				break;
		}

		if (i == MAIL_CUSTOM_FLAGS_COUNT)
			i = -1;

		func(value, item_len, i, context);

		value += item_len;
		len -= item_len;
	}
}

int mbox_skip_crlf(IBuffer *inbuf)
{
	const unsigned char *data;
	size_t size, pos;

	pos = 0;
	while (i_buffer_read_data(inbuf, &data, &size, pos) > 0) {
		if (pos == 0) {
			if (data[0] == '\n') {
				i_buffer_skip(inbuf, 1);
				return TRUE;
			}
			if (data[0] != '\r')
				return FALSE;

			pos++;
		}

		if (size > 1 && pos == 1) {
			if (data[1] != '\n')
				return FALSE;

			i_buffer_skip(inbuf, 2);
			return TRUE;
		}
	}

	/* end of file */
	return TRUE;
}

void mbox_skip_empty_lines(IBuffer *inbuf)
{
	const unsigned char *data;
	size_t i, size;

	/* skip empty lines at beginning */
	while (i_buffer_read_data(inbuf, &data, &size, 0) > 0) {
		for (i = 0; i < size; i++) {
			if (data[i] != '\r' && data[i] != '\n')
				break;
		}

		i_buffer_skip(inbuf, i);

		if (i < size)
			break;
	}
}

static int mbox_is_valid_from(IBuffer *inbuf, size_t startpos)
{
	const unsigned char *msg;
	size_t i, size;

	i = startpos;
	while (i_buffer_read_data(inbuf, &msg, &size, i) > 0) {
		for (; i < size; i++) {
			if (msg[i] == '\n') {
				msg += startpos;
				i -= startpos;
				return mbox_from_parse_date((const char *) msg,
							    size) != (time_t)-1;
			}
		}
	}

	return FALSE;
}

static void mbox_skip_forward(IBuffer *inbuf, int header)
{
	const unsigned char *msg;
	size_t i, size, startpos;
	int lastmsg, state, new_state;

	/* read until "[\r]\nFrom " is found. assume '\n' at beginning of
	   buffer */
	startpos = i = 0; lastmsg = TRUE;
	state = '\n';
	while (i_buffer_read_data(inbuf, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			new_state = 0;
			switch (state) {
			case '\n':
				if (msg[i] == 'F')
					new_state = 'F';
				else if (header) {
					if (msg[i] == '\n') {
						/* \n\n */
						i_buffer_skip(inbuf, i+1);
						return;
					}

					if (msg[i] == '\r')
						new_state = '\r';
				}
				break;
			case '\r':
				if (msg[i] == '\n') {
					/* \n\r\n */
					i_buffer_skip(inbuf, i+1);
					return;
				}
				break;
			case 'F':
				if (msg[i] == 'r')
					new_state = 'r';
				break;
			case 'r':
				if (msg[i] == 'o')
					new_state = 'o';
				break;
			case 'o':
				if (msg[i] == 'm')
					new_state = 'm';
				break;
			case 'm':
				if (msg[i] == ' ') {
					if (mbox_is_valid_from(inbuf, i+1)) {
						/* Go back "From" */
						i -= 4;

						/* Go back \n, unless we're at
						   beginning of buffer */
						if (i > 0)
							i--;

						/* Go back \r if it's there */
						if (i > 0 && msg[i-1] == '\r')
							i--;

						i_buffer_skip(inbuf, i);
						return;
					}
				}
				break;
			}

			if (new_state == 0 && msg[i] == '\n')
				state = '\n';
			else
				state = new_state;
		}

		/* Leave enough space to go back "\r\nFrom" */
		startpos = i < 6 ? i : 6;
		i -= startpos;

		i_buffer_skip(inbuf, i);
	}

	/* end of file, leave the last [\r]\n */
	msg = i_buffer_get_data(inbuf, &size);
	if (size == startpos && startpos > 0) {
		if (msg[startpos-1] == '\n')
			startpos--;
		if (startpos > 0 && msg[startpos-1] == '\r')
			startpos--;
	}

	i_buffer_skip(inbuf, startpos);
}

void mbox_skip_header(IBuffer *inbuf)
{
	mbox_skip_forward(inbuf, TRUE);
}

void mbox_skip_message(IBuffer *inbuf)
{
	mbox_skip_forward(inbuf, FALSE);
}

int mbox_verify_end_of_body(IBuffer *inbuf, uoff_t end_offset)
{
	const unsigned char *data;
	size_t size;

	if (end_offset > inbuf->v_size) {
		/* missing data */
		return FALSE;
	}

	i_buffer_seek(inbuf, end_offset);

	if (inbuf->v_offset == inbuf->v_size) {
		/* end of file. a bit unexpected though,
		   since \n is missing. */
		return TRUE;
	}

	/* read forward a bit */
	if (i_buffer_read_data(inbuf, &data, &size, 6) < 0)
		return FALSE;

	/* either there should be the next From-line,
	   or [\r]\n at end of file */
	if (size > 0 && data[0] == '\r') {
		data++; size--;
	}
	if (size > 0) {
		if (data[0] != '\n')
			return FALSE;

		data++; size--;
	}

	return size == 0 ||
		(size >= 5 && strncmp((const char *) data, "From ", 5) == 0);
}

int mbox_mail_get_location(MailIndex *index, MailIndexRecord *rec,
			   uoff_t *offset, uoff_t *hdr_size, uoff_t *body_size)
{
	MailIndexDataRecordHeader *data_hdr;
	const uoff_t *location;
	size_t size;

	if (offset != NULL) {
		location = index->lookup_field_raw(index, rec,
						   DATA_FIELD_LOCATION, &size);
		if (location == NULL) {
			index_data_set_corrupted(index->data,
				"Missing location field for record %u",
				rec->uid);
			return FALSE;
		} else if (size != sizeof(uoff_t) || *location > OFF_T_MAX) {
			index_data_set_corrupted(index->data,
				"Invalid location field for record %u",
				rec->uid);
			return FALSE;
		}

		*offset = *location;
	}

	if (hdr_size != NULL || body_size != NULL) {
		data_hdr = mail_index_data_lookup_header(index->data, rec);
		if (data_hdr == NULL) {
			index_set_corrupted(index,
				"Missing data header for record %u", rec->uid);
			return FALSE;
		}

		if ((rec->data_fields & DATA_HDR_HEADER_SIZE) == 0) {
			index_set_corrupted(index,
				"Missing header size for record %u", rec->uid);
			return FALSE;
		}

		if ((rec->data_fields & DATA_HDR_BODY_SIZE) == 0) {
			index_set_corrupted(index,
				"Missing body size for record %u", rec->uid);
			return FALSE;
		}

		if (hdr_size != NULL)
			*hdr_size = data_hdr->header_size;
		if (body_size != NULL)
			*body_size = data_hdr->body_size;
	}

	return TRUE;
}

MailIndex *mbox_index_alloc(const char *dir, const char *mbox_path)
{
	MailIndex *index;
	int len;

	i_assert(dir != NULL);

	index = i_new(MailIndex, 1);
	memcpy(index, &mbox_index, sizeof(MailIndex));

	index->fd = -1;
	index->mbox_fd = -1;
	index->mbox_sync_counter = (unsigned int)-1;
	index->dir = i_strdup(dir);

	len = strlen(index->dir);
	if (index->dir[len-1] == '/')
		index->dir[len-1] = '\0';

	index->mbox_path = i_strdup(mbox_path);
	return (MailIndex *) index;
}

static void mbox_index_free(MailIndex *index)
{
        mbox_file_close_fd(index);
	mail_index_close(index);
	i_free(index->dir);
	i_free(index);
}

static int mbox_index_update_flags(MailIndex *index, MailIndexRecord *rec,
				   unsigned int seq, MailFlags flags,
				   int external_change)
{
	if (!mail_index_update_flags(index, rec, seq, flags, external_change))
		return FALSE;

	if (!external_change) {
		rec->index_flags |= INDEX_MAIL_FLAG_DIRTY;
		index->header->flags |= MAIL_INDEX_FLAG_DIRTY_MESSAGES;
	}
	return TRUE;
}

MailIndex mbox_index = {
	mail_index_open,
	mail_index_open_or_create,
	mbox_index_free,
	mail_index_set_lock,
	mail_index_try_lock,
	mbox_index_rebuild,
	mail_index_fsck,
	mbox_index_sync,
	mail_index_get_header,
	mail_index_lookup,
	mail_index_next,
        mail_index_lookup_uid_range,
	mail_index_lookup_field,
	mail_index_lookup_field_raw,
	mail_index_cache_fields_later,
	mbox_open_mail,
	mail_get_internal_date,
	mail_index_expunge,
	mbox_index_update_flags,
	mail_index_append_begin,
	mail_index_append_end,
	mail_index_update_begin,
	mail_index_update_end,
	mail_index_update_field,
	mail_index_update_field_raw,
	mail_index_get_last_error,
	mail_index_is_diskspace_error,
	mail_index_is_inconsistency_error,

	MAIL_INDEX_PRIVATE_FILL
};
