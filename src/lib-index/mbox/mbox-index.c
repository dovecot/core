/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"
#include "mail-index-data.h"
#include "mail-custom-flags.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Don't try reading more custom flags than this. */
#define MAX_CUSTOM_FLAGS 1024

extern struct mail_index mbox_index;

int mbox_set_syscall_error(struct mail_index *index, const char *function)
{
	i_assert(function != NULL);

	index_set_error(index, "%s failed with mbox file %s: %m",
			function, index->mailbox_path);
	return FALSE;
}

int mbox_file_open(struct mail_index *index)
{
	struct stat st;
	int fd;

	i_assert(index->mbox_fd == -1);

	fd = open(index->mailbox_path, index->mailbox_readonly ?
		  O_RDONLY : O_RDWR);
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

struct istream *mbox_get_stream(struct mail_index *index, uoff_t offset,
				enum mail_lock_type lock_type)
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

	if (index->mbox_stream == NULL) {
		if (index->mail_read_mmaped) {
			index->mbox_stream =
				i_stream_create_mmap(index->mbox_fd,
						     default_pool,
						     MAIL_MMAP_BLOCK_SIZE,
						     0, 0, FALSE);
		} else {
			if (lseek(index->mbox_fd, 0, SEEK_SET) < 0) {
				mbox_set_syscall_error(index, "lseek()");
				return NULL;
			}

			index->mbox_stream =
				i_stream_create_file(index->mbox_fd,
						     default_pool,
						     MAIL_READ_BLOCK_SIZE,
						     FALSE);
		}
	}

	i_stream_set_read_limit(index->mbox_stream, 0);
	i_stream_set_start_offset(index->mbox_stream, (uoff_t)offset);
	i_stream_seek(index->mbox_stream, 0);

	i_stream_ref(index->mbox_stream);
	return index->mbox_stream;
}

void mbox_file_close_stream(struct mail_index *index)
{
	if (index->mbox_stream != NULL) {
		i_stream_close(index->mbox_stream);
		i_stream_unref(index->mbox_stream);
		index->mbox_stream = NULL;
	}
}

void mbox_file_close_fd(struct mail_index *index)
{
	mbox_file_close_stream(index);

	if (index->mbox_fd != -1) {
		if (close(index->mbox_fd) < 0)
			i_error("close(mbox) failed: %m");
		index->mbox_fd = -1;
	}
}

void mbox_header_init_context(struct mbox_header_context *ctx,
			      struct mail_index *index,
			      struct istream *input)
{
	memset(ctx, 0, sizeof(struct mbox_header_context));
	md5_init(&ctx->md5);

	ctx->index = index;
	ctx->input = input;
	ctx->custom_flags = mail_custom_flags_list_get(index->custom_flags);
	ctx->content_length = (uoff_t)-1;
}

void mbox_header_free_context(struct mbox_header_context *ctx __attr_unused__)
{
}

static enum mail_flags
mbox_get_status_flags(const unsigned char *value, size_t len)
{
	enum mail_flags flags;
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

static void mbox_update_custom_flags(const unsigned char *value __attr_unused__,
				     size_t len __attr_unused__,
				     int index, void *context)
{
	enum mail_flags *flags = context;

	if (index >= 0)
		*flags |= 1 << (index + MAIL_CUSTOM_FLAG_1_BIT);
}

static enum mail_flags
mbox_get_keyword_flags(const unsigned char *value, size_t len,
		       const char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT])
{
	enum mail_flags flags;

	flags = 0;
	mbox_keywords_parse(value, len, custom_flags,
			    mbox_update_custom_flags, &flags);
	return flags;
}

static void mbox_parse_imapbase(const unsigned char *value, size_t len,
				struct mbox_header_context *ctx)
{
	const char *flag, *str;
	char *end;
	buffer_t *buf;
	size_t pos, start;
	enum mail_flags flags;
	unsigned int count;
	int ret;

	t_push();

	/* <uid validity> <last uid> */
	str = t_strndup(value, len);
	ctx->uid_validity = strtoul(str, &end, 10);
	ctx->uid_last = strtoul(end, &end, 10);
	pos = end - str;

	while (pos < len && value[pos] == ' ')
		pos++;

	if (pos == len) {
		t_pop();
		return;
	}

	/* we're at the 3rd field now, which begins the list of custom flags */
	buf = buffer_create_dynamic(data_stack_pool,
				    MAIL_CUSTOM_FLAGS_COUNT *
				    sizeof(const char *),
				    MAX_CUSTOM_FLAGS * sizeof(const char *));
	for (start = pos; ; pos++) {
		if (pos == len || value[pos] == ' ' || value[pos] == '\t') {
			if (start != pos) {
				flag = t_strdup_until(value+start, value+pos);
				if (buffer_append(buf, flag, sizeof(flag)) == 0)
					break;
			}
			start = pos+1;

			if (pos == len)
				break;
		}
	}

	flags = MAIL_CUSTOM_FLAGS_MASK;
	count = buffer_get_used_size(buf) / sizeof(const char *);
	ret = mail_custom_flags_fix_list(ctx->index->custom_flags, &flags,
					 buffer_free_without_data(buf), count);

	t_pop();
}

void mbox_header_cb(struct message_part *part __attr_unused__,
		    struct message_header_line *hdr, void *context)
{
	struct mbox_header_context *ctx = context;
	uoff_t start_offset, end_offset;
	size_t i;
	int fixed = FALSE;

	if (hdr == NULL) {
		/* End of headers */
		if (!ctx->set_read_limit)
			return;

		/* a) use Content-Length, b) search for "From "-line */
		start_offset = ctx->input->v_offset;
		i_stream_set_read_limit(ctx->input, 0);

		end_offset = start_offset + ctx->content_length;
		if (ctx->content_length == (uoff_t)-1 ||
		    !mbox_verify_end_of_body(ctx->input, end_offset)) {
			if (ctx->content_length != (uoff_t)-1) {
				i_stream_seek(ctx->input, start_offset);
				ctx->content_length_broken = TRUE;
			}
			mbox_skip_message(ctx->input);
			end_offset = ctx->input->v_offset;
			ctx->content_length = end_offset - start_offset;
		}

		i_stream_seek(ctx->input, start_offset);
		i_stream_set_read_limit(ctx->input, end_offset);
		return;
	}

	if (hdr->eoh)
		return;

	/* Pretty much copy&pasted from popa3d by Solar Designer */
	switch (*hdr->name) {
	case 'R':
	case 'r':
		if (!ctx->received &&
		    strcasecmp(hdr->name, "Received") == 0) {
			/* get only the first received-header */
			fixed = TRUE;
			if (!hdr->continues)
				ctx->received = TRUE;
		}
		break;

	case 'C':
	case 'c':
		if (ctx->set_read_limit &&
		    strcasecmp(hdr->name, "Content-Length") == 0) {
			/* manual parsing, so we can deal with uoff_t */
			ctx->content_length = 0;
			for (i = 0; i < hdr->value_len; i++) {
				if (hdr->value[i] < '0' ||
				    hdr->value[i] > '9') {
					/* invalid */
					ctx->content_length = 0;
					break;
				}

				ctx->content_length = ctx->content_length * 10 +
					(hdr->value[i] - '0');
			}
		}
		break;

	case 'D':
	case 'd':
		if (strcasecmp(hdr->name, "Delivered-To") == 0)
			fixed = TRUE;
		else if (!ctx->received && strcasecmp(hdr->name, "Date") == 0) {
			/* Received-header contains date too,
			   and more trusted one */
			fixed = TRUE;
		}
		break;

	case 'M':
	case 'm':
		if (!ctx->received &&
		    strcasecmp(hdr->name, "Message-ID") == 0) {
			/* Received-header contains unique ID too,
			   and more trusted one */
			fixed = TRUE;
		}
		break;

	case 'S':
	case 's':
		if (strcasecmp(hdr->name, "Status") == 0) {
			/* update message flags */
			ctx->flags |= mbox_get_status_flags(hdr->value,
							    hdr->value_len);
		}
		break;

	case 'X':
	case 'x':
		if (strcasecmp(hdr->name, "X-Delivery-ID:") == 0) {
			/* Let the local delivery agent help generate unique
			   ID's but don't blindly trust this header alone as
			   it could just as easily come from the remote. */
			fixed = TRUE;
		} else if (strcasecmp(hdr->name, "X-UID") == 0) {
			ctx->uid = 0;
			for (i = 0; i < hdr->value_len; i++) {
				if (hdr->value[i] < '0' ||
				    hdr->value[i] > '9')
					break;
				ctx->uid = ctx->uid * 10 + (hdr->value[i]-'0');
			}
		} else if (strcasecmp(hdr->name, "X-Status") == 0) {
			/* update message flags */
			ctx->flags |= mbox_get_status_flags(hdr->value,
							    hdr->value_len);
		} else if (strcasecmp(hdr->name, "X-Keywords") == 0) {
			/* update custom message flags */
			ctx->flags |= mbox_get_keyword_flags(hdr->value,
							     hdr->value_len,
							     ctx->custom_flags);
		} else if (strcasecmp(hdr->name, "X-IMAPbase") == 0) {
			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				break;
			}
			mbox_parse_imapbase(hdr->full_value,
					    hdr->full_value_len, ctx);
		}
		break;
	}

	if (fixed)
		md5_update(&ctx->md5, hdr->value, hdr->value_len);
}

void mbox_keywords_parse(const unsigned char *value, size_t len,
			 const char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT],
			 void (*func)(const unsigned char *, size_t,
				      int, void *),
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
			    memcasecmp(custom_flags[i], value, item_len) == 0)
				break;
		}

		if (i == MAIL_CUSTOM_FLAGS_COUNT)
			i = -1;

		func(value, item_len, i, context);

		value += item_len;
		len -= item_len;
	}
}

int mbox_skip_crlf(struct istream *input)
{
	const unsigned char *data;
	size_t size, pos;

	pos = 0;
	while (i_stream_read_data(input, &data, &size, pos) > 0) {
		if (pos == 0) {
			if (data[0] == '\n') {
				i_stream_skip(input, 1);
				return TRUE;
			}
			if (data[0] != '\r')
				return FALSE;

			pos++;
		}

		if (size > 1 && pos == 1) {
			if (data[1] != '\n')
				return FALSE;

			i_stream_skip(input, 2);
			return TRUE;
		}
	}

	/* end of file */
	return TRUE;
}

void mbox_skip_empty_lines(struct istream *input)
{
	const unsigned char *data;
	size_t i, size;

	/* skip empty lines at beginning */
	while (i_stream_read_data(input, &data, &size, 0) > 0) {
		for (i = 0; i < size; i++) {
			if (data[i] != '\r' && data[i] != '\n')
				break;
		}

		i_stream_skip(input, i);

		if (i < size)
			break;
	}
}

static int mbox_is_valid_from(struct istream *input, size_t startpos)
{
	const unsigned char *msg;
	size_t i, size;

	i = startpos;
	while (i_stream_read_data(input, &msg, &size, i) > 0) {
		for (; i < size; i++) {
			if (msg[i] == '\n') {
				msg += startpos;
				i -= startpos;
				return mbox_from_parse_date(msg, size) !=
					(time_t)-1;
			}
		}
	}

	return FALSE;
}

static void mbox_skip_forward(struct istream *input, int header)
{
	const unsigned char *msg;
	size_t i, size, startpos, eoh;
	int lastmsg, state, new_state;

	/* read until "[\r]\nFrom " is found. assume '\n' at beginning of
	   buffer */
	startpos = i = 0; eoh = 0; lastmsg = TRUE;
	state = '\n';
	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			new_state = 0;
			switch (state) {
			case '\n':
				if (msg[i] == 'F')
					new_state = 'F';
				else if (header) {
					if (msg[i] == '\n') {
						/* \n\n, but if we have
						   0-byte message body the
						   following \n may belong
						   to "From "-line */
						eoh = i+1;
						header = FALSE;
						new_state = '\n';
					} else if (msg[i] == '\r') {
						/* possibly \n\r\n */
						new_state = '\r';
					}
				}
				break;
			case '\r':
				if (msg[i] == '\n') {
					/* \n\r\n */
					eoh = i+1;
					header = FALSE;
					new_state = '\n';
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
					int valid;

					valid = mbox_is_valid_from(input, i+1);

					/* we may have trashed msg above,
					   get it again */
					msg = i_stream_get_data(input, &size);

					if (valid) {
						/* Go back "From" */
						i -= 4;

						/* Go back \n, unless we're at
						   beginning of buffer */
						if (i > 0)
							i--;

						/* Go back \r if it's there */
						if (i > 0 && msg[i-1] == '\r')
							i--;

						i_stream_skip(input, i);
						return;
					}
				}
				break;
			}

			if (new_state != 0)
				state = new_state;
			else if (eoh == 0)
				state = msg[i] == '\n' ? '\n' : 0;
			else {
				/* end of header position confirmed */
				i_stream_skip(input, eoh);
				return;
			}
		}

		/* Leave enough space to go back "\r\nFrom" plus one for the
		   end-of-headers check */
		startpos = i < 7 ? i : 7;
		i -= startpos;

		if (eoh != 0) {
			i_assert(i < eoh);
			eoh -= i;
		}

		i_stream_skip(input, i);
	}

	if (eoh != 0) {
		/* make sure we didn't end with \n\n or \n\r\n. In these
		   cases the last [\r]\n doesn't belong to our message. */
		if (eoh < size && (msg[eoh] != '\r' || eoh < size-1)) {
			i_stream_skip(input, eoh);
			return;
		}
	}

	/* end of file, leave the last [\r]\n */
	msg = i_stream_get_data(input, &size);
	if (size == startpos && startpos > 0) {
		if (msg[startpos-1] == '\n')
			startpos--;
		if (startpos > 0 && msg[startpos-1] == '\r')
			startpos--;
	}

	i_stream_skip(input, startpos);
}

void mbox_skip_header(struct istream *input)
{
	mbox_skip_forward(input, TRUE);
}

void mbox_skip_message(struct istream *input)
{
	mbox_skip_forward(input, FALSE);
}

int mbox_verify_end_of_body(struct istream *input, uoff_t end_offset)
{
	const unsigned char *data;
	size_t size;

	if (end_offset > input->v_size) {
		/* missing data */
		return FALSE;
	}

	i_stream_seek(input, end_offset);

	if (input->v_offset == input->v_size) {
		/* end of file. a bit unexpected though,
		   since \n is missing. */
		return TRUE;
	}

	/* read forward a bit */
	if (i_stream_read_data(input, &data, &size, 6) < 0)
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

int mbox_mail_get_location(struct mail_index *index,
			   struct mail_index_record *rec,
			   uoff_t *offset, uoff_t *hdr_size, uoff_t *body_size)
{
	struct mail_index_data_record_header *data_hdr;
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

struct mail_index *mbox_index_alloc(const char *dir, const char *mbox_path)
{
	struct mail_index *index;

	i_assert(mbox_path != NULL);

	index = i_new(struct mail_index, 1);
	memcpy(index, &mbox_index, sizeof(struct mail_index));

	index->mbox_fd = -1;
	index->mbox_sync_counter = (unsigned int)-1;
	index->mailbox_readonly = access(mbox_path, W_OK) < 0;

	index->mailbox_path = i_strdup(mbox_path);
	mail_index_init(index, dir);
	return index;
}

static void mbox_index_free(struct mail_index *index)
{
        mbox_file_close_fd(index);
	mail_index_close(index);
	i_free(index->dir);
	i_free(index->mailbox_path);
	i_free(index);
}

static int mbox_index_set_lock(struct mail_index *index,
			       enum mail_lock_type lock_type)
{
	if (lock_type == MAIL_LOCK_UNLOCK)
		(void)mbox_unlock(index);
	return mail_index_set_lock(index, lock_type);
}

static int mbox_index_try_lock(struct mail_index *index,
			       enum mail_lock_type lock_type)
{
	if (lock_type == MAIL_LOCK_UNLOCK)
		(void)mbox_unlock(index);
	return mail_index_try_lock(index, lock_type);
}

static int mbox_index_expunge(struct mail_index *index,
			      struct mail_index_record *rec,
			      unsigned int seq, int external_change)
{
	if (!mail_index_expunge(index, rec, seq, external_change))
		return FALSE;

	if (seq == 1) {
		/* Our message containing X-IMAPbase was deleted.
		   Get it back there. */
		index->header->flags |= MAIL_INDEX_FLAG_DIRTY_MESSAGES |
			MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS;
	}
	return TRUE;
}

static int mbox_index_update_flags(struct mail_index *index,
				   struct mail_index_record *rec,
				   unsigned int seq, enum mail_flags flags,
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

static int mbox_index_append_end(struct mail_index *index,
				 struct mail_index_record *rec)
{
	if (!mail_index_append_end(index, rec))
		return FALSE;

	/* update last_uid in X-IMAPbase */
	index->header->flags |= MAIL_INDEX_FLAG_DIRTY_MESSAGES |
		MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS;
	return TRUE;
}

struct mail_index mbox_index = {
	mail_index_open,
	mbox_index_free,
	mbox_index_set_lock,
	mbox_index_try_lock,
        mail_index_set_lock_notify_callback,
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
	mbox_index_expunge,
	mbox_index_update_flags,
	mail_index_append_begin,
	mbox_index_append_end,
	mail_index_append_abort,
	mail_index_update_begin,
	mail_index_update_end,
	mail_index_update_abort,
	mail_index_update_field,
	mail_index_update_field_raw,
	mail_index_get_last_error,
	mail_index_get_last_error_text,

	MAIL_INDEX_PRIVATE_FILL
};
