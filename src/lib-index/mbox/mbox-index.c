/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "rfc822-tokenize.h"
#include "mbox-index.h"
#include "mail-index-util.h"
#include "mail-index-data.h"
#include "mail-custom-flags.h"

static MailIndex mbox_index;

int mbox_set_syscall_error(MailIndex *index, const char *function)
{
	i_assert(function != NULL);

	index_set_error(index, "%s failed with mbox file %s: %m",
			function, index->mbox_path);
	return FALSE;
}

void mbox_header_init_context(MboxHeaderContext *ctx, MailIndex *index)
{
	memset(ctx, 0, sizeof(MboxHeaderContext));
	md5_init(&ctx->md5);

	ctx->index = index;
	ctx->custom_flags = mail_custom_flags_list_get(index->custom_flags);
}

void mbox_header_free_context(MboxHeaderContext *ctx)
{
	mail_custom_flags_list_unref(ctx->index->custom_flags);
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

	mail_custom_flags_list_unref(ctx->index->custom_flags);

	flags = MAIL_CUSTOM_FLAGS_MASK;
	ret = mail_custom_flags_fix_list(ctx->index->custom_flags, &flags,
					 custom_flags, idx);

	ctx->custom_flags =
		mail_custom_flags_list_get(ctx->index->custom_flags);

	t_pop();

	return ret > 0;
}

void mbox_header_func(MessagePart *part __attr_unused__,
		      const char *name, size_t name_len,
		      const char *value, size_t value_len,
		      void *context)
{
	MboxHeaderContext *ctx = context;
	int fixed = FALSE;

	/* Pretty much copy&pasted from popa3d by Solar Designer */
	switch (*name) {
	case 'R':
	case 'r':
		if (!ctx->received && name_len == 8 &&
		    strncasecmp(name, "Received", 8) == 0) {
			ctx->received = TRUE;
			fixed = TRUE;
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

int mbox_skip_crlf(IOBuffer *inbuf)
{
	unsigned char *data;
	size_t size, pos;

	pos = 0;
	while (io_buffer_read_data(inbuf, &data, &size, pos) >= 0) {
		if (size > 0 && pos == 0) {
			if (data[0] == '\n') {
				io_buffer_skip(inbuf, 1);
				return TRUE;
			}
			if (data[0] != '\r')
				return FALSE;

			pos++;
		}
		if (size > 1 && pos == 1) {
			if (data[1] != '\n')
				return FALSE;

			io_buffer_skip(inbuf, 2);
			return TRUE;
		}
	}

	/* end of file */
	return TRUE;
}

int mbox_mail_get_start_offset(MailIndex *index, MailIndexRecord *rec,
			       uoff_t *offset)
{
	const uoff_t *location;
	size_t size;

	location = index->lookup_field_raw(index, rec,
					   FIELD_TYPE_LOCATION, &size);
	if (location == NULL) {
		index_data_set_corrupted(index->data, "Missing location field "
					 "for record %u", rec->uid);
		*offset = 0;
		return FALSE;
	} else if (size != sizeof(uoff_t) || *location > OFF_T_MAX) {
		index_data_set_corrupted(index->data, "Invalid location field "
					 "for record %u", rec->uid);
		*offset = 0;
		return FALSE;
	} else {
		*offset = *location;
		return TRUE;
	}
}

MailIndex *mbox_index_alloc(const char *dir, const char *mbox_path)
{
	MailIndex *index;
	int len;

	i_assert(dir != NULL);

	index = i_new(MailIndex, 1);
	memcpy(index, &mbox_index, sizeof(MailIndex));

	index->fd = -1;
	index->dir = i_strdup(dir);

	len = strlen(index->dir);
	if (index->dir[len-1] == '/')
		index->dir[len-1] = '\0';

	index->mbox_path = i_strdup(mbox_path);
	return (MailIndex *) index;
}

static void mbox_index_free(MailIndex *index)
{
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

	rec->index_flags |= INDEX_MAIL_FLAG_DIRTY;
	index->header->flags |= MAIL_INDEX_FLAG_DIRTY_MESSAGES;
	return TRUE;
}

static MailIndex mbox_index = {
	mail_index_open,
	mail_index_open_or_create,
	mbox_index_free,
	mail_index_set_lock,
	mail_index_try_lock,
	mbox_index_rebuild,
	mbox_index_fsck,
	mbox_index_sync,
	mail_index_get_header,
	mail_index_lookup,
	mail_index_next,
        mail_index_lookup_uid_range,
	mail_index_lookup_field,
	mail_index_lookup_field_raw,
	mail_index_get_sequence,
	mbox_open_mail,
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
