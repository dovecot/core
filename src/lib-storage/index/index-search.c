/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "mmap-util.h"
#include "rfc822-tokenize.h"
#include "imap-date.h"
#include "index-storage.h"
#include "mail-index-util.h"
#include "mail-search.h"

#include <stdlib.h>
#include <ctype.h>

#define ARG_SET_RESULT(arg, res) \
	STMT_START { \
		(arg)->result = !(arg)->not ? (res) : -(res); \
	} STMT_END

typedef struct {
	IndexMailbox *ibox;
	MailIndexRecord *rec;
	unsigned int seq;
} SearchIndexContext;

typedef struct {
	MailSearchArg *args;
	int custom_header;

	const char *name, *value;
	size_t name_len, value_len;
} SearchHeaderContext;

typedef struct {
	MailSearchArg *args;
	const char *msg;
	size_t size;

	size_t max_searchword_len;
} SearchTextContext;

static int msgset_contains(const char *set, unsigned int match_num,
			   unsigned int max_num)
{
	unsigned int num, num2;

	while (*set != '\0') {
		if (*set == '*') {
			set++;
			num = max_num;
		} else {
			num = 0;
			while (*set >= '0' && *set <= '9') {
				num = num*10 + (*set-'0');
				set++;
			}
		}

		if (*set == ',' || *set == '\0') {
			if (num == match_num)
				return TRUE;
			if (*set == '\0')
				return FALSE;
		} else if (*set == ':') {
			set++;

			if (*set == '*') {
				set++;

				if (match_num >= num && num <= max_num)
					return TRUE;
			} else {
				num2 = 0;
				while (*set >= '0' && *set <= '9') {
					num2 = num2*10 + (*set-'0');
					set++;
				}

				if (match_num >= num && match_num <= num2)
					return TRUE;
			}

			if (*set != ',')
				return FALSE;
		}

		set++;
	}

	return FALSE;
}

static uoff_t str_to_uoff_t(const char *str)
{
	uoff_t num;

	num = 0;
	while (*str != '\0') {
		if (*str < '0' || *str > '9')
			return 0;

		num = num*10 + (*str - '0');
	}

	return num;
}

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_index(IndexMailbox *ibox, MailIndexRecord *rec,
				  unsigned int seq, MailSearchArgType type,
				  const char *value)
{
	time_t t;
	uoff_t size;

	switch (type) {
	case SEARCH_ALL:
		return TRUE;
	case SEARCH_SET:
		return msgset_contains(value, seq, ibox->synced_messages_count);
	case SEARCH_UID:
		return msgset_contains(value, rec->uid,
				       ibox->synced_messages_count);

	/* flags */
	case SEARCH_ANSWERED:
		return rec->msg_flags & MAIL_ANSWERED;
	case SEARCH_DELETED:
		return rec->msg_flags & MAIL_DELETED;
	case SEARCH_DRAFT:
		return rec->msg_flags & MAIL_DRAFT;
	case SEARCH_FLAGGED:
		return rec->msg_flags & MAIL_FLAGGED;
	case SEARCH_SEEN:
		return rec->msg_flags & MAIL_SEEN;
	case SEARCH_RECENT:
		return rec->uid >= ibox->index->first_recent_uid;
	case SEARCH_KEYWORD:
		return FALSE;

	/* dates */
	case SEARCH_BEFORE:
		if (!imap_parse_date(value, &t))
			return FALSE;
		return rec->internal_date < t;
	case SEARCH_ON:
		if (!imap_parse_date(value, &t))
			return FALSE;
		return rec->internal_date >= t &&
			rec->internal_date < t + 3600*24;
	case SEARCH_SINCE:
		if (!imap_parse_date(value, &t))
			return FALSE;
		return rec->internal_date >= t;

	case SEARCH_SENTBEFORE:
		if (!imap_parse_date(value, &t))
			return FALSE;
		return rec->sent_date < t;
	case SEARCH_SENTON:
		if (!imap_parse_date(value, &t))
			return FALSE;
		return rec->sent_date >= t && rec->sent_date < t + 3600*24;
	case SEARCH_SENTSINCE:
		if (!imap_parse_date(value, &t))
			return FALSE;
		return rec->sent_date >= t;

	/* sizes, only with fastscanning */
	case SEARCH_SMALLER:
		if (!mail_index_get_virtual_size(ibox->index, rec, TRUE, &size))
			return -1;
		return size < str_to_uoff_t(value);
	case SEARCH_LARGER:
		if (!mail_index_get_virtual_size(ibox->index, rec, TRUE, &size))
			return -1;
		return size > str_to_uoff_t(value);

	default:
		return -1;
	}
}

static void search_index_arg(MailSearchArg *arg, void *context)
{
	SearchIndexContext *ctx = context;

	switch (search_arg_match_index(ctx->ibox, ctx->rec, ctx->seq,
				       arg->type, arg->value.str)) {
	case -1:
		/* unknown */
		break;
	case 0:
		ARG_SET_RESULT(arg, -1);
		break;
	default:
		ARG_SET_RESULT(arg, 1);
		break;
	}
}

static int match_field(MailIndex *index, MailIndexRecord *rec,
		       MailField field, const char *value)
{
	const char *field_value;
	size_t i, value_len;

	field_value = index->lookup_field(index, rec, field);
	if (field_value == NULL)
		return -1;

	/* note: value is already uppercased */
	value_len = strlen(value);
	for (i = 0; field_value[i] != '\0'; i++) {
		if (value[0] == i_toupper(field_value[i]) &&
		    strncasecmp(value, field_value+i, value_len) == 0)
			return 1;
	}

	return 0;
}

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_cached(MailIndex *index, MailIndexRecord *rec,
				   MailSearchArgType type, const char *value)
{
	switch (type) {
	case SEARCH_FROM:
		return match_field(index, rec, FIELD_TYPE_FROM, value);
	case SEARCH_TO:
		return match_field(index, rec, FIELD_TYPE_TO, value);
	case SEARCH_CC:
		return match_field(index, rec, FIELD_TYPE_CC, value);
	case SEARCH_BCC:
		return match_field(index, rec, FIELD_TYPE_BCC, value);
	case SEARCH_SUBJECT:
		return match_field(index, rec, FIELD_TYPE_SUBJECT, value);
	default:
		return -1;
	}
}

static void search_cached_arg(MailSearchArg *arg, void *context)
{
	SearchIndexContext *ctx = context;

	switch (search_arg_match_cached(ctx->ibox->index, ctx->rec,
					arg->type, arg->value.str)) {
	case -1:
		/* unknown */
		break;
	case 0:
		ARG_SET_RESULT(arg, -1);
		break;
	default:
		ARG_SET_RESULT(arg, 1);
		break;
	}
}

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_slow(MailIndex *index, MailIndexRecord *rec,
				 MailSearchArgType type, const char *value)
{
	uoff_t size;

	switch (type) {
	/* sizes, only with fastscanning */
	case SEARCH_SMALLER:
		if (!mail_index_get_virtual_size(index, rec, FALSE, &size))
			return -1;
		return size < str_to_uoff_t(value);
	case SEARCH_LARGER:
		if (!mail_index_get_virtual_size(index, rec, FALSE, &size))
			return -1;
		return size > str_to_uoff_t(value);

	default:
		return -1;
	}
}

static void search_slow_arg(MailSearchArg *arg, void *context)
{
	SearchIndexContext *ctx = context;

	switch (search_arg_match_slow(ctx->ibox->index, ctx->rec,
				      arg->type, arg->value.str)) {
	case -1:
		/* unknown */
		break;
	case 0:
		ARG_SET_RESULT(arg, -1);
		break;
	default:
		ARG_SET_RESULT(arg, 1);
		break;
	}
}

/* needle must be uppercased */
static int header_value_match(const char *haystack, size_t haystack_len,
			      const char *needle)
{
	const char *n;
	size_t i, j, needle_len, max;

	if (*needle == '\0')
		return TRUE;

	needle_len = strlen(needle);
	if (haystack_len < needle_len)
		return FALSE;

	max = haystack_len - needle_len;
	for (i = 0; i <= max; i++) {
		if (needle[0] != i_toupper(haystack[i]))
			continue;

		for (j = i, n = needle; j < haystack_len; j++) {
			if (haystack[j] == '\r') {
				if (j+1 != haystack_len)
					j++;
			}

			if (haystack[j] == '\n' && j+1 < haystack_len &&
			    IS_LWSP(haystack[j+1])) {
				/* long header continuation */
				j++;
			}

			if (*n++ != i_toupper(haystack[j]))
				break;

			if (*n == '\0')
				return 1;
		}
	}

	return -1;
}

static void search_header_arg(MailSearchArg *arg, void *context)
{
	SearchHeaderContext *ctx = context;
	const char *value;
	size_t len;
	int ret;

	/* first check that the field name matches to argument. */
	switch (arg->type) {
	case SEARCH_FROM:
		if (ctx->name_len != 4 ||
		    strncasecmp(ctx->name, "From", 4) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_TO:
		if (ctx->name_len != 2 ||
		    strncasecmp(ctx->name, "To", 2) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_CC:
		if (ctx->name_len != 2 ||
		    strncasecmp(ctx->name, "Cc", 2) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_BCC:
		if (ctx->name_len != 3 ||
		    strncasecmp(ctx->name, "Bcc", 3) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_SUBJECT:
		if (ctx->name_len != 7 ||
		    strncasecmp(ctx->name, "Subject", 7) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_HEADER:
		ctx->custom_header = TRUE;

		len = strlen(arg->value.str);
		if (ctx->name_len != len ||
		    strncasecmp(ctx->name, arg->value.str, len) != 0)
			return;

		value = arg->hdr_value;
	default:
		return;
	}

	/* then check if the value matches */
	ret = header_value_match(ctx->value, ctx->value_len, value);
        ARG_SET_RESULT(arg, ret);
}

static void search_header(MessagePart *part __attr_unused__,
			  const char *name, size_t name_len,
			  const char *value, size_t value_len,
			  void *context)
{
	SearchHeaderContext *ctx = context;

	if (ctx->custom_header ||
	    (name_len == 4 && strncasecmp(name, "From", 4) == 0) ||
	    (name_len == 2 && strncasecmp(name, "To", 2) == 0) ||
	    (name_len == 2 && strncasecmp(name, "Cc", 2) == 0) ||
	    (name_len == 3 && strncasecmp(name, "Bcc", 3) == 0) ||
	    (name_len == 7 && strncasecmp(name, "Subject", 7) == 0)) {
		ctx->name = name;
		ctx->value = value;
		ctx->name_len = name_len;
		ctx->value_len = value_len;

		ctx->custom_header = FALSE;
		mail_search_args_foreach(ctx->args, search_header_arg, ctx);
	}
}

static void search_text(MailSearchArg *arg, SearchTextContext *ctx)
{
	const char *p;
	size_t i, len, max;

	if (arg->result != 0)
		return;

	len = strlen(arg->value.str);
	if (len > ctx->max_searchword_len)
		ctx->max_searchword_len = len;

	if (ctx->size >= len) {
		max = ctx->size-len;
		for (i = 0, p = ctx->msg; i <= max; i++, p++) {
			if (i_toupper(*p) == arg->value.str[0] &&
			    strncasecmp(p, arg->value.str, len) == 0) {
				/* match */
				ARG_SET_RESULT(arg, 1);
				return;
			}
		}
	}
}

static void search_text_header(MailSearchArg *arg, void *context)
{
	SearchTextContext *ctx = context;

	if (arg->type == SEARCH_TEXT)
		search_text(arg, ctx);
}

static void search_text_body(MailSearchArg *arg, void *context)
{
	SearchTextContext *ctx = context;

	if (arg->type == SEARCH_TEXT || arg->type == SEARCH_BODY)
		search_text(arg, ctx);
}

static void search_text_set_unmatched(MailSearchArg *arg,
				      void *context __attr_unused__)
{
	if (arg->type == SEARCH_TEXT || arg->type == SEARCH_BODY)
		ARG_SET_RESULT(arg, -1);
}

static void search_arg_match_data(IOBuffer *inbuf, unsigned int max_size,
				  MailSearchArg *args,
				  MailSearchForeachFunc search_func)
{
	SearchTextContext ctx;
	size_t size;
	ssize_t ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.args = args;

	/* do this in blocks: read data, compare it for all search words, skip
	   for block size - (strlen(largest_searchword)-1) and continue. */
	while (max_size > 0 &&
	       (ret = io_buffer_read_max(inbuf, max_size)) > 0) {
		ctx.msg = io_buffer_get_data(inbuf, &size);
		if (size > 0) {
			ctx.size = max_size < size ? max_size : size;
			max_size -= ctx.size;

			mail_search_args_foreach(args, search_func, &ctx);

			if (ctx.max_searchword_len < size)
				size -= ctx.max_searchword_len-1;
			io_buffer_skip(inbuf, size);
		}
	}
}

static int search_arg_match_text(IndexMailbox *ibox, MailIndexRecord *rec,
				 MailSearchArg *args)
{
	IOBuffer *inbuf;
	int have_headers, have_body, have_text;

	/* first check what we need to use */
	mail_search_args_analyze(args, &have_headers, &have_body, &have_text);
	if (!have_headers && !have_body && !have_text)
		return TRUE;

	inbuf = ibox->index->open_mail(ibox->index, rec);
	if (inbuf == NULL)
		return FALSE;

	if (have_headers) {
		SearchHeaderContext ctx;

		memset(&ctx, 0, sizeof(ctx));

		/* header checks */
		ctx.custom_header = TRUE;
		ctx.args = args;
		message_parse_header(NULL, inbuf, NULL, search_header, &ctx);
	}

	if (have_text) {
		if (inbuf->offset != 0) {
			/* need to rewind back to beginning of headers */
			if (!io_buffer_seek(inbuf, 0)) {
				i_error("io_buffer_seek() failed: %m");
				return FALSE;
			}
		}

		search_arg_match_data(inbuf, rec->header_size,
				      args, search_text_header);
	}

	if (have_text || have_body) {
		if (inbuf->offset != rec->header_size) {
			/* skip over headers */
			i_assert(inbuf->offset == 0);
			io_buffer_skip(inbuf, rec->header_size);
		}

		search_arg_match_data(inbuf, UINT_MAX, args, search_text_body);

		/* set the rest as unmatched */
		mail_search_args_foreach(args, search_text_set_unmatched, NULL);
	}

	(void)close(inbuf->fd);
	io_buffer_destroy(inbuf);
	return TRUE;
}

static void seq_update(const char *set, unsigned int *first_seq,
		       unsigned int *last_seq, unsigned int max_value)
{
	unsigned int seq;

	while (*set != '\0') {
		if (*set == '*') {
			seq = max_value;
			set++;
		} else {
			seq = 0;
			while (*set >= '0' && *set <= '9') {
				seq = seq*10 + (*set-'0');
				set++;
			}
		}

		if (seq != 0) {
			if (*first_seq == 0 || seq < *first_seq)
				*first_seq = seq;
			if (*last_seq == 0 || seq > *last_seq)
				*last_seq = seq;
		}

		set++;
	}
}

static void search_get_sequid(IndexMailbox *ibox, MailSearchArg *args,
			      unsigned int *first_seq, unsigned int *last_seq,
			      unsigned int *first_uid, unsigned int *last_uid)
{
	for (; args != NULL; args = args->next) {
		if (args->type == SEARCH_OR || args->type == SEARCH_SUB) {
			search_get_sequid(ibox, args->value.subargs,
					  first_seq, last_seq,
					  first_uid, last_uid);
		} if (args->type == SEARCH_SET) {
			seq_update(args->value.str, first_seq, last_seq,
				   ibox->synced_messages_count);
		} else if (args->type == SEARCH_UID) {
			seq_update(args->value.str, first_uid, last_uid,
				   ibox->index->header->next_uid-1);
		} else if (args->type == SEARCH_ALL) {
			/* go through everything */
			*first_seq = 1;
			*last_seq = ibox->synced_messages_count;
			return;
		}
	}
}

static void search_get_sequences(IndexMailbox *ibox, MailSearchArg *args,
				 unsigned int *first_seq,
				 unsigned int *last_seq)
{
	MailIndexRecord *rec;
	unsigned int seq, first_uid, last_uid;

	*first_seq = *last_seq = 0;
	first_uid = last_uid = 0;

	search_get_sequid(ibox, args, first_seq, last_seq,
			  &first_uid, &last_uid);

	/* seq_update() should make sure that these can't happen */
	i_assert(*first_seq <= *last_seq);
	i_assert(first_uid <= last_uid);

	if (first_uid != 0 && (*first_seq != 1 ||
			       *last_seq != ibox->synced_messages_count)) {
		/* UIDs were used - see if they affect the sequences */
		rec = ibox->index->lookup_uid_range(ibox->index,
						    first_uid, last_uid);
		if (rec != NULL) {
			/* update lower UID */
			seq = ibox->index->get_sequence(ibox->index, rec);
			if (seq < *first_seq)
				*first_seq = seq;

			/* update higher UID .. except we don't really
			   know it and it'd be uselessly slow to find it.
			   use a kludgy method which might limit the
			   sequences. */
			seq += last_uid-first_uid;
			if (seq >= ibox->synced_messages_count)
				seq = ibox->synced_messages_count;

			if (seq > *last_seq)
				*last_seq = seq;
		}
	}

	if (*first_seq == 0)
		*first_seq = 1;
	if (*last_seq == 0)
		*last_seq = ibox->synced_messages_count;

	i_assert(*first_seq <= *last_seq);
}

static void search_messages(IndexMailbox *ibox, MailSearchArg *args,
			    IOBuffer *outbuf, int uid_result)
{
	SearchIndexContext ctx;
	MailIndexRecord *rec;
	unsigned int first_seq, last_seq, seq;
	char num[MAX_LARGEST_T_STRLEN+10];

	if (ibox->synced_messages_count == 0)
		return;

	/* see if we can limit the records we look at */
	search_get_sequences(ibox, args, &first_seq, &last_seq);

	ctx.ibox = ibox;
	rec = ibox->index->lookup(ibox->index, first_seq);
	for (seq = first_seq; rec != NULL && seq <= last_seq; seq++) {
		ctx.rec = rec;
		ctx.seq = seq;

		mail_search_args_reset(args);

		mail_search_args_foreach(args, search_index_arg, &ctx);
		mail_search_args_foreach(args, search_cached_arg, &ctx);
		mail_search_args_foreach(args, search_slow_arg, &ctx);

		if (search_arg_match_text(ibox, rec, args) &&
		    args->result == 1) {
			i_snprintf(num, sizeof(num), " %u",
				   uid_result ? rec->uid : seq);
			io_buffer_send(outbuf, num, strlen(num));
		}
		rec = ibox->index->next(ibox->index, rec);
	}
}

int index_storage_search(Mailbox *box, MailSearchArg *args,
			 IOBuffer *outbuf, int uid_result)
{
	IndexMailbox *ibox = (IndexMailbox *) box;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(ibox);

	io_buffer_send(outbuf, "* SEARCH", 8);
	search_messages(ibox, args, outbuf, uid_result);
	io_buffer_send(outbuf, "\r\n", 2);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	return TRUE;
}
