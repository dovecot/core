/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "mmap-util.h"
#include "rfc822-date.h"
#include "rfc822-tokenize.h"
#include "index-storage.h"
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
} SearchIndexData;

typedef struct {
	MailSearchArg *args;
	int custom_header;

	const char *name, *value;
	unsigned int name_len, value_len;
} SearchHeaderData;

typedef struct {
	MailSearchArg *args;
	const char *msg;
	size_t size;
	int last_block;
} SearchTextData;

/* truncate timestamp to day */
static time_t timestamp_trunc(time_t t)
{
	struct tm *tm;

	tm = localtime(&t);
	tm->tm_hour = tm->tm_min = tm->tm_sec = 0;

	return mktime(tm);
}

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

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_index(IndexMailbox *ibox, MailIndexRecord *rec,
				  unsigned int seq, MailSearchArgType type,
				  const char *value)
{
	time_t t;

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
		if (!rfc822_parse_date(value, &t))
			return FALSE;
		return rec->internal_date < timestamp_trunc(t);
	case SEARCH_ON:
		if (!rfc822_parse_date(value, &t))
			return FALSE;
		t = timestamp_trunc(t);
		return rec->internal_date >= t &&
			rec->internal_date < t + 3600*24;
	case SEARCH_SINCE:
		if (!rfc822_parse_date(value, &t))
			return FALSE;
		return rec->internal_date >= timestamp_trunc(t);

	case SEARCH_SENTBEFORE:
		if (!rfc822_parse_date(value, &t))
			return FALSE;
		return rec->sent_date < timestamp_trunc(t);
	case SEARCH_SENTON:
		if (!rfc822_parse_date(value, &t))
			return FALSE;
		t = timestamp_trunc(t);
		return rec->sent_date >= t &&
			rec->sent_date < t + 3600*24;
	case SEARCH_SENTSINCE:
		if (!rfc822_parse_date(value, &t))
			return FALSE;
		return rec->sent_date >= timestamp_trunc(t);

	/* sizes */
	case SEARCH_SMALLER:
		return rec->full_virtual_size < strtoul(value, NULL, 10);
	case SEARCH_LARGER:
		return rec->full_virtual_size > strtoul(value, NULL, 10);

	default:
		return -1;
	}
}

static void search_index_arg(MailSearchArg *arg, void *user_data)
{
	SearchIndexData *data = user_data;

	switch (search_arg_match_index(data->ibox, data->rec, data->seq,
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
	unsigned int i, value_len;

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

static void search_cached_arg(MailSearchArg *arg, void *user_data)
{
	SearchIndexData *data = user_data;

	switch (search_arg_match_cached(data->ibox->index, data->rec,
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
static int header_value_match(const char *haystack, unsigned int haystack_len,
			      const char *needle)
{
	const char *n;
	unsigned int i, j, needle_len, max;

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

static void search_header_arg(MailSearchArg *arg, void *user_data)
{
	SearchHeaderData *data = user_data;
	const char *value;
	unsigned int len;
	int ret;

	/* first check that the field name matches to argument. */
	switch (arg->type) {
	case SEARCH_FROM:
		if (data->name_len != 4 ||
		    strncasecmp(data->name, "From", 4) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_TO:
		if (data->name_len != 2 ||
		    strncasecmp(data->name, "To", 2) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_CC:
		if (data->name_len != 2 ||
		    strncasecmp(data->name, "Cc", 2) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_BCC:
		if (data->name_len != 3 ||
		    strncasecmp(data->name, "Bcc", 3) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_SUBJECT:
		if (data->name_len != 7 ||
		    strncasecmp(data->name, "Subject", 7) != 0)
			return;
		value = arg->value.str;
		break;
	case SEARCH_HEADER:
		data->custom_header = TRUE;

		len = strlen(arg->value.str);
		if (data->name_len != len ||
		    strncasecmp(data->name, arg->value.str, len) != 0)
			return;

		value = arg->hdr_value;
	default:
		return;
	}

	/* then check if the value matches */
	ret = header_value_match(data->value, data->value_len, value);
        ARG_SET_RESULT(arg, ret);
}

static void search_header(MessagePart *part __attr_unused__,
			  const char *name, unsigned int name_len,
			  const char *value, unsigned int value_len,
			  void *user_data)
{
	SearchHeaderData *data = user_data;

	if (data->custom_header ||
	    (name_len == 4 && strncasecmp(name, "From", 4) == 0) ||
	    (name_len == 2 && strncasecmp(name, "To", 2) == 0) ||
	    (name_len == 2 && strncasecmp(name, "Cc", 2) == 0) ||
	    (name_len == 3 && strncasecmp(name, "Bcc", 3) == 0) ||
	    (name_len == 7 && strncasecmp(name, "Subject", 7) == 0)) {
		data->name = name;
		data->value = value;
		data->name_len = name_len;
		data->value_len = value_len;

		data->custom_header = FALSE;
		mail_search_args_foreach(data->args, search_header_arg, data);
	}
}

static void search_text(MailSearchArg *arg, SearchTextData *data)
{
	const char *p;
	unsigned int i, len, max;

	if (arg->result != 0)
		return;

	len = strlen(arg->value.str);
	max = data->size-len;
	for (i = 0, p = data->msg; i <= max; i++, p++) {
		if (i_toupper(*p) == arg->value.str[0] &&
		    strncasecmp(p, arg->value.str, len) == 0) {
			/* match */
			ARG_SET_RESULT(arg, 1);
			return;
		}
	}

	if (data->last_block)
		ARG_SET_RESULT(arg, -1);
}

static void search_text_header(MailSearchArg *arg, void *user_data)
{
	SearchTextData *data = user_data;

	if (arg->type == SEARCH_TEXT)
		search_text(arg, data);
}

static void search_text_body(MailSearchArg *arg, void *user_data)
{
	SearchTextData *data = user_data;

	if (arg->type == SEARCH_TEXT || arg->type == SEARCH_BODY)
		search_text(arg, data);
}

static int search_arg_match_text(IndexMailbox *ibox, MailIndexRecord *rec,
				 MailSearchArg *args)
{
	const char *msg;
	void *mmap_base;
	off_t offset;
	size_t size, mmap_length;
	int fd, failed;
	int have_headers, have_body, have_text;

	/* first check what we need to use */
	mail_search_args_analyze(args, &have_headers, &have_body, &have_text);
	if (!have_headers && !have_body && !have_text)
		return TRUE;

	fd = ibox->index->open_mail(ibox->index, rec, &offset, &size);
	if (fd == -1)
		return FALSE;

	mmap_base = mmap_aligned(fd, PROT_READ, offset, size,
				 (void **) &msg, &mmap_length);
	if (mmap_base == MAP_FAILED) {
		failed = TRUE;
		mail_storage_set_critical(ibox->box.storage, "mmap() failed "
					  "for msg %u: %m", rec->uid);
	} else {
		failed = FALSE;
		(void)madvise(mmap_base, mmap_length, MADV_SEQUENTIAL);

		if (have_headers) {
			SearchHeaderData data;

			memset(&data, 0, sizeof(data));

			/* header checks */
			data.custom_header = TRUE;
			data.args = args;
			message_parse_header(NULL, msg, size, NULL,
					     search_header, &data);
		}

		if (have_text) {
			/* first search text from header*/
			SearchTextData data;

			data.args = args;
			data.msg = msg;
			data.size = rec->header_size;
			data.last_block = FALSE;

			mail_search_args_foreach(args, search_text_header,
						 &data);
		}

		if (have_text || have_body) {
			/* search text from body */
			SearchTextData data;

			/* FIXME: we should check this in blocks, so the whole
			   message doesn't need to be in memory */
			data.args = args;
			data.msg = msg + rec->header_size;
			data.size = size - rec->header_size;
			data.last_block = TRUE;

			mail_search_args_foreach(args, search_text_body, &data);
		}
	}

	(void)munmap(mmap_base, mmap_length);
	(void)close(fd);
	return !failed;
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

		seq++;
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
}

static void search_messages(IndexMailbox *ibox, MailSearchArg *args,
			    IOBuffer *outbuf, int uid_result)
{
	SearchIndexData data;
	MailIndexRecord *rec;
	unsigned int first_seq, last_seq, seq;
	char num[MAX_INT_STRLEN+10];

	/* see if we can limit the records we look at */
	search_get_sequences(ibox, args, &first_seq, &last_seq);

	data.ibox = ibox;

	rec = ibox->index->lookup(ibox->index, first_seq);
	for (seq = first_seq; rec != NULL && seq <= last_seq; seq++) {
		data.rec = rec;
		data.seq = seq;

		mail_search_args_reset(args);

		mail_search_args_foreach(args, search_index_arg, &data);
		mail_search_args_foreach(args, search_cached_arg, &data);

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
	int failed;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
		failed = TRUE;
	else {
		io_buffer_send(outbuf, "* SEARCH", 8);

		search_messages(ibox, args, outbuf, uid_result);
		failed = !ibox->index->set_lock(ibox->index,
						MAIL_LOCK_UNLOCK);
		io_buffer_send(outbuf, "\r\n", 2);
	}

	if (failed)
		(void)mail_storage_set_index_error(ibox);

	return !failed;
}
