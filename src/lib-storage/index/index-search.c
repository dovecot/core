/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-address.h"
#include "message-date.h"
#include "message-body-search.h"
#include "message-header-search.h"
#include "imap-date.h"
#include "imap-envelope.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "index-mail.h"
#include "mail-custom-flags.h"
#include "mail-modifylog.h"
#include "mail-search.h"

#include <stdlib.h>
#include <ctype.h>

#define ARG_SET_RESULT(arg, res) \
	STMT_START { \
		(arg)->result = !(arg)->not ? (res) : \
			(res) == -1 ? -1 : !(res); \
	} STMT_END

#define TXT_UNKNOWN_CHARSET "[BADCHARSET] Unknown charset"
#define TXT_INVALID_SEARCH_KEY "Invalid search key"

struct mail_search_context {
	struct index_mailbox *ibox;
	char *charset;
	struct mail_search_arg *args;

	struct messageset_context *msgset_ctx;
	struct index_mail imail;
	struct mail *mail;

	pool_t hdr_pool;
	const char *error;

	int failed;
};

struct search_header_context {
        struct mail_search_context *index_context;
	struct mail_search_arg *args;

	const unsigned char *name, *value;
	size_t name_len, value_len;

	unsigned int custom_header:1;
	unsigned int threading:1;
};

struct search_body_context {
        struct mail_search_context *index_ctx;
	struct istream *input;
	const struct message_part *part;
};

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

			if (num == 0)
				return FALSE;
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

				if (num2 == 0)
					return FALSE;

				if (num > num2) {
					/* swap, as specified by latest
					   IMAP4rev1 draft */
					unsigned int temp = num;
					num = num2;
					num2 = temp;
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
		str++;
	}

	return num;
}

static int search_keyword(struct mail_index *index,
			  struct mail_index_record *rec, const char *value)
{
	const char **custom_flags;
	int i;

	if ((rec->msg_flags & MAIL_CUSTOM_FLAGS_MASK) == 0)
		return FALSE;

	custom_flags = mail_custom_flags_list_get(index->custom_flags);
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (custom_flags[i] != NULL &&
		    strcasecmp(custom_flags[i], value) == 0) {
			return rec->msg_flags &
				(1 << (MAIL_CUSTOM_FLAG_1_BIT+i));
		}
	}

	return FALSE;
}

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_index(struct index_mailbox *ibox,
				  struct mail_index_record *rec,
				  unsigned int client_seq,
				  enum mail_search_arg_type type,
				  const char *value)
{
	switch (type) {
	case SEARCH_ALL:
		return 1;
	case SEARCH_SET:
		return msgset_contains(value, client_seq,
				       ibox->synced_messages_count);
	case SEARCH_UID:
		return msgset_contains(value, rec->uid,
				       ibox->index->header->next_uid-1);

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
		return search_keyword(ibox->index, rec, value);

	default:
		return -1;
	}
}

static void search_index_arg(struct mail_search_arg *arg, void *context)
{
	struct mail_search_context *ctx = context;

	switch (search_arg_match_index(ctx->ibox, ctx->imail.data.rec,
				       ctx->mail->seq,
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
static int search_arg_match_cached(struct mail_search_context *ctx,
				   enum mail_search_arg_type type,
				   const char *value)
{
	time_t internal_date, search_time;
	uoff_t virtual_size, search_size;

	switch (type) {
	/* internal dates */
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		internal_date = ctx->mail->get_received_date(ctx->mail);
		if (internal_date == (time_t)-1)
			return -1;

		if (!imap_parse_date(value, &search_time))
			return 0;

		switch (type) {
		case SEARCH_BEFORE:
			return internal_date < search_time;
		case SEARCH_ON:
			return internal_date >= search_time &&
				internal_date < search_time + 3600*24;
		case SEARCH_SINCE:
			return internal_date >= search_time;
		default:
			/* unreachable */
			break;
		}

	/* sizes */
	case SEARCH_SMALLER:
	case SEARCH_LARGER:
		virtual_size = ctx->mail->get_size(ctx->mail);
		if (virtual_size == (uoff_t)-1)
			return -1;

		search_size = str_to_uoff_t(value);
		if (type == SEARCH_SMALLER)
			return virtual_size < search_size;
		else
			return virtual_size > search_size;

	default:
		return -1;
	}
}

static void search_cached_arg(struct mail_search_arg *arg, void *context)
{
	struct mail_search_context *ctx = context;

	switch (search_arg_match_cached(ctx, arg->type,
					arg->value.str)) {
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

static int search_sent(enum mail_search_arg_type type, const char *search_value,
		       const char *sent_value)
{
	time_t search_time, sent_time;
	int timezone_offset;

	if (sent_value == NULL)
		return 0;

	if (!imap_parse_date(search_value, &search_time))
		return 0;

	/* NOTE: Latest IMAP4rev1 draft specifies that timezone is ignored
	   in searches. sent_time is returned as UTC, so change it. */
	if (!message_date_parse((const unsigned char *) sent_value, (size_t)-1,
				&sent_time, &timezone_offset))
		return 0;
	sent_time -= timezone_offset * 60;

	switch (type) {
	case SEARCH_SENTBEFORE:
		return sent_time < search_time;
	case SEARCH_SENTON:
		return sent_time >= search_time &&
			sent_time < search_time + 3600*24;
	case SEARCH_SENTSINCE:
		return sent_time >= search_time;
	default:
                i_unreached();
	}
}

static struct header_search_context *
search_header_context(struct mail_search_context *ctx,
		      struct mail_search_arg *arg)
{
	int unknown_charset;

	if (arg->context != NULL) {
                message_header_search_reset(arg->context);
		return arg->context;
	}

	if (ctx->hdr_pool == NULL) {
		ctx->hdr_pool =
			pool_alloconly_create("message_header_search", 8192);
	}

	arg->context = message_header_search_init(ctx->hdr_pool, arg->value.str,
						  ctx->charset,
						  &unknown_charset);
	if (arg->context == NULL) {
		ctx->error = unknown_charset ?
			TXT_UNKNOWN_CHARSET : TXT_INVALID_SEARCH_KEY;
	}

	return arg->context;
}

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_envelope(struct mail_search_context *ctx,
				     struct mail_search_arg *arg)
{
	struct mail_index *index = ctx->ibox->index;
	enum imap_envelope_field env_field;
        struct header_search_context *hdr_search_ctx;
	const char *envelope, *field;
	int ret;

	switch (arg->type) {
	case SEARCH_SENTBEFORE:
	case SEARCH_SENTON:
	case SEARCH_SENTSINCE:
                env_field = IMAP_ENVELOPE_DATE;
		break;

	case SEARCH_FROM:
                env_field = IMAP_ENVELOPE_FROM;
		break;
	case SEARCH_TO:
                env_field = IMAP_ENVELOPE_TO;
		break;
	case SEARCH_CC:
                env_field = IMAP_ENVELOPE_CC;
		break;
	case SEARCH_BCC:
                env_field = IMAP_ENVELOPE_BCC;
		break;
	case SEARCH_SUBJECT:
                env_field = IMAP_ENVELOPE_SUBJECT;
		break;

	case SEARCH_IN_REPLY_TO:
                env_field = IMAP_ENVELOPE_IN_REPLY_TO;
		break;
	case SEARCH_MESSAGE_ID:
                env_field = IMAP_ENVELOPE_MESSAGE_ID;
		break;
	default:
		return -1;
	}

	t_push();

	/* get field from hopefully cached envelope */
	envelope = index->lookup_field(index, ctx->imail.data.rec,
				       DATA_FIELD_ENVELOPE);
	if (envelope != NULL) {
		ret = imap_envelope_parse(envelope, env_field,
					  IMAP_ENVELOPE_RESULT_TYPE_STRING,
					  &field) ? 1 : -1;
	} else {
		index->cache_fields_later(index, DATA_FIELD_ENVELOPE);
		field = NULL;
		ret = -1;
	}

	if (ret != -1) {
		switch (arg->type) {
		case SEARCH_SENTBEFORE:
		case SEARCH_SENTON:
		case SEARCH_SENTSINCE:
			ret = search_sent(arg->type, arg->value.str, field);
		default:
			if (arg->value.str[0] == '\0') {
				/* we're just testing existence of the field.
				   assume it matches with non-NIL values. */
				ret = field != NULL ? 1 : 0;
				break;
			}

			if (field == NULL) {
				/* doesn't exist */
				ret = 0;
				break;
			}

			hdr_search_ctx = search_header_context(ctx, arg);
			if (hdr_search_ctx == NULL) {
				ret = 0;
				break;
			}

			ret = message_header_search(
						(const unsigned char *) field,
						strlen(field),
						hdr_search_ctx) ? 1 : 0;
		}
	}
	t_pop();
	return ret;
}

static void search_envelope_arg(struct mail_search_arg *arg, void *context)
{
	struct mail_search_context *ctx = context;

	switch (search_arg_match_envelope(ctx, arg)) {
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

static void search_header_arg(struct mail_search_arg *arg, void *context)
{
	struct search_header_context *ctx = context;
        struct header_search_context *hdr_search_ctx;
	size_t len;
	int ret;

	/* first check that the field name matches to argument. */
	switch (arg->type) {
	case SEARCH_SENTBEFORE:
	case SEARCH_SENTON:
	case SEARCH_SENTSINCE:
		/* date is handled differently than others */
		if (ctx->name_len == 4 &&
		    memcasecmp(ctx->name, "Date", 4) == 0) {
			search_sent(arg->type, arg->value.str,
				    t_strndup(ctx->value, ctx->value_len));
		}
		return;

	case SEARCH_FROM:
		if (ctx->name_len != 4 || memcasecmp(ctx->name, "From", 4) != 0)
			return;
		break;
	case SEARCH_TO:
		if (ctx->name_len != 2 || memcasecmp(ctx->name, "To", 2) != 0)
			return;
		break;
	case SEARCH_CC:
		if (ctx->name_len != 2 || memcasecmp(ctx->name, "Cc", 2) != 0)
			return;
		break;
	case SEARCH_BCC:
		if (ctx->name_len != 3 || memcasecmp(ctx->name, "Bcc", 3) != 0)
			return;
		break;
	case SEARCH_SUBJECT:
		if (ctx->name_len != 7 ||
		    memcasecmp(ctx->name, "Subject", 7) != 0)
			return;
		break;
	case SEARCH_HEADER:
		ctx->custom_header = TRUE;

		len = strlen(arg->hdr_field_name);
		if (ctx->name_len != len ||
		    memcasecmp(ctx->name, arg->hdr_field_name, len) != 0)
			return;
	case SEARCH_TEXT:
		/* TEXT goes through all headers */
		ctx->custom_header = TRUE;
		break;
	default:
		return;
	}

	if (arg->value.str[0] == '\0') {
		/* we're just testing existence of the field. always matches. */
		ret = 1;
	} else {
		t_push();

		hdr_search_ctx = search_header_context(ctx->index_context, arg);
		if (hdr_search_ctx == NULL)
			ret = 0;
		else if (arg->type == SEARCH_FROM || arg->type == SEARCH_TO ||
			 arg->type == SEARCH_CC || arg->type == SEARCH_BCC) {
			/* we have to match against normalized address */
			struct message_address *addr;
			string_t *str;

			addr = message_address_parse(data_stack_pool,
						     ctx->value, ctx->value_len,
						     0);
			str = t_str_new(ctx->value_len);
			message_address_write(str, addr);
			ret = message_header_search(str_data(str), str_len(str),
						    hdr_search_ctx) ? 1 : 0;
		} else {
			ret = message_header_search(ctx->value, ctx->value_len,
						    hdr_search_ctx) ? 1 : 0;
		}
		t_pop();
	}

        ARG_SET_RESULT(arg, ret);
}

static void search_header(struct message_part *part,
			  const unsigned char *name, size_t name_len,
			  const unsigned char *value, size_t value_len,
			  void *context)
{
	struct search_header_context *ctx = context;

	index_mail_parse_header(part, name, name_len, value, value_len,
				ctx->index_context->mail);

	if ((ctx->custom_header && name_len > 0) ||
	    (name_len == 4 && memcasecmp(name, "Date", 4) == 0) ||
	    (name_len == 4 && memcasecmp(name, "From", 4) == 0) ||
	    (name_len == 2 && memcasecmp(name, "To", 2) == 0) ||
	    (name_len == 2 && memcasecmp(name, "Cc", 2) == 0) ||
	    (name_len == 3 && memcasecmp(name, "Bcc", 3) == 0) ||
	    (name_len == 7 && memcasecmp(name, "Subject", 7) == 0)) {
		ctx->name = name;
		ctx->value = value;
		ctx->name_len = name_len;
		ctx->value_len = value_len;

		ctx->custom_header = FALSE;
		mail_search_args_foreach(ctx->args, search_header_arg, ctx);
	}
}

static void search_body(struct mail_search_arg *arg, void *context)
{
	struct search_body_context *ctx = context;
	int ret, unknown_charset;

	if (ctx->index_ctx->error != NULL)
		return;

	if (arg->type == SEARCH_TEXT || arg->type == SEARCH_BODY) {
		i_stream_seek(ctx->input, 0);
		ret = message_body_search(arg->value.str,
					  ctx->index_ctx->charset,
					  &unknown_charset, ctx->input,
					  ctx->part, arg->type == SEARCH_TEXT);

		if (ret < 0) {
			ctx->index_ctx->error = unknown_charset ?
				TXT_UNKNOWN_CHARSET : TXT_INVALID_SEARCH_KEY;
		}

		ARG_SET_RESULT(arg, ret > 0);
	}
}

static int search_arg_match_text(struct mail_search_arg *args,
				 struct mail_search_context *ctx)
{
	struct istream *input;
	int have_headers, have_body, have_text;

	/* first check what we need to use */
	mail_search_args_analyze(args, &have_headers, &have_body, &have_text);
	if (!have_headers && !have_body && !have_text)
		return TRUE;

	if (have_headers || have_text) {
		struct search_header_context hdr_ctx;

		input = ctx->mail->get_stream(ctx->mail, NULL, NULL);
		if (input == NULL)
			return FALSE;

		memset(&hdr_ctx, 0, sizeof(hdr_ctx));
		hdr_ctx.index_context = ctx;
		hdr_ctx.custom_header = TRUE;
		hdr_ctx.args = args;

		index_mail_init_parse_header(&ctx->imail);
		message_parse_header(NULL, input, NULL,
				     search_header, &hdr_ctx);
	} else {
		struct message_size hdr_size;

		input = ctx->mail->get_stream(ctx->mail, &hdr_size, NULL);
		if (input == NULL)
			return FALSE;

		i_stream_seek(input, hdr_size.physical_size);
	}

	if (have_text || have_body) {
		struct search_body_context body_ctx;

		memset(&body_ctx, 0, sizeof(body_ctx));
		body_ctx.index_ctx = ctx;
		body_ctx.input = input;
		body_ctx.part = ctx->mail->get_parts(ctx->mail);

		mail_search_args_foreach(args, search_body, &body_ctx);
	}
	return TRUE;
}

static int seq_update(const char *set, unsigned int *first_seq,
		      unsigned int *last_seq, unsigned int max_value)
{
	unsigned int seq;
	int first = TRUE;

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

		if (seq == 0)
			return FALSE;

		if (*first_seq == 0 || seq < *first_seq)
			*first_seq = seq;
		if (*last_seq == 0 || seq > *last_seq)
			*last_seq = seq;

		if (*set != '\0') {
			if (*set == ',')
				first = TRUE;
			else if (*set == ':' && first)
				first = FALSE;
			else
				return FALSE;
			set++;
		}
	}

	return TRUE;
}

static int search_get_sequid(struct index_mailbox *ibox,
			     const struct mail_search_arg *args,
			     unsigned int *first_seq, unsigned int *last_seq,
			     unsigned int *first_uid, unsigned int *last_uid)
{
	for (; args != NULL; args = args->next) {
		if (args->type == SEARCH_OR || args->type == SEARCH_SUB) {
			if (!search_get_sequid(ibox, args->value.subargs,
					       first_seq, last_seq,
					       first_uid, last_uid))
				return FALSE;
		} if (args->type == SEARCH_SET) {
			if (!seq_update(args->value.str, first_seq, last_seq,
					ibox->synced_messages_count)) {
				mail_storage_set_error(ibox->box.storage,
						       "Invalid messageset: %s",
						       args->value.str);
				return FALSE;
			}
		} else if (args->type == SEARCH_UID) {
			if (!seq_update(args->value.str, first_uid, last_uid,
					ibox->index->header->next_uid-1)) {
				mail_storage_set_error(ibox->box.storage,
						       "Invalid messageset: %s",
						       args->value.str);
				return FALSE;
			}
		} else if (args->type == SEARCH_ALL) {
			/* go through everything */
			*first_seq = 1;
			*last_seq = ibox->synced_messages_count;
			return TRUE;
		}
	}

	return TRUE;
}

static int search_limit_by_flags(struct index_mailbox *ibox,
				 const struct mail_search_arg *args,
				 unsigned int *first_uid,
				 unsigned int *last_uid)
{
	struct mail_index_header *hdr;
	unsigned int uid;

	hdr = ibox->index->header;
	for (; args != NULL; args = args->next) {
		if (args->type == SEARCH_SEEN) {
			/* SEEN with 0 seen? */
			if (!args->not && hdr->seen_messages_count == 0)
				return FALSE;

			/* UNSEEN with all seen? */
			if (args->not &&
			    hdr->seen_messages_count == hdr->messages_count)
				return FALSE;

			/* UNSEEN with lowwater limiting */
			uid = hdr->first_unseen_uid_lowwater;
			if (args->not && *first_uid < uid)
				*first_uid = uid;
		}

		if (args->type == SEARCH_DELETED) {
			/* DELETED with 0 deleted? */
			if (!args->not && hdr->deleted_messages_count == 0)
				return FALSE;

			/* UNDELETED with all deleted? */
			if (!args->not &&
			    hdr->deleted_messages_count == hdr->messages_count)
				return FALSE;

			/* DELETED with lowwater limiting */
			uid = hdr->first_deleted_uid_lowwater;
			if (!args->not && *first_uid < uid)
				*first_uid = uid;
		}

		if (args->type == SEARCH_RECENT) {
			uid = ibox->index->first_recent_uid;
			if (!args->not && *first_uid < uid)
				*first_uid = ibox->index->first_recent_uid;
			else if (args->not && *last_uid >= uid)
				*last_uid = uid-1;
		}
	}

	return *first_uid <= *last_uid;
}

static int client_seq_to_uid(struct index_mailbox *ibox,
			     unsigned int seq, unsigned int *uid)
{
	struct mail_index_record *rec;
	unsigned int expunges_before;

	if (seq > ibox->synced_messages_count) {
		mail_storage_set_error(ibox->box.storage,
				       "Sequence out of range: %u", seq);
		return FALSE;
	}

	if (mail_modifylog_seq_get_expunges(ibox->index->modifylog, seq, seq,
					    &expunges_before) == NULL)
		return FALSE;

	seq -= expunges_before;

	rec = ibox->index->lookup(ibox->index, seq);
	*uid = rec == NULL ? 0 : rec->uid;
	return TRUE;
}

static int search_get_uid_range(struct index_mailbox *ibox,
				const struct mail_search_arg *args,
				unsigned int *first_uid, unsigned int *last_uid)
{
	unsigned int first_seq, last_seq, uid;

	*first_uid = *last_uid = 0;
	first_seq = last_seq = 0;

	if (!search_get_sequid(ibox, args, &first_seq, &last_seq,
			       first_uid, last_uid))
		return -1;

	/* seq_update() should make sure that these can't happen */
	i_assert(first_seq <= last_seq);
	i_assert(*first_uid <= *last_uid);

	if (first_seq > 1) {
		if (!client_seq_to_uid(ibox, first_seq, &uid))
			return -1;
		if (uid == 0)
			return 0;

		if (*first_uid == 0 || uid < *first_uid)
			*first_uid = uid;
	}

	if (last_seq > 1 && last_seq != ibox->synced_messages_count) {
		if (!client_seq_to_uid(ibox, last_seq, &uid))
			return -1;
		if (uid == 0)
			return 0;

		if (*last_uid == 0 || uid > *last_uid)
			*last_uid = uid;
	}

	if (*first_uid == 0)
		*first_uid = 1;
	if (*last_uid == 0 || last_seq == ibox->synced_messages_count)
		*last_uid = ibox->index->header->next_uid-1;

	/* UNSEEN and DELETED in root search level may limit the range */
	if (!search_limit_by_flags(ibox, args, first_uid, last_uid))
		return 0;

	i_assert(*first_uid <= *last_uid);
	return 1;
}

int index_storage_search_get_sorting(struct mailbox *box __attr_unused__,
				     enum mail_sort_type *sort_program)
{
	/* currently we don't support sorting */
	*sort_program = MAIL_SORT_END;
	return TRUE;
}

struct mail_search_context *
index_storage_search_init(struct mailbox *box, const char *charset,
			  struct mail_search_arg *args,
			  const enum mail_sort_type *sort_program,
			  enum mail_fetch_field wanted_fields,
			  const char *const wanted_headers[])
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mail_search_context *ctx;
	unsigned int first_uid, last_uid;

	if (sort_program != NULL && *sort_program != MAIL_SORT_END) {
		i_error("BUG: index_storage_search_init(): "
			"invalid sort_program");
		return NULL;
	}

	if (!index_storage_sync_and_lock(ibox, TRUE, MAIL_LOCK_SHARED))
		return NULL;

	ctx = i_new(struct mail_search_context, 1);
	ctx->ibox = ibox;
	ctx->charset = i_strdup(charset);
	ctx->args = args;

	ctx->mail = (struct mail *) &ctx->imail;
	index_mail_init(ibox, &ctx->imail, wanted_fields, wanted_headers);

	if (ibox->synced_messages_count == 0)
		return ctx;

	/* see if we can limit the records we look at */
	switch (search_get_uid_range(ibox, args, &first_uid, &last_uid)) {
	case -1:
		/* error */
		ctx->failed = TRUE;
		return ctx;
	case 0:
		/* nothing found */
		return ctx;
	}

	ctx->msgset_ctx =
		index_messageset_init_range(ibox, first_uid, last_uid, TRUE);
	return ctx;
}

int index_storage_search_deinit(struct mail_search_context *ctx)
{
	int ret;

	ret = !ctx->failed && ctx->error == NULL;

	if (ctx->msgset_ctx != NULL) {
		if (index_messageset_deinit(ctx->msgset_ctx) < 0)
			ret = FALSE;
	}

	if (!index_storage_lock(ctx->ibox, MAIL_LOCK_UNLOCK))
		ret = FALSE;

	if (ctx->error != NULL) {
		mail_storage_set_error(ctx->ibox->box.storage,
				       "%s", ctx->error);
	}

	if (ctx->hdr_pool != NULL)
		pool_unref(ctx->hdr_pool);

	if (ctx->ibox->fetch_mail.pool != NULL)
		index_mail_deinit(&ctx->ibox->fetch_mail);
        index_mail_deinit(&ctx->imail);
	i_free(ctx);
	return ret;
}

struct mail *index_storage_search_next(struct mail_search_context *ctx)
{
	const struct messageset_mail *msgset_mail;
        struct mail_search_arg *arg;
	int found, ret;

	if (ctx->msgset_ctx == NULL) {
		/* initialization failed or didn't found any messages */
		return NULL;
	}

	do {
		msgset_mail = index_messageset_next(ctx->msgset_ctx);
		if (msgset_mail == NULL)
			return NULL;

		ctx->mail->seq = msgset_mail->client_seq;
		ctx->mail->uid = msgset_mail->rec->uid;
		ret = index_mail_next(&ctx->imail, msgset_mail->rec);

		if (ret < 0)
			return NULL;

		if (ret == 0)
			found = FALSE;
		else {
			mail_search_args_reset(ctx->args);

			t_push();

			mail_search_args_foreach(ctx->args, search_index_arg,
						 ctx);
			mail_search_args_foreach(ctx->args, search_cached_arg,
						 ctx);
			mail_search_args_foreach(ctx->args, search_envelope_arg,
						 ctx);
			found = search_arg_match_text(ctx->args, ctx);

			t_pop();

			if (ctx->error != NULL)
				return NULL;
		}

		if (found) {
			for (arg = ctx->args; arg != NULL; arg = arg->next) {
				if (arg->result != 1) {
					found = FALSE;
					break;
				}
			}
		}
	} while (!found);

	return ctx->mail;
}
