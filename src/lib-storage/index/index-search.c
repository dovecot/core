/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-address.h"
#include "message-date.h"
#include "message-body-search.h"
#include "message-header-search.h"
#include "imap-date.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "index-mail.h"
#include "mail-custom-flags.h"
#include "mail-modifylog.h"
#include "mail-search.h"

#include <stdlib.h>
#include <ctype.h>

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

        struct message_header_line *hdr;

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
					/* swap, as specified by RFC-3501 */
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
		ARG_SET_RESULT(arg, 0);
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
	time_t date, search_time;
	uoff_t virtual_size, search_size;
	int timezone_offset;

	switch (type) {
	/* internal dates */
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		date = ctx->mail->get_received_date(ctx->mail);
		if (date == (time_t)-1)
			return -1;

		if (!imap_parse_date(value, &search_time))
			return 0;

		switch (type) {
		case SEARCH_BEFORE:
			return date < search_time;
		case SEARCH_ON:
			return date >= search_time &&
				date < search_time + 3600*24;
		case SEARCH_SINCE:
			return date >= search_time;
		default:
			/* unreachable */
			break;
		}

	/* sent dates */
	case SEARCH_SENTBEFORE:
	case SEARCH_SENTON:
	case SEARCH_SENTSINCE:
		/* NOTE: RFC-3501 specifies that timezone is ignored
		   in searches. date is returned as UTC, so change it. */
		date = ctx->mail->get_date(ctx->mail, &timezone_offset);
		if (date == (time_t)-1)
			return -1;
		date += timezone_offset * 60;

		if (!imap_parse_date(value, &search_time))
			return 0;

		switch (type) {
		case SEARCH_SENTBEFORE:
			return date < search_time;
		case SEARCH_SENTON:
			return date >= search_time &&
				date < search_time + 3600*24;
		case SEARCH_SENTSINCE:
			return date >= search_time;
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
		ARG_SET_RESULT(arg, 0);
		break;
	default:
		ARG_SET_RESULT(arg, 1);
		break;
	}
}

static int search_sent(enum mail_search_arg_type type, const char *search_value,
		       const unsigned char *sent_value, size_t sent_value_len)
{
	time_t search_time, sent_time;
	int timezone_offset;

	if (sent_value == NULL)
		return 0;

	if (!imap_parse_date(search_value, &search_time))
		return 0;

	/* NOTE: RFC-3501 specifies that timezone is ignored
	   in searches. sent_time is returned as UTC, so change it. */
	if (!message_date_parse(sent_value, sent_value_len,
				&sent_time, &timezone_offset))
		return 0;
	sent_time += timezone_offset * 60;

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

static void search_header_arg(struct mail_search_arg *arg, void *context)
{
	struct search_header_context *ctx = context;
        struct header_search_context *hdr_search_ctx;
	int ret;

	/* first check that the field name matches to argument. */
	switch (arg->type) {
	case SEARCH_SENTBEFORE:
	case SEARCH_SENTON:
	case SEARCH_SENTSINCE:
		/* date is handled differently than others */
		if (strcasecmp(ctx->hdr->name, "Date") == 0) {
			if (ctx->hdr->continues) {
				ctx->hdr->use_full_value = TRUE;
				return;
			}
			ret = search_sent(arg->type, arg->value.str,
					  ctx->hdr->full_value,
					  ctx->hdr->full_value_len);
			ARG_SET_RESULT(arg, ret);
		}
		return;

	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
		ctx->custom_header = TRUE;

		if (strcasecmp(ctx->hdr->name, arg->hdr_field_name) != 0)
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
		if (ctx->hdr->continues) {
			ctx->hdr->use_full_value = TRUE;
			return;
		}

		t_push();

		hdr_search_ctx = search_header_context(ctx->index_context, arg);
		if (hdr_search_ctx == NULL)
			ret = 0;
		else if (arg->type == SEARCH_HEADER_ADDRESS) {
			/* we have to match against normalized address */
			struct message_address *addr;
			string_t *str;

			addr = message_address_parse(pool_datastack_create(),
						     ctx->hdr->full_value,
						     ctx->hdr->full_value_len,
						     0);
			str = t_str_new(ctx->hdr->value_len);
			message_address_write(str, addr);
			ret = message_header_search(str_data(str), str_len(str),
						    hdr_search_ctx) ? 1 : 0;
		} else {
			ret = message_header_search(ctx->hdr->full_value,
						    ctx->hdr->full_value_len,
						    hdr_search_ctx) ? 1 : 0;
		}
		t_pop();
	}

	if (ret == 1 ||
	    (arg->type != SEARCH_TEXT && arg->type != SEARCH_HEADER)) {
		/* set only when we definitely know if it's a match */
		ARG_SET_RESULT(arg, ret);
	}
}

static void search_header_unmatch(struct mail_search_arg *arg,
				  void *context __attr_unused__)
{
	switch (arg->type) {
	case SEARCH_SENTBEFORE:
	case SEARCH_SENTON:
	case SEARCH_SENTSINCE:
		if (arg->not) {
			/* date header not found, so we match only for
			   NOT searches */
			ARG_SET_RESULT(arg, 0);
		}
		break;
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
		ARG_SET_RESULT(arg, 0);
		break;
	default:
		break;
	}
}

static void search_header(struct message_part *part,
                          struct message_header_line *hdr, void *context)
{
	struct search_header_context *ctx = context;

	if (hdr == NULL) {
		/* end of headers, mark all unknown SEARCH_HEADERs unmatched */
		mail_search_args_foreach(ctx->args, search_header_unmatch, ctx);
		return;
	}

	if (hdr->eoh)
		return;

	index_mail_parse_header(part, hdr, &ctx->index_context->imail);

	if (ctx->custom_header || strcasecmp(hdr->name, "Date") == 0) {
		ctx->hdr = hdr;

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
	const char *const *headers;
	int have_headers, have_body;

	/* first check what we need to use */
	headers = mail_search_args_analyze(args, &have_headers, &have_body);
	if (!have_headers && !have_body)
		return TRUE;

	if (have_headers) {
		struct search_header_context hdr_ctx;

		if (have_body)
			headers = NULL;

		input = headers == NULL ?
			ctx->mail->get_stream(ctx->mail, NULL, NULL) :
			ctx->mail->get_headers(ctx->mail, headers);
		if (input == NULL)
			return FALSE;

		memset(&hdr_ctx, 0, sizeof(hdr_ctx));
		hdr_ctx.index_context = ctx;
		hdr_ctx.custom_header = TRUE;
		hdr_ctx.args = args;

		index_mail_parse_header_init(&ctx->imail, headers);
		message_parse_header(NULL, input, NULL,
				     search_header, &hdr_ctx);
	} else {
		struct message_size hdr_size;

		input = ctx->mail->get_stream(ctx->mail, &hdr_size, NULL);
		if (input == NULL)
			return FALSE;

		i_stream_seek(input, hdr_size.physical_size);
	}

	if (have_body) {
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

struct search_msgset_context {
	struct index_mailbox *ibox;

	unsigned int first_seq, last_seq;
	unsigned int first_uid, last_uid;

	struct mail_search_arg *msgset_arg;
	unsigned int msgset_arg_count;
};

static int search_parse_msgset_args(struct search_msgset_context *ctx,
				    struct mail_search_arg *args)
{
	struct index_mailbox *ibox = ctx->ibox;

	for (; args != NULL; args = args->next) {
		/* FIXME: we don't check if OR condition can limit the range.
		   It's a bit tricky and unlikely to affect performance much. */
		if (args->type == SEARCH_SUB) {
			if (!search_parse_msgset_args(ctx, args->value.subargs))
				return FALSE;
		} else if (args->type == SEARCH_SET) {
			ctx->msgset_arg = args;
			ctx->msgset_arg_count++;
			if (!seq_update(args->value.str,
					&ctx->first_seq, &ctx->last_seq,
					ibox->synced_messages_count)) {
				mail_storage_set_syntax_error(ibox->box.storage,
					"Invalid messageset: %s",
					args->value.str);
				return FALSE;
			}
		} else if (args->type == SEARCH_UID) {
			ctx->msgset_arg = args;
			ctx->msgset_arg_count++;
			if (!seq_update(args->value.str,
					&ctx->first_uid, &ctx->last_uid,
					ibox->index->header->next_uid-1)) {
				mail_storage_set_syntax_error(ibox->box.storage,
					"Invalid messageset: %s",
					args->value.str);
				return FALSE;
			}
		} else if (args->type == SEARCH_ALL) {
			/* go through everything */
			ctx->first_seq = 1;
			ctx->last_seq = ibox->synced_messages_count;
			ctx->msgset_arg_count++;
			return TRUE;
		}
	}

	return TRUE;
}

static int search_limit_by_flags(struct index_mailbox *ibox,
				 struct mail_search_arg *args,
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

			if (hdr->seen_messages_count == hdr->messages_count) {
				/* UNSEEN with all seen? */
				if (args->not)
					return FALSE;

				/* SEEN with all seen */
				args->match_always = TRUE;
			} else {
				/* UNSEEN with lowwater limiting */
				uid = hdr->first_unseen_uid_lowwater;
				if (args->not && *first_uid < uid)
					*first_uid = uid;
			}
		}

		if (args->type == SEARCH_DELETED) {
			/* DELETED with 0 deleted? */
			if (!args->not && hdr->deleted_messages_count == 0)
				return FALSE;

			if (hdr->deleted_messages_count ==
			    hdr->messages_count) {
				/* UNDELETED with all deleted? */
				if (args->not)
					return FALSE;

				/* DELETED with all deleted */
				args->match_always = TRUE;
			} else {
				/* DELETED with lowwater limiting */
				uid = hdr->first_deleted_uid_lowwater;
				if (!args->not && *first_uid < uid)
					*first_uid = uid;
			}
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
		mail_storage_set_syntax_error(ibox->box.storage,
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

static int search_get_msgset(struct index_mailbox *ibox,
			     struct mail_search_arg *args,
			     struct messageset_context **msgset_r)
{
        struct search_msgset_context ctx;
	unsigned int uid;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ibox = ibox;

	if (!search_parse_msgset_args(&ctx, args))
		return -1;

	/* seq_update() should make sure that these can't happen */
	i_assert(ctx.first_seq <= ctx.last_seq);
	i_assert(ctx.first_uid <= ctx.last_uid);

	if (ctx.first_seq > 1) {
		if (!client_seq_to_uid(ibox, ctx.first_seq, &uid))
			return -1;
		if (uid == 0)
			return 0;

		if (ctx.first_uid == 0 || uid < ctx.first_uid)
			ctx.first_uid = uid;
	}

	if (ctx.last_seq > 1 && ctx.last_seq != ibox->synced_messages_count) {
		if (!client_seq_to_uid(ibox, ctx.last_seq, &uid))
			return -1;
		if (uid == 0)
			return 0;

		if (ctx.last_uid == 0 || uid > ctx.last_uid)
			ctx.last_uid = uid;
	}

	if (ctx.first_uid == 0)
		ctx.first_uid = 1;
	if (ctx.last_uid == 0 || ctx.last_seq == ibox->synced_messages_count)
		ctx.last_uid = ibox->index->header->next_uid-1;

	/* UNSEEN and DELETED in root search level may limit the range */
	if (!search_limit_by_flags(ibox, args, &ctx.first_uid, &ctx.last_uid))
		return 0;

	i_assert(ctx.first_uid <= ctx.last_uid);

	if (ctx.msgset_arg != NULL && ctx.msgset_arg_count == 1) {
		/* one messageset argument, we can use it */
		*msgset_r = index_messageset_init(ibox,
				ctx.msgset_arg->value.str,
				ctx.msgset_arg->type == SEARCH_UID, TRUE);
		/* we might be able to limit it some more */
		index_messageset_limit_range(*msgset_r,
					     ctx.first_uid, ctx.last_uid);
		ctx.msgset_arg->match_always = TRUE;
	} else {
		*msgset_r = index_messageset_init_range(ibox, ctx.first_uid,
							ctx.last_uid, TRUE);
	}
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

	if (sort_program != NULL && *sort_program != MAIL_SORT_END) {
		i_error("BUG: index_storage_search_init(): "
			"invalid sort_program");
		return NULL;
	}

	if (!index_storage_sync_and_lock(ibox, TRUE, TRUE, MAIL_LOCK_SHARED))
		return NULL;

	ctx = i_new(struct mail_search_context, 1);
	ctx->ibox = ibox;
	ctx->charset = i_strdup(charset);
	ctx->args = args;

	ctx->mail = (struct mail *) &ctx->imail;
	index_mail_init(ibox, &ctx->imail, wanted_fields, wanted_headers);

	if (ibox->synced_messages_count == 0)
		return ctx;

	mail_search_args_reset(ctx->args, TRUE);

	/* see if we can limit the records we look at */
	switch (search_get_msgset(ibox, args, &ctx->msgset_ctx)) {
	case -1:
		/* error */
		ctx->failed = TRUE;
		return ctx;
	case 0:
		/* nothing found */
		return ctx;
	}

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

	if (ctx->ibox->fetch_mail.pool != NULL)
		index_mail_deinit(&ctx->ibox->fetch_mail);
	if (ctx->imail.pool != NULL)
		index_mail_deinit(&ctx->imail);

	if (!index_storage_lock(ctx->ibox, MAIL_LOCK_UNLOCK))
		ret = FALSE;

	if (ctx->error != NULL) {
		mail_storage_set_error(ctx->ibox->box.storage,
				       "%s", ctx->error);
	}

	if (ctx->hdr_pool != NULL)
		pool_unref(ctx->hdr_pool);

	i_free(ctx);
	return ret;
}

static int search_match_next(struct mail_search_context *ctx)
{
        struct mail_search_arg *arg;
	int ret;

	/* check the index matches first */
	mail_search_args_reset(ctx->args, FALSE);
	ret = mail_search_args_foreach(ctx->args, search_index_arg, ctx);
	if (ret >= 0)
		return ret > 0;

	/* next search only from cached arguments */
	ret = mail_search_args_foreach(ctx->args, search_cached_arg, ctx);
	if (ret >= 0)
		return ret > 0;

	/* open the mail file and check the rest */
	if (!search_arg_match_text(ctx->args, ctx))
		return FALSE;

	for (arg = ctx->args; arg != NULL; arg = arg->next) {
		if (arg->result != 1)
			return FALSE;
	}

	return TRUE;
}

struct mail *index_storage_search_next(struct mail_search_context *ctx)
{
	const struct messageset_mail *msgset_mail;
	int ret;

	if (ctx->msgset_ctx == NULL) {
		/* initialization failed or didn't found any messages */
		return NULL;
	}

	do {
		msgset_mail = index_messageset_next(ctx->msgset_ctx);
		if (msgset_mail == NULL) {
			ret = -1;
			break;
		}

		ctx->mail->seq = msgset_mail->client_seq;
		ctx->mail->uid = msgset_mail->rec->uid;

		ret = index_mail_next(&ctx->imail, msgset_mail->rec,
				      msgset_mail->idx_seq, TRUE);
		if (ret <= 0) {
			if (ret < 0)
				break;
			continue;
		}

		t_push();
		ret = search_match_next(ctx);
		t_pop();

		if (ctx->error != NULL)
			ret = -1;
	} while (ret == 0);

	if (ret < 0) {
		/* error or last record */
		index_mail_deinit(&ctx->imail);
		return NULL;
	}

	return ctx->mail;
}
