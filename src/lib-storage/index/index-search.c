/* Copyright (C) 2002-2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "message-address.h"
#include "message-date.h"
#include "message-search.h"
#include "message-parser.h"
#include "index-storage.h"
#include "index-mail.h"
#include "index-sort.h"
#include "mail-search.h"

#include <stdlib.h>
#include <ctype.h>

#define TXT_UNKNOWN_CHARSET "[BADCHARSET] Unknown charset"
#define TXT_INVALID_SEARCH_KEY "Invalid search key"

#define SEARCH_NONBLOCK_COUNT 20
#define SEARCH_NOTIFY_INTERVAL_SECS 10

struct index_search_context {
        struct mail_search_context mail_ctx;
	struct mail_index_view *view;
	struct index_mailbox *ibox;

	uint32_t seq1, seq2;
	struct mail *mail;
	struct index_mail *imail;

	pool_t search_pool;
	const char *error;

	struct timeval search_start_time, last_notify;

	unsigned int failed:1;
	unsigned int sorted:1;
	unsigned int have_seqsets:1;
};

struct search_header_context {
        struct index_search_context *index_context;
	struct mail_search_arg *args;

        struct message_header_line *hdr;

	unsigned int parse_headers:1;
	unsigned int custom_header:1;
	unsigned int threading:1;
};

struct search_body_context {
        struct index_search_context *index_ctx;
	struct istream *input;
	const struct message_part *part;
};

static const enum message_header_parser_flags hdr_parser_flags =
	MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE;

static void search_parse_msgset_args(const struct mail_index_header *hdr,
				     struct mail_search_arg *args,
				     uint32_t *seq1_r, uint32_t *seq2_r,
				     bool not);

static int seqset_contains(struct mail_search_seqset *set, uint32_t seq)
{
	while (set != NULL) {
		if (seq >= set->seq1 && seq <= set->seq2)
			return TRUE;
		set = set->next;
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

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_index(struct index_mail *imail,
				  enum mail_search_arg_type type,
				  const char *value)
{
	enum mail_flags flags = imail->data.flags;
	const char *const *keywords;

	switch (type) {
	/* flags */
	case SEARCH_ANSWERED:
		return flags & MAIL_ANSWERED;
	case SEARCH_DELETED:
		return flags & MAIL_DELETED;
	case SEARCH_DRAFT:
		return flags & MAIL_DRAFT;
	case SEARCH_FLAGGED:
		return flags & MAIL_FLAGGED;
	case SEARCH_SEEN:
		return flags & MAIL_SEEN;
	case SEARCH_RECENT:
		return mail_get_flags(&imail->mail.mail) & MAIL_RECENT;
	case SEARCH_KEYWORD:
		keywords = mail_get_keywords(&imail->mail.mail);
		while (*keywords != NULL) {
			if (strcasecmp(*keywords, value) == 0)
				return 1;
			keywords++;
		}
		return 0;

	default:
		return -1;
	}
}

static void search_init_seqset_arg(struct mail_search_arg *arg,
				   struct index_search_context *ctx)
{
	switch (arg->type) {
	case SEARCH_SEQSET:
		ctx->have_seqsets = TRUE;
		break;
	case SEARCH_ALL:
		if (!arg->not)
			arg->match_always = TRUE;
		break;
	default:
		break;
	}
}

static void search_seqset_arg(struct mail_search_arg *arg,
			      struct index_search_context *ctx)
{
	if (arg->type == SEARCH_SEQSET) {
		if (seqset_contains(arg->value.seqset, ctx->mail_ctx.seq))
			ARG_SET_RESULT(arg, 1);
		else
			ARG_SET_RESULT(arg, 0);
	}
}

static void search_index_arg(struct mail_search_arg *arg,
			     struct index_search_context *ctx)
{
	switch (search_arg_match_index(ctx->imail, arg->type,
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

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_cached(struct index_search_context *ctx,
				   struct mail_search_arg *arg)
{
	uoff_t virtual_size, search_size;
	time_t date;
	int timezone_offset;

	switch (arg->type) {
	/* internal dates */
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		if (mail_get_received_date(ctx->mail, &date) < 0)
			return -1;

		switch (arg->type) {
		case SEARCH_BEFORE:
			return date < arg->value.time;
		case SEARCH_ON:
			return date >= arg->value.time &&
				date < arg->value.time + 3600*24;
		case SEARCH_SINCE:
			return date >= arg->value.time;
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
		if (mail_get_date(ctx->mail, &date, &timezone_offset) < 0)
			return -1;
		date += timezone_offset * 60;

		switch (arg->type) {
		case SEARCH_SENTBEFORE:
			return date < arg->value.time;
		case SEARCH_SENTON:
			return date >= arg->value.time &&
				date < arg->value.time + 3600*24;
		case SEARCH_SENTSINCE:
			return date >= arg->value.time;
		default:
			/* unreachable */
			break;
		}

	/* sizes */
	case SEARCH_SMALLER:
	case SEARCH_LARGER:
		if (mail_get_virtual_size(ctx->mail, &virtual_size) < 0)
			return -1;

		search_size = str_to_uoff_t(arg->value.str);
		if (arg->type == SEARCH_SMALLER)
			return virtual_size < search_size;
		else
			return virtual_size > search_size;

	default:
		return -1;
	}
}

static void search_cached_arg(struct mail_search_arg *arg,
			      struct index_search_context *ctx)
{
	switch (search_arg_match_cached(ctx, arg)) {
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

static int search_sent(enum mail_search_arg_type type, time_t search_time,
		       const unsigned char *sent_value, size_t sent_value_len)
{
	time_t sent_time;
	int timezone_offset;

	if (sent_value == NULL)
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

static struct message_search_context *
msg_search_arg_context(struct index_search_context *ctx,
		       struct mail_search_arg *arg)
{
	struct message_search_context *arg_ctx = arg->context;
	enum message_search_flags flags;
	int ret;

	if (arg_ctx != NULL)
		return arg_ctx;

	if (ctx->search_pool == NULL)
		ctx->search_pool = pool_alloconly_create("search pool", 8192);

	flags = (arg->type == SEARCH_BODY || arg->type == SEARCH_BODY_FAST) ?
		MESSAGE_SEARCH_FLAG_SKIP_HEADERS : 0;

	ret = message_search_init(ctx->search_pool, arg->value.str,
				  ctx->mail_ctx.charset, flags,
				  &arg_ctx);
	if (ret > 0) {
		arg->context = arg_ctx;
		return arg_ctx;
	}
	if (ret == 0)
		ctx->error = TXT_UNKNOWN_CHARSET;
	else
		ctx->error = TXT_INVALID_SEARCH_KEY;
	return NULL;
}

static void search_header_arg(struct mail_search_arg *arg,
			      struct search_header_context *ctx)
{
        struct message_search_context *msg_search_ctx;
	struct message_block block;
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
			ret = search_sent(arg->type, arg->value.time,
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
		break;
	default:
		return;
	}

	if (arg->value.str[0] == '\0') {
		/* we're just testing existence of the field. always matches. */
		ARG_SET_RESULT(arg, 1);
		return;
	}

	if (ctx->hdr->continues) {
		ctx->hdr->use_full_value = TRUE;
		return;
	}

	memset(&block, 0, sizeof(block));
	msg_search_ctx = msg_search_arg_context(ctx->index_context, arg);
	if (msg_search_ctx == NULL)
		ret = 0;
	else if (arg->type == SEARCH_HEADER_ADDRESS) {
		/* we have to match against normalized address */
		struct message_address *addr;
		string_t *str;

		t_push();
		addr = message_address_parse(pool_datastack_create(),
					     ctx->hdr->full_value,
					     ctx->hdr->full_value_len,
					     (unsigned int)-1, TRUE);
		str = t_str_new(ctx->hdr->value_len);
		message_address_write(str, addr);
		block.data = str_data(str);
		block.size = str_len(str);
		ret = message_search_more_decoded(msg_search_ctx, &block);
		t_pop();
	} else {
		block.data = ctx->hdr->full_value;
		block.size = ctx->hdr->full_value_len;
		ret = message_search_more_decoded(msg_search_ctx, &block);
	}

	if (ret > 0 ||
	    (arg->type != SEARCH_HEADER &&
	     arg->type != SEARCH_HEADER_ADDRESS)) {
		/* set only when we definitely know if it's a match */
		ARG_SET_RESULT(arg, ret);
	}
}

static void search_header_unmatch(struct mail_search_arg *arg,
				  void *context ATTR_UNUSED)
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

static void search_header(struct message_header_line *hdr,
			  struct search_header_context *ctx)
{
	if (hdr == NULL) {
		/* end of headers, mark all unknown SEARCH_HEADERs unmatched */
		mail_search_args_foreach(ctx->args, search_header_unmatch, ctx);
		return;
	}

	if (hdr->eoh)
		return;

	if (ctx->parse_headers)
		index_mail_parse_header(NULL, hdr, ctx->index_context->imail);

	if (ctx->custom_header || strcasecmp(hdr->name, "Date") == 0) {
		ctx->hdr = hdr;

		ctx->custom_header = FALSE;
		mail_search_args_foreach(ctx->args, search_header_arg, ctx);
	}
}

static void search_body(struct mail_search_arg *arg,
			struct search_body_context *ctx)
{
	struct message_search_context *msg_search_ctx;
	int ret;

	if (ctx->index_ctx->error != NULL)
		return;

	switch (arg->type) {
	case SEARCH_BODY:
	case SEARCH_BODY_FAST:
	case SEARCH_TEXT:
	case SEARCH_TEXT_FAST:
		break;
	default:
		return;
	}

	msg_search_ctx = msg_search_arg_context(ctx->index_ctx, arg);
	if (msg_search_ctx == NULL) {
		ARG_SET_RESULT(arg, 0);
		return;
	}

	i_stream_seek(ctx->input, 0);
	ret = message_search_msg(msg_search_ctx, ctx->input, ctx->part);
	if (ret < 0) {
		mail_cache_set_corrupted(ctx->index_ctx->ibox->cache,
			"Broken message structure for mail UID %u",
			ctx->index_ctx->mail->uid);

		/* get the body parts, and try again */
		ctx->index_ctx->imail->data.parts = NULL;

		i_stream_seek(ctx->input, 0);
		ret = message_search_msg(msg_search_ctx, ctx->input, NULL);
		if (ret < 0)
			i_panic("Couldn't fix broken body structure");
	}

	ARG_SET_RESULT(arg, ret > 0);
}

static bool search_arg_match_text(struct mail_search_arg *args,
				  struct index_search_context *ctx)
{
	struct istream *input;
	struct mailbox_header_lookup_ctx *headers_ctx;
	const char *const *headers;
	bool have_headers, have_body;

	/* first check what we need to use */
	headers = mail_search_args_analyze(args, &have_headers, &have_body);
	if (!have_headers && !have_body)
		return TRUE;

	if (have_headers) {
		struct search_header_context hdr_ctx;

		if (have_body)
			headers = NULL;

		if (headers == NULL) {
			headers_ctx = NULL;
			if (mail_get_stream(ctx->mail, NULL, NULL, &input) < 0)
				return FALSE;
		} else {
			/* FIXME: do this once in init */
			i_assert(*headers != NULL);
			headers_ctx =
				mailbox_header_lookup_init(&ctx->ibox->box,
							   headers);
			if (mail_get_header_stream(ctx->mail, headers_ctx,
						   &input) < 0) {
				mailbox_header_lookup_deinit(&headers_ctx);
				return FALSE;
			}
		}

		memset(&hdr_ctx, 0, sizeof(hdr_ctx));
		hdr_ctx.index_context = ctx;
		hdr_ctx.custom_header = TRUE;
		hdr_ctx.args = args;
		hdr_ctx.parse_headers = headers == NULL &&
			index_mail_want_parse_headers(ctx->imail);

		if (hdr_ctx.parse_headers)
			index_mail_parse_header_init(ctx->imail, headers_ctx);
		message_parse_header(input, NULL, hdr_parser_flags,
				     search_header, &hdr_ctx);
		if (headers_ctx != NULL)
			mailbox_header_lookup_deinit(&headers_ctx);
	} else {
		struct message_size hdr_size;

		if (mail_get_stream(ctx->mail, &hdr_size, NULL, &input) < 0)
			return FALSE;

		i_stream_seek(input, hdr_size.physical_size);
	}

	if (have_body) {
		struct search_body_context body_ctx;

		memset(&body_ctx, 0, sizeof(body_ctx));
		body_ctx.index_ctx = ctx;
		body_ctx.input = input;
		(void)mail_get_parts(ctx->mail, &body_ctx.part);

		mail_search_args_foreach(args, search_body, &body_ctx);
	}
	return TRUE;
}

static void update_seqs(const struct mail_search_seqset *set,
			const struct mail_index_header *hdr,
			uint32_t *seq1_r, uint32_t *seq2_r, bool not)
{
	if (!not) {
		/* seq1..seq2 */
		if (*seq1_r < set->seq1 || *seq1_r == 0)
			*seq1_r = set->seq1;
		if (*seq2_r > set->seq2)
			*seq2_r = set->seq2;
	} else {
		if (set->seq1 == 1) {
			/* seq2+1..count */
			if (set->seq2 == hdr->messages_count) {
				/* completely outside our range */
				*seq1_r = (uint32_t)-1;
				*seq2_r = 0;
			} else {
				if (*seq1_r < set->seq2 + 1)
					*seq1_r = set->seq2 + 1;
			}
		} else if (set->seq2 == hdr->messages_count) {
			/* 1..seq1-1 */
			if (*seq2_r > set->seq1 - 1)
				*seq2_r = set->seq1 - 1;
		}
	}
}

static void search_msgset_fix(const struct mail_index_header *hdr,
			      struct mail_search_seqset *set,
			      uint32_t *seq1_r, uint32_t *seq2_r, bool not)
{
	struct mail_search_seqset full_set;
	uint32_t min_seq = (uint32_t)-1, max_seq = 0;

	for (; set != NULL; set = set->next) {
		if (set->seq1 > hdr->messages_count) {
			if (set->seq1 != (uint32_t)-1 &&
			    set->seq2 != (uint32_t)-1) {
				set->seq1 = set->seq2 = 0;
				if (not)
					continue;

				/* completely outside our range */
				*seq1_r = (uint32_t)-1;
				*seq2_r = 0;
				return;
			}
			/* either seq1 or seq2 is '*', so the last message is
			   in range. */
			set->seq1 = hdr->messages_count;
		}
		if (set->seq2 > hdr->messages_count)
			set->seq2 = hdr->messages_count;

		if (set->seq1 == 0 || set->seq2 == 0) {
			/* this shouldn't happen. treat as nonexisting. */
			*seq1_r = (uint32_t)-1;
			*seq2_r = 0;
			return;
		}

		if (set->seq1 < min_seq)
			min_seq = set->seq1;
		if (set->seq2 > max_seq)
			max_seq = set->seq2;
	}

	full_set.seq1 = min_seq;
	full_set.seq2 = max_seq;
	full_set.next = NULL;
	update_seqs(&full_set, hdr, seq1_r, seq2_r, not);
	return;
}

static void search_or_parse_msgset_args(const struct mail_index_header *hdr,
					struct mail_search_arg *args,
					uint32_t *seq1_r, uint32_t *seq2_r,
					bool not)
{
	uint32_t seq1, seq2, min_seq1 = 0, max_seq2 = 0;

	for (; args != NULL; args = args->next) {
		bool cur_not = args->not;

		if (not)
			cur_not = !cur_not;
		seq1 = 1; seq2 = hdr->messages_count;

		if (args->type == SEARCH_SUB) {
			search_parse_msgset_args(hdr, args->value.subargs,
						 &seq1, &seq2, cur_not);
		} else if (args->type == SEARCH_OR) {
			search_or_parse_msgset_args(hdr, args->value.subargs,
						    &seq1, &seq2, cur_not);
		} else if (args->type == SEARCH_SEQSET) {
			search_msgset_fix(hdr, args->value.seqset,
					  &seq1, &seq2, cur_not);
		}

		if (min_seq1 == 0) {
			min_seq1 = seq1;
			max_seq2 = seq2;
		} else {
			if (seq1 < min_seq1)
				min_seq1 = seq1;
			if (seq2 > max_seq2)
				max_seq2 = seq2;
		}
	}
	i_assert(min_seq1 != 0);

	if (min_seq1 > *seq1_r)
		*seq1_r = min_seq1;
	if (max_seq2 < *seq2_r)
		*seq2_r = max_seq2;
}

static void search_parse_msgset_args(const struct mail_index_header *hdr,
				     struct mail_search_arg *args,
				     uint32_t *seq1_r, uint32_t *seq2_r,
				     bool not)
{
	for (; args != NULL; args = args->next) {
		bool cur_not = args->not;

		if (not)
			cur_not = !cur_not;

		if (args->type == SEARCH_SUB) {
			search_parse_msgset_args(hdr, args->value.subargs,
						 seq1_r, seq2_r, cur_not);
		} else if (args->type == SEARCH_OR) {
			/* go through our children and use the widest seqset
			   range */
			search_or_parse_msgset_args(hdr, args->value.subargs,
						    seq1_r, seq2_r, cur_not);
		} else if (args->type == SEARCH_SEQSET) {
			search_msgset_fix(hdr, args->value.seqset,
					  seq1_r, seq2_r, cur_not);
		}
	}
}

static void search_limit_lowwater(struct index_search_context *ctx,
				  uint32_t uid_lowwater, uint32_t *first_seq)
{
	uint32_t seq1, seq2;

	if (uid_lowwater == 0)
		return;

	mail_index_lookup_uid_range(ctx->view, uid_lowwater, (uint32_t)-1,
				    &seq1, &seq2);
	if (*first_seq < seq1)
		*first_seq = seq1;
}

static bool search_limit_by_flags(struct index_search_context *ctx,
				  const struct mail_index_header *hdr,
				  struct mail_search_arg *args,
				  uint32_t *seq1, uint32_t *seq2)
{
	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_SEEN:
			/* SEEN with 0 seen? */
			if (!args->not && hdr->seen_messages_count == 0)
				return FALSE;

			if (hdr->seen_messages_count == hdr->messages_count) {
				/* UNSEEN with all seen? */
				if (args->not)
					return FALSE;

				/* SEEN with all seen */
				args->match_always = TRUE;
			} else if (args->not) {
				/* UNSEEN with lowwater limiting */
				search_limit_lowwater(ctx,
                                	hdr->first_unseen_uid_lowwater, seq1);
			}
			break;
		case SEARCH_DELETED:
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
			} else if (!args->not) {
				/* DELETED with lowwater limiting */
				search_limit_lowwater(ctx,
                                	hdr->first_deleted_uid_lowwater, seq1);
			}
			break;
		case SEARCH_ALL:
			if (args->not)
				return FALSE;
			break;
		default:
			break;
		}
	}

	return *seq1 <= *seq2;
}

static void search_get_seqset(struct index_search_context *ctx,
			      struct mail_search_arg *args)
{
        const struct mail_index_header *hdr;

	hdr = mail_index_get_header(ctx->view);
	if (hdr->messages_count == 0) {
		/* no messages, don't check sequence ranges. although we could
		   give error message then for FETCH, we shouldn't do it for
		   UID FETCH. */
		ctx->seq1 = 1;
		ctx->seq2 = 0;
		return;
	}

	ctx->seq1 = 1;
	ctx->seq2 = hdr->messages_count;

	search_parse_msgset_args(hdr, args, &ctx->seq1, &ctx->seq2, FALSE);
	if (ctx->seq1 == 0) {
		ctx->seq1 = 1;
		ctx->seq2 = hdr->messages_count;
	}
	if (ctx->seq1 > ctx->seq2) {
		/* no matches */
		return;
	}

	/* UNSEEN and DELETED in root search level may limit the range */
	if (!search_limit_by_flags(ctx, hdr, args, &ctx->seq1, &ctx->seq2)) {
		/* no matches */
		ctx->seq1 = 1;
		ctx->seq2 = 0;
	}
}

struct mail_search_context *
index_storage_search_init(struct mailbox_transaction_context *_t,
			  const char *charset, struct mail_search_arg *args,
			  const enum mail_sort_type *sort_program)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct index_search_context *ctx;

	ctx = i_new(struct index_search_context, 1);
	ctx->mail_ctx.transaction = _t;
	ctx->ibox = t->ibox;
	ctx->view = t->trans_view;
	ctx->mail_ctx.charset = i_strdup(charset);
	ctx->mail_ctx.args = args;
	ctx->mail_ctx.sort_program = index_sort_program_init(_t, sort_program);

	array_create(&ctx->mail_ctx.module_contexts, default_pool,
		     sizeof(void *), 5);

	mail_search_args_reset(ctx->mail_ctx.args, TRUE);

	search_get_seqset(ctx, args);
	(void)mail_search_args_foreach(args, search_init_seqset_arg, ctx);

	/* Need to reset results for match_always cases */
	mail_search_args_reset(ctx->mail_ctx.args, FALSE);
	return &ctx->mail_ctx;
}

static void search_arg_deinit(struct mail_search_arg *arg,
			      void *context ATTR_UNUSED)
{
	struct message_search_context *search_ctx = arg->context;

	if (search_ctx != NULL) {
		message_search_deinit(&search_ctx);
		arg->context = NULL;
	}
}

int index_storage_search_deinit(struct mail_search_context *_ctx)
{
        struct index_search_context *ctx = (struct index_search_context *)_ctx;
	int ret;

	ret = ctx->failed || ctx->error != NULL ? -1 : 0;

	if (ctx->error != NULL) {
		mail_storage_set_error(ctx->ibox->box.storage,
				       MAIL_ERROR_PARAMS, ctx->error);
	}

	mail_search_args_reset(ctx->mail_ctx.args, FALSE);
	(void)mail_search_args_foreach(ctx->mail_ctx.args,
				       search_arg_deinit, NULL);

	if (ctx->search_pool != NULL)
		pool_unref(&ctx->search_pool);

	if (ctx->mail_ctx.sort_program != NULL)
		index_sort_program_deinit(&ctx->mail_ctx.sort_program);
	array_free(&ctx->mail_ctx.module_contexts);
	i_free(ctx->mail_ctx.charset);
	i_free(ctx);
	return ret;
}

static bool search_match_next(struct index_search_context *ctx)
{
        struct mail_search_arg *arg;
	int ret;

	/* check the index matches first */
	ret = mail_search_args_foreach(ctx->mail_ctx.args,
				       search_index_arg, ctx);
	if (ret >= 0)
		return ret > 0;

	/* next search only from cached arguments */
	ret = mail_search_args_foreach(ctx->mail_ctx.args,
				       search_cached_arg, ctx);
	if (ret >= 0)
		return ret > 0;

	/* open the mail file and check the rest */
	if (!search_arg_match_text(ctx->mail_ctx.args, ctx))
		return FALSE;

	for (arg = ctx->mail_ctx.args; arg != NULL; arg = arg->next) {
		if (arg->result != 1)
			return FALSE;
	}

	return TRUE;
}

static void index_storage_search_notify(struct mailbox *box,
					struct index_search_context *ctx)
{
	const struct mail_index_header *hdr;
	const char *text;
	float percentage;
	unsigned int msecs, secs;

	if (ctx->last_notify.tv_sec == 0) {
		/* set the search time in here, in case a plugin
		   already spent some time indexing the mailbox */
		ctx->search_start_time = ioloop_timeval;
	} else if (box->storage->callbacks->notify_ok != NULL) {
		hdr = mail_index_get_header(ctx->ibox->view);

		percentage = ctx->mail->seq * 100.0 / hdr->messages_count;
		msecs = (ioloop_timeval.tv_sec -
			 ctx->search_start_time.tv_sec) * 1000 +
			(ioloop_timeval.tv_usec -
			 ctx->search_start_time.tv_usec) / 1000;
		secs = (msecs / (percentage / 100.0) - msecs) / 1000;

		t_push();
		text = t_strdup_printf("Searched %d%% of the mailbox, "
				       "ETA %d:%02d", (int)percentage,
				       secs/60, secs%60);
		box->storage->callbacks->
			notify_ok(box, text, box->storage->callback_context);
		t_pop();
	}
	ctx->last_notify = ioloop_timeval;
}

int index_storage_search_next_nonblock(struct mail_search_context *_ctx,
				       struct mail *mail, bool *tryagain_r)
{
        struct index_search_context *ctx = (struct index_search_context *)_ctx;
	struct mailbox *box = _ctx->transaction->box;
	unsigned int count = 0;
	int ret;

	*tryagain_r = FALSE;

	if (ctx->sorted) {
		/* everything searched at this point already. just returning
		   matches from sort list */
		if (!index_sort_list_next(ctx->mail_ctx.sort_program, mail))
			return 0;
		return 1;
	}

	ctx->mail = mail;
	ctx->imail = (struct index_mail *)mail;

	if (ioloop_time - ctx->last_notify.tv_sec >=
	    SEARCH_NOTIFY_INTERVAL_SECS)
		index_storage_search_notify(box, ctx);

	while ((ret = box->v.search_next_update_seq(_ctx)) > 0) {
		mail_set_seq(mail, _ctx->seq);

		t_push();
		ret = search_match_next(ctx) ? 1 : 0;
		t_pop();

		mail_search_args_reset(ctx->mail_ctx.args, FALSE);

		if (ctx->error != NULL)
			ret = -1;
		if (ret != 0) {
			if (ctx->mail_ctx.sort_program == NULL)
				break;

			index_sort_list_add(ctx->mail_ctx.sort_program, mail);
		}

		if (++count == SEARCH_NONBLOCK_COUNT) {
			*tryagain_r = TRUE;
			return 0;
		}
	}
	if (ret < 0)
		ctx->failed = TRUE;
	ctx->mail = NULL;
	ctx->imail = NULL;

	if (ctx->mail_ctx.sort_program != NULL && ret == 0) {
		/* finished searching the messages. now sort them and start
		   returning the messages. */
		ctx->sorted = TRUE;
		index_sort_list_finish(ctx->mail_ctx.sort_program);
		return index_storage_search_next_nonblock(_ctx, mail,
							  tryagain_r);
	}

	return ret;
}

int index_storage_search_next_update_seq(struct mail_search_context *_ctx)
{
        struct index_search_context *ctx = (struct index_search_context *)_ctx;
	int ret;

	if (_ctx->seq == 0) {
		/* first time */
		_ctx->seq = ctx->seq1;
	} else {
		_ctx->seq++;
	}

	if (!ctx->have_seqsets)
		return _ctx->seq <= ctx->seq2 ? 1 : 0;

	ret = 0;
	while (_ctx->seq <= ctx->seq2) {
		/* check if the sequence matches */
		ret = mail_search_args_foreach(ctx->mail_ctx.args,
					       search_seqset_arg, ctx);
		if (ret != 0)
			break;

		/* doesn't, try next one */
		_ctx->seq++;
		mail_search_args_reset(ctx->mail_ctx.args, FALSE);
	}
	return ret == 0 ? 0 : 1;
}
