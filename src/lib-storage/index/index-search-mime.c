/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "message-date.h"
#include "message-address.h"
#include "message-part-data.h"
#include "imap-bodystructure.h"
#include "mail-search.h"
#include "mail-search-mime.h"
#include "index-search-private.h"

struct search_mimepart_stack {
	unsigned int index;
};

struct search_mimepart_context {
	pool_t pool;
	struct index_search_context *index_ctx;

	/* message parts parsed from BODYSTRUCTURE */
	struct message_part *mime_parts, *mime_part;

	string_t *buf;

	unsigned int depth, index;
	ARRAY(struct search_mimepart_stack) stack;
};

static void search_mime_arg(struct mail_search_mime_arg *arg,
			      struct search_mimepart_context *mpctx);

static int seach_arg_mime_parent_match(struct search_mimepart_context *mpctx,
				   struct mail_search_mime_arg *args)
{
	struct message_part *part = mpctx->mime_part;
	unsigned int prev_depth, prev_index;
	struct search_mimepart_stack *level;
	int ret;

	if (args->value.subargs == NULL) {
		/* PARENT EXISTS: matches if this part has a parent.
		 */
		return (part->parent != NULL ? 1 : 0);
	}

	/* PARENT <mpart-key>: matches if this part's parent matches the
	   mpart-key (subargs).
	 */

	prev_depth = mpctx->depth;
	prev_index = mpctx->index;

	level = array_idx_modifiable
		(&mpctx->stack, mpctx->depth-1);

	mpctx->mime_part = part->parent;
	mail_search_mime_args_reset(args->value.subargs, TRUE);

	mpctx->index = level->index;
	mpctx->depth = mpctx->depth-1;
	ret = mail_search_mime_args_foreach
		(args->value.subargs, search_mime_arg, mpctx);

	mpctx->mime_part = part;
	mpctx->index = prev_index;
	mpctx->depth = prev_depth;
	return ret;
}

static int seach_arg_mime_child_match(struct search_mimepart_context *mpctx,
				   struct mail_search_mime_arg *args)
{
	struct message_part *part, *prev_part;
	unsigned int prev_depth, prev_index, depth;
	struct search_mimepart_stack *level;
	int ret = 0;

	part = mpctx->mime_part;
	if (args->value.subargs == NULL) {
		/* CHILD EXISTS: matches if this part has any children; i.e., it is
		   multipart.
		 */
		return (part->children != NULL ? 1 : 0);
	}

	/* CHILD <mpart-key>: matches if this part has any child that mathes
	   the mpart-key (subargs).
	 */

	prev_part = part;
	prev_depth = mpctx->depth;
	prev_index = mpctx->index;

	depth = mpctx->depth;
	T_BEGIN {
		ARRAY(struct search_mimepart_stack) prev_stack;

		/* preserve current stack for any nested CHILD PARENT nastiness */
		t_array_init(&prev_stack, 16);
		array_copy(&prev_stack.arr, 0, &mpctx->stack.arr, 0,
			array_count(&mpctx->stack));

		depth++;
		if (depth < array_count(&mpctx->stack))
			level = array_idx_modifiable(&mpctx->stack, depth);
		else {
			i_assert(depth == array_count(&mpctx->stack));
			level = array_append_space(&mpctx->stack);
		}
		level->index = 1;

		part = part->children;
		while (part != NULL) {
			mpctx->mime_part = part;
			mail_search_mime_args_reset(args->value.subargs, TRUE);

			mpctx->depth = depth - prev_depth;
			mpctx->index = level->index;
			if ((ret=mail_search_mime_args_foreach
				(args->value.subargs, search_mime_arg, mpctx)) != 0)
				break;
			if (part->children != NULL) {
				depth++;
				if (depth < array_count(&mpctx->stack))
					level = array_idx_modifiable(&mpctx->stack, depth);
				else {
					i_assert(depth == array_count(&mpctx->stack));
					level = array_append_space(&mpctx->stack);
				}
				level->index = 1;
				part = part->children;
			} else {
				while (part->next == NULL) {
					if (part->parent == NULL || part->parent == prev_part)
						break;
					depth--;
					level = array_idx_modifiable(&mpctx->stack, depth);
					part = part->parent;
				}
				level->index++;
				part = part->next;
			}
		}

		array_clear(&mpctx->stack);
		array_copy(&mpctx->stack.arr, 0, &prev_stack.arr, 0,
			array_count(&prev_stack));
	} T_END;

	mpctx->mime_part = prev_part;
	mpctx->index = prev_index;
	mpctx->depth = prev_depth;
	return ret;
}

static int
seach_arg_mime_substring_match(
	struct search_mimepart_context *mpctx ATTR_UNUSED,
	const char *key, const char *value)
{
	if (value == NULL)
		return 0;

	/* FIXME: Normalization is required */
	return (strstr(value, key) != NULL ? 1 : 0);
}

static int
seach_arg_mime_envelope_time_match(
	struct search_mimepart_context *mpctx ATTR_UNUSED,
	enum mail_search_mime_arg_type type, time_t search_time,
	const struct message_part_envelope *envelope)
{
	time_t sent_time;
	int timezone_offset;

	if (envelope == NULL)
		return 0;

	/* NOTE: RFC-3501 specifies that timezone is ignored
	   in searches. sent_time is returned as UTC, so change it. */
	// FIXME: adjust comment
	if (!message_date_parse((const unsigned char *)envelope->date,
			strlen(envelope->date), &sent_time, &timezone_offset))
		return 0;
	sent_time += timezone_offset * 60;

	switch (type) {
	case SEARCH_MIME_SENTBEFORE:
		return sent_time < search_time ? 1 : 0;
	case SEARCH_MIME_SENTON:
		return (sent_time >= search_time &&
			sent_time < search_time + 3600*24) ? 1 : 0;
	case SEARCH_MIME_SENTSINCE:
		return sent_time >= search_time ? 1 : 0;
	default:
		i_unreached();
	}
}

static int
seach_arg_mime_envelope_address_match(
	struct search_mimepart_context *mpctx ATTR_UNUSED,
	enum mail_search_mime_arg_type type, const char *key,
	const struct message_part_envelope *envelope)
{
	const struct message_address *addrs;
	string_t *addrs_enc;

	if (envelope == NULL)
		return 0;

	switch (type) {
	case SEARCH_MIME_CC:
		addrs = envelope->cc;
		break;
	case SEARCH_MIME_BCC:
		addrs = envelope->bcc;
		break;
	case SEARCH_MIME_FROM:
		addrs = envelope->from;
		break;
	case SEARCH_MIME_SENDER:
		addrs = envelope->sender;
		break;
	case SEARCH_MIME_REPLY_TO:
		addrs = envelope->reply_to;
		break;
	case SEARCH_MIME_TO:
		addrs = envelope->to;
		break;
	default:
		i_unreached();
	}

	/* FIXME: do we need to normalize anything? at least case insensitivity.
	   MIME header encoding will make this a bit difficult, so it should
	   probably be normalized directly in the struct message_address. */

	addrs_enc = t_str_new(128);
	message_address_write(addrs_enc, addrs);
	return (strstr(str_c(addrs_enc), key) != NULL ? 1 : 0);
}

static int
seach_arg_mime_filename_match(struct search_mimepart_context *mpctx,
				   struct mail_search_mime_arg *arg)
{
	struct index_search_context *ictx = mpctx->index_ctx;
	struct message_part *part = mpctx->mime_part;
	char *key;
	const char *value;
	size_t vlen, alen;

	if (!message_part_data_get_filename(part, &value))
		return 0;

	if (mpctx->buf == NULL)
		mpctx->buf = str_new(default_pool, 256);

	if (arg->context == NULL) {
		str_truncate(mpctx->buf, 0);

		if (ictx->mail_ctx.normalizer(arg->value.str,
			strlen(arg->value.str), mpctx->buf) < 0)
			i_panic("search key not utf8: %s", arg->value.str);
		key = i_strdup(str_c(mpctx->buf));
		arg->context = (void *)key;
	} else {
		key = (char *)arg->context;
	}

	str_truncate(mpctx->buf, 0);
	if (ictx->mail_ctx.normalizer(value,
		strlen(value), mpctx->buf) >= 0)
		value = str_c(mpctx->buf);

	switch (arg->type) {
	case SEARCH_MIME_FILENAME_IS:
		return (strcmp(value, key) == 0 ? 1 : 0);
	case SEARCH_MIME_FILENAME_CONTAINS:
		return (strstr(value, key) != NULL ? 1 : 0);
	case SEARCH_MIME_FILENAME_BEGINS:
		return (str_begins(value, key) ? 1 : 0);
	case SEARCH_MIME_FILENAME_ENDS:
		vlen = strlen(value);
		alen = strlen(key);
		return (str_begins(value + (vlen - alen), key) ? 1 : 0);
	default:
		break;
	}
	i_unreached();
}
static void
search_arg_mime_filename_deinit(
	struct search_mimepart_context *mpctx ATTR_UNUSED,
	struct mail_search_mime_arg *arg)
{
	char *key = (char *)arg->context;

	i_free(key);
}

static int
seach_arg_mime_param_match(const struct message_part_param *params,
				   unsigned int params_count,
				   const char *name, const char *key)
{
	unsigned int i;

	/* FIXME: Is normalization required? */

	for (i = 0; i < params_count; i++) {
		if (strcasecmp(params[i].name, name) == 0) {
			if (key == NULL || *key == '\0')
				return 1;
			return (strstr(params[i].value, key) != NULL ? 1 : 0);
		}
	}
	return 0;
}

static int
seach_arg_mime_language_match(struct search_mimepart_context *mpctx,
				   const char *key)
{
	struct message_part_data *data = mpctx->mime_part->data;
	const char *const *lang;

	i_assert(data != NULL);

	lang = data->content_language;
	if (lang != NULL) {
		while (*lang != NULL) {
			/* FIXME: Should use RFC 4647 matching rules */
			if (strcasecmp(*lang, key) == 0)
				return 1;
			lang++;
		}
	}
	return 0;
}

/* Returns >0 = matched, 0 = not matched (unused), -1 = unknown */
static int search_mime_arg_match(struct search_mimepart_context *mpctx,
				   struct mail_search_mime_arg *arg)
{
	struct message_part *part = mpctx->mime_part;
	const struct message_part_data *data = part->data;

	i_assert(data != NULL);

	switch (arg->type) {
	case SEARCH_MIME_OR:
	case SEARCH_MIME_SUB:
		i_unreached();

	case SEARCH_MIME_SIZE_EQUAL:
		return (part->body_size.virtual_size == arg->value.size ? 1 : 0);
	case SEARCH_MIME_SIZE_LARGER:
		return (part->body_size.virtual_size > arg->value.size ? 1 : 0);
	case SEARCH_MIME_SIZE_SMALLER:
		return (part->body_size.virtual_size < arg->value.size ? 1 : 0);

	case SEARCH_MIME_DESCRIPTION:
		return seach_arg_mime_substring_match(mpctx,
			arg->value.str, data->content_description);
	case SEARCH_MIME_DISPOSITION_TYPE:
		return (data->content_disposition != NULL &&
			strcasecmp(data->content_disposition,
				arg->value.str) == 0 ? 1 : 0);
	case SEARCH_MIME_DISPOSITION_PARAM:
		return seach_arg_mime_param_match
			(data->content_disposition_params,
				data->content_disposition_params_count,
				arg->field_name, arg->value.str);
	case SEARCH_MIME_ENCODING:
		return (data->content_transfer_encoding != NULL &&
			strcasecmp(data->content_transfer_encoding,
				arg->value.str) == 0 ? 1 : 0);
	case SEARCH_MIME_ID:
		return (data->content_id != NULL &&
			strcasecmp(data->content_id,
				arg->value.str) == 0 ? 1 : 0);
	case SEARCH_MIME_LANGUAGE:
		return seach_arg_mime_language_match(mpctx, arg->value.str);
	case SEARCH_MIME_LOCATION:
		return (data->content_location != NULL &&
			strcasecmp(data->content_location,
				arg->value.str) == 0 ? 1 : 0);
	case SEARCH_MIME_MD5:
		return (data->content_md5 != NULL &&
			strcmp(data->content_md5,
				arg->value.str) == 0 ? 1 : 0);

	case SEARCH_MIME_TYPE:
		return (data->content_type != NULL &&
			strcasecmp(data->content_type,
				arg->value.str) == 0 ? 1 : 0);
	case SEARCH_MIME_SUBTYPE:
		return (data->content_subtype != NULL &&
			strcasecmp(data->content_subtype,
				arg->value.str) == 0 ? 1 : 0);
	case SEARCH_MIME_PARAM:
		return seach_arg_mime_param_match
			(data->content_type_params,
				data->content_type_params_count,
				arg->field_name, arg->value.str);

	case SEARCH_MIME_SENTBEFORE:
	case SEARCH_MIME_SENTON:
	case SEARCH_MIME_SENTSINCE:
		return seach_arg_mime_envelope_time_match
			(mpctx, arg->type, arg->value.time, data->envelope);

	case SEARCH_MIME_CC:
	case SEARCH_MIME_BCC:
	case SEARCH_MIME_FROM:
	case SEARCH_MIME_REPLY_TO:
	case SEARCH_MIME_SENDER:
	case SEARCH_MIME_TO:
		return seach_arg_mime_envelope_address_match
			(mpctx, arg->type, arg->value.str, data->envelope);

	case SEARCH_MIME_SUBJECT:
		if (data->envelope == NULL)
			return 0;
		return seach_arg_mime_substring_match(mpctx,
			arg->value.str, data->envelope->subject);
	case SEARCH_MIME_IN_REPLY_TO:
		if (data->envelope == NULL)
			return 0;
		return seach_arg_mime_substring_match(mpctx,
			arg->value.str, data->envelope->in_reply_to);
	case SEARCH_MIME_MESSAGE_ID:
		if (data->envelope == NULL)
			return 0;
		return seach_arg_mime_substring_match(mpctx,
			arg->value.str, data->envelope->message_id);

	case SEARCH_MIME_DEPTH_EQUAL:
		return (mpctx->depth == arg->value.number ? 1 : 0);
	case SEARCH_MIME_DEPTH_MIN:
		return (mpctx->depth >= arg->value.number ? 1 : 0);
	case SEARCH_MIME_DEPTH_MAX:
		return (mpctx->depth <= arg->value.number ? 1 : 0);
	case SEARCH_MIME_INDEX:
		return (mpctx->index == arg->value.number ? 1 : 0);

	case SEARCH_MIME_PARENT:
		return seach_arg_mime_parent_match(mpctx, arg);
	case SEARCH_MIME_CHILD:
		return seach_arg_mime_child_match(mpctx, arg);

	case SEARCH_MIME_FILENAME_IS:
	case SEARCH_MIME_FILENAME_CONTAINS:
	case SEARCH_MIME_FILENAME_BEGINS:
	case SEARCH_MIME_FILENAME_ENDS:
		return seach_arg_mime_filename_match(mpctx, arg);

	case SEARCH_MIME_HEADER:
	case SEARCH_MIME_BODY:
	case SEARCH_MIME_TEXT:
		break;
	}
	return -1;
}

static void search_mime_arg(struct mail_search_mime_arg *arg,
			      struct search_mimepart_context *mpctx)
{
	switch (search_mime_arg_match(mpctx, arg)) {
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

static int seach_arg_mime_parts_match(struct search_mimepart_context *mpctx,
				   struct mail_search_mime_arg *args,
				   struct message_part *parts)
{
	struct message_part *part;
	struct search_mimepart_stack *level;
	int ret;

	level = array_append_space(&mpctx->stack);
	level->index = 1;

	part = parts;
	while (part != NULL) {
		mpctx->mime_part = part;
		mail_search_mime_args_reset(args, TRUE);

		mpctx->index = level->index;
		mpctx->depth = array_count(&mpctx->stack)-1;

		if ((ret=mail_search_mime_args_foreach
			(args, search_mime_arg, mpctx)) != 0)
			return ret;
		if (part->children != NULL) {
			level = array_append_space(&mpctx->stack);
			level->index = 1;
			part = part->children;
		} else {
			while (part->next == NULL) {
				if (part->parent == NULL)
					break;
				array_pop_back(&mpctx->stack);
				level = array_idx_modifiable
					(&mpctx->stack, array_count(&mpctx->stack)-1);
				part = part->parent;
			}
			level->index++;
			part = part->next;
		}
	}

	return 0;
}

/* Returns >0 = matched, 0 = not matched, -1 = unknown */
static int search_arg_match_mimepart(struct search_mimepart_context *mpctx,
				   struct mail_search_arg *arg)
{
	struct index_search_context *ctx = mpctx->index_ctx;
	const char *bodystructure, *error;

	if (arg->type != SEARCH_MIMEPART)
		return -1;

	if (mpctx->pool == NULL) {
		mpctx->pool = pool_alloconly_create
			(MEMPOOL_GROWING"search mime parts", 4096);
		p_array_init(&mpctx->stack, mpctx->pool, 16);
	}
	if (mpctx->mime_parts == NULL) {
		/* FIXME: could the mail object already have message_part tree with
		   data? */
		if (mail_get_special(ctx->cur_mail,
			MAIL_FETCH_IMAP_BODYSTRUCTURE, &bodystructure) < 0)
			return -1;
		if (imap_bodystructure_parse_full(bodystructure, mpctx->pool,
			&mpctx->mime_parts, &error) < 0)
			return -1;
	}

	/* FIXME: implement HEADER, BODY and TEXT (not from BODYSTRUCTURE)
	   Needs to support FTS */
	return seach_arg_mime_parts_match
		(mpctx, arg->value.mime_part->args, mpctx->mime_parts);
}

static void search_mimepart_arg(struct mail_search_arg *arg,
			      struct search_mimepart_context *mpctx)
{
	switch (search_arg_match_mimepart(mpctx, arg)) {
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

int index_search_mime_arg_match(struct mail_search_arg *args,
	struct index_search_context *ctx)
{
	struct search_mimepart_context mpctx;
	int ret;

	i_zero(&mpctx);
	mpctx.index_ctx = ctx;

	ret = mail_search_args_foreach(args,
				       search_mimepart_arg, &mpctx);

	pool_unref(&mpctx.pool);
	str_free(&mpctx.buf);
	return ret;
}

static void
search_mime_arg_deinit(struct mail_search_mime_arg *arg,
			      struct search_mimepart_context *mpctx ATTR_UNUSED)
{
	switch (arg->type) {
	case SEARCH_MIME_FILENAME_IS:
	case SEARCH_MIME_FILENAME_CONTAINS:
	case SEARCH_MIME_FILENAME_BEGINS:
	case SEARCH_MIME_FILENAME_ENDS:
		search_arg_mime_filename_deinit(mpctx, arg);
		break;
	default:
		break;
	}
}

void index_search_mime_arg_deinit(struct mail_search_arg *arg,
	struct index_search_context *ctx)
{
	struct search_mimepart_context mpctx;
	struct mail_search_mime_arg *args;

	i_assert(arg->type == SEARCH_MIMEPART);
	args = arg->value.mime_part->args;

	i_zero(&mpctx);
	mpctx.index_ctx = ctx;

	mail_search_mime_args_reset(args, TRUE);
	(void)mail_search_mime_args_foreach(args,
		search_mime_arg_deinit, &mpctx);
}
