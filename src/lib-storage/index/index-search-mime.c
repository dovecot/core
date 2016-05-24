/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
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
	struct imap_message_part *mime_parts, *mime_part;
	unsigned int depth, index;
	ARRAY(struct search_mimepart_stack) stack;
};

static void search_mime_arg(struct mail_search_mime_arg *arg,
			    struct search_mimepart_context *mpctx);

static int seach_arg_mime_parent_match(struct search_mimepart_context *mpctx,
				       struct mail_search_mime_arg *args)
{
	struct imap_message_part *part = mpctx->mime_part;
	unsigned int prev_depth, prev_index;
	struct search_mimepart_stack *level;
	int ret;

	if (args->value.subargs == NULL) {
		/* EXISTS */
		return (part->parent != NULL ? 1 : 0);
	}

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
	struct imap_message_part *part, *prev_part;
	unsigned int prev_depth, prev_index, depth;
	struct search_mimepart_stack *level;
	int ret = 0;

	part = mpctx->mime_part;
	if (args->value.subargs == NULL) {
		/* EXISTS */
		return (part->children != NULL ? 1 : 0);
	}

	prev_part = part;
	prev_depth = mpctx->depth;
	prev_index = mpctx->index;

	depth = mpctx->depth;
	T_BEGIN {
		ARRAY(struct search_mimepart_stack) prev_stack;

		/* preserve current stack for any nested CHILD PARENT nastyness */
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

/* Returns >0 = matched, 0 = not matched (unused), -1 = unknown */
static int search_mime_arg_match(struct search_mimepart_context *mpctx,
				 struct mail_search_mime_arg *arg)
{
	struct imap_message_part *part = mpctx->mime_part;
	const char *value;

	// FIXME: implement proper substring searches where required

	switch (arg->type) {
	case SEARCH_MIME_SIZE_EQUAL:
		return (part->body_size == arg->value.size ? 1 : 0);
	case SEARCH_MIME_SIZE_LARGER:
		return (part->body_size > arg->value.size ? 1 : 0);
	case SEARCH_MIME_SIZE_SMALLER:
		return (part->body_size < arg->value.size ? 1 : 0);

	case SEARCH_MIME_DESCRIPTION:
		return -1; // FIXME
	case SEARCH_MIME_DISPOSITION_TYPE:
		return part->content_disposition != NULL &&
			strcasecmp(part->content_disposition,
				   arg->value.str) == 0 ? 1 : 0;
	case SEARCH_MIME_DISPOSITION_PARAM:
		return -1; // FIXME		
	case SEARCH_MIME_ENCODING:
		return part->content_transfer_encoding != NULL &&
			strcasecmp(part->content_transfer_encoding,
				   arg->value.str) == 0 ? 1 : 0;
	case SEARCH_MIME_ID:
		return part->content_id != NULL &&
			strcasecmp(part->content_id,
				   arg->value.str) == 0 ? 1 : 0;
	case SEARCH_MIME_LANGUAGE:
		return -1; // FIXME
	case SEARCH_MIME_LOCATION:
		return part->content_location != NULL &&
			strcasecmp(part->content_location,
				   arg->value.str) == 0 ? 1 : 0;
	case SEARCH_MIME_MD5:
		return part->content_md5 != NULL &&
			strcmp(part->content_md5,
			       arg->value.str) == 0 ? 1 : 0;

	case SEARCH_MIME_TYPE:
		return part->content_type != NULL &&
			strcasecmp(part->content_type,
				   arg->value.str) == 0 ? 1 : 0;
	case SEARCH_MIME_SUBTYPE:
		return part->content_subtype != NULL &&
			strcasecmp(part->content_subtype,
				   arg->value.str) == 0 ? 1 : 0;
	case SEARCH_MIME_PARAM:
		return -1; // FIXME

	case SEARCH_MIME_SENTBEFORE:
	case SEARCH_MIME_SENTON:
	case SEARCH_MIME_SENTSINCE:
		return -1; // FIXME: need envelope

	case SEARCH_MIME_CC:
	case SEARCH_MIME_BCC:
	case SEARCH_MIME_FROM:
	case SEARCH_MIME_IN_REPLY_TO:
	case SEARCH_MIME_SENDER:
	case SEARCH_MIME_SUBJECT:
	case SEARCH_MIME_TO:
		return -1; // FIXME: need envelope

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

	case SEARCH_MIME_LINES_EQUAL:
		return (part->lines == arg->value.number ? 1 : 0);
	case SEARCH_MIME_LINES_MORE:
		return (part->lines > arg->value.number ? 1 : 0);
	case SEARCH_MIME_LINES_FEWER:
		return (part->lines < arg->value.number ? 1 : 0);

	case SEARCH_MIME_FILENAME_IS:
	case SEARCH_MIME_FILENAME_CONTAINS:
	case SEARCH_MIME_FILENAME_BEGINS:
	case SEARCH_MIME_FILENAME_ENDS:
		if (!imap_message_part_get_filename(part, &value))
			return 0;
		switch (arg->type) {
		case SEARCH_MIME_FILENAME_IS:
			return (strcmp(value, arg->value.str) == 0 ? 1 : 0);
		case SEARCH_MIME_FILENAME_CONTAINS:
			return (strstr(value, arg->value.str) != NULL ? 1 : 0);
		case SEARCH_MIME_FILENAME_BEGINS:
			return (strncmp(value,
				arg->value.str, strlen(arg->value.str)) == 0 ? 1 : 0);
		case SEARCH_MIME_FILENAME_ENDS: {
				size_t vlen = strlen(value), alen = strlen(arg->value.str);
				return (strncmp(value + (vlen - alen),
					arg->value.str, alen) == 0 ? 1 : 0);
			}
		default:
			i_unreached();
		}
	default:
		return -1;
	}
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
				      struct imap_message_part *parts)
{
	struct imap_message_part *part;
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
				array_delete(&mpctx->stack, array_count(&mpctx->stack)-1, 1);
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
		if (mail_get_special(ctx->cur_mail,
			MAIL_FETCH_IMAP_BODYSTRUCTURE, &bodystructure) < 0)
			return -1;
		if (imap_message_parts_parse(bodystructure, mpctx->pool,
			&mpctx->mime_parts, &error) < 0)
			return -1;
	}

	// FIXME: implement HEADER, BODY and TEXT (not from BODYSTRUCTURE)

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

	memset(&mpctx, 0, sizeof(mpctx));
	mpctx.index_ctx = ctx;

	ret = mail_search_args_foreach(args,
				       search_mimepart_arg, &mpctx);

	if (mpctx.pool != NULL)
		pool_unref(&mpctx.pool);
	return ret;
}

