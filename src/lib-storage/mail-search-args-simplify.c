/* Copyright (c) 2002-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "mail-search.h"

struct mail_search_simplify_prev_arg {
	struct {
		enum mail_search_arg_type type;
		enum mail_search_arg_flag search_flags;
		enum mail_search_date_type date_type;
		bool match_not;
		bool fuzzy;
	} bin_mask;
	const char *hdr_field_name_mask;
	const char *str_mask;

	struct mail_search_arg *prev_arg;
};

struct mail_search_simplify_ctx {
	pool_t pool;
	/* arg mask => prev_arg */
	HASH_TABLE(struct mail_search_simplify_prev_arg *,
		   struct mail_search_simplify_prev_arg *) prev_args;
	bool parent_and;
	bool removals;
};

static int
mail_search_simplify_prev_arg_cmp(const struct mail_search_simplify_prev_arg *arg1,
				  const struct mail_search_simplify_prev_arg *arg2)
{
	int ret;

	ret = memcmp(&arg1->bin_mask, &arg2->bin_mask, sizeof(arg1->bin_mask));
	if (ret == 0)
		ret = null_strcmp(arg1->hdr_field_name_mask, arg2->hdr_field_name_mask);
	if (ret == 0)
		ret = null_strcmp(arg1->str_mask, arg2->str_mask);
	return ret;
}

static unsigned int
mail_search_simplify_prev_arg_hash(const struct mail_search_simplify_prev_arg *arg)
{
	unsigned int hash;

	hash = mem_hash(&arg->bin_mask, sizeof(arg->bin_mask));
	if (arg->hdr_field_name_mask != NULL)
		hash ^= str_hash(arg->hdr_field_name_mask);
	if (arg->str_mask != NULL)
		hash ^= str_hash(arg->str_mask);
	return hash;
}

static void mail_search_arg_get_base_mask(const struct mail_search_arg *arg,
					  struct mail_search_simplify_prev_arg *mask_r)
{
	memset(mask_r, 0, sizeof(*mask_r));
	mask_r->bin_mask.type = arg->type;
	mask_r->bin_mask.match_not = arg->match_not;
	mask_r->bin_mask.fuzzy = arg->fuzzy;
	mask_r->bin_mask.search_flags = arg->value.search_flags;
}

static struct mail_search_arg **
mail_search_args_simplify_get_prev_argp(struct mail_search_simplify_ctx *ctx,
					const struct mail_search_simplify_prev_arg *mask)
{
	struct mail_search_simplify_prev_arg *prev_arg;

	prev_arg = hash_table_lookup(ctx->prev_args, mask);
	if (prev_arg == NULL) {
		prev_arg = p_new(ctx->pool, struct mail_search_simplify_prev_arg, 1);
		prev_arg->bin_mask = mask->bin_mask;
		prev_arg->hdr_field_name_mask =
			p_strdup(ctx->pool, mask->hdr_field_name_mask);
		prev_arg->str_mask =
			p_strdup(ctx->pool, mask->str_mask);
		hash_table_insert(ctx->prev_args, prev_arg, prev_arg);
	}
	return &prev_arg->prev_arg;
}

static bool mail_search_args_merge_flags(struct mail_search_simplify_ctx *ctx,
					 struct mail_search_arg *args)
{
	struct mail_search_simplify_prev_arg mask;
	struct mail_search_arg **prev_argp;

	if (!((!args->match_not && ctx->parent_and) ||
	      (args->match_not && !ctx->parent_and)))
		return FALSE;

	mail_search_arg_get_base_mask(args, &mask);
	prev_argp = mail_search_args_simplify_get_prev_argp(ctx, &mask);

	if (*prev_argp == NULL) {
		*prev_argp = args;
		return FALSE;
	} else {
		(*prev_argp)->value.flags |= args->value.flags;
		return TRUE;
	}
}

static bool mail_search_args_merge_set(struct mail_search_simplify_ctx *ctx,
				       struct mail_search_arg *args)
{
	struct mail_search_simplify_prev_arg mask;
	struct mail_search_arg **prev_argp;

	if (!((!args->match_not && ctx->parent_and) ||
	      (args->match_not && !ctx->parent_and)))
		return FALSE;

	mail_search_arg_get_base_mask(args, &mask);
	prev_argp = mail_search_args_simplify_get_prev_argp(ctx, &mask);

	if (*prev_argp == NULL) {
		*prev_argp = args;
		return FALSE;
	} else {
		seq_range_array_merge(&(*prev_argp)->value.seqset,
				      &args->value.seqset);
		return TRUE;
	}
}

static bool mail_search_args_merge_time(struct mail_search_simplify_ctx *ctx,
					struct mail_search_arg *args)
{
	struct mail_search_simplify_prev_arg mask;
	struct mail_search_arg **prev_argp, *prev_arg;

	mail_search_arg_get_base_mask(args, &mask);
	mask.bin_mask.date_type = args->value.date_type;
	prev_argp = mail_search_args_simplify_get_prev_argp(ctx, &mask);

	if (*prev_argp == NULL) {
		*prev_argp = args;
		return FALSE;
	}

	prev_arg = *prev_argp;
	switch (args->type) {
	case SEARCH_BEFORE:
		if (ctx->parent_and) {
			if (prev_arg->value.time < args->value.time) {
				/* prev_arg < 5 AND arg < 10 */
			} else {
				/* prev_arg < 10 AND arg < 5 */
				prev_arg->value.time = args->value.time;
			}
		} else {
			if (prev_arg->value.time < args->value.time) {
				/* prev_arg < 5 OR arg < 10 */
				prev_arg->value.time = args->value.time;
			} else {
				/* prev_arg < 10 OR arg < 5 */
			}
		}
		return TRUE;
	case SEARCH_ON:
		if (prev_arg->value.time == args->value.time)
			return TRUE;
		return FALSE;
	case SEARCH_SINCE:
		if (ctx->parent_and) {
			if (prev_arg->value.time < args->value.time) {
				/* prev_arg >= 5 AND arg >= 10 */
				prev_arg->value.time = args->value.time;
			} else {
				/* prev_arg >= 10 AND arg >= 5 */
			}
		} else {
			if (prev_arg->value.time < args->value.time) {
				/* prev_arg >= 5 OR arg >= 10 */
			} else {
				/* prev_arg >= 10 OR arg >= 5 */
				prev_arg->value.time = args->value.time;
			}
		}
		return TRUE;
	default:
		break;
	}
	return FALSE;
}

static bool mail_search_args_merge_size(struct mail_search_simplify_ctx *ctx,
					struct mail_search_arg *args)
{
	struct mail_search_simplify_prev_arg mask;
	struct mail_search_arg **prev_argp, *prev_arg;

	mail_search_arg_get_base_mask(args, &mask);
	prev_argp = mail_search_args_simplify_get_prev_argp(ctx, &mask);

	if (*prev_argp == NULL) {
		*prev_argp = args;
		return FALSE;
	}

	prev_arg = *prev_argp;
	switch (args->type) {
	case SEARCH_SMALLER:
		if (ctx->parent_and) {
			if (prev_arg->value.size < args->value.size) {
				/* prev_arg < 5 AND arg < 10 */
			} else {
				/* prev_arg < 10 AND arg < 5 */
				prev_arg->value.size = args->value.size;
			}
		} else {
			if (prev_arg->value.size < args->value.size) {
				/* prev_arg < 5 OR arg < 10 */
				prev_arg->value.size = args->value.size;
			} else {
				/* prev_arg < 10 OR arg < 5 */
			}
		}
		return TRUE;
	case SEARCH_LARGER:
		if (ctx->parent_and) {
			if (prev_arg->value.size < args->value.size) {
				/* prev_arg >= 5 AND arg >= 10 */
				prev_arg->value.size = args->value.size;
			} else {
				/* prev_arg >= 10 AND arg >= 5 */
			}
		} else {
			if (prev_arg->value.size < args->value.size) {
				/* prev_arg >= 5 OR arg >= 10 */
			} else {
				/* prev_arg >= 10 OR arg >= 5 */
				prev_arg->value.size = args->value.size;
			}
		}
		return TRUE;
	default:
		break;
	}
	return FALSE;
}

static bool mail_search_args_merge_text(struct mail_search_simplify_ctx *ctx,
					struct mail_search_arg *args)
{
	struct mail_search_simplify_prev_arg mask;
	struct mail_search_arg **prev_argp;

	mail_search_arg_get_base_mask(args, &mask);
	mask.hdr_field_name_mask = args->hdr_field_name;
	mask.str_mask = args->value.str;
	prev_argp = mail_search_args_simplify_get_prev_argp(ctx, &mask);

	if (*prev_argp == NULL) {
		*prev_argp = args;
		return FALSE;
	}
	/* duplicate search word. */
	return TRUE;
}

static bool
mail_search_args_simplify_sub(struct mailbox *box,
			      struct mail_search_arg *args, bool parent_and)
{
	struct mail_search_simplify_ctx ctx;
	struct mail_search_arg *sub, *prev_arg = NULL;
	bool merged;

	memset(&ctx, 0, sizeof(ctx));
	ctx.parent_and = parent_and;
	ctx.pool = pool_alloconly_create("mail search args simplify", 1024);
	hash_table_create(&ctx.prev_args, ctx.pool, 0,
			  mail_search_simplify_prev_arg_hash,
			  mail_search_simplify_prev_arg_cmp);

	while (args != NULL) {
		if (args->match_not && (args->type == SEARCH_SUB ||
					args->type == SEARCH_OR)) {
			/* neg(p and q and ..) == neg(p) or neg(q) or ..
			   neg(p or q or ..) == neg(p) and neg(q) and .. */
			args->type = args->type == SEARCH_SUB ?
				SEARCH_OR : SEARCH_SUB;
			args->match_not = FALSE;
			sub = args->value.subargs;
			do {
				sub->match_not = !sub->match_not;
				sub = sub->next;
			} while (sub != NULL);
		}

		if ((args->type == SEARCH_SUB && parent_and) ||
		    (args->type == SEARCH_OR && !parent_and) ||
		    ((args->type == SEARCH_SUB || args->type == SEARCH_OR) &&
		     args->value.subargs->next == NULL)) {
			/* p and (q and ..) == p and q and ..
			   p or (q or ..) == p or q or ..
			   (p) = p */
			sub = args->value.subargs;
			for (; sub->next != NULL; sub = sub->next) ;
			sub->next = args->next;
			*args = *args->value.subargs;
			continue;
		}

		if (args->type == SEARCH_SUB ||
		    args->type == SEARCH_OR ||
		    args->type == SEARCH_INTHREAD) {
			if (mail_search_args_simplify_sub(box, args->value.subargs,
							  args->type != SEARCH_OR))
				ctx.removals = TRUE;
		}

		/* try to merge arguments */
		switch (args->type) {
		case SEARCH_FLAGS:
			merged = mail_search_args_merge_flags(&ctx, args);
			break;
		case SEARCH_SEQSET:
		case SEARCH_UIDSET:
			merged = mail_search_args_merge_set(&ctx, args);
			break;
		case SEARCH_BEFORE:
		case SEARCH_ON:
		case SEARCH_SINCE:
			merged = mail_search_args_merge_time(&ctx, args);
			break;
		case SEARCH_SMALLER:
		case SEARCH_LARGER:
			merged = mail_search_args_merge_size(&ctx, args);
			break;
		case SEARCH_HEADER:
		case SEARCH_HEADER_ADDRESS:
		case SEARCH_HEADER_COMPRESS_LWSP:
		case SEARCH_BODY:
		case SEARCH_TEXT:
			merged = mail_search_args_merge_text(&ctx, args);
			break;
		default:
			merged = FALSE;
			break;
		}
		if (merged) {
			i_assert(prev_arg != NULL);
			prev_arg->next = args->next;
			args = args->next;
			ctx.removals = TRUE;
			continue;
		}

		prev_arg = args;
		args = args->next;
	}
	hash_table_destroy(&ctx.prev_args);
	pool_unref(&ctx.pool);
	return ctx.removals;
}

static bool
mail_search_args_unnest_inthreads(struct mail_search_args *args,
				  struct mail_search_arg **argp,
				  bool parent_inthreads, bool parent_and)
{
	struct mail_search_arg *arg, *thread_arg, *or_arg;
	bool child_inthreads = FALSE, non_inthreads = FALSE;

	for (arg = *argp; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_SUB:
		case SEARCH_OR:
			if (!mail_search_args_unnest_inthreads(args,
					&arg->value.subargs, parent_inthreads,
					arg->type != SEARCH_OR)) {
				arg->result = 1;
				child_inthreads = TRUE;
			} else {
				arg->result = 0;
				non_inthreads = TRUE;
			}
			break;
		case SEARCH_INTHREAD:
			if (mail_search_args_unnest_inthreads(args,
					&arg->value.subargs, TRUE, TRUE)) {
				/* children converted to SEARCH_INTHREADs */
				arg->type = SEARCH_SUB;
			}
			args->have_inthreads = TRUE;
			arg->result = 1;
			child_inthreads = TRUE;
			break;
		default:
			arg->result = 0;
			non_inthreads = TRUE;
			break;
		}
	}

	if (!parent_inthreads || !child_inthreads || !non_inthreads)
		return FALSE;

	/* put all non-INTHREADs under a single INTHREAD */
	thread_arg = p_new(args->pool, struct mail_search_arg, 1);
	thread_arg->type = SEARCH_INTHREAD;

	while (*argp != NULL) {
		arg = *argp;
		argp = &(*argp)->next;

		if (arg->result == 0) {
			/* not an INTHREAD or a SUB/OR with only INTHREADs */
			arg->next = thread_arg->value.subargs;
			thread_arg->value.subargs = arg;
		}
	}
	if (!parent_and) {
		/* We want to OR the args */
		or_arg = p_new(args->pool, struct mail_search_arg, 1);
		or_arg->type = SEARCH_OR;
		or_arg->value.subargs = thread_arg->value.subargs;
		thread_arg->value.subargs = or_arg;
	}
	return TRUE;
}

void mail_search_args_simplify(struct mail_search_args *args)
{
	bool removals;

	args->simplified = TRUE;

	removals = mail_search_args_simplify_sub(args->box, args->args, TRUE);
	if (mail_search_args_unnest_inthreads(args, &args->args,
					      FALSE, TRUE)) {
		/* we may have added some extra SUBs that could be dropped */
		mail_search_args_simplify_sub(args->box, args->args, TRUE);
	}
	while (removals)
		removals = mail_search_args_simplify_sub(args->box, args->args, TRUE);
}
