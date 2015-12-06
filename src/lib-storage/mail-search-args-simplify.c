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
mail_search_args_have_equal(const struct mail_search_arg *args,
			    const struct mail_search_arg *wanted_arg)
{
	const struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		if (mail_search_arg_one_equals(arg, wanted_arg))
			return TRUE;
	}
	return FALSE;
}

static bool
mail_search_args_remove_equal(struct mail_search_arg *parent_arg,
			      const struct mail_search_arg *wanted_arg,
			      bool check_subs)
{
	struct mail_search_arg **argp;
	bool found = FALSE;

	for (argp = &parent_arg->value.subargs; (*argp) != NULL; ) {
		if (mail_search_arg_one_equals(*argp, wanted_arg)) {
			*argp = (*argp)->next;
			found = TRUE;
		} else if (check_subs) {
			i_assert((*argp)->type == SEARCH_SUB);
			if (!mail_search_args_remove_equal(*argp, wanted_arg, FALSE)) {
				/* we already verified that this should have
				   existed. */
				i_unreached();
			}
			if ((*argp)->value.subargs == NULL)
				*argp = (*argp)->next;
			else
				argp = &(*argp)->next;
			found = TRUE;
		} else {
			argp = &(*argp)->next;
		}
	}
	return found;
}

static bool
mail_search_args_have_all_equal(struct mail_search_arg *parent_arg,
				const struct mail_search_arg *wanted_args)
{
	const struct mail_search_arg *arg;

	i_assert(parent_arg->type == SEARCH_SUB);

	for (arg = wanted_args; arg != NULL; arg = arg->next) {
		if (!mail_search_args_have_equal(parent_arg->value.subargs, arg))
			return FALSE;
	}
	return TRUE;
}

static unsigned int
mail_search_args_count(const struct mail_search_arg *args)
{
	unsigned int count;

	for (count = 0; args != NULL; count++)
		args = args->next;
	return count;
}

static bool
mail_search_args_simplify_or_drop_redundent_args(struct mail_search_arg *parent_arg)
{
	struct mail_search_arg *arg, **argp, one_arg, *lowest_arg = NULL;
	unsigned int count, lowest_count = UINT_MAX;
	bool ret = FALSE;

	/* find the arg which has the lowest number of child args */
	for (arg = parent_arg->value.subargs; arg != NULL; arg = arg->next) {
		if (arg->type != SEARCH_SUB) {
			one_arg = *arg;
			one_arg.next = NULL;
			lowest_arg = &one_arg;
			break;
		}
		count = mail_search_args_count(arg->value.subargs);
		if (count < lowest_count) {
			lowest_arg = arg->value.subargs;
			lowest_count = count;
		}
	}
	i_assert(lowest_arg != NULL);

	/* if there are any args that include lowest_arg, drop the arg since
	   it's redundant. (non-SUB duplicates are dropped elsewhere.) */
	for (argp = &parent_arg->value.subargs; *argp != NULL; ) {
		if (*argp != lowest_arg && (*argp)->type == SEARCH_SUB &&
		    (*argp)->value.subargs != lowest_arg &&
		    mail_search_args_have_all_equal(*argp, lowest_arg)) {
			*argp = (*argp)->next;
			ret = TRUE;
		} else {
			argp = &(*argp)->next;
		}
	}
	return ret;
}

static bool
mail_search_args_simplify_extract_common_and(struct mail_search_arg *parent_arg,
					     pool_t pool)
{
	struct mail_search_arg *arg, *sub_arg, *sub_next;
	struct mail_search_arg *or_arg, *common_args = NULL;

	i_assert(parent_arg->type == SEARCH_OR);
	i_assert(!parent_arg->match_not);

	/* find the first SEARCH_SUB */
	for (arg = parent_arg->value.subargs; arg != NULL; arg = arg->next) {
		if (arg->type == SEARCH_SUB)
			break;
	}
	if (arg == NULL)
		return FALSE;

	for (sub_arg = arg->value.subargs; sub_arg != NULL; sub_arg = sub_next) {
		sub_next = sub_arg->next;

		/* check if sub_arg is found from all the args */
		for (arg = parent_arg->value.subargs; arg != NULL; arg = arg->next) {
			if (mail_search_arg_one_equals(arg, sub_arg)) {
				/* the whole arg matches */
			} else if (arg->type == SEARCH_SUB &&
				   mail_search_args_have_equal(arg->value.subargs, sub_arg)) {
				/* exists as subarg */
			} else {
				break;
			}
		}
		if (arg != NULL)
			continue;

		/* extract the arg and put it to common_args */
		mail_search_args_remove_equal(parent_arg, sub_arg, TRUE);
		sub_arg->next = common_args;
		common_args = sub_arg;
	}
	if (common_args == NULL)
		return FALSE;

	if (parent_arg->value.subargs == NULL) {
		/* there are only common args */
		parent_arg->type = SEARCH_SUB;
		parent_arg->value.subargs = common_args;
	} else {
		/* replace OR arg with AND(common_args, OR(non_common_args)) */
		or_arg = p_new(pool, struct mail_search_arg, 1);
		*or_arg = *parent_arg;
		or_arg->next = common_args;

		parent_arg->type = SEARCH_SUB;
		parent_arg->value.subargs = or_arg;
	}
	return TRUE;
}

static bool
mail_search_args_simplify_sub(struct mailbox *box, pool_t pool,
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
			ctx.removals = TRUE;
			continue;
		}

		if (args->type == SEARCH_SUB ||
		    args->type == SEARCH_OR ||
		    args->type == SEARCH_INTHREAD) {
			if (args->type == SEARCH_OR) {
				if (mail_search_args_simplify_or_drop_redundent_args(args))
					ctx.removals = TRUE;
				if (mail_search_args_simplify_extract_common_and(args, pool))
					ctx.removals = TRUE;
			}
			if (mail_search_args_simplify_sub(box, pool, args->value.subargs,
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

	removals = mail_search_args_simplify_sub(args->box, args->pool, args->args, TRUE);
	if (mail_search_args_unnest_inthreads(args, &args->args,
					      FALSE, TRUE)) {
		/* we may have added some extra SUBs that could be dropped */
		if (mail_search_args_simplify_sub(args->box, args->pool, args->args, TRUE))
			removals = TRUE;
	}
	while (removals)
		removals = mail_search_args_simplify_sub(args->box, args->pool, args->args, TRUE);
}
