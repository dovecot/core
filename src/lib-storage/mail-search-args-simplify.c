/* Copyright (c) 2002-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-search.h"

static void
mail_search_args_simplify_sub(struct mailbox *box,
			      struct mail_search_arg *args, bool parent_and)
{
	struct mail_search_arg *sub, *prev = NULL;
	struct mail_search_arg *prev_flags_arg, *prev_not_flags_arg;

	prev_flags_arg = prev_not_flags_arg = NULL;
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
			mail_search_args_simplify_sub(box, args->value.subargs,
						      args->type != SEARCH_OR);
		}

		/* merge all flags arguments */
		if (args->type == SEARCH_FLAGS &&
		    !args->match_not && parent_and) {
			if (prev_flags_arg == NULL)
				prev_flags_arg = args;
			else {
				prev_flags_arg->value.flags |=
					args->value.flags;
				prev->next = args->next;
				args = args->next;
				continue;
			}
		} else if (args->type == SEARCH_FLAGS && args->match_not &&
			   !parent_and) {
			if (prev_not_flags_arg == NULL)
				prev_not_flags_arg = args;
			else {
				prev_not_flags_arg->value.flags |=
					args->value.flags;
				prev->next = args->next;
				args = args->next;
				continue;
			}
		}

		prev = args;
		args = args->next;
	}
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
	args->simplified = TRUE;

	mail_search_args_simplify_sub(args->box, args->args, TRUE);
	if (mail_search_args_unnest_inthreads(args, &args->args,
					      FALSE, TRUE)) {
		/* we may have added some extra SUBs that could be dropped */
		mail_search_args_simplify_sub(args->box, args->args, TRUE);
	}
}
