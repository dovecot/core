/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-search.h"

void mail_search_args_reset(struct mail_search_arg *args)
{
	while (args != NULL) {
		if (args->type == SEARCH_OR || args->type == SEARCH_SUB)
			mail_search_args_reset(args->value.subargs);
		args->result = -1;

		args = args->next;
	}
}

static void search_arg_foreach(struct mail_search_arg *arg,
			       mail_search_foreach_callback_t callback,
			       void *context)
{
	struct mail_search_arg *subarg;

	if (arg->result != -1)
		return;

	if (arg->type == SEARCH_SUB) {
		/* sublist of conditions */
		i_assert(arg->value.subargs != NULL);

		arg->result = 1;
		subarg = arg->value.subargs;
		while (subarg != NULL) {
			if (subarg->result == -1)
				search_arg_foreach(subarg, callback, context);

			if (subarg->result == -1)
				arg->result = -1;
			else if (subarg->result == arg->not) {
				/* didn't match */
				arg->result = 0;
				break;
			}

			subarg = subarg->next;
		}
	} else if (arg->type == SEARCH_OR) {
		/* OR-list of conditions */
		i_assert(arg->value.subargs != NULL);

		subarg = arg->value.subargs;
		arg->result = 0;
		while (subarg != NULL) {
			if (subarg->result == -1)
				search_arg_foreach(subarg, callback, context);

			if (subarg->result != -1) {
				if (subarg->result == !arg->not) {
					/* matched */
					arg->result = 1;
					break;
				}
			} else {
				arg->result = -1;
			}

			subarg = subarg->next;
		}
	} else {
		/* just a single condition */
		callback(arg, context);
	}
}

int mail_search_args_foreach(struct mail_search_arg *args,
			     mail_search_foreach_callback_t callback,
			     void *context)
{
	int result;

	result = 1;
	for (; args != NULL; args = args->next) {
		search_arg_foreach(args, callback, context);

		if (args->result == 0) {
			/* didn't match */
			return 0;
		}

		if (args->result == -1)
			result = -1;
	}

	return result;
}

static void search_arg_analyze(struct mail_search_arg *arg, int *have_headers,
			       int *have_body, int *have_text)
{
	struct mail_search_arg *subarg;

	if (arg->result != -1)
		return;

	switch (arg->type) {
	case SEARCH_OR:
	case SEARCH_SUB:
		subarg = arg->value.subargs;
		while (subarg != NULL) {
			if (subarg->result == -1) {
				search_arg_analyze(subarg, have_headers,
						   have_body, have_text);
			}

			subarg = subarg->next;
		}
		break;
	case SEARCH_SENTBEFORE:
	case SEARCH_SENTON:
	case SEARCH_SENTSINCE:
	case SEARCH_FROM:
	case SEARCH_TO:
	case SEARCH_CC:
	case SEARCH_BCC:
	case SEARCH_SUBJECT:
	case SEARCH_IN_REPLY_TO:
	case SEARCH_MESSAGE_ID:
	case SEARCH_HEADER:
		*have_headers = TRUE;
		break;
	case SEARCH_BODY:
		*have_body = TRUE;
		break;
	case SEARCH_TEXT:
		*have_text = TRUE;
		break;
	default:
		break;
	}
}

void mail_search_args_analyze(struct mail_search_arg *args, int *have_headers,
			      int *have_body, int *have_text)
{
	*have_headers = *have_body = *have_text = FALSE;

	for (; args != NULL; args = args->next)
		search_arg_analyze(args, have_headers, have_body, have_text);
}

