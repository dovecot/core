/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-search.h"

typedef struct {
	Pool pool;
	const char *error;
} SearchBuildData;

static MailSearchArg *search_arg_new(Pool pool, MailSearchArgType type)
{
	MailSearchArg *arg;

	arg = p_new(pool, MailSearchArg, 1);
	arg->type = type;

	return arg;
}

#define ARG_NEW(type, value) \
	arg_new(data, args, next_sarg, type, value)

static int arg_new(SearchBuildData *data, ImapArg **args,
		   MailSearchArg **next_sarg, MailSearchArgType type, int value)
{
	MailSearchArg *sarg;

	*next_sarg = sarg = search_arg_new(data->pool, type);
	if (value == 0)
		return TRUE;

	/* first arg */
	if (*args == NULL) {
		data->error = "Missing parameter for argument";
		return FALSE;
	}

	sarg->value.str = str_ucase((*args)->data.str);
	*args += 1;

	/* second arg */
	if (value == 2) {
		if ((*args)->type == IMAP_ARG_EOL) {
			data->error = "Missing parameter for argument";
			return FALSE;
		}

                sarg->hdr_field_name = sarg->value.str;
		sarg->value.str = str_ucase((*args)->data.str);
		*args += 1;
	}

	return TRUE;
}

static int search_arg_build(SearchBuildData *data, ImapArg **args,
			    MailSearchArg **next_sarg)
{
	MailSearchArg **subargs;
	ImapArg *arg;
	char *str;

	if ((*args)->type == IMAP_ARG_EOL) {
		data->error = "Missing argument";
		return FALSE;
	}

	arg = *args;

	if (arg->type == IMAP_ARG_NIL) {
		/* NIL not allowed */
		data->error = "NIL not allowed";
		return FALSE;
	}

	if (arg->type == IMAP_ARG_LIST) {
		ImapArg *listargs = arg->data.list->args;

		*next_sarg = search_arg_new(data->pool, SEARCH_SUB);
		subargs = &(*next_sarg)->value.subargs;
		while (listargs->type != IMAP_ARG_EOL) {
			if (!search_arg_build(data, &listargs, subargs))
				return FALSE;
			subargs = &(*subargs)->next;
		}

		*args += 1;
		return TRUE;
	}

	i_assert(arg->type == IMAP_ARG_ATOM ||
		 arg->type == IMAP_ARG_STRING);

	/* string argument - get the name and jump to next */
	str = arg->data.str;
	*args += 1;
	str_ucase(str);

	switch (*str) {
	case 'A':
		if (strcmp(str, "ANSWERED") == 0)
			return ARG_NEW(SEARCH_ANSWERED, 0);
		else if (strcmp(str, "ALL") == 0)
			return ARG_NEW(SEARCH_ALL, 0);
		break;
	case 'B':
		if (strcmp(str, "BODY") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_BODY, 1);
		} else if (strcmp(str, "BEFORE") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_BEFORE, 1);
		} else if (strcmp(str, "BCC") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_BCC, 1);
		}
		break;
	case 'C':
		if (strcmp(str, "CC") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_CC, 1);
		}
		break;
	case 'D':
		if (strcmp(str, "DELETED") == 0)
			return ARG_NEW(SEARCH_DELETED, 0);
		else if (strcmp(str, "DRAFT") == 0)
			return ARG_NEW(SEARCH_DRAFT, 0);
		break;
	case 'F':
		if (strcmp(str, "FLAGGED") == 0)
			return ARG_NEW(SEARCH_FLAGGED, 0);
		else if (strcmp(str, "FROM") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_FROM, 1);
		}
		break;
	case 'H':
		if (strcmp(str, "HEADER") == 0) {
			/* <field-name> <string> */
			const char *key;

			if ((*args)->type == IMAP_ARG_EOL) {
				data->error = "Missing parameter for HEADER";
				return FALSE;
			}
			key = str_ucase((*args)->data.str);

			if (strcmp(key, "FROM") == 0) {
				*args += 1;
				return ARG_NEW(SEARCH_FROM, 1);
			} else if (strcmp(key, "TO") == 0) {
				*args += 1;
				return ARG_NEW(SEARCH_TO, 1);
			} else if (strcmp(key, "CC") == 0) {
				*args += 1;
				return ARG_NEW(SEARCH_CC, 1);
			} else if (strcmp(key, "BCC") == 0) {
				*args += 1;
				return ARG_NEW(SEARCH_BCC, 1);
			} else if (strcmp(key, "SUBJECT") == 0) {
				*args += 1;
				return ARG_NEW(SEARCH_SUBJECT, 1);
			} else if (strcmp(key, "IN-REPLY-TO") == 0) {
				*args += 1;
				return ARG_NEW(SEARCH_IN_REPLY_TO, 1);
			} else if (strcmp(key, "MESSAGE-ID") == 0) {
				*args += 1;
				return ARG_NEW(SEARCH_MESSAGE_ID, 1);
			} else {
				return ARG_NEW(SEARCH_HEADER, 2);
			}
		}
		break;
	case 'K':
		if (strcmp(str, "KEYWORD") == 0) {
			/* <flag> */
			return ARG_NEW(SEARCH_KEYWORD, 1);
		}
		break;
	case 'L':
		if (strcmp(str, "LARGER") == 0) {
			/* <n> */
			return ARG_NEW(SEARCH_LARGER, 1);
		}
		break;
	case 'N':
		if (strcmp(str, "NOT") == 0) {
			if (!search_arg_build(data, args, next_sarg))
				return FALSE;
			(*next_sarg)->not = !(*next_sarg)->not;
			return TRUE;
		} else if (strcmp(str, "NEW") == 0) {
			/* NEW == (RECENT UNSEEN) */
			*next_sarg = search_arg_new(data->pool, SEARCH_SUB);

			subargs = &(*next_sarg)->value.subargs;
			*subargs = search_arg_new(data->pool, SEARCH_RECENT);
			(*subargs)->next = search_arg_new(data->pool,
							  SEARCH_SEEN);
			(*subargs)->next->not = TRUE;
			return TRUE;
		}
		break;
	case 'O':
		if (strcmp(str, "OR") == 0) {
			/* <search-key1> <search-key2> */
			*next_sarg = search_arg_new(data->pool, SEARCH_OR);

			subargs = &(*next_sarg)->value.subargs;
			for (;;) {
				if (!search_arg_build(data, args, subargs))
					return FALSE;

				subargs = &(*subargs)->next;

				/* <key> OR <key> OR ... <key> - put them all
				   under one SEARCH_OR list. */
				if ((*args)->type == IMAP_ARG_EOL)
					break;

				if ((*args)->type != IMAP_ARG_ATOM ||
				    strcasecmp((*args)->data.str, "OR") != 0)
					break;

				*args += 1;
			}

			if (!search_arg_build(data, args, subargs))
				return FALSE;
			return TRUE;
		} if (strcmp(str, "ON") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_ON, 1);
		} if (strcmp(str, "OLD") == 0) {
			/* OLD == NOT RECENT */
			if (!ARG_NEW(SEARCH_RECENT, 0))
				return FALSE;

			(*next_sarg)->not = TRUE;
			return TRUE;
		}
		break;
	case 'R':
		if (strcmp(str, "RECENT") == 0)
			return ARG_NEW(SEARCH_RECENT, 0);
		break;
	case 'S':
		if (strcmp(str, "SEEN") == 0)
			return ARG_NEW(SEARCH_SEEN, 0);
		else if (strcmp(str, "SUBJECT") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_SUBJECT, 1);
		} else if (strcmp(str, "SENTBEFORE") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_SENTBEFORE, 1);
		} else if (strcmp(str, "SENTON") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_SENTON, 1);
		} else if (strcmp(str, "SENTSINCE") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_SENTSINCE, 1);
		} else if (strcmp(str, "SINCE") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_SINCE, 1);
		} else if (strcmp(str, "SMALLER") == 0) {
			/* <n> */
			return ARG_NEW(SEARCH_SMALLER, 1);
		}
		break;
	case 'T':
		if (strcmp(str, "TEXT") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_TEXT, 1);
		} else if (strcmp(str, "TO") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_TO, 1);
		}
		break;
	case 'U':
		if (strcmp(str, "UID") == 0) {
			/* <message set> */
			return ARG_NEW(SEARCH_UID, 1);
		} else if (strcmp(str, "UNANSWERED") == 0) {
			if (!ARG_NEW(SEARCH_ANSWERED, 0))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNDELETED") == 0) {
			if (!ARG_NEW(SEARCH_DELETED, 0))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNDRAFT") == 0) {
			if (!ARG_NEW(SEARCH_DRAFT, 0))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNFLAGGED") == 0) {
			if (!ARG_NEW(SEARCH_FLAGGED, 0))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNKEYWORD") == 0) {
			if (!ARG_NEW(SEARCH_KEYWORD, 0))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNSEEN") == 0) {
			if (!ARG_NEW(SEARCH_SEEN, 0))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		}
		break;
	default:
		if (*str == '*' || (*str >= '0' && *str <= '9')) {
			/* <message-set> */
			if (!ARG_NEW(SEARCH_SET, 0))
				return FALSE;

			(*next_sarg)->value.str = str;
			return TRUE;
		}
		break;
	}

	data->error = t_strconcat("Unknown argument ", str, NULL);
	return FALSE;
}

MailSearchArg *mail_search_args_build(Pool pool, ImapArg *args,
				      const char **error)
{
        SearchBuildData data;
	MailSearchArg *first_sarg, **sargs;

	data.pool = pool;
	data.error = NULL;

	/* get the first arg */
	first_sarg = NULL; sargs = &first_sarg;
	while (args->type != IMAP_ARG_EOL) {
		if (!search_arg_build(&data, &args, sargs)) {
			*error = data.error;
			return NULL;
		}
		sargs = &(*sargs)->next;
	}

	*error = NULL;
	return first_sarg;
}

void mail_search_args_reset(MailSearchArg *args)
{
	while (args != NULL) {
		if (args->type == SEARCH_OR || args->type == SEARCH_SUB)
			mail_search_args_reset(args->value.subargs);
		args->result = 0;

		args = args->next;
	}
}

static void search_arg_foreach(MailSearchArg *arg, MailSearchForeachFunc func,
			       void *context)
{
	MailSearchArg *subarg;

	if (arg->result != 0)
		return;

	if (arg->type == SEARCH_SUB) {
		/* sublist of conditions */
		i_assert(arg->value.subargs != NULL);

		arg->result = 1;
		subarg = arg->value.subargs;
		while (subarg != NULL) {
			if (subarg->result == 0)
				search_arg_foreach(subarg, func, context);

			if (subarg->result == -1) {
				/* failed */
				arg->result = -1;
				break;
			}

			if (subarg->result == 0)
				arg->result = 0;

			subarg = subarg->next;
		}
	} else if (arg->type == SEARCH_OR) {
		/* OR-list of conditions */
		i_assert(arg->value.subargs != NULL);

		subarg = arg->value.subargs;
		arg->result = -1;
		while (subarg != NULL) {
			if (subarg->result == 0)
				search_arg_foreach(subarg, func, context);

			if (subarg->result == 1) {
				/* matched */
				arg->result = 1;
				break;
			}

			if (subarg->result == 0)
				arg->result = 0;

			subarg = subarg->next;
		}
	} else {
		/* just a single condition */
		func(arg, context);
	}
}

int mail_search_args_foreach(MailSearchArg *args, MailSearchForeachFunc func,
			     void *context)
{
	int result;

	result = 1;
	for (; args != NULL; args = args->next) {
		search_arg_foreach(args, func, context);

		if (args->result == -1) {
			/* failed, abort */
			return -1;
		}

		if (args->result == 0)
			result = 0;
	}

	return result;
}

static void search_arg_analyze(MailSearchArg *arg, int *have_headers,
			       int *have_body, int *have_text)
{
	MailSearchArg *subarg;

	if (arg->result != 0)
		return;

	switch (arg->type) {
	case SEARCH_OR:
	case SEARCH_SUB:
		subarg = arg->value.subargs;
		while (subarg != NULL) {
			if (subarg->result == 0) {
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

void mail_search_args_analyze(MailSearchArg *args, int *have_headers,
			      int *have_body, int *have_text)
{
	*have_headers = *have_body = *have_text = FALSE;

	for (; args != NULL; args = args->next)
		search_arg_analyze(args, have_headers, have_body, have_text);
}

