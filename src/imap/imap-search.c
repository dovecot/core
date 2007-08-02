/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "imap-date.h"
#include "imap-search.h"
#include "imap-parser.h"
#include "imap-messageset.h"

struct search_build_data {
	pool_t pool;
        struct mailbox *box;
	const char *error;
};

static int
imap_uidset_parse(pool_t pool, struct mailbox *box, const char *uidset,
		  struct mail_search_seqset **seqset_r, const char **error_r)
{
	struct mail_search_seqset *seqset, **p;
	bool last;

	*seqset_r = imap_messageset_parse(pool, uidset);
	if (*seqset_r == NULL) {
		*error_r = "Invalid UID messageset";
		return -1;
	}

	p = seqset_r;
	for (seqset = *seqset_r; seqset != NULL; seqset = seqset->next) {
		if (seqset->seq1 == (uint32_t)-1) {
			/* last message, stays same */
			continue;
		}

		last = seqset->seq2 == (uint32_t)-1;
		if (mailbox_get_uids(box, seqset->seq1, seqset->seq2,
				     &seqset->seq1, &seqset->seq2) < 0) {
			struct mail_storage *storage = mailbox_get_storage(box);
			enum mail_error error;

			*error_r = mail_storage_get_last_error(storage, &error);
			return -1;
		}

		if (seqset->seq1 == 0 && last) {
			/* we need special case for too_high_uid:* case */
			seqset->seq1 = seqset->seq2 = (uint32_t)-1;
		}

		if (seqset->seq1 != 0)
			p = &seqset->next;
		else
			*p = seqset->next;
	}

	*error_r = NULL;
	return 0;
}

static struct mail_search_arg *
search_arg_new(pool_t pool, enum mail_search_arg_type type)
{
	struct mail_search_arg *arg;

	arg = p_new(pool, struct mail_search_arg, 1);
	arg->type = type;

	return arg;
}

#define ARG_NEW(type) \
	arg_new(data, args, next_sarg, type, TRUE, NULL)

#define ARG_NEW_FLAG(type) \
	arg_new(data, args, next_sarg, type, FALSE, NULL)

#define ARG_NEW_HEADER(type, hdr_name) \
	arg_new(data, args, next_sarg, type, TRUE, hdr_name)

static bool arg_new(struct search_build_data *data,
		    const struct imap_arg **args,
		    struct mail_search_arg **next_sarg,
		    enum mail_search_arg_type type, bool have_value,
		    const char *hdr_name)
{
	struct mail_search_arg *sarg;

	*next_sarg = sarg = search_arg_new(data->pool, type);
	if (!have_value)
		return TRUE;

	if ((*args)->type == IMAP_ARG_EOL) {
		data->error = "Missing parameter for argument";
		return FALSE;
	}

	if ((*args)->type != IMAP_ARG_ATOM &&
	    (*args)->type != IMAP_ARG_STRING) {
		data->error = "Invalid parameter for argument";
		return FALSE;
	}

	switch (type) {
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
	case SEARCH_SENTBEFORE:
	case SEARCH_SENTON:
	case SEARCH_SENTSINCE:
		if (!imap_parse_date(IMAP_ARG_STR(*args), &sarg->value.time)) {
			data->error = "Invalid search date parameter";
			return FALSE;
		}
	default:
		sarg->value.str = p_strdup(data->pool, IMAP_ARG_STR(*args));
		break;
	}
	*args += 1;

	if (hdr_name != NULL)
                sarg->hdr_field_name = p_strdup(data->pool, hdr_name);

	return TRUE;
}

static bool search_arg_build(struct search_build_data *data,
			     const struct imap_arg **args,
			     struct mail_search_arg **next_sarg)
{
        struct mail_search_seqset *seqset;
	struct mail_search_arg **subargs;
	const struct imap_arg *arg;
	const char *str;

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
		const struct imap_arg *listargs = IMAP_ARG_LIST_ARGS(arg);

		if (listargs->type == IMAP_ARG_EOL) {
			data->error = "Empty list not allowed";
			return FALSE;
		}

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
	str = IMAP_ARG_STR(arg);
	*args += 1;
	str = t_str_ucase(str);

	switch (*str) {
	case 'A':
		if (strcmp(str, "ANSWERED") == 0)
			return ARG_NEW_FLAG(SEARCH_ANSWERED);
		else if (strcmp(str, "ALL") == 0)
			return ARG_NEW_FLAG(SEARCH_ALL);
		break;
	case 'B':
		if (strcmp(str, "BODY") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_BODY);
		} else if (strcmp(str, "BEFORE") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_BEFORE);
		} else if (strcmp(str, "BCC") == 0) {
			/* <string> */
			return ARG_NEW_HEADER(SEARCH_HEADER_ADDRESS, str);
		}
		break;
	case 'C':
		if (strcmp(str, "CC") == 0) {
			/* <string> */
			return ARG_NEW_HEADER(SEARCH_HEADER_ADDRESS, str);
		}
		break;
	case 'D':
		if (strcmp(str, "DELETED") == 0)
			return ARG_NEW_FLAG(SEARCH_DELETED);
		else if (strcmp(str, "DRAFT") == 0)
			return ARG_NEW_FLAG(SEARCH_DRAFT);
		break;
	case 'F':
		if (strcmp(str, "FLAGGED") == 0)
			return ARG_NEW_FLAG(SEARCH_FLAGGED);
		else if (strcmp(str, "FROM") == 0) {
			/* <string> */
			return ARG_NEW_HEADER(SEARCH_HEADER_ADDRESS, str);
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
			if ((*args)->type != IMAP_ARG_ATOM &&
			    (*args)->type != IMAP_ARG_STRING) {
				data->error = "Invalid parameter for HEADER";
				return FALSE;
			}

			key = t_str_ucase(IMAP_ARG_STR(*args));
			*args += 1;
			return ARG_NEW_HEADER(SEARCH_HEADER, key);
		}
		break;
	case 'K':
		if (strcmp(str, "KEYWORD") == 0) {
			/* <flag> */
			return ARG_NEW(SEARCH_KEYWORD);
		}
		break;
	case 'L':
		if (strcmp(str, "LARGER") == 0) {
			/* <n> */
			return ARG_NEW(SEARCH_LARGER);
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
				    strcasecmp(IMAP_ARG_STR_NONULL(*args),
					       "OR") != 0)
					break;

				*args += 1;
			}

			if (!search_arg_build(data, args, subargs))
				return FALSE;
			return TRUE;
		} if (strcmp(str, "ON") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_ON);
		} if (strcmp(str, "OLD") == 0) {
			/* OLD == NOT RECENT */
			if (!ARG_NEW_FLAG(SEARCH_RECENT))
				return FALSE;

			(*next_sarg)->not = TRUE;
			return TRUE;
		}
		break;
	case 'R':
		if (strcmp(str, "RECENT") == 0)
			return ARG_NEW_FLAG(SEARCH_RECENT);
		break;
	case 'S':
		if (strcmp(str, "SEEN") == 0)
			return ARG_NEW_FLAG(SEARCH_SEEN);
		else if (strcmp(str, "SUBJECT") == 0) {
			/* <string> */
			return ARG_NEW_HEADER(SEARCH_HEADER, str);
		} else if (strcmp(str, "SENTBEFORE") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_SENTBEFORE);
		} else if (strcmp(str, "SENTON") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_SENTON);
		} else if (strcmp(str, "SENTSINCE") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_SENTSINCE);
		} else if (strcmp(str, "SINCE") == 0) {
			/* <date> */
			return ARG_NEW(SEARCH_SINCE);
		} else if (strcmp(str, "SMALLER") == 0) {
			/* <n> */
			return ARG_NEW(SEARCH_SMALLER);
		}
		break;
	case 'T':
		if (strcmp(str, "TEXT") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_TEXT);
		} else if (strcmp(str, "TO") == 0) {
			/* <string> */
			return ARG_NEW_HEADER(SEARCH_HEADER_ADDRESS, str);
		}
		break;
	case 'U':
		if (strcmp(str, "UID") == 0) {
			/* <message set> */
			if (!ARG_NEW(SEARCH_SEQSET))
				return FALSE;

			return imap_uidset_parse(data->pool, data->box,
						 (*next_sarg)->value.str,
						 &(*next_sarg)->value.seqset,
						 &data->error) == 0;
		} else if (strcmp(str, "UNANSWERED") == 0) {
			if (!ARG_NEW_FLAG(SEARCH_ANSWERED))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNDELETED") == 0) {
			if (!ARG_NEW_FLAG(SEARCH_DELETED))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNDRAFT") == 0) {
			if (!ARG_NEW_FLAG(SEARCH_DRAFT))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNFLAGGED") == 0) {
			if (!ARG_NEW_FLAG(SEARCH_FLAGGED))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNKEYWORD") == 0) {
			/* <flag> */
			if (!ARG_NEW(SEARCH_KEYWORD))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNSEEN") == 0) {
			if (!ARG_NEW_FLAG(SEARCH_SEEN))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		}
		break;
	case 'X':
		if (strcmp(str, "X-BODY-FAST") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_BODY_FAST);
		} else if (strcmp(str, "X-TEXT-FAST") == 0) {
			/* <string> */
			return ARG_NEW(SEARCH_TEXT_FAST);
		}
		break;
	default:
		if (*str == '*' || (*str >= '0' && *str <= '9')) {
			/* <message-set> */
			seqset = imap_messageset_parse(data->pool, str);
			if (seqset == NULL) {
				data->error = "Invalid messageset";
				return FALSE;
			}

			if (!ARG_NEW_FLAG(SEARCH_SEQSET))
				return FALSE;

			(*next_sarg)->value.seqset = seqset;
			return TRUE;
		}
		break;
	}

	data->error = t_strconcat("Unknown argument ", str, NULL);
	return FALSE;
}

struct mail_search_arg *
imap_search_args_build(pool_t pool, struct mailbox *box,
		       const struct imap_arg *args, const char **error_r)
{
        struct search_build_data data;
	struct mail_search_arg *first_sarg, **sargs;

	*error_r = NULL;

	data.box = box;
	data.pool = pool;
	data.error = NULL;

	/* get the first arg */
	first_sarg = NULL; sargs = &first_sarg;
	while (args->type != IMAP_ARG_EOL) {
		if (!search_arg_build(&data, &args, sargs)) {
			*error_r = data.error;
			return NULL;
		}
		sargs = &(*sargs)->next;
	}

	return first_sarg;
}

static int imap_search_get_msgset_arg(struct client_command_context *cmd,
				      const char *messageset,
				      struct mail_search_arg **arg_r,
				      const char **error_r)
{
	struct mail_search_arg *arg;

	arg = p_new(cmd->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_SEQSET;
	arg->value.seqset = imap_messageset_parse(cmd->pool, messageset);
	/* when there are no messages, all messagesets are invalid.
	   if there's at least one message:
	    - * gives seq1 = seq2 = (uint32_t)-1
	    - n:* should work if n <= messages_count
	    - n:m or m should work if m <= messages_count
	*/
	if (arg->value.seqset == NULL || cmd->client->messages_count == 0 ||
	    (arg->value.seqset->seq1 > cmd->client->messages_count &&
	     arg->value.seqset->seq1 != (uint32_t)-1) ||
	    (arg->value.seqset->seq2 > cmd->client->messages_count &&
	     arg->value.seqset->seq2 != (uint32_t)-1)) {
		*error_r = "Invalid messageset";
		return -1;
	}
	*arg_r = arg;
	return 0;
}

static int
imap_search_get_uidset_arg(pool_t pool, struct mailbox *box, const char *uidset,
			   struct mail_search_arg **arg_r, const char **error_r)
{
	struct mail_search_arg *arg;

	arg = p_new(pool, struct mail_search_arg, 1);
	arg->type = SEARCH_SEQSET;
	*arg_r = arg;
	return imap_uidset_parse(pool, box, uidset, &arg->value.seqset,
				 error_r);
}

struct mail_search_arg *
imap_search_get_arg(struct client_command_context *cmd,
		    const char *set, bool uid)
{
	struct mail_search_arg *search_arg = NULL;
	const char *error;
	int ret;

	if (!uid) {
		ret = imap_search_get_msgset_arg(cmd, set, &search_arg, &error);
	} else {
		ret = imap_search_get_uidset_arg(cmd->pool,
						 cmd->client->mailbox, set,
						 &search_arg, &error);
	}
	if (ret < 0) {
		client_send_command_error(cmd, error);
		return NULL;
	}

	return search_arg;
}
