/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "imap-date.h"
#include "imap-parser.h"
#include "imap-seqset.h"
#include "mail-search-build.h"
#include "mail-storage.h"

#include <stdlib.h>

struct search_build_data {
	pool_t pool;
	const char *error;
};

static struct mail_search_arg *
search_arg_new(pool_t pool, enum mail_search_arg_type type)
{
	struct mail_search_arg *arg;

	arg = p_new(pool, struct mail_search_arg, 1);
	arg->type = type;

	return arg;
}

static bool
arg_get_next(struct search_build_data *data, const struct imap_arg **args,
	     const char **value_r)
{
	if ((*args)->type == IMAP_ARG_EOL) {
		data->error = "Missing parameter for argument";
		return FALSE;
	}
	if ((*args)->type != IMAP_ARG_ATOM &&
	    (*args)->type != IMAP_ARG_STRING) {
		data->error = "Invalid parameter for argument";
		return FALSE;
	}

	*value_r = IMAP_ARG_STR(*args);
	*args += 1;
	return TRUE;
}

#define ARG_NEW_SINGLE(type) \
	arg_new_single(data, next_sarg, type)
static bool
arg_new_single(struct search_build_data *data,
	       struct mail_search_arg **next_sarg,
	       enum mail_search_arg_type type)
{
	*next_sarg = search_arg_new(data->pool, type);
	return TRUE;
}

#define ARG_NEW_STR(type) \
	arg_new_str(data, args, next_sarg, type)
static bool
arg_new_str(struct search_build_data *data,
	    const struct imap_arg **args, struct mail_search_arg **next_sarg,
	    enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;

	*next_sarg = sarg = search_arg_new(data->pool, type);
	if (!arg_get_next(data, args, &value))
		return FALSE;
	sarg->value.str = p_strdup(data->pool, value);
	return TRUE;
}

#define ARG_NEW_FLAGS(flags) \
	arg_new_flags(data, next_sarg, flags)
static bool
arg_new_flags(struct search_build_data *data,
	      struct mail_search_arg **next_sarg, enum mail_flags flags)
{
	struct mail_search_arg *sarg;

	*next_sarg = sarg = search_arg_new(data->pool, SEARCH_FLAGS);
	sarg->value.flags = flags;
	return TRUE;
}

#define ARG_NEW_SIZE(type) \
	arg_new_size(data, args, next_sarg, type)
static bool
arg_new_size(struct search_build_data *data,
	     const struct imap_arg **args, struct mail_search_arg **next_sarg,
	     enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;
	char *p;

	*next_sarg = sarg = search_arg_new(data->pool, type);
	if (!arg_get_next(data, args, &value))
		return FALSE;

	sarg->value.size = strtoull(value, &p, 10);
	if (*p != '\0') {
		data->error = "Invalid search size parameter";
		return FALSE;
	}
	return TRUE;
}

#define ARG_NEW_DATE(type) \
	arg_new_date(data, args, next_sarg, type)
static bool
arg_new_date(struct search_build_data *data,
	     const struct imap_arg **args, struct mail_search_arg **next_sarg,
	     enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;

	*next_sarg = sarg = search_arg_new(data->pool, type);
	if (!arg_get_next(data, args, &value))
		return FALSE;
	if (!imap_parse_date(value, &sarg->value.time)) {
		data->error = "Invalid search date parameter";
		return FALSE;
	}
	return TRUE;
}

#define ARG_NEW_INTERVAL(type) \
	arg_new_interval(data, args, next_sarg, type)
static bool
arg_new_interval(struct search_build_data *data,
		 const struct imap_arg **args,
		 struct mail_search_arg **next_sarg,
		 enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;
	unsigned long interval;
	char *p;

	*next_sarg = sarg = search_arg_new(data->pool, type);
	if (!arg_get_next(data, args, &value))
		return FALSE;

	interval = strtoul(value, &p, 10);
	if (interval == 0 || *p != '\0') {
		data->error = "Invalid search interval parameter";
		return FALSE;
	}
	sarg->value.search_flags = MAIL_SEARCH_ARG_FLAG_USE_TZ;
	sarg->value.time = ioloop_time - interval;
	return TRUE;
}

#define ARG_NEW_HEADER(type, hdr_name) \
	arg_new_header(data, args, next_sarg, type, hdr_name)
static bool
arg_new_header(struct search_build_data *data,
	       const struct imap_arg **args, struct mail_search_arg **next_sarg,
	       enum mail_search_arg_type type, const char *hdr_name)
{
	struct mail_search_arg *sarg;
	const char *value;

	*next_sarg = sarg = search_arg_new(data->pool, type);
	if (!arg_get_next(data, args, &value))
		return FALSE;

	sarg->hdr_field_name = p_strdup(data->pool, hdr_name);
	sarg->value.str = p_strdup(data->pool, value);
	return TRUE;
}

static bool
arg_modseq_set_name(struct search_build_data *data,
		    struct mail_search_arg *sarg, const char *name)
{
	name = t_str_lcase(name);
	if (strncmp(name, "/flags/", 7) != 0) {
		data->error = "Invalid MODSEQ entry";
		return FALSE;
	}
	name += 7;

	if (*name == '\\') {
		/* system flag */
		name++;
		if (strcmp(name, "answered") == 0)
			sarg->value.flags = MAIL_ANSWERED;
		else if (strcmp(name, "flagged") == 0)
			sarg->value.flags = MAIL_FLAGGED;
		else if (strcmp(name, "deleted") == 0)
			sarg->value.flags = MAIL_DELETED;
		else if (strcmp(name, "seen") == 0)
			sarg->value.flags = MAIL_SEEN;
		else if (strcmp(name, "draft") == 0)
			sarg->value.flags = MAIL_DRAFT;
		else {
			data->error = "Invalid MODSEQ system flag";
			return FALSE;
		}
		return TRUE;
	}
	sarg->value.str = p_strdup(data->pool, name);
	return TRUE;
}

static bool
arg_modseq_set_type(struct search_build_data *data,
		    struct mail_search_modseq *modseq, const char *name)
{
	if (strcasecmp(name, "all") == 0)
		modseq->type = MAIL_SEARCH_MODSEQ_TYPE_ANY;
	else if (strcasecmp(name, "priv") == 0)
		modseq->type = MAIL_SEARCH_MODSEQ_TYPE_PRIVATE;
	else if (strcasecmp(name, "shared") == 0)
		modseq->type = MAIL_SEARCH_MODSEQ_TYPE_SHARED;
	else {
		data->error = "Invalid MODSEQ type";
		return FALSE;
	}
	return TRUE;
}

#define ARG_NEW_MODSEQ() \
	arg_new_modseq(data, args, next_sarg)
static bool
arg_new_modseq(struct search_build_data *data,
	       const struct imap_arg **args, struct mail_search_arg **next_sarg)
{
	struct mail_search_arg *sarg;
	const char *value;

	*next_sarg = sarg = search_arg_new(data->pool, SEARCH_MODSEQ);
	if (!arg_get_next(data, args, &value))
		return FALSE;

	sarg->value.modseq = p_new(data->pool, struct mail_search_modseq, 1);
	if ((*args)[-1].type == IMAP_ARG_STRING) {
		/* <name> <type> */
		if (!arg_modseq_set_name(data, sarg, value))
			return FALSE;

		if (!arg_get_next(data, args, &value))
			return FALSE;
		if (!arg_modseq_set_type(data, sarg->value.modseq, value))
			return FALSE;

		if (!arg_get_next(data, args, &value))
			return FALSE;
	}
	if (!is_numeric(value, '\0')) {
		data->error = "Invalid MODSEQ value";
		return FALSE;
	}
	sarg->value.modseq->modseq = strtoull(value, NULL, 10);
	return TRUE;
}

static bool search_arg_build(struct search_build_data *data,
			     const struct imap_arg **args,
			     struct mail_search_arg **next_sarg)
{
	struct mail_search_arg **subargs, *sarg;
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
			return ARG_NEW_FLAGS(MAIL_ANSWERED);
		else if (strcmp(str, "ALL") == 0)
			return ARG_NEW_SINGLE(SEARCH_ALL);
		break;
	case 'B':
		if (strcmp(str, "BODY") == 0) {
			/* <string> */
			if (IMAP_ARG_TYPE_IS_STRING((*args)->type) &&
			    *IMAP_ARG_STR(*args) == '\0') {
				*args += 1;
				return ARG_NEW_SINGLE(SEARCH_ALL);
			}
			return ARG_NEW_STR(SEARCH_BODY);
		} else if (strcmp(str, "BEFORE") == 0) {
			/* <date> */
			return ARG_NEW_DATE(SEARCH_BEFORE);
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
			return ARG_NEW_FLAGS(MAIL_DELETED);
		else if (strcmp(str, "DRAFT") == 0)
			return ARG_NEW_FLAGS(MAIL_DRAFT);
		break;
	case 'F':
		if (strcmp(str, "FLAGGED") == 0)
			return ARG_NEW_FLAGS(MAIL_FLAGGED);
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
	case 'I':
		if (strcmp(str, "INTHREAD") == 0) {
			/* <algorithm> <search key> */
			enum mail_thread_type thread_type;
			const char *str;

			if ((*args)->type != IMAP_ARG_ATOM) {
				data->error = "Invalid parameter for INTHREAD";
				return FALSE;
			}

			str = IMAP_ARG_STR_NONULL(*args);
			if (!mail_thread_type_parse(str, &thread_type)) {
				data->error = "Unknown thread algorithm";
				return FALSE;
			}
			*args += 1;

			*next_sarg = search_arg_new(data->pool,
						    SEARCH_INTHREAD);
			(*next_sarg)->value.thread_type = thread_type;
			subargs = &(*next_sarg)->value.subargs;
			return search_arg_build(data, args, subargs);
		}
		break;
	case 'K':
		if (strcmp(str, "KEYWORD") == 0) {
			return ARG_NEW_STR(SEARCH_KEYWORDS);
		}
		break;
	case 'L':
		if (strcmp(str, "LARGER") == 0) {
			/* <n> */
			return ARG_NEW_SIZE(SEARCH_LARGER);
		}
		break;
	case 'M':
		if (strcmp(str, "MODSEQ") == 0) {
			/* [<name> <type>] <n> */
			return ARG_NEW_MODSEQ();
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
			*subargs = search_arg_new(data->pool, SEARCH_FLAGS);
			(*subargs)->value.flags = MAIL_RECENT;
			(*subargs)->next = search_arg_new(data->pool,
							  SEARCH_FLAGS);
			(*subargs)->next->value.flags = MAIL_SEEN;
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
			return ARG_NEW_DATE(SEARCH_ON);
		} if (strcmp(str, "OLD") == 0) {
			/* OLD == NOT RECENT */
			if (!ARG_NEW_FLAGS(MAIL_RECENT))
				return FALSE;

			(*next_sarg)->not = TRUE;
			return TRUE;
		} if (strcmp(str, "OLDER") == 0) {
			/* <interval> - WITHIN extension */
			if (!ARG_NEW_INTERVAL(SEARCH_BEFORE))
				return FALSE;

			/* we need to match also equal, but standard BEFORE
			   compares with "<" */
			(*next_sarg)->value.time++;
			return TRUE;
		}
		break;
	case 'R':
		if (strcmp(str, "RECENT") == 0)
			return ARG_NEW_FLAGS(MAIL_RECENT);
		break;
	case 'S':
		if (strcmp(str, "SEEN") == 0)
			return ARG_NEW_FLAGS(MAIL_SEEN);
		else if (strcmp(str, "SUBJECT") == 0) {
			/* <string> */
			return ARG_NEW_HEADER(SEARCH_HEADER_COMPRESS_LWSP, str);
		} else if (strcmp(str, "SENTBEFORE") == 0) {
			/* <date> */
			return ARG_NEW_DATE(SEARCH_SENTBEFORE);
		} else if (strcmp(str, "SENTON") == 0) {
			/* <date> */
			return ARG_NEW_DATE(SEARCH_SENTON);
		} else if (strcmp(str, "SENTSINCE") == 0) {
			/* <date> */
			return ARG_NEW_DATE(SEARCH_SENTSINCE);
		} else if (strcmp(str, "SINCE") == 0) {
			/* <date> */
			return ARG_NEW_DATE(SEARCH_SINCE);
		} else if (strcmp(str, "SMALLER") == 0) {
			/* <n> */
			return ARG_NEW_SIZE(SEARCH_SMALLER);
		}
		break;
	case 'T':
		if (strcmp(str, "TEXT") == 0) {
			/* <string> */
			if (IMAP_ARG_TYPE_IS_STRING((*args)->type) &&
			    *IMAP_ARG_STR(*args) == '\0') {
				*args += 1;
				return ARG_NEW_SINGLE(SEARCH_ALL);
			}
			return ARG_NEW_STR(SEARCH_TEXT);
		} else if (strcmp(str, "TO") == 0) {
			/* <string> */
			return ARG_NEW_HEADER(SEARCH_HEADER_ADDRESS, str);
		}
		break;
	case 'U':
		if (strcmp(str, "UID") == 0) {
			/* <message set> */
			if (!ARG_NEW_STR(SEARCH_UIDSET))
				return FALSE;

			sarg = *next_sarg;
			p_array_init(&sarg->value.seqset, data->pool, 16);
			if (strcmp(sarg->value.str, "$") == 0) {
				/* SEARCHRES: delay initialization */
				return TRUE;
			}
			if (imap_seq_set_parse(sarg->value.str,
					       &sarg->value.seqset) < 0) {
				data->error = "Invalid UID messageset";
				return FALSE;
			}
			return TRUE;
		} else if (strcmp(str, "UNANSWERED") == 0) {
			if (!ARG_NEW_FLAGS(MAIL_ANSWERED))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNDELETED") == 0) {
			if (!ARG_NEW_FLAGS(MAIL_DELETED))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNDRAFT") == 0) {
			if (!ARG_NEW_FLAGS(MAIL_DRAFT))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNFLAGGED") == 0) {
			if (!ARG_NEW_FLAGS(MAIL_FLAGGED))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNKEYWORD") == 0) {
			if (!ARG_NEW_STR(SEARCH_KEYWORDS))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		} else if (strcmp(str, "UNSEEN") == 0) {
			if (!ARG_NEW_FLAGS(MAIL_SEEN))
				return FALSE;
			(*next_sarg)->not = TRUE;
			return TRUE;
		}
		break;
	case 'Y':
		if (strcmp(str, "YOUNGER") == 0) {
			/* <interval> - WITHIN extension */
			return ARG_NEW_INTERVAL(SEARCH_SINCE);
		}
		break;
	case 'X':
		if (strcmp(str, "X-BODY-FAST") == 0) {
			/* <string> */
			if (IMAP_ARG_TYPE_IS_STRING((*args)->type) &&
			    *IMAP_ARG_STR(*args) == '\0') {
				*args += 1;
				return ARG_NEW_SINGLE(SEARCH_ALL);
			}
			return ARG_NEW_STR(SEARCH_BODY_FAST);
		} else if (strcmp(str, "X-TEXT-FAST") == 0) {
			/* <string> */
			if (IMAP_ARG_TYPE_IS_STRING((*args)->type) &&
			    *IMAP_ARG_STR(*args) == '\0') {
				*args += 1;
				return ARG_NEW_SINGLE(SEARCH_ALL);
			}
			return ARG_NEW_STR(SEARCH_TEXT_FAST);
		} else if (strcmp(str, "X-GUID") == 0) {
			/* <string> */
			return ARG_NEW_STR(SEARCH_GUID);
		} else if (strcmp(str, "X-MAILBOX") == 0) {
			/* <string> */
			return ARG_NEW_STR(SEARCH_MAILBOX);
		}
		break;
	default:
		if (*str == '*' || (*str >= '0' && *str <= '9')) {
			/* <message-set> */
			if (!ARG_NEW_SINGLE(SEARCH_SEQSET))
				return FALSE;

			p_array_init(&(*next_sarg)->value.seqset,
				     data->pool, 16);
			if (imap_seq_set_parse(str, &(*next_sarg)->value.seqset) < 0) {
				data->error = "Invalid messageset";
				return FALSE;
			}
			return TRUE;
		} else if (strcmp(str, "$") == 0) {
			/* SEARCHRES: delay initialization */
			if (!ARG_NEW_SINGLE(SEARCH_UIDSET))
				return FALSE;

			(*next_sarg)->value.str = p_strdup(data->pool, "$");
			p_array_init(&(*next_sarg)->value.seqset,
				     data->pool, 16);
			return TRUE;
		}
		break;
	}

	data->error = t_strconcat("Unknown argument ", str, NULL);
	return FALSE;
}

int mail_search_build_from_imap_args(const struct imap_arg *imap_args,
				     const char *charset,
				     struct mail_search_args **args_r,
				     const char **error_r)
{
        struct search_build_data data;
	struct mail_search_args *args;
	struct mail_search_arg **sargs;

	*args_r = NULL;
	*error_r = NULL;

	args = mail_search_build_init();
	args->charset = p_strdup(args->pool, charset);

	data.pool = args->pool;
	data.error = NULL;

	sargs = &args->args;
	while (imap_args->type != IMAP_ARG_EOL) {
		if (!search_arg_build(&data, &imap_args, sargs)) {
			pool_unref(&args->pool);
			*error_r = data.error;
			return -1;
		}
		sargs = &(*sargs)->next;
	}

	*args_r = args;
	return 0;
}

struct mail_search_args *mail_search_build_init(void)
{
	struct mail_search_args *args;
	pool_t pool;

	pool = pool_alloconly_create("mail search args", 4096);
	args = p_new(pool, struct mail_search_args, 1);
	args->pool = pool;
	args->refcount = 1;
	return args;
}

void mail_search_build_add_all(struct mail_search_args *args)
{
	struct mail_search_arg *arg;

	arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_ALL;

	arg->next = args->args;
	args->args = arg;
}

void mail_search_build_add_seqset(struct mail_search_args *args,
				  uint32_t seq1, uint32_t seq2)
{
	struct mail_search_arg *arg;

	arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_SEQSET;
	p_array_init(&arg->value.seqset, args->pool, 1);
	seq_range_array_add_range(&arg->value.seqset, seq1, seq2);

	arg->next = args->args;
	args->args = arg;
}
