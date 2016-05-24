/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "utc-offset.h"
#include "imap-date.h"
#include "imap-util.h"
#include "imap-quote.h"
#include "mail-search.h"
#include "mail-search-mime.h"

/*
 *
 */

static struct mail_search_mime_arg *
mail_search_mime_arg_dup_one(pool_t pool,
	const struct mail_search_mime_arg *arg)
{
	struct mail_search_mime_arg *new_arg;

	new_arg = p_new(pool, struct mail_search_mime_arg, 1);
	new_arg->type = arg->type;
	new_arg->match_not = arg->match_not;
	new_arg->match_always = arg->match_always;
	new_arg->nonmatch_always = arg->nonmatch_always;

	switch (arg->type) {
	case SEARCH_MIME_OR:
	case SEARCH_MIME_SUB:
		new_arg->value.subargs =
			mail_search_mime_arg_dup(pool, arg->value.subargs);
		break;
	case SEARCH_MIME_SIZE_EQUAL:
	case SEARCH_MIME_SIZE_LARGER:
	case SEARCH_MIME_SIZE_SMALLER:
		new_arg->value.size = arg->value.size;
		break;
	case SEARCH_MIME_HEADER:
		new_arg->field_name = p_strdup(pool, arg->field_name);
		/* fall through */
	case SEARCH_MIME_DESCRIPTION:
	case SEARCH_MIME_DISPOSITION_TYPE:
	case SEARCH_MIME_DISPOSITION_PARAM:
	case SEARCH_MIME_ENCODING:
	case SEARCH_MIME_ID:
	case SEARCH_MIME_LANGUAGE:
	case SEARCH_MIME_LOCATION:
	case SEARCH_MIME_MD5:
	case SEARCH_MIME_TYPE:
	case SEARCH_MIME_SUBTYPE:
	case SEARCH_MIME_PARAM:
	case SEARCH_MIME_BODY:
	case SEARCH_MIME_TEXT:
	case SEARCH_MIME_CC:
	case SEARCH_MIME_BCC:
	case SEARCH_MIME_FROM:
	case SEARCH_MIME_IN_REPLY_TO:
	case SEARCH_MIME_MESSAGE_ID:
	case SEARCH_MIME_REPLY_TO:
	case SEARCH_MIME_SENDER:
	case SEARCH_MIME_SUBJECT:
	case SEARCH_MIME_TO:
	case SEARCH_MIME_FILENAME_IS:
	case SEARCH_MIME_FILENAME_CONTAINS:
	case SEARCH_MIME_FILENAME_BEGINS:
	case SEARCH_MIME_FILENAME_ENDS:
		new_arg->value.str =
			p_strdup(pool, arg->value.str);
		break;
	case SEARCH_MIME_SENTBEFORE:
	case SEARCH_MIME_SENTON:
	case SEARCH_MIME_SENTSINCE:
		new_arg->value.time = arg->value.time;
		break;
	case SEARCH_MIME_PARENT:
	case SEARCH_MIME_CHILD:
		if (new_arg->value.subargs != NULL) {
			new_arg->value.subargs =
				mail_search_mime_arg_dup(pool, arg->value.subargs);
		}
		break;
	case SEARCH_MIME_DEPTH_EQUAL:
	case SEARCH_MIME_DEPTH_MIN:
	case SEARCH_MIME_DEPTH_MAX:
	case SEARCH_MIME_INDEX:
		new_arg->value.number = arg->value.number;
		break;
	}
	return new_arg;
}

struct mail_search_mime_arg *
mail_search_mime_arg_dup(pool_t pool,
	const struct mail_search_mime_arg *arg)
{
	struct mail_search_mime_arg *new_arg = NULL, **dest = &new_arg;

	for (; arg != NULL; arg = arg->next) {
		*dest = mail_search_mime_arg_dup_one(pool, arg);
		dest = &(*dest)->next;
	}
	return new_arg;
}

struct mail_search_mime_part *
mail_search_mime_part_dup(pool_t pool,
	const struct mail_search_mime_part *mpart)
{
	struct mail_search_mime_part *new_mpart;

	new_mpart = p_new(pool, struct mail_search_mime_part, 1);
	new_mpart->simplified = mpart->simplified;
	new_mpart->args = mail_search_mime_arg_dup(pool, mpart->args);
	return new_mpart;
}

/*
 *
 */

void mail_search_mime_args_reset(struct mail_search_mime_arg *args,
	bool full_reset)
{
	while (args != NULL) {
		if (args->type == SEARCH_MIME_OR || args->type == SEARCH_MIME_SUB)
			mail_search_mime_args_reset(args->value.subargs, full_reset);

		if (args->match_always) {
			if (!full_reset)
				args->result = 1;
			else {
				args->match_always = FALSE;
				args->result = -1;
			}
		} else if (args->nonmatch_always) {
			if (!full_reset)
				args->result = 0;
			else {
				args->nonmatch_always = FALSE;
				args->result = -1;
			}
		} else {
			args->result = -1;
		}

		args = args->next;
	}
}

static void search_mime_arg_foreach(struct mail_search_mime_arg *arg,
			       mail_search_mime_foreach_callback_t *callback,
			       void *context)
{
	struct mail_search_mime_arg *subarg;

	if (arg->result != -1)
		return;

	if (arg->type == SEARCH_MIME_SUB) {
		/* sublist of conditions */
		i_assert(arg->value.subargs != NULL);

		arg->result = 1;
		subarg = arg->value.subargs;
		while (subarg != NULL) {
			if (subarg->result == -1)
				search_mime_arg_foreach(subarg, callback, context);

			if (subarg->result == -1)
				arg->result = -1;
			else if (subarg->result == 0) {
				/* didn't match */
				arg->result = 0;
				break;
			}

			subarg = subarg->next;
		}
		if (arg->match_not && arg->result != -1)
			arg->result = arg->result > 0 ? 0 : 1;
	} else if (arg->type == SEARCH_MIME_OR) {
		/* OR-list of conditions */
		i_assert(arg->value.subargs != NULL);

		subarg = arg->value.subargs;
		arg->result = 0;
		while (subarg != NULL) {
			if (subarg->result == -1)
				search_mime_arg_foreach(subarg, callback, context);

			if (subarg->result == -1)
				arg->result = -1;
			else if (subarg->result > 0) {
				/* matched */
				arg->result = 1;
				break;
			}

			subarg = subarg->next;
		}
		if (arg->match_not && arg->result != -1)
			arg->result = arg->result > 0 ? 0 : 1;
	} else {
		/* just a single condition */
		callback(arg, context);
	}
}

#undef mail_search_mime_args_foreach
int mail_search_mime_args_foreach(struct mail_search_mime_arg *args,
			     mail_search_mime_foreach_callback_t *callback,
			     void *context)
{
	int result;

	result = 1;
	for (; args != NULL; args = args->next) {
		search_mime_arg_foreach(args, callback, context);

		if (args->result == 0) {
			/* didn't match */
			return 0;
		}

		if (args->result == -1)
			result = -1;
	}

	return result;
}

/*
 *
 */

bool mail_search_mime_arg_one_equals(const struct mail_search_mime_arg *arg1,
				const struct mail_search_mime_arg *arg2)
{
	if (arg1->type != arg2->type ||
	    arg1->match_not != arg2->match_not)
		return FALSE;

	switch (arg1->type) {
	case SEARCH_MIME_OR:
	case SEARCH_MIME_SUB:
		return mail_search_mime_arg_equals(arg1->value.subargs,
					      arg2->value.subargs);

	case SEARCH_MIME_SIZE_EQUAL:
	case SEARCH_MIME_SIZE_LARGER:
	case SEARCH_MIME_SIZE_SMALLER:
		return arg1->value.size == arg2->value.size;

	case SEARCH_MIME_HEADER:
	case SEARCH_MIME_DISPOSITION_PARAM:
	case SEARCH_MIME_PARAM:
		if (strcasecmp(arg1->field_name, arg2->field_name) != 0)
			return FALSE;
		/* fall through */
	case SEARCH_MIME_DESCRIPTION:
	case SEARCH_MIME_DISPOSITION_TYPE:
	case SEARCH_MIME_ENCODING:
	case SEARCH_MIME_ID:
	case SEARCH_MIME_LANGUAGE:
	case SEARCH_MIME_LOCATION:
	case SEARCH_MIME_MD5:
	case SEARCH_MIME_TYPE:
	case SEARCH_MIME_SUBTYPE:
	case SEARCH_MIME_BODY:
	case SEARCH_MIME_TEXT:
	case SEARCH_MIME_CC:
	case SEARCH_MIME_BCC:
	case SEARCH_MIME_FROM:
	case SEARCH_MIME_IN_REPLY_TO:
	case SEARCH_MIME_MESSAGE_ID:
	case SEARCH_MIME_REPLY_TO:
	case SEARCH_MIME_SENDER:
	case SEARCH_MIME_SUBJECT:
	case SEARCH_MIME_TO:
	case SEARCH_MIME_FILENAME_IS:
	case SEARCH_MIME_FILENAME_CONTAINS:
	case SEARCH_MIME_FILENAME_BEGINS:
	case SEARCH_MIME_FILENAME_ENDS:
		/* don't bother doing case-insensitive comparison. we should support
		   full i18n case-insensitivity (or the active comparator
		   in future). */
		return strcmp(arg1->value.str, arg2->value.str) == 0;

	case SEARCH_MIME_SENTBEFORE:
	case SEARCH_MIME_SENTON:
	case SEARCH_MIME_SENTSINCE:
		return arg1->value.time == arg2->value.time;

	case SEARCH_MIME_PARENT:
	case SEARCH_MIME_CHILD:
		if (arg1->value.subargs == NULL)
			return arg2->value.subargs == NULL;
		if (arg2->value.subargs == NULL)
			return FALSE;
		return mail_search_mime_arg_equals(arg1->value.subargs,
					      arg2->value.subargs);

	case SEARCH_MIME_DEPTH_EQUAL:
	case SEARCH_MIME_DEPTH_MIN:
	case SEARCH_MIME_DEPTH_MAX:
	case SEARCH_MIME_INDEX:
		return arg1->value.number == arg2->value.number;
		break;
	}
	i_unreached();
	return FALSE;
}

bool mail_search_mime_arg_equals(const struct mail_search_mime_arg *arg1,
			    const struct mail_search_mime_arg *arg2)
{
	while (arg1 != NULL && arg2 != NULL) {
		if (!mail_search_mime_arg_one_equals(arg1, arg2))
			return FALSE;
		arg1 = arg1->next;
		arg2 = arg2->next;
	}
	return arg1 == NULL && arg2 == NULL;
}

bool mail_search_mime_parts_equal(const struct mail_search_mime_part *mpart1,
			    const struct mail_search_mime_part *mpart2)
{
	i_assert(mpart1->simplified == mpart2->simplified);

	return mail_search_mime_arg_equals(mpart1->args, mpart2->args);
}

/*
 *
 */

void mail_search_mime_simplify(struct mail_search_mime_part *mpart)
{
	mpart->simplified = TRUE;

	// FIXME: implement and use
}

/*
 *
 */

static bool
mail_search_mime_subargs_to_imap(string_t *dest,
	const struct mail_search_mime_arg *args,
	const char *prefix, const char **error_r)
{
	const struct mail_search_mime_arg *arg;

	str_append_c(dest, '(');
	for (arg = args; arg != NULL; arg = arg->next) {
		if (arg->next != NULL)
			str_append(dest, prefix);
		if (!mail_search_mime_arg_to_imap(dest, arg, error_r))
			return FALSE;
		if (arg->next != NULL)
			str_append_c(dest, ' ');
	}
	str_append_c(dest, ')');
	return TRUE;
}

static bool
mail_search_mime_arg_to_imap_date(string_t *dest,
	const struct mail_search_mime_arg *arg)
{
	time_t timestamp = arg->value.time;
	const char *str;
	struct tm *tm;
	int tz_offset;

	tm = localtime(&timestamp);
	tz_offset = utc_offset(tm, timestamp);
	timestamp -= tz_offset * 60;

	if (!imap_to_date(timestamp, &str))
		return FALSE;
	str_printfa(dest, " \"%s\"", str);
	return TRUE;
}

bool mail_search_mime_arg_to_imap(string_t *dest,
	const struct mail_search_mime_arg *arg, const char **error_r)
{
	if (arg->match_not)
		str_append(dest, "NOT ");
	switch (arg->type) {
	case SEARCH_MIME_OR:
		if (!mail_search_mime_subargs_to_imap
			(dest, arg->value.subargs, "OR ", error_r))
			return FALSE;
		break;
	case SEARCH_MIME_SUB:
		if (!mail_search_mime_subargs_to_imap
			(dest, arg->value.subargs, "", error_r))
			return FALSE;
		break;
	case SEARCH_MIME_SIZE_EQUAL:
		str_printfa(dest, "SIZE %llu",
			(unsigned long long)arg->value.size);
		break;
	case SEARCH_MIME_SIZE_LARGER:
		str_printfa(dest, "SIZE LARGER %llu",
			(unsigned long long)arg->value.size);
		break;
	case SEARCH_MIME_SIZE_SMALLER:
		str_printfa(dest, "SIZE SMALLER %llu",
			(unsigned long long)arg->value.size);
		break;
	case SEARCH_MIME_DESCRIPTION:
		str_append(dest, "DESCRIPTION ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_DISPOSITION_TYPE:
		str_append(dest, "DISPOSITION TYPE ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_DISPOSITION_PARAM:
		str_append(dest, "DISPOSITION PARAM ");
		imap_append_astring(dest, arg->field_name);
		str_append_c(dest, ' ');
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_ENCODING:
		str_append(dest, "ENCODING ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_ID:
		str_append(dest, "ID ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_LANGUAGE:
		str_append(dest, "LANGUAGE ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_LOCATION:
		str_append(dest, "LOCATION ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_MD5:
		str_append(dest, "MD5 ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_TYPE:
		str_append(dest, "TYPE ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_SUBTYPE:
		str_append(dest, "SUBTYPE ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_PARAM:
		str_append(dest, "PARAM ");
		imap_append_astring(dest, arg->field_name);
		str_append_c(dest, ' ');
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_HEADER:
		str_append(dest, "HEADER ");
		imap_append_astring(dest, arg->field_name);
		str_append_c(dest, ' ');
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_BODY:
		str_append(dest, "BODY ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_TEXT:
		str_append(dest, "TEXT ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_CC:
		str_append(dest, "CC ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_BCC:
		str_append(dest, "BCC ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_FROM:
		str_append(dest, "FROM ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_IN_REPLY_TO:
		str_append(dest, "IN-REPLY-TO ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_MESSAGE_ID:
		str_append(dest, "MESSAGE-ID ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_REPLY_TO:
		str_append(dest, "REPLY-TO ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_SENDER:
		str_append(dest, "SENDER ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_SENTBEFORE:
		str_append(dest, "SENTBEFORE");
		if (!mail_search_mime_arg_to_imap_date(dest, arg)) {
			*error_r = t_strdup_printf(
				"SENTBEFORE can't be written as IMAP MIMEPART key "
				"for timestamp %ld", (long)arg->value.time);
			return FALSE;
		}
		break;
	case SEARCH_MIME_SENTON:
		str_append(dest, "SENTON");
		if (!mail_search_mime_arg_to_imap_date(dest, arg)) {
			*error_r = t_strdup_printf(
				"SENTON can't be written as IMAP MIMEPART key "
				"for timestamp %ld", (long)arg->value.time);
			return FALSE;
		}
		break;
	case SEARCH_MIME_SENTSINCE:
		str_append(dest, "SENTSINCE");
		if (!mail_search_mime_arg_to_imap_date(dest, arg)) {
			*error_r = t_strdup_printf(
				"SENTSINCE can't be written as IMAP MIMEPART key "
				"for timestamp %ld", (long)arg->value.time);
			return FALSE;
		}
		break;
	case SEARCH_MIME_SUBJECT:
		str_append(dest, "SUBJECT ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_TO:
		str_append(dest, "TO ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_DEPTH_EQUAL:
		str_printfa(dest, "DEPTH %u", arg->value.number);
		break;
	case SEARCH_MIME_DEPTH_MIN:
		str_printfa(dest, "DEPTH MIN %u", arg->value.number);
		break;
	case SEARCH_MIME_DEPTH_MAX:
		str_printfa(dest, "DEPTH MAX %u", arg->value.number);
		break;
	case SEARCH_MIME_INDEX:
		str_printfa(dest, "INDEX %u", arg->value.number);
		break;
	case SEARCH_MIME_PARENT:
		str_append(dest, "PARENT ");
		if (arg->value.subargs == NULL)
			str_append(dest, "EXISTS");
		else if (!mail_search_mime_subargs_to_imap
			(dest, arg->value.subargs, "", error_r))
			return FALSE;
		break;
	case SEARCH_MIME_CHILD:
		str_append(dest, "CHILD ");
		if (arg->value.subargs == NULL)
			str_append(dest, "EXISTS");
		else if (!mail_search_mime_subargs_to_imap
			(dest, arg->value.subargs, "", error_r))
			return FALSE;
		break;
	case SEARCH_MIME_FILENAME_IS:
		str_append(dest, "FILENAME IS ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_FILENAME_CONTAINS:
		str_append(dest, "FILENAME CONTAINS ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_FILENAME_BEGINS:
		str_append(dest, "FILENAME BEGINS ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MIME_FILENAME_ENDS:
		str_append(dest, "FILENAME ENDS ");
		imap_append_astring(dest, arg->value.str);
		break;
	}
	return TRUE;
}

bool mail_search_mime_part_to_imap(string_t *dest,
	const struct mail_search_mime_part *mpart, const char **error_r)
{
	const struct mail_search_mime_arg *arg;

	i_assert(mpart->args != NULL);
	if (mpart->args->next == NULL) {
		if (!mail_search_mime_arg_to_imap(dest, mpart->args, error_r))
			return FALSE;
	} else {
		str_append_c(dest, '(');
		for (arg = mpart->args; arg != NULL; arg = arg->next) {
			if (!mail_search_mime_arg_to_imap(dest, arg, error_r))
				return FALSE;
			if (arg->next != NULL)
				str_append_c(dest, ' ');
		}
		str_append_c(dest, ')');
	}
	return TRUE;
}

