/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "utc-offset.h"
#include "mail-index.h"
#include "imap-date.h"
#include "imap-util.h"
#include "imap-quote.h"
#include "mail-search.h"
#include "mail-search-mime.h"

#include <time.h>

static bool
mail_search_subargs_to_imap(string_t *dest, const struct mail_search_arg *args,
			    const char *prefix, const char **error_r)
{
	const struct mail_search_arg *arg;

	if (prefix[0] == '\0')
		str_append_c(dest, '(');
	for (arg = args; arg != NULL; arg = arg->next) {
		if (arg->next != NULL)
			str_append(dest, prefix);
		if (!mail_search_arg_to_imap(dest, arg, error_r))
			return FALSE;
		if (arg->next != NULL)
			str_append_c(dest, ' ');
	}
	if (prefix[0] == '\0')
		str_append_c(dest, ')');
	return TRUE;
}

static bool
mail_search_arg_to_imap_date(string_t *dest, const struct mail_search_arg *arg)
{
	time_t timestamp = arg->value.time;
	const char *str;

	if ((arg->value.search_flags &
	     MAIL_SEARCH_ARG_FLAG_UTC_TIMES) == 0) {
		struct tm *tm = localtime(&timestamp);
		int tz_offset = utc_offset(tm, timestamp);
		timestamp -= tz_offset * 60;
	}
	if (!imap_to_date(timestamp, &str))
		return FALSE;
	str_printfa(dest, " \"%s\"", str);
	return TRUE;
}

static void
mail_search_arg_to_imap_flags(string_t *dest, enum mail_flags flags)
{
	static const char *flag_names[] = {
		"ANSWERED", "FLAGGED", "DELETED", "SEEN", "DRAFT", "RECENT"
	};

	i_assert(flags != 0);

	if (!bits_is_power_of_two(flags))
		str_append_c(dest, '(');
	for (unsigned int i = 0; i < N_ELEMENTS(flag_names); i++) {
		if ((flags & (1 << i)) != 0) {
			str_append(dest, flag_names[i]);
			str_append_c(dest, ' ');
		}
	}

	str_truncate(dest, str_len(dest)-1);
	if (!bits_is_power_of_two(flags))
		str_append_c(dest, ')');
}

bool mail_search_arg_to_imap(string_t *dest, const struct mail_search_arg *arg,
			     const char **error_r)
{
	unsigned int start_pos;

	if (arg->match_not)
		str_append(dest, "NOT ");
	start_pos = str_len(dest);
	switch (arg->type) {
	case SEARCH_OR:
		if (!mail_search_subargs_to_imap(dest, arg->value.subargs,
						 "OR ", error_r))
			return FALSE;
		break;
	case SEARCH_SUB:
		if (!mail_search_subargs_to_imap(dest, arg->value.subargs,
						 "", error_r))
			return FALSE;
		break;
	case SEARCH_ALL:
		str_append(dest, "ALL");
		break;
	case SEARCH_SEQSET:
		imap_write_seq_range(dest, &arg->value.seqset);
		break;
	case SEARCH_UIDSET:
		str_append(dest, "UID ");
		imap_write_seq_range(dest, &arg->value.seqset);
		break;
	case SEARCH_FLAGS:
		mail_search_arg_to_imap_flags(dest, arg->value.flags);
		break;
	case SEARCH_KEYWORDS: {
		const struct mail_keywords *kw = arg->initialized.keywords;
		const ARRAY_TYPE(keywords) *names_arr;
		const char *const *namep;
		unsigned int i;

		if (kw == NULL || kw->count == 0) {
			/* uninitialized / invalid keyword */
			str_printfa(dest, "KEYWORD %s", arg->value.str);
			break;
		}

		names_arr = mail_index_get_keywords(kw->index);

		if (kw->count > 1)
			str_append_c(dest, '(');
		for (i = 0; i < kw->count; i++) {
			namep = array_idx(names_arr, kw->idx[i]);
			if (i > 0)
				str_append_c(dest, ' ');
			str_printfa(dest, "KEYWORD %s", *namep);
		}
		if (kw->count > 1)
			str_append_c(dest, ')');
		break;
	}

	case SEARCH_BEFORE:
		switch (arg->value.date_type) {
		case MAIL_SEARCH_DATE_TYPE_SENT:
			str_append(dest, "SENTBEFORE");
			break;
		case MAIL_SEARCH_DATE_TYPE_RECEIVED:
			str_append(dest, "BEFORE");
			break;
		case MAIL_SEARCH_DATE_TYPE_SAVED:
			str_append(dest, "SAVEDBEFORE");
			break;
		}
		if (mail_search_arg_to_imap_date(dest, arg))
			;
		else if (arg->value.date_type != MAIL_SEARCH_DATE_TYPE_RECEIVED ||
			 arg->value.time > ioloop_time) {
			*error_r = t_strdup_printf(
				"SEARCH_BEFORE can't be written as IMAP for timestamp %ld (type=%d, utc_times=%d)",
				(long)arg->value.time, arg->value.date_type,
				(arg->value.search_flags & MAIL_SEARCH_ARG_FLAG_UTC_TIMES) != 0);
			return FALSE;
		} else {
			str_truncate(dest, start_pos);
			str_printfa(dest, "OLDER %u",
				    (unsigned int)(ioloop_time - arg->value.time + 1));
		}
		break;
	case SEARCH_ON:
		switch (arg->value.date_type) {
		case MAIL_SEARCH_DATE_TYPE_SENT:
			str_append(dest, "SENTON");
			break;
		case MAIL_SEARCH_DATE_TYPE_RECEIVED:
			str_append(dest, "ON");
			break;
		case MAIL_SEARCH_DATE_TYPE_SAVED:
			str_append(dest, "SAVEDON");
			break;
		}
		if (!mail_search_arg_to_imap_date(dest, arg)) {
			*error_r = t_strdup_printf(
				"SEARCH_ON can't be written as IMAP for timestamp %ld (type=%d, utc_times=%d)",
				(long)arg->value.time, arg->value.date_type,
				(arg->value.search_flags & MAIL_SEARCH_ARG_FLAG_UTC_TIMES) != 0);
			return FALSE;
		}
		break;
	case SEARCH_SINCE:
		switch (arg->value.date_type) {
		case MAIL_SEARCH_DATE_TYPE_SENT:
			str_append(dest, "SENTSINCE");
			break;
		case MAIL_SEARCH_DATE_TYPE_RECEIVED:
			str_append(dest, "SINCE");
			break;
		case MAIL_SEARCH_DATE_TYPE_SAVED:
			str_append(dest, "SAVEDSINCE");
			break;
		}
		if (mail_search_arg_to_imap_date(dest, arg))
			;
		else if (arg->value.date_type != MAIL_SEARCH_DATE_TYPE_RECEIVED ||
			 arg->value.time >= ioloop_time) {
			*error_r = t_strdup_printf(
				"SEARCH_SINCE can't be written as IMAP for timestamp %ld (type=%d, utc_times=%d)",
				(long)arg->value.time, arg->value.date_type,
				(arg->value.search_flags & MAIL_SEARCH_ARG_FLAG_UTC_TIMES) != 0);
			return FALSE;
		} else {
			str_truncate(dest, start_pos);
			str_printfa(dest, "YOUNGER %u",
				    (unsigned int)(ioloop_time - arg->value.time));
		}
		break;
	case SEARCH_SMALLER:
		str_printfa(dest, "SMALLER %"PRIuUOFF_T, arg->value.size);
		break;
	case SEARCH_LARGER:
		str_printfa(dest, "LARGER %"PRIuUOFF_T, arg->value.size);
		break;
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		if (strcasecmp(arg->hdr_field_name, "From") == 0 ||
		    strcasecmp(arg->hdr_field_name, "To") == 0 ||
		    strcasecmp(arg->hdr_field_name, "Cc") == 0 ||
		    strcasecmp(arg->hdr_field_name, "Bcc") == 0 ||
		    strcasecmp(arg->hdr_field_name, "Subject") == 0)
			str_append(dest, t_str_ucase(arg->hdr_field_name));
		else {
			str_append(dest, "HEADER ");
			imap_append_astring(dest, arg->hdr_field_name);
		}
		str_append_c(dest, ' ');
		imap_append_astring(dest, arg->value.str);
		break;

	case SEARCH_BODY:
		str_append(dest, "BODY ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_TEXT:
		str_append(dest, "TEXT ");
		imap_append_astring(dest, arg->value.str);
		break;

	/* extensions */
	case SEARCH_MODSEQ: {
		bool extended_output = FALSE;

		str_append(dest, "MODSEQ ");
		if (arg->value.str != NULL) {
			str_printfa(dest, "/flags/%s", arg->value.str);
			extended_output = TRUE;
		} else if (arg->value.flags != 0) {
			str_append(dest, "/flags/");
			imap_write_flags(dest, arg->value.flags, NULL);
			extended_output = TRUE;
		}
		if (extended_output) {
			str_append_c(dest, ' ');
			switch (arg->value.modseq->type) {
			case MAIL_SEARCH_MODSEQ_TYPE_ANY:
				str_append(dest, "all");
				break;
			case MAIL_SEARCH_MODSEQ_TYPE_PRIVATE:
				str_append(dest, "priv");
				break;
			case MAIL_SEARCH_MODSEQ_TYPE_SHARED:
				str_append(dest, "shared");
				break;
			}
			str_append_c(dest, ' ');
		}
		str_printfa(dest, "%"PRIu64, arg->value.modseq->modseq);
		break;
	}
	case SEARCH_SAVEDATESUPPORTED:
		str_append(dest, "SAVEDATESUPPORTED");
		break;
	case SEARCH_INTHREAD:
		str_append(dest, "INTHREAD ");
		imap_append_astring(dest, mail_thread_type_to_str(arg->value.thread_type));
		str_append_c(dest, ' ');
		if (!mail_search_subargs_to_imap(dest, arg->value.subargs,
						 "", error_r))
			return FALSE;
		break;
	case SEARCH_GUID:
		str_append(dest, "EMAILID ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_MAILBOX:
		*error_r = "SEARCH_MAILBOX can't be written as IMAP";
		return FALSE;
	case SEARCH_MAILBOX_GUID:
		*error_r = "SEARCH_MAILBOX_GUID can't be written as IMAP";
		return FALSE;
	case SEARCH_MAILBOX_GLOB:
		str_append(dest, "X-MAILBOX ");
		imap_append_astring(dest, arg->value.str);
		break;
	case SEARCH_REAL_UID:
		str_append(dest, "X-REAL-UID ");
		imap_write_seq_range(dest, &arg->value.seqset);
		break;
	case SEARCH_MIMEPART:
		str_append(dest, "MIMEPART ");
		if (!mail_search_mime_part_to_imap(dest,
			arg->value.mime_part, error_r))
			return FALSE;
		break;
	}
	return TRUE;
}

bool mail_search_args_to_imap(string_t *dest, const struct mail_search_arg *args,
			      const char **error_r)
{
	const struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		if (!mail_search_arg_to_imap(dest, arg, error_r))
			return FALSE;
		if (arg->next != NULL)
			str_append_c(dest, ' ');
	}
	return TRUE;
}
