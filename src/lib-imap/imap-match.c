/* Copyright (C) 2002 Timo Sirainen

   imap_match_init() logic originates from Cyrus, but the code is fully
   rewritten.
*/

#include "lib.h"
#include "imap-match.h"

#include <ctype.h>

struct imap_match_glob {
	pool_t pool;

	bool inboxcase;
	const char *inboxcase_end;

	char sep_char;
	char pattern[1];
};

/* name of "INBOX" - must not have repeated substrings */
static const char inbox[] = "INBOX";
#define INBOXLEN (sizeof(inbox) - 1)

struct imap_match_glob *
imap_match_init(pool_t pool, const char *pattern,
		bool inboxcase, char separator)
{
	struct imap_match_glob *glob;
	const char *p, *inboxp;
	char *dst;

	/* +1 from struct */
	glob = p_malloc(pool, sizeof(struct imap_match_glob) + strlen(pattern));
	glob->pool = pool;
	glob->sep_char = separator;

	/* @UNSAFE: compress the pattern */
	dst = glob->pattern;
	while (*pattern != '\0') {
		if (*pattern == '*' || *pattern == '%') {
			/* remove duplicate hierarchy wildcards */
			while (*pattern == '%') pattern++;

			/* "%*" -> "*" */
			if (*pattern == '*') {
				/* remove duplicate wildcards */
				while (*pattern == '*' || *pattern == '%')
					pattern++;
				*dst++ = '*';
			} else {
				*dst++ = '%';
			}
		} else {
			*dst++ = *pattern++;
		}
	}
	*dst++ = '\0';

	if (inboxcase) {
		/* check if we could be comparing INBOX. */
		inboxp = inbox;
		glob->inboxcase = TRUE;
                p = glob->pattern;
		for (; *p != '\0' && *p != '*' && *p != separator; p++) {
			if (*p != '%') {
				inboxp = strchr(inboxp, i_toupper(*p));
				if (inboxp == NULL) {
					glob->inboxcase = FALSE;
					break;
				}

				if (*++inboxp == '\0') {
					/* now check that it doesn't end with
					   any invalid chars */
					if (*++p == '%') p++;
					if (*p != '\0' && *p != '*' &&
					    *p != separator)
						glob->inboxcase = FALSE;
					break;
				}
			}
		}
	}

	return glob;
}

void imap_match_deinit(struct imap_match_glob **glob)
{
	p_free((*glob)->pool, *glob);
	*glob = NULL;
}

static inline bool cmp_chr(const struct imap_match_glob *glob,
			   const char *data, char patternchr)
{
	return *data == patternchr ||
		(glob->inboxcase_end != NULL && data < glob->inboxcase_end &&
		 i_toupper(*data) == i_toupper(patternchr));
}

static enum imap_match_result
match_sub(const struct imap_match_glob *glob, const char **data_p,
	  const char **pattern_p)
{
	const char *pattern, *data;
	enum imap_match_result ret, best_ret;

	data = *data_p; pattern = *pattern_p;

	while (*pattern != '\0' && *pattern != '*' && *pattern != '%') {
		if (!cmp_chr(glob, data, *pattern)) {
			return *data == '\0' && *pattern == glob->sep_char ?
				IMAP_MATCH_CHILDREN : IMAP_MATCH_NO;
		}
		data++; pattern++;
	}

        best_ret = IMAP_MATCH_NO;
	while (*pattern == '%') {
		pattern++;

		if (*pattern == '\0') {
			while (*data != '\0' && *data != glob->sep_char)
				data++;
			break;
		}

		while (*data != '\0') {
			if (cmp_chr(glob, data, *pattern)) {
				ret = match_sub(glob, &data, &pattern);
				if (ret > 0)
					break;

				if (ret == IMAP_MATCH_CHILDREN ||
				    (ret == IMAP_MATCH_PARENT &&
				     best_ret == IMAP_MATCH_NO))
					best_ret = ret;
			}

			if (*data == glob->sep_char)
				break;

			data++;
		}
	}

	if (*pattern != '*') {
		if (*data == '\0' && *pattern != '\0')
			return *pattern == glob->sep_char ?
				IMAP_MATCH_CHILDREN : best_ret;

		if (*data != '\0') {
			return best_ret != IMAP_MATCH_NO ||
				*pattern != '\0' || *data != glob->sep_char ?
				best_ret : IMAP_MATCH_PARENT;
		}
	}

	*data_p = data;
	*pattern_p = pattern;
	return IMAP_MATCH_YES;
}

enum imap_match_result
imap_match(struct imap_match_glob *glob, const char *data)
{
	const char *pattern;
	int ret;

	if (glob->inboxcase &&
	    strncasecmp(data, inbox, INBOXLEN) == 0 &&
	    (data[INBOXLEN] == '\0' || data[INBOXLEN] == glob->sep_char))
		glob->inboxcase_end = data + INBOXLEN;
	else
		glob->inboxcase_end = NULL;

	pattern = glob->pattern;
	if (*pattern != '*') {
		if ((ret = match_sub(glob, &data, &pattern)) <= 0)
			return ret;

		if (*pattern == '\0')
			return IMAP_MATCH_YES;
	}

	while (*pattern == '*') {
		pattern++;

		if (*pattern == '\0')
			return IMAP_MATCH_YES;

		while (*data != '\0') {
			if (cmp_chr(glob, data, *pattern)) {
				if (match_sub(glob, &data, &pattern) > 0)
					break;
			}

			data++;
		}
	}

	return *data == '\0' && *pattern == '\0' ?
		IMAP_MATCH_YES : IMAP_MATCH_CHILDREN;
}
