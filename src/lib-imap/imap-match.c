/* Copyright (C) 2002 Timo Sirainen

   imap_match_init() logic originates from Cyrus, but the code is fully
   rewritten.
*/

#include "lib.h"
#include "imap-match.h"

#include <ctype.h>

struct imap_match_glob {
	pool_t pool;

	int inboxcase;
	const char *inboxcase_end;

	char sep_char;
	char mask[1];
};

/* name of "INBOX" - must not have repeated substrings */
static const char inbox[] = "INBOX";
#define INBOXLEN (sizeof(inbox) - 1)

struct imap_match_glob *
imap_match_init(pool_t pool, const char *mask, int inboxcase, char separator)
{
	struct imap_match_glob *glob;
	const char *p, *inboxp;
	char *dst;

	/* +1 from struct */
	glob = p_malloc(pool, sizeof(struct imap_match_glob) + strlen(mask));
	glob->pool = pool;
	glob->sep_char = separator;

	/* @UNSAFE: compress the mask */
	dst = glob->mask;
	while (*mask != '\0') {
		if (*mask == '*' || *mask == '%') {
			/* remove duplicate hierarchy wildcards */
			while (*mask == '%') mask++;

			/* "%*" -> "*" */
			if (*mask == '*') {
				/* remove duplicate wildcards */
				while (*mask == '*' || *mask == '%')
					mask++;
				*dst++ = '*';
			} else {
				*dst++ = '%';
			}
		} else {
			*dst++ = *mask++;
		}
	}
	*dst++ = '\0';

	if (inboxcase) {
		/* check if we could be comparing INBOX. */
		inboxp = inbox;
		glob->inboxcase = TRUE;
		for (p = glob->mask; *p != '\0' && *p != '*'; p++) {
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
					    *p != glob->sep_char)
						glob->inboxcase = FALSE;
					break;
				}
			}
		}

		if (glob->inboxcase && inboxp != NULL && *inboxp != '\0' &&
		    *p != '*' && (p != glob->mask && p[-1] != '%'))
			glob->inboxcase = FALSE;
	}

	return glob;
}

void imap_match_deinit(struct imap_match_glob *glob)
{
	p_free(glob->pool, glob);
}

static inline int cmp_chr(const struct imap_match_glob *glob,
			  const char *data, char maskchr)
{
	return *data == maskchr ||
		(glob->inboxcase_end != NULL && data < glob->inboxcase_end &&
		 i_toupper(*data) == i_toupper(maskchr));
}

static enum imap_match_result
match_sub(const struct imap_match_glob *glob, const char **data_p,
	  const char **mask_p)
{
	const char *mask, *data;
	enum imap_match_result ret, best_ret;

	data = *data_p; mask = *mask_p;

	while (*mask != '\0' && *mask != '*' && *mask != '%') {
		if (!cmp_chr(glob, data, *mask)) {
			return *data == '\0' && *mask == glob->sep_char ?
				IMAP_MATCH_CHILDREN : IMAP_MATCH_NO;
		}
		data++; mask++;
	}

        best_ret = IMAP_MATCH_NO;
	while (*mask == '%') {
		mask++;

		if (*mask == '\0') {
			while (*data != '\0' && *data != glob->sep_char)
				data++;
			break;
		}

		while (*data != '\0') {
			if (cmp_chr(glob, data, *mask)) {
				ret = match_sub(glob, &data, &mask);
				if (ret > 0)
					break;

				if (ret == IMAP_MATCH_CHILDREN)
					best_ret = IMAP_MATCH_CHILDREN;
			}

			if (*data == glob->sep_char)
				break;

			data++;
		}
	}

	if (*mask != '*') {
		if (*data == '\0' && *mask != '\0')
			return *mask == glob->sep_char ?
				IMAP_MATCH_CHILDREN : best_ret;

		if (*data != '\0') {
			return best_ret != IMAP_MATCH_NO ||
				*mask != '\0' || *data != glob->sep_char ?
				best_ret : IMAP_MATCH_PARENT;
		}
	}

	*data_p = data;
	*mask_p = mask;
	return IMAP_MATCH_YES;
}

enum imap_match_result
imap_match(struct imap_match_glob *glob, const char *data)
{
	const char *mask;
	int ret;

	if (glob->inboxcase &&
	    strncasecmp(data, inbox, INBOXLEN) == 0 &&
	    (data[INBOXLEN] == '\0' || data[INBOXLEN] == glob->sep_char))
		glob->inboxcase_end = data + INBOXLEN;
	else
		glob->inboxcase_end = NULL;

	mask = glob->mask;
	if (*mask != '*') {
		if ((ret = match_sub(glob, &data, &mask)) <= 0)
			return ret;

		if (*mask == '\0')
			return IMAP_MATCH_YES;
	}

	while (*mask == '*') {
		mask++;

		if (*mask == '\0')
			return IMAP_MATCH_YES;

		while (*data != '\0') {
			if (cmp_chr(glob, data, *mask)) {
				if (match_sub(glob, &data, &mask) > 0)
					break;
			}

			data++;
		}
	}

	return *data == '\0' && *mask == '\0' ?
		IMAP_MATCH_YES : IMAP_MATCH_CHILDREN;
}
