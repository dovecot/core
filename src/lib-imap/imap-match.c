/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* imap_match_init() logic originates from Cyrus, but the code is fully
   rewritten. */

#include "lib.h"
#include "array.h"
#include "imap-match.h"

#include <ctype.h>

struct imap_match_pattern {
	const char *pattern;
	bool inboxcase;
};

struct imap_match_glob {
	pool_t pool;

	struct imap_match_pattern *patterns;

	char sep;
	char patterns_data[FLEXIBLE_ARRAY_MEMBER];
};

struct imap_match_context {
	const char *inboxcase_end;

	char sep;
	bool inboxcase;
};

/* name of "INBOX" - must not have repeated substrings */
static const char inbox[] = "INBOX";
#define INBOXLEN (sizeof(inbox) - 1)

struct imap_match_glob *
imap_match_init(pool_t pool, const char *pattern,
		bool inboxcase, char separator)
{
	const char *patterns[2];

	patterns[0] = pattern;
	patterns[1] = NULL;
	return imap_match_init_multiple(pool, patterns, inboxcase, separator);
}

static const char *pattern_compress(const char *pattern)
{
	char *dest, *ret;

	dest = ret = t_strdup_noconst(pattern);

	/* @UNSAFE: compress the pattern */
	while (*pattern != '\0') {
		if (*pattern == '*' || *pattern == '%') {
			/* remove duplicate hierarchy wildcards */
			while (*pattern == '%') pattern++;

			/* "%*" -> "*" */
			if (*pattern == '*') {
				/* remove duplicate wildcards */
				while (*pattern == '*' || *pattern == '%')
					pattern++;
				*dest++ = '*';
			} else {
				*dest++ = '%';
			}
		} else {
			*dest++ = *pattern++;
		}
	}
	*dest = '\0';
	return ret;
}

static bool pattern_is_inboxcase(const char *pattern, char separator)
{
	const char *p = pattern, *inboxp = inbox;

	/* skip over exact matches */
	while (*inboxp == i_toupper(*p) && *p != '\0') {
		inboxp++; p++;
	}
	if (*p != '%') {
		return *p == '*' || *p == separator ||
			(*inboxp == '\0' && *p == '\0');
	}

	/* handle 'I%B%X' style checks */
	for (; *p != '\0' && *p != '*' && *p != separator; p++) {
		if (*p != '%') {
			inboxp = strchr(inboxp, i_toupper(*p));
			if (inboxp == NULL)
				return FALSE;

			if (*++inboxp == '\0') {
				/* now check that it doesn't end with
				   any invalid chars */
				if (*++p == '%') p++;
				if (*p != '\0' && *p != '*' &&
				    *p != separator)
					return FALSE;
				break;
			}
		}
	}
	return TRUE;
}

static struct imap_match_glob *
imap_match_init_multiple_real(pool_t pool, const char *const *patterns,
			      bool inboxcase, char separator)
{
	struct imap_match_glob *glob;
	struct imap_match_pattern *match_patterns;
	unsigned int i, len, pos, patterns_count, patterns_data_len = 0;

	patterns_count = str_array_length(patterns);
	match_patterns = p_new(pool, struct imap_match_pattern,
			       patterns_count + 1);

	/* compress the patterns */
	for (i = 0; i < patterns_count; i++) {
		match_patterns[i].pattern = pattern_compress(patterns[i]);
		match_patterns[i].inboxcase = inboxcase &&
			pattern_is_inboxcase(match_patterns[i].pattern,
					     separator);

		patterns_data_len += strlen(match_patterns[i].pattern) + 1;
	}
	patterns_count = i;

	/* now we know how much memory we need */
	glob = p_malloc(pool, sizeof(struct imap_match_glob) +
			patterns_data_len);
	glob->pool = pool;
	glob->sep = separator;

	/* copy pattern strings to our allocated memory */
	for (i = 0, pos = 0; i < patterns_count; i++) {
		len = strlen(match_patterns[i].pattern) + 1;
		i_assert(pos + len <= patterns_data_len);

		/* @UNSAFE */
		memcpy(glob->patterns_data + pos,
		       match_patterns[i].pattern, len);
		match_patterns[i].pattern = glob->patterns_data + pos;
		pos += len;
	}
	glob->patterns = match_patterns;
	return glob;
}

struct imap_match_glob *
imap_match_init_multiple(pool_t pool, const char *const *patterns,
			 bool inboxcase, char separator)
{
	struct imap_match_glob *glob;

	if (pool->datastack_pool) {
		return imap_match_init_multiple_real(pool, patterns,
						     inboxcase, separator);
	}
	T_BEGIN {
		glob = imap_match_init_multiple_real(pool, patterns,
						     inboxcase, separator);
	} T_END;
	return glob;
}

void imap_match_deinit(struct imap_match_glob **glob)
{
	p_free((*glob)->pool, (*glob)->patterns);
	p_free((*glob)->pool, *glob);
	*glob = NULL;
}

static struct imap_match_glob *
imap_match_dup_real(pool_t pool, const struct imap_match_glob *glob)
{
	ARRAY_TYPE(const_string) patterns;
	const struct imap_match_pattern *p;
	bool inboxcase = FALSE;

	t_array_init(&patterns, 8);
	for (p = glob->patterns; p->pattern != NULL; p++) {
		if (p->inboxcase)
			inboxcase = TRUE;
		array_append(&patterns, &p->pattern, 1);
	}
	(void)array_append_space(&patterns);
	return imap_match_init_multiple_real(pool, array_idx(&patterns, 0),
					     inboxcase, glob->sep);
}

struct imap_match_glob *
imap_match_dup(pool_t pool, const struct imap_match_glob *glob)
{
	struct imap_match_glob *new_glob;

	if (pool->datastack_pool) {
		return imap_match_dup_real(pool, glob);
	} else {
		T_BEGIN {
			new_glob = imap_match_dup_real(pool, glob);
		} T_END;
		return new_glob;
	}
}

bool imap_match_globs_equal(const struct imap_match_glob *glob1,
			    const struct imap_match_glob *glob2)
{
	const struct imap_match_pattern *p1 = glob1->patterns;
	const struct imap_match_pattern *p2 = glob2->patterns;

	if (glob1->sep != glob2->sep)
		return FALSE;

	for (; p1->pattern != NULL && p2->pattern != NULL; p1++, p2++) {
		if (strcmp(p1->pattern, p2->pattern) != 0)
			return FALSE;
		if (p1->inboxcase != p2->inboxcase)
			return FALSE;
	}
	return p1->pattern == p2->pattern;
}

#define CMP_CUR_CHR(ctx, data, pattern) \
	(*(data) == *(pattern) || \
	 (i_toupper(*(data)) == i_toupper(*(pattern)) && \
	 (data) < (ctx)->inboxcase_end))

static enum imap_match_result
match_sub(struct imap_match_context *ctx, const char **data_p,
	  const char **pattern_p)
{
	enum imap_match_result ret, match;
	unsigned int i;
	const char *data = *data_p, *pattern = *pattern_p;

	/* match all non-wildcards */
	i = 0;
	while (pattern[i] != '\0' && pattern[i] != '*' && pattern[i] != '%') {
		if (!CMP_CUR_CHR(ctx, data+i, pattern+i)) {
			if (data[i] != '\0')
				return IMAP_MATCH_NO;
			if (pattern[i] == ctx->sep)
				return IMAP_MATCH_CHILDREN;
			if (i > 0 && pattern[i-1] == ctx->sep) {
				/* data="foo/" pattern = "foo/bar/%" */
				return IMAP_MATCH_CHILDREN;
			}
			return IMAP_MATCH_NO;
		}
		i++;
	}
	data += i;
	pattern += i;

	if (*data == '\0' && *data_p != data && data[-1] == ctx->sep &&
	    *pattern != '\0') {
		/* data="/" pattern="/%..." */
		match = IMAP_MATCH_CHILDREN;
	} else {
		match = IMAP_MATCH_NO;
	}
	while (*pattern == '%') {
		pattern++;

		if (*pattern == '\0') {
			/* match, if this is the last hierarchy */
			while (*data != '\0' && *data != ctx->sep)
				data++;
			break;
		}

		/* skip over this hierarchy */
		while (*data != '\0') {
			if (CMP_CUR_CHR(ctx, data, pattern)) {
				ret = match_sub(ctx, &data, &pattern);
				if (ret == IMAP_MATCH_YES)
					break;

				match |= ret;
			}

			if (*data == ctx->sep)
				break;

			data++;
		}
	}

	if (*pattern != '*') {
		if (*data == '\0' && *pattern != '\0') {
			if (*pattern == ctx->sep)
				match |= IMAP_MATCH_CHILDREN;
			return match;
		}

		if (*data != '\0') {
			if (*pattern == '\0' && *data == ctx->sep)
				match |= IMAP_MATCH_PARENT;
			return match;
		}
	}

	*data_p = data;
	*pattern_p = pattern;
	return IMAP_MATCH_YES;
}

static enum imap_match_result
imap_match_pattern(struct imap_match_context *ctx,
		   const char *data, const char *pattern)
{
	enum imap_match_result ret, match;

	ctx->inboxcase_end = data;
	if (ctx->inboxcase && strncasecmp(data, inbox, INBOXLEN) == 0 &&
	    (data[INBOXLEN] == '\0' || data[INBOXLEN] == ctx->sep)) {
		/* data begins with INBOX/, use case-insensitive comparison
		   for it */
		ctx->inboxcase_end += INBOXLEN;
	}

	if (*pattern != '*') {
		/* handle the pattern up to the first '*' */
		ret = match_sub(ctx, &data, &pattern);
		if (ret != IMAP_MATCH_YES || *pattern == '\0')
			return ret;
	}

	match = IMAP_MATCH_CHILDREN;
	while (*pattern == '*') {
		pattern++;

		if (*pattern == '\0')
			return IMAP_MATCH_YES;

		while (*data != '\0') {
			if (CMP_CUR_CHR(ctx, data, pattern)) {
				ret = match_sub(ctx, &data, &pattern);
				if (ret == IMAP_MATCH_YES)
					break;
				match |= ret;
			}

			data++;
		}
	}

	return *data == '\0' && *pattern == '\0' ?
		IMAP_MATCH_YES : match;
}

enum imap_match_result
imap_match(struct imap_match_glob *glob, const char *data)
{
	struct imap_match_context ctx;
	unsigned int i;
	enum imap_match_result ret, match;

	match = IMAP_MATCH_NO;
	ctx.sep = glob->sep;
	for (i = 0; glob->patterns[i].pattern != NULL; i++) {
		ctx.inboxcase = glob->patterns[i].inboxcase;

		ret = imap_match_pattern(&ctx, data, glob->patterns[i].pattern);
		if (ret == IMAP_MATCH_YES)
			return IMAP_MATCH_YES;

		match |= ret;
	}

	return match;
}
