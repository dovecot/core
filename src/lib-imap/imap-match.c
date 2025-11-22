/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* imap_match_init() logic originates from Cyrus, but the code is fully
   rewritten. */

#include "lib.h"
#include "array.h"
#include "unichar.h"
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
	unsigned int i, patterns_count;
	size_t len, pos, patterns_data_len = 0;

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
	if (glob == NULL || *glob == NULL)
		return;
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
		array_push_back(&patterns, &p->pattern);
	}
	array_append_zero(&patterns);
	return imap_match_init_multiple_real(pool, array_front(&patterns),
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

static inline bool
match_gc(struct imap_match_context *ctx,
	 struct uni_gc_scanner *gcsc_data, struct uni_gc_scanner *gcsc_pattern)
{
	const unsigned char *pat_gc, *data_gc;
	size_t pat_gc_size, data_gc_size;

	pat_gc = uni_gc_scan_get(gcsc_pattern, &pat_gc_size);
	data_gc = uni_gc_scan_get(gcsc_data, &data_gc_size);

	if (pat_gc_size != data_gc_size)
		return FALSE;
	if (memcmp(data_gc, pat_gc, data_gc_size) == 0)
		return TRUE;
	if (data_gc_size != 1)
		return FALSE;
	return ((const char *)data_gc < ctx->inboxcase_end &&
		i_toupper(data_gc[0]) == i_toupper(pat_gc[0]));
}

static enum imap_match_result
match_sub(struct imap_match_context *ctx,
	  struct uni_gc_scanner *gcsc_data_p,
	  struct uni_gc_scanner *gcsc_pattern_p)
{
	enum imap_match_result ret, match;
	struct uni_gc_scanner gcsc_data = *gcsc_data_p;
	struct uni_gc_scanner gcsc_pattern = *gcsc_pattern_p;
	const unsigned char *pat_gc_prev = NULL, *data_gc_prev = NULL;
	size_t pat_gc_prev_size = 0, data_gc_prev_size = 0;

	/* match all non-wildcards */
	while (!uni_gc_scan_at_end(&gcsc_pattern) &&
	       !uni_gc_scan_ascii_equals(&gcsc_pattern, '*') &&
	       !uni_gc_scan_ascii_equals(&gcsc_pattern, '%')) {
		if (!match_gc(ctx, &gcsc_data, &gcsc_pattern)) {
			if (!uni_gc_scan_at_end(&gcsc_data))
				return IMAP_MATCH_NO;
			if (uni_gc_scan_ascii_equals(&gcsc_pattern, ctx->sep))
				return IMAP_MATCH_CHILDREN;
			if (pat_gc_prev_size == 1 &&
			    pat_gc_prev[0] == ctx->sep) {
				/* data="foo/" pattern = "foo/bar/%" */
				return IMAP_MATCH_CHILDREN;
			}
			return IMAP_MATCH_NO;
		}

		pat_gc_prev = uni_gc_scan_get(&gcsc_pattern, &pat_gc_prev_size);
		data_gc_prev = uni_gc_scan_get(&gcsc_data, &data_gc_prev_size);
		uni_gc_scan_shift(&gcsc_pattern);
		uni_gc_scan_shift(&gcsc_data);
	}
	if (uni_gc_scan_at_end(&gcsc_data) &&
	    data_gc_prev_size == 1 && data_gc_prev[0] == ctx->sep &&
	    !uni_gc_scan_at_end(&gcsc_pattern)) {
		/* data="/" pattern="/%..." */
		match = IMAP_MATCH_CHILDREN;
	} else {
		match = IMAP_MATCH_NO;
	}
	while (uni_gc_scan_ascii_equals(&gcsc_pattern, '%')) {
		uni_gc_scan_shift(&gcsc_pattern);

		if (uni_gc_scan_at_end(&gcsc_pattern)) {
			/* match, if this is the last hierarchy */
			while (!uni_gc_scan_at_end(&gcsc_data) &&
			       !uni_gc_scan_ascii_equals(&gcsc_data, ctx->sep))
				uni_gc_scan_shift(&gcsc_data);
			break;
		}

		/* skip over this hierarchy */
		while (!uni_gc_scan_at_end(&gcsc_data)) {
			if (match_gc(ctx, &gcsc_data, &gcsc_pattern)) {
				ret = match_sub(ctx, &gcsc_data,
						&gcsc_pattern);
				if (ret == IMAP_MATCH_YES)
					break;

				match |= ret;
			}

			if (uni_gc_scan_ascii_equals(&gcsc_data, ctx->sep))
				break;

			uni_gc_scan_shift(&gcsc_data);
		}
	}

	if (!uni_gc_scan_ascii_equals(&gcsc_pattern, '*')) {
		if (uni_gc_scan_at_end(&gcsc_data) &&
		    !uni_gc_scan_at_end(&gcsc_pattern)) {
			if (uni_gc_scan_ascii_equals(&gcsc_pattern,
						     ctx->sep))
				match |= IMAP_MATCH_CHILDREN;
			return match;
		}

		if (!uni_gc_scan_at_end(&gcsc_data)) {
			if (uni_gc_scan_at_end(&gcsc_pattern) &&
			    uni_gc_scan_ascii_equals(&gcsc_data, ctx->sep))
				match |= IMAP_MATCH_PARENT;
			return match;
		}
	}

	*gcsc_data_p = gcsc_data;
	*gcsc_pattern_p = gcsc_pattern;
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

	struct uni_gc_scanner gcsc_data;
	struct uni_gc_scanner gcsc_pattern;

	uni_gc_scanner_init(&gcsc_data, data, strlen(data));
	uni_gc_scanner_init(&gcsc_pattern, pattern, strlen(pattern));

	if (!uni_gc_scan_ascii_equals(&gcsc_pattern, '*')) {
		/* handle the pattern up to the first '*' */
		ret = match_sub(ctx, &gcsc_data, &gcsc_pattern);
		if (ret != IMAP_MATCH_YES ||
		    uni_gc_scan_at_end(&gcsc_pattern))
			return ret;
	}

	match = IMAP_MATCH_CHILDREN;
	while (uni_gc_scan_ascii_equals(&gcsc_pattern, '*')) {
		uni_gc_scan_shift(&gcsc_pattern);

		if (uni_gc_scan_at_end(&gcsc_pattern))
			return IMAP_MATCH_YES;

		while (!uni_gc_scan_at_end(&gcsc_data)) {
			if (match_gc(ctx, &gcsc_data, &gcsc_pattern)) {
				ret = match_sub(ctx, &gcsc_data, &gcsc_pattern);
				if (ret == IMAP_MATCH_YES)
					break;
				match |= ret;
			}
			uni_gc_scan_shift(&gcsc_data);
		}
	}

	return ((uni_gc_scan_at_end(&gcsc_data) &&
	         uni_gc_scan_at_end(&gcsc_pattern)) ?
	        IMAP_MATCH_YES : match);
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
