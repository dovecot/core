/* Copyright (c) Dovecot authors, see top-level COPYING file */

/* imap_match_init() logic originates from Cyrus, but the code is fully
   rewritten. */

#include "lib.h"
#include "array.h"
#include "unichar.h"
#include "imap-match.h"

#include <ctype.h>

/* Pattern matching is implemented as a Thompson-style NFA simulation over
   grapheme clusters.  Each grapheme cluster in the (compressed) pattern
   becomes one NFA state:

     LITERAL - must consume a matching grapheme cluster (with inboxcase
               fallback for single-octet clusters in the inboxcase region)
     PERCENT - may consume any number (including zero) of non-separator
               grapheme clusters
     STAR    - may consume any number (including zero) of grapheme clusters

   A virtual ACCEPT position sits at index n_states.  Simulation tracks the
   set of active positions in a bitmap.  Epsilon transitions (skipping a
   PERCENT or STAR without consuming) are applied as a single forward pass
   because the NFA is linear: each state can only epsilon-skip to i+1.

   Complexity is O(n_data * n_pattern) regardless of wildcard count or
   pattern shape, so there is no backtracking and no way for a malicious
   pattern or mailbox name to trigger exponential CPU usage. */

enum imap_match_nfa_type {
	IMAP_MATCH_NFA_LITERAL = 0,
	IMAP_MATCH_NFA_PERCENT,
	IMAP_MATCH_NFA_STAR,
};

struct imap_match_nfa_state {
	uint8_t type; /* enum imap_match_nfa_type */
	/* TRUE iff from this state some input string that starts with the
	   separator character can lead the NFA to ACCEPT.  Precomputed at
	   construction time and used to decide IMAP_MATCH_CHILDREN when the
	   data string does not already end with a separator. */
	bool sep_accept;
	/* For LITERAL states: number of octets in the grapheme cluster. */
	uint16_t gc_size;
	/* For LITERAL states: pointer into the glob's pattern string. */
	const unsigned char *gc;
};

struct imap_match_pattern {
	const char *pattern; /* compressed pattern, pointer into patterns_data */
	bool inboxcase;

	unsigned int n_states;
	struct imap_match_nfa_state *states; /* n_states entries */
};

struct imap_match_glob {
	pool_t pool;

	struct imap_match_pattern *patterns;

	char sep;
	char patterns_data[FLEXIBLE_ARRAY_MEMBER];
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

static void
imap_match_compile(pool_t pool, struct imap_match_pattern *pat, char sep)
{
	struct uni_gc_scanner sc;
	unsigned int count = 0;
	size_t pattern_len = strlen(pat->pattern);

	/* count grapheme clusters to size the state array */
	uni_gc_scanner_init(&sc, pat->pattern, pattern_len);
	while (!uni_gc_scan_at_end(&sc)) {
		count++;
		(void)uni_gc_scan_shift(&sc);
	}
	pat->n_states = count;
	pat->states = count == 0 ? NULL :
		p_new(pool, struct imap_match_nfa_state, count);

	/* populate states */
	uni_gc_scanner_init(&sc, pat->pattern, pattern_len);
	for (unsigned int i = 0; i < count; i++) {
		size_t gc_size;
		const unsigned char *gc = uni_gc_scan_get(&sc, &gc_size);
		struct imap_match_nfa_state *s = &pat->states[i];

		if (gc_size == 1 && gc[0] == '%')
			s->type = IMAP_MATCH_NFA_PERCENT;
		else if (gc_size == 1 && gc[0] == '*')
			s->type = IMAP_MATCH_NFA_STAR;
		else {
			s->type = IMAP_MATCH_NFA_LITERAL;
			s->gc = gc;
			i_assert(gc_size <= UINT16_MAX);
			s->gc_size = (uint16_t)gc_size;
		}
		(void)uni_gc_scan_shift(&sc);
	}

	/* precompute sep_accept[] backward: sep_accept[i] is TRUE iff from
	   state i some input string starting with the separator can reach
	   the ACCEPT position (n_states).  For any j <= n_states there is
	   always some path to ACCEPT (each state either consumes at most
	   one character or is epsilon-skippable), so sep_accept[i] reduces
	   to "is there a j reachable from i via epsilon-skips that can
	   consume the separator?" */
	for (int i = (int)count - 1; i >= 0; i--) {
		const struct imap_match_nfa_state *s = &pat->states[i];
		bool consume_sep =
			s->type == IMAP_MATCH_NFA_STAR ||
			(s->type == IMAP_MATCH_NFA_LITERAL &&
			 s->gc_size == 1 &&
			 s->gc[0] == (unsigned char)sep);
		bool eps_skippable =
			s->type == IMAP_MATCH_NFA_PERCENT ||
			s->type == IMAP_MATCH_NFA_STAR;
		bool next_sep_accept =
			(unsigned int)(i + 1) < count ?
			pat->states[i + 1].sep_accept : FALSE;

		pat->states[i].sep_accept =
			consume_sep || (eps_skippable && next_sep_accept);
	}
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
	size_t glob_alloc_size =
		MALLOC_ADD(sizeof(struct imap_match_glob), patterns_data_len);
	glob = p_malloc(pool, glob_alloc_size);
	glob->pool = pool;
	glob->sep = separator;

	/* copy pattern strings to our allocated memory and compile NFA */
	for (i = 0, pos = 0; i < patterns_count; i++) {
		len = strlen(match_patterns[i].pattern) + 1;
		i_assert(pos + len <= patterns_data_len);

		/* @UNSAFE */
		memcpy(glob->patterns_data + pos,
		       match_patterns[i].pattern, len);
		match_patterns[i].pattern = glob->patterns_data + pos;
		pos += len;

		imap_match_compile(pool, &match_patterns[i], separator);
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

void imap_match_deinit(struct imap_match_glob **_glob)
{
	struct imap_match_glob *glob = *_glob;

	if (glob == NULL)
		return;
	*_glob = NULL;

	struct imap_match_pattern *p;
	for (p = glob->patterns; p->pattern != NULL; p++) {
		if (p->states != NULL)
			p_free(glob->pool, p->states);
	}
	p_free(glob->pool, glob->patterns);
	p_free(glob->pool, glob);
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

static bool
literal_matches(const struct imap_match_nfa_state *s,
		const unsigned char *data_gc, size_t data_gc_size,
		bool inboxcase_pos)
{
	if (s->gc_size != data_gc_size)
		return FALSE;
	if (memcmp(s->gc, data_gc, data_gc_size) == 0)
		return TRUE;
	if (data_gc_size != 1)
		return FALSE;
	return inboxcase_pos &&
		i_toupper(data_gc[0]) == i_toupper(s->gc[0]);
}

static void
nfa_eps_close(const struct imap_match_pattern *pat, uint64_t *bits)
{
	/* Linear forward pass: since each state can only epsilon-skip to
	   i+1, one pass suffices to propagate skips through consecutive
	   skippable states. */
	for (unsigned int i = 0; i < pat->n_states; i++) {
		if (!bit64_get(bits, i))
			continue;
		uint8_t t = pat->states[i].type;
		if (t == IMAP_MATCH_NFA_PERCENT || t == IMAP_MATCH_NFA_STAR)
			bit64_set(bits, i + 1);
	}
}

static enum imap_match_result
imap_match_pattern_run(const struct imap_match_pattern *pat,
		       const char *data, char sep, bool inboxcase_pattern)
{
	const char *inboxcase_end = data;

	if (inboxcase_pattern &&
	    strncasecmp(data, inbox, INBOXLEN) == 0 &&
	    (data[INBOXLEN] == '\0' || data[INBOXLEN] == sep)) {
		/* data begins with INBOX/, use case-insensitive comparison
		   for the INBOX portion */
		inboxcase_end += INBOXLEN;
	}

	unsigned int n_bits = pat->n_states + 1;
	unsigned int n_words = (n_bits + 63) / 64;
	enum imap_match_result result = IMAP_MATCH_NO;
	bool parent_flag = FALSE;
	bool data_ends_with_sep = FALSE;

	uint64_t *cur = t_new(uint64_t, n_words);
	uint64_t *next = t_new(uint64_t, n_words);

	/* initial active set: {0} with epsilon closure */
	bit64_set(cur, 0);
	nfa_eps_close(pat, cur);

	struct uni_gc_scanner sc;
	uni_gc_scanner_init(&sc, data, strlen(data));

	while (!uni_gc_scan_at_end(&sc)) {
		size_t gc_size;
		const unsigned char *gc = uni_gc_scan_get(&sc, &gc_size);
		bool gc_is_sep = gc_size == 1 && gc[0] == (unsigned char)sep;
		bool inboxcase_pos = (const char *)gc < inboxcase_end;

		/* PARENT: ACCEPT is reachable here and there is still at least
		   one more hierarchy level of data after this point. */
		if (gc_is_sep && bit64_get(cur, pat->n_states))
			parent_flag = TRUE;

		memset(next, 0, n_words * sizeof(*next));
		for (unsigned int i = 0; i < pat->n_states; i++) {
			if (!bit64_get(cur, i))
				continue;
			const struct imap_match_nfa_state *s =
				&pat->states[i];
			switch (s->type) {
			case IMAP_MATCH_NFA_LITERAL:
				if (literal_matches(s, gc, gc_size,
						    inboxcase_pos))
					bit64_set(next, i + 1);
				break;
			case IMAP_MATCH_NFA_PERCENT:
				if (!gc_is_sep)
					bit64_set(next, i);
				break;
			case IMAP_MATCH_NFA_STAR:
				bit64_set(next, i);
				break;
			}
		}

		uint64_t *tmp = cur; cur = next; next = tmp;
		nfa_eps_close(pat, cur);
		data_ends_with_sep = gc_is_sep;

		(void)uni_gc_scan_shift(&sc);
	}

	if (bit64_get(cur, pat->n_states))
		result = IMAP_MATCH_YES;
	else {
		bool has_nonaccept = FALSE;
		bool has_sep_accept = FALSE;
		for (unsigned int i = 0; i < pat->n_states; i++) {
			if (!bit64_get(cur, i))
				continue;
			has_nonaccept = TRUE;
			if (pat->states[i].sep_accept) {
				has_sep_accept = TRUE;
				break;
			}
		}
		if (has_nonaccept &&
		    (data_ends_with_sep || has_sep_accept))
			result |= IMAP_MATCH_CHILDREN;
		if (parent_flag)
			result |= IMAP_MATCH_PARENT;
	}
	return result;
}

enum imap_match_result
imap_match(struct imap_match_glob *glob, const char *data)
{
	unsigned int i;
	enum imap_match_result ret, match;

	match = IMAP_MATCH_NO;
	for (i = 0; glob->patterns[i].pattern != NULL; i++) {
		T_BEGIN {
			ret = imap_match_pattern_run(&glob->patterns[i], data,
						     glob->sep,
						     glob->patterns[i].inboxcase);
		} T_END;
		if (ret == IMAP_MATCH_YES)
			return IMAP_MATCH_YES;

		match |= ret;
	}

	return match;
}
