/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imap-match.h"
#include "expire-set.h"


struct expire_set {
	pool_t pool;
	ARRAY(struct imap_match_glob *) globs;
};

struct expire_set *expire_set_init(const char *const *patterns)
{
	struct expire_set *set;
	struct imap_match_glob *glob;
	const char *const *pattern;
	pool_t pool;

	pool = pool_alloconly_create("Expire pool", 512);
	set = p_new(pool, struct expire_set, 1);
	set->pool = pool;
	p_array_init(&set->globs, set->pool, 16);

	for (pattern = patterns; *pattern != NULL; pattern++) {
		glob = imap_match_init(set->pool, *pattern, TRUE, '/');
		array_push_back(&set->globs, &glob);
	}
	return set;
}

void expire_set_deinit(struct expire_set **_set)
{
	struct expire_set *set = *_set;

	*_set = NULL;
	pool_unref(&set->pool);
}

bool expire_set_lookup(struct expire_set *set, const char *mailbox)
{
	struct imap_match_glob *const *globp;

	array_foreach(&set->globs, globp) {
		if (imap_match(*globp, mailbox) == IMAP_MATCH_YES)
			return TRUE;
	}
	return FALSE;
}
