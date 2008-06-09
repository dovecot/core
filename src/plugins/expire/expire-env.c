/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imap-match.h"
#include "expire-env.h"

#include <stdlib.h>

enum expire_type {
	EXPIRE_TYPE_EXPUNGE,
	EXPIRE_TYPE_ALTMOVE
};

struct expire_box {
	const char *pattern;
	struct imap_match_glob *glob;

	enum expire_type type;
	unsigned int expire_secs;
};

struct expire_env {
	pool_t pool;
	ARRAY_DEFINE(expire_boxes, struct expire_box);
};

static void expire_env_parse(struct expire_env *env, const char *str,
			     enum expire_type type)
{
	struct expire_box box;
	char *const *names;
	unsigned int len;

	if (str == NULL)
		return;

	names = p_strsplit(env->pool, str, " ");
	len = str_array_length((const char *const *)names);

	p_array_init(&env->expire_boxes, env->pool, len / 2);
	for (; *names != NULL; names += 2) {
		if (names[1] == NULL) {
			i_fatal("expire: Missing expire days for mailbox '%s'",
				*names);
		}

		box.pattern = *names;
		/* FIXME: hardcoded separator isn't very good */
		box.glob = imap_match_init(env->pool, box.pattern, TRUE, '/');
		box.type = type;
		box.expire_secs = strtoul(names[1], NULL, 10) * 3600 * 24;

		array_append(&env->expire_boxes, &box, 1);
	}
}

struct expire_env *expire_env_init(const char *expunges, const char *altmoves)
{
	struct expire_env *env;
	pool_t pool;

	pool = pool_alloconly_create("Expire pool", 512);
	env = p_new(pool, struct expire_env, 1);
	env->pool = pool;

	expire_env_parse(env, expunges, EXPIRE_TYPE_EXPUNGE);
	expire_env_parse(env, altmoves, EXPIRE_TYPE_ALTMOVE);
	return env;
}

void expire_env_deinit(struct expire_env *env)
{
	pool_unref(&env->pool);
}

bool expire_box_find(struct expire_env *env, const char *name,
		     unsigned int *expunge_secs_r,
		     unsigned int *altmove_secs_r)
{
	const struct expire_box *expire_boxes;
	unsigned int i, count;
	unsigned int secs, expunge_min = 0, altmove_min = 0;

	expire_boxes = array_get(&env->expire_boxes, &count);
	for (i = 0; i < count; i++) {
		if (imap_match(expire_boxes[i].glob, name) == IMAP_MATCH_YES) {
			secs = expire_boxes[i].expire_secs;
			i_assert(secs > 0);

			switch (expire_boxes[i].type) {
			case EXPIRE_TYPE_EXPUNGE:
				if (expunge_min == 0 || expunge_min > secs)
					expunge_min = secs;
				break;
			case EXPIRE_TYPE_ALTMOVE:
				if (altmove_min == 0 || altmove_min > secs)
					altmove_min = secs;
				break;
			}
		}
	}
	*expunge_secs_r = expunge_min;
	*altmove_secs_r = altmove_min;
	return expunge_min > 0 || altmove_min > 0;
}

unsigned int expire_box_find_min_secs(struct expire_env *env, const char *name,
				      bool *altmove_r)
{
	unsigned int secs1, secs2;

	(void)expire_box_find(env, name, &secs1, &secs2);
	if (secs1 != 0 && (secs1 < secs2 || secs2 == 0)) {
		*altmove_r = FALSE;
		return secs1;
	} else {
		*altmove_r = TRUE;
		return secs2;
	}
}
