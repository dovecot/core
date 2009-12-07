/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imap-match.h"
#include "mail-namespace.h"
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

static void
expire_env_parse(struct expire_env *env, struct mail_namespace *namespaces,
		 const char *str, enum expire_type type)
{
	struct expire_box box;
	struct mail_namespace *ns;
	char *const *names;
	const char *ns_name;
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
		ns_name = *names;
		ns = mail_namespace_find(namespaces, &ns_name);
		if (ns == NULL && *box.pattern != '*') {
			i_warning("expire: No namespace found for mailbox: %s",
				  box.pattern);
		}

		box.glob = imap_match_init(env->pool, box.pattern, TRUE,
					   ns == NULL ? '/' : ns->sep);
		box.type = type;
		box.expire_secs = strtoul(names[1], NULL, 10) * 3600 * 24;

		if (namespaces->user->mail_debug) {
			i_info("expire: pattern=%s type=%s secs=%u",
			       box.pattern, type == EXPIRE_TYPE_EXPUNGE ?
			       "expunge" : "altmove", box.expire_secs);
		}

		array_append(&env->expire_boxes, &box, 1);
	}
}

struct expire_env *expire_env_init(struct mail_namespace *namespaces,
				   const char *expunges, const char *altmoves)
{
	struct expire_env *env;
	pool_t pool;

	pool = pool_alloconly_create("Expire pool", 512);
	env = p_new(pool, struct expire_env, 1);
	env->pool = pool;

	expire_env_parse(env, namespaces, expunges, EXPIRE_TYPE_EXPUNGE);
	expire_env_parse(env, namespaces, altmoves, EXPIRE_TYPE_ALTMOVE);
	return env;
}

void expire_env_deinit(struct expire_env **_env)
{
	struct expire_env *env = *_env;

	*_env = NULL;
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
