/* Copyright (C) 2006 PT.COM / SAPO. Code by Timo Sirainen. */

#include "lib.h"
#include "array.h"
#include "expire-env.h"

#include <stdlib.h>

struct expire_env {
	pool_t pool;
	ARRAY_DEFINE(expire_boxes, struct expire_box);
};

struct expire_env *expire_env_init(const char *str)
{
	struct expire_env *env;
	struct expire_box box;
	pool_t pool;
	char *const *names;
	unsigned int len;

	pool = pool_alloconly_create("Expire pool", 512);
	env = p_new(pool, struct expire_env, 1);
	env->pool = pool;

	names = p_strsplit(pool, str, " ");
	len = str_array_length((const char *const *)names);

	p_array_init(&env->expire_boxes, pool, len / 2);
	for (; *names != NULL; names += 2) {
		if (names[1] == NULL) {
			i_fatal("expire: Missing expire days for mailbox '%s'",
				*names);
		}

		box.name = *names;
		box.expire_secs = strtoul(names[1], NULL, 10) * 3600 * 24;
		array_append(&env->expire_boxes, &box, 1);
	}

	return env;
}

void expire_env_deinit(struct expire_env *env)
{
	pool_unref(&env->pool);
}

const struct expire_box *expire_box_find(struct expire_env *env,
					 const char *name)
{
	const struct expire_box *expire_boxes;
	unsigned int i, count;

	expire_boxes = array_get(&env->expire_boxes, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(name, expire_boxes[i].name) == 0)
			return &expire_boxes[i];
	}
	return NULL;
}
