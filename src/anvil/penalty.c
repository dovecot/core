/* Copyright (C) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "llist.h"
#include "penalty.h"

#include <time.h>

#define PENALTY_DEFAULT_EXPIRE_SECS (60*60)

struct penalty_rec {
	/* ordered by last_update */
	struct penalty_rec *prev, *next;

	char *ident;
	unsigned int penalty;
	time_t last_update;
};

struct penalty {
	/* ident => penalty_rec */
	struct hash_table *hash;
	struct penalty_rec *oldest, *newest;

	unsigned int expire_secs;
	struct timeout *to;
};

struct penalty *penalty_init(void)
{
	struct penalty *penalty;

	penalty = i_new(struct penalty, 1);
	penalty->hash =
		hash_table_create(default_pool, default_pool, 0,
				  str_hash, (hash_cmp_callback_t *)strcmp);
	penalty->expire_secs = PENALTY_DEFAULT_EXPIRE_SECS;
	return penalty;
}

static void penalty_rec_free(struct penalty *penalty, struct penalty_rec *rec)
{
	DLLIST2_REMOVE(&penalty->oldest, &penalty->newest, rec);
	i_free(rec->ident);
	i_free(rec);
}

void penalty_deinit(struct penalty **_penalty)
{
	struct penalty *penalty = *_penalty;

	*_penalty = NULL;

	while (penalty->oldest != NULL)
		penalty_rec_free(penalty, penalty->oldest);
	hash_table_destroy(&penalty->hash);

	if (penalty->to != NULL)
		timeout_remove(&penalty->to);
	i_free(penalty);
}

void penalty_set_expire_secs(struct penalty *penalty, unsigned int expire_secs)
{
	penalty->expire_secs = expire_secs;
}

unsigned int penalty_get(struct penalty *penalty, const char *ident,
			 time_t *last_update_r)
{
	struct penalty_rec *rec;

	rec = hash_table_lookup(penalty->hash, ident);
	if (rec == NULL) {
		*last_update_r = 0;
		return 0;
	} else {
		*last_update_r = rec->last_update;
		return rec->penalty;
	}
}

static void penalty_timeout(struct penalty *penalty)
{
	time_t expire_time;

	expire_time = ioloop_time - penalty->expire_secs;
	while (penalty->oldest != NULL &&
	       penalty->oldest->last_update <= expire_time) {
		hash_table_remove(penalty->hash, penalty->oldest->ident);
		penalty_rec_free(penalty, penalty->oldest);
	}

	timeout_remove(&penalty->to);
	if (penalty->oldest != NULL) {
		unsigned int diff = penalty->oldest->last_update - expire_time;
		penalty->to = timeout_add(diff * 1000,
					  penalty_timeout, penalty);
	}
}

void penalty_set(struct penalty *penalty, const char *ident,
		 unsigned int value)
{
	struct penalty_rec *rec;

	rec = hash_table_lookup(penalty->hash, ident);
	if (rec == NULL) {
		rec = i_new(struct penalty_rec, 1);
		rec->ident = i_strdup(ident);
		hash_table_insert(penalty->hash, rec->ident, rec);
	} else {
		DLLIST2_REMOVE(&penalty->oldest, &penalty->newest, rec);
	}
	rec->penalty = value;
	rec->last_update = time(NULL);
	DLLIST2_APPEND(&penalty->oldest, &penalty->newest, rec);

	if (penalty->to == NULL) {
		penalty->to = timeout_add(penalty->expire_secs * 1000,
					  penalty_timeout, penalty);
	}
}
