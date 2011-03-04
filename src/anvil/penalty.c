/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "llist.h"
#include "ostream.h"
#include "penalty.h"

#include <time.h>

#define PENALTY_DEFAULT_EXPIRE_SECS (60*60)
#define PENALTY_CHECKSUM_SAVE_COUNT
#define CHECKSUM_VALUE_COUNT 2
#define CHECKSUM_VALUE_PTR_COUNT 10

#define LAST_UPDATE_BITS 15

struct penalty_rec {
	/* ordered by last_update */
	struct penalty_rec *prev, *next;

	char *ident;
	unsigned int last_penalty;

	unsigned int penalty:16;
	unsigned int last_update:LAST_UPDATE_BITS; /* last_penalty + n */
	unsigned int checksum_is_pointer:1;
	/* we use value up to two different checksums.
	   after that switch to pointer. */
	union {
		unsigned int value[CHECKSUM_VALUE_COUNT];
		unsigned int *value_ptr;
	} checksum;
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
	if (rec->checksum_is_pointer)
		i_free(rec->checksum.value_ptr);
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

static bool
penalty_bump_checksum(struct penalty_rec *rec, unsigned int checksum)
{
	unsigned int *checksums;
	unsigned int i, count;

	if (!rec->checksum_is_pointer) {
		checksums = rec->checksum.value;
		count = CHECKSUM_VALUE_COUNT;
	} else {
		checksums = rec->checksum.value_ptr;
		count = CHECKSUM_VALUE_PTR_COUNT;
	}

	for (i = 0; i < count; i++) {
		if (checksums[i] == checksum) {
			if (i > 0) {
				memcpy(checksums + 1, checksums,
				       sizeof(checksums[0]) * i);
				checksums[0] = checksum;
			}
			return TRUE;
		}
	}
	return FALSE;
}

static void penalty_add_checksum(struct penalty_rec *rec, unsigned int checksum)
{
	unsigned int *checksums;

	i_assert(checksum != 0);

	if (!rec->checksum_is_pointer) {
		if (rec->checksum.value[CHECKSUM_VALUE_COUNT-1] == 0) {
			memcpy(rec->checksum.value + 1, rec->checksum.value,
			       sizeof(rec->checksum.value[0]) *
			       (CHECKSUM_VALUE_COUNT-1));
			rec->checksum.value[0] = checksum;
			return;
		}

		/* switch to using a pointer */
		checksums = i_new(unsigned int, CHECKSUM_VALUE_PTR_COUNT);
		memcpy(checksums, rec->checksum.value,
		       sizeof(checksums[0]) * CHECKSUM_VALUE_COUNT);
		rec->checksum.value_ptr = checksums;
		rec->checksum_is_pointer = TRUE;
	}

	memcpy(rec->checksum.value_ptr + 1, rec->checksum.value_ptr,
	       sizeof(rec->checksum.value_ptr[0]) *
	       (CHECKSUM_VALUE_PTR_COUNT-1));
	rec->checksum.value_ptr[0] = checksum;
}

unsigned int penalty_get(struct penalty *penalty, const char *ident,
			 time_t *last_penalty_r)
{
	struct penalty_rec *rec;

	rec = hash_table_lookup(penalty->hash, ident);
	if (rec == NULL) {
		*last_penalty_r = 0;
		return 0;
	}

	*last_penalty_r = rec->last_penalty;
	return rec->penalty;
}

static void penalty_timeout(struct penalty *penalty)
{
	struct penalty_rec *rec;
	time_t rec_last_update, expire_time;
	unsigned int diff;

	timeout_remove(&penalty->to);

	expire_time = ioloop_time - penalty->expire_secs;
	while (penalty->oldest != NULL) {
		rec = penalty->oldest;

		rec_last_update = rec->last_penalty + rec->last_update;
		if (rec_last_update > expire_time) {
			diff = rec_last_update - expire_time;
			penalty->to = timeout_add(diff * 1000,
						  penalty_timeout, penalty);
			break;
		}
		hash_table_remove(penalty->hash, rec->ident);
		penalty_rec_free(penalty, rec);
	}
}

void penalty_inc(struct penalty *penalty, const char *ident,
		 unsigned int checksum, unsigned int value)
{
	struct penalty_rec *rec;
	time_t diff;

	i_assert(value > 0 || checksum == 0);
	i_assert(value <= INT_MAX);

	rec = hash_table_lookup(penalty->hash, ident);
	if (rec == NULL) {
		rec = i_new(struct penalty_rec, 1);
		rec->ident = i_strdup(ident);
		hash_table_insert(penalty->hash, rec->ident, rec);
	} else {
		DLLIST2_REMOVE(&penalty->oldest, &penalty->newest, rec);
	}

	if (checksum == 0) {
		rec->penalty = value;
		rec->last_penalty = ioloop_time;
	} else {
		if (penalty_bump_checksum(rec, checksum))
			rec->penalty = value - 1;
		else {
			penalty_add_checksum(rec, checksum);
			rec->penalty = value;
			rec->last_penalty = ioloop_time;
		}
	}

	diff = ioloop_time - rec->last_penalty;
	if (diff >= (1 << LAST_UPDATE_BITS)) {
		rec->last_update = (1 << LAST_UPDATE_BITS) - 1;
		rec->last_penalty = ioloop_time - rec->last_update;
	} else {
		rec->last_update = diff;
	}

	DLLIST2_APPEND(&penalty->oldest, &penalty->newest, rec);

	if (penalty->to == NULL) {
		penalty->to = timeout_add(penalty->expire_secs * 1000,
					  penalty_timeout, penalty);
	}
}

bool penalty_has_checksum(struct penalty *penalty, const char *ident,
			  unsigned int checksum)
{
	struct penalty_rec *rec;
	const unsigned int *checksums;
	unsigned int i, count;

	rec = hash_table_lookup(penalty->hash, ident);
	if (rec == NULL)
		return FALSE;

	if (!rec->checksum_is_pointer) {
		checksums = rec->checksum.value;
		count = CHECKSUM_VALUE_COUNT;
	} else {
		checksums = rec->checksum.value_ptr;
		count = CHECKSUM_VALUE_PTR_COUNT;
	}

	for (i = 0; i < count; i++) {
		if (checksums[i] == checksum)
			return TRUE;
	}
	return FALSE;
}

void penalty_dump(struct penalty *penalty, struct ostream *output)
{
	const struct penalty_rec *rec;
	string_t *str = t_str_new(256);

	for (rec = penalty->oldest; rec != NULL; rec = rec->next) {
		str_truncate(str, 0);
		str_tabescape_write(str, rec->ident);
		str_printfa(str, "\t%u\t%u\t%u\n",
			    rec->penalty, rec->last_penalty,
			    rec->last_penalty + rec->last_update);
		if (o_stream_send(output, str_data(str), str_len(str)) < 0)
			break;
	}
	(void)o_stream_send(output, "\n", 1);
}
