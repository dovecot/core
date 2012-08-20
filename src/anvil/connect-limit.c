/* Copyright (c) 2009-2012 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "connect-limit.h"

struct ident_pid {
	/* ident string points to ident_hash keys */
	const char *ident;
	pid_t pid;
	unsigned int refcount;
};

struct connect_limit {
	/* ident => unsigned int refcount */
	HASH_TABLE(char *, void *) ident_hash;
	/* struct ident_pid => struct ident_pid */
	HASH_TABLE(struct ident_pid *, struct ident_pid *) ident_pid_hash;
};

static unsigned int ident_pid_hash(const struct ident_pid *i)
{
	return str_hash(i->ident) ^ i->pid;
}

static int ident_pid_cmp(const struct ident_pid *i1, const struct ident_pid *i2)
{
	if (i1->pid < i2->pid)
		return -1;
	else if (i1->pid > i2->pid)
		return 1;
	else
		return strcmp(i1->ident, i2->ident);
}

struct connect_limit *connect_limit_init(void)
{
	struct connect_limit *limit;

	limit = i_new(struct connect_limit, 1);
	hash_table_create(&limit->ident_hash, default_pool, 0, str_hash, strcmp);
	hash_table_create(&limit->ident_pid_hash, default_pool, 0,
			  ident_pid_hash, ident_pid_cmp);
	return limit;
}

void connect_limit_deinit(struct connect_limit **_limit)
{
	struct connect_limit *limit = *_limit;

	*_limit = NULL;
	hash_table_destroy(&limit->ident_hash);
	hash_table_destroy(&limit->ident_pid_hash);
	i_free(limit);
}

unsigned int connect_limit_lookup(struct connect_limit *limit,
				  const char *ident)
{
	void *value;

	value = hash_table_lookup(limit->ident_hash, ident);
	return POINTER_CAST_TO(value, unsigned int);
}

void connect_limit_connect(struct connect_limit *limit, pid_t pid,
			   const char *ident)
{
	struct ident_pid *i, lookup_i;
	char *key;
	void *value;

	if (!hash_table_lookup_full(limit->ident_hash, ident,
				    &key, &value)) {
		key = i_strdup(ident);
		value = POINTER_CAST(1);
		hash_table_insert(limit->ident_hash, key, value);
	} else {
		value = POINTER_CAST(POINTER_CAST_TO(value, unsigned int) + 1);
		hash_table_update(limit->ident_hash, key, value);
	}

	lookup_i.ident = ident;
	lookup_i.pid = pid;
	i = hash_table_lookup(limit->ident_pid_hash, &lookup_i);
	if (i == NULL) {
		i = i_new(struct ident_pid, 1);
		i->ident = key;
		i->pid = pid;
		i->refcount = 1;
		hash_table_insert(limit->ident_pid_hash, i, i);
	} else {
		i->refcount++;
	}
}

static void
connect_limit_ident_hash_unref(struct connect_limit *limit, const char *ident)
{
	char *key;
	void *value;
	unsigned int new_refcount;

	if (!hash_table_lookup_full(limit->ident_hash, ident, &key, &value))
		i_panic("connect limit hash tables are inconsistent");

	new_refcount = POINTER_CAST_TO(value, unsigned int) - 1;
	if (new_refcount > 0) {
		value = POINTER_CAST(new_refcount);
		hash_table_update(limit->ident_hash, key, value);
	} else {
		hash_table_remove(limit->ident_hash, key);
		i_free(key);
	}
}

void connect_limit_disconnect(struct connect_limit *limit, pid_t pid,
			      const char *ident)
{
	struct ident_pid *i, lookup_i;

	lookup_i.ident = ident;
	lookup_i.pid = pid;

	i = hash_table_lookup(limit->ident_pid_hash, &lookup_i);
	if (i == NULL) {
		i_error("connect limit: disconnection for unknown "
			"pid %s + ident %s", dec2str(pid), ident);
		return;
	}

	if (--i->refcount == 0) {
		hash_table_remove(limit->ident_pid_hash, i);
		i_free(i);
	}

	connect_limit_ident_hash_unref(limit, ident);
}

void connect_limit_disconnect_pid(struct connect_limit *limit, pid_t pid)
{
	struct hash_iterate_context *iter;
	struct ident_pid *i, *value;

	/* this should happen rarely (or never), so this slow implementation
	   should be fine. */
	iter = hash_table_iterate_init(limit->ident_pid_hash);
	while (hash_table_iterate(iter, limit->ident_pid_hash, &i, &value)) {
		if (i->pid == pid) {
			hash_table_remove(limit->ident_pid_hash, i);
			for (; i->refcount > 0; i->refcount--)
				connect_limit_ident_hash_unref(limit, i->ident);
			i_free(i);
		}
	}
	hash_table_iterate_deinit(&iter);
}

void connect_limit_dump(struct connect_limit *limit, struct ostream *output)
{
	struct hash_iterate_context *iter;
	struct ident_pid *i, *value;
	string_t *str = t_str_new(256);

	iter = hash_table_iterate_init(limit->ident_pid_hash);
	while (hash_table_iterate(iter, limit->ident_pid_hash, &i, &value)) {
		str_truncate(str, 0);
		str_tabescape_write(str, i->ident);
		str_printfa(str, "\t%ld\t%u\n", (long)i->pid, i->refcount);
		if (o_stream_send(output, str_data(str), str_len(str)) < 0)
			break;
	}
	hash_table_iterate_deinit(&iter);
	o_stream_nsend(output, "\n", 1);
}
