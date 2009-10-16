/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
#include "hash.h"
#include "login-proxy-state.h"

struct login_proxy_state {
	struct hash_table *hash;
	pool_t pool;
};

static unsigned int login_proxy_record_hash(const void *p)
{
	const struct login_proxy_record *rec = p;

	return net_ip_hash(&rec->ip) ^ rec->port;
}

static int login_proxy_record_cmp(const void *p1, const void *p2)
{
	const struct login_proxy_record *rec1 = p1, *rec2 = p2;

	if (!net_ip_compare(&rec1->ip, &rec2->ip))
		return 1;

	return (int)rec1->port - (int)rec2->port;
}

struct login_proxy_state *login_proxy_state_init(void)
{
	struct login_proxy_state *state;

	state = i_new(struct login_proxy_state, 1);
	state->pool = pool_alloconly_create("login proxy state", 1024);
	state->hash = hash_table_create(default_pool, state->pool, 0,
					login_proxy_record_hash,
					login_proxy_record_cmp);
	return state;
}

void login_proxy_state_deinit(struct login_proxy_state **_state)
{
	struct login_proxy_state *state = *_state;

	*_state = NULL;
	hash_table_destroy(&state->hash);
	pool_unref(&state->pool);
	i_free(state);
}

struct login_proxy_record *
login_proxy_state_get(struct login_proxy_state *state,
		      const struct ip_addr *ip, unsigned int port)
{
	struct login_proxy_record *rec, key;

	memset(&key, 0, sizeof(key));
	key.ip = *ip;
	key.port = port;

	rec = hash_table_lookup(state->hash, &key);
	if (rec == NULL) {
		rec = p_new(state->pool, struct login_proxy_record, 1);
		rec->ip = *ip;
		rec->port = port;
		hash_table_insert(state->hash, rec, rec);
	}
	return rec;
}
