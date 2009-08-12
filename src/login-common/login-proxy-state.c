/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
#include "hash.h"
#include "login-proxy-state.h"

struct login_proxy_state {
	struct hash_table *hash;
	pool_t pool;
};

static unsigned int ip_addr_hash(const void *p)
{
	const struct ip_addr *ip = p;

	return net_ip_hash(ip);
}

static int ip_addr_cmp(const void *p1, const void *p2)
{
	const struct ip_addr *ip1 = p1, *ip2 = p2;

	return net_ip_compare(ip1, ip2) ? 0 : 1;
}

struct login_proxy_state *login_proxy_state_init(void)
{
	struct login_proxy_state *state;

	state = i_new(struct login_proxy_state, 1);
	state->pool = pool_alloconly_create("login proxy state", 1024);
	state->hash = hash_table_create(default_pool, state->pool, 0,
					ip_addr_hash, ip_addr_cmp);
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
		      const struct ip_addr *ip)
{
	struct login_proxy_record *rec;
	struct ip_addr *new_ip;

	rec = hash_table_lookup(state->hash, ip);
	if (rec == NULL) {
		new_ip = p_new(state->pool, struct ip_addr, 1);
		*new_ip = *ip;

		rec = p_new(state->pool, struct login_proxy_record, 1);
		hash_table_insert(state->hash, new_ip, rec);
	}
	return rec;
}
