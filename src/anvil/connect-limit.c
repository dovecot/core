/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "connect-limit.h"

struct userip {
	char *username;
	char *service;
	struct ip_addr ip;
};

struct ident_pid {
	/* points to userip_hash keys */
	struct userip *userip;
	pid_t pid;
	unsigned int refcount;
};

struct connect_limit {
	/* userip => unsigned int refcount */
	HASH_TABLE(struct userip *, void *) userip_hash;
	/* (userip, pid) => struct ident_pid */
	HASH_TABLE(struct ident_pid *, struct ident_pid *) ident_pid_hash;
};

static unsigned int userip_hash(const struct userip *userip)
{
	return str_hash(userip->username) ^ str_hash(userip->service) ^
		net_ip_hash(&userip->ip);
}

static int userip_cmp(const struct userip *userip1,
		      const struct userip *userip2)
{
	int ret = strcmp(userip1->username, userip2->username);
	if (ret != 0)
		return ret;
	ret = net_ip_cmp(&userip1->ip, &userip2->ip);
	if (ret != 0)
		return ret;
	return strcmp(userip1->service, userip2->service);
}

static unsigned int ident_pid_hash(const struct ident_pid *i)
{
	return userip_hash(i->userip) ^ i->pid;
}

static int ident_pid_cmp(const struct ident_pid *i1, const struct ident_pid *i2)
{
	if (i1->pid < i2->pid)
		return -1;
	else if (i1->pid > i2->pid)
		return 1;
	else
		return userip_cmp(i1->userip, i2->userip);
}

struct connect_limit *connect_limit_init(void)
{
	struct connect_limit *limit;

	limit = i_new(struct connect_limit, 1);
	hash_table_create(&limit->userip_hash, default_pool, 0,
			  userip_hash, userip_cmp);
	hash_table_create(&limit->ident_pid_hash, default_pool, 0,
			  ident_pid_hash, ident_pid_cmp);
	return limit;
}

void connect_limit_deinit(struct connect_limit **_limit)
{
	struct connect_limit *limit = *_limit;

	*_limit = NULL;
	hash_table_destroy(&limit->userip_hash);
	hash_table_destroy(&limit->ident_pid_hash);
	i_free(limit);
}

unsigned int connect_limit_lookup(struct connect_limit *limit,
				  const struct connect_limit_key *key)
{
	struct userip userip_lookup = {
		.username = (char *)key->username,
		.service = (char *)key->service,
		.ip = key->ip,
	};
	void *value;

	value = hash_table_lookup(limit->userip_hash, &userip_lookup);
	return POINTER_CAST_TO(value, unsigned int);
}

void connect_limit_connect(struct connect_limit *limit, pid_t pid,
			   const struct connect_limit_key *key)
{
	struct ident_pid *i, lookup_i;
	struct userip *userip;
	void *value;

	struct userip userip_lookup = {
		.username = (char *)key->username,
		.service = (char *)key->service,
		.ip = key->ip,
	};
	if (!hash_table_lookup_full(limit->userip_hash, &userip_lookup,
				    &userip, &value)) {
		userip = i_new(struct userip, 1);
		userip->username = i_strdup(key->username);
		userip->service = i_strdup(key->service);
		userip->ip = key->ip;
		value = POINTER_CAST(1);
		hash_table_insert(limit->userip_hash, userip, value);
	} else {
		value = POINTER_CAST(POINTER_CAST_TO(value, unsigned int) + 1);
		hash_table_update(limit->userip_hash, userip, value);
	}

	lookup_i.userip = userip;
	lookup_i.pid = pid;
	i = hash_table_lookup(limit->ident_pid_hash, &lookup_i);
	if (i == NULL) {
		i = i_new(struct ident_pid, 1);
		i->userip = userip;
		i->pid = pid;
		i->refcount = 1;
		hash_table_insert(limit->ident_pid_hash, i, i);
	} else {
		i->refcount++;
	}
}

static void
userip_hash_unref(struct connect_limit *limit,
		  const struct userip *userip_lookup)
{
	struct userip *userip;
	void *value;
	unsigned int new_refcount;

	if (!hash_table_lookup_full(limit->userip_hash,
				    userip_lookup, &userip, &value))
		i_panic("connect limit hash tables are inconsistent");

	new_refcount = POINTER_CAST_TO(value, unsigned int) - 1;
	if (new_refcount > 0) {
		value = POINTER_CAST(new_refcount);
		hash_table_update(limit->userip_hash, userip, value);
	} else {
		hash_table_remove(limit->userip_hash, userip);
		i_free(userip->username);
		i_free(userip->service);
		i_free(userip);
	}
}

void connect_limit_disconnect(struct connect_limit *limit, pid_t pid,
			      const struct connect_limit_key *key)
{
	struct ident_pid *i, lookup_i;
	struct userip userip_lookup = {
		.username = (char *)key->username,
		.service = (char *)key->service,
		.ip = key->ip,
	};

	lookup_i.userip = &userip_lookup;
	lookup_i.pid = pid;

	i = hash_table_lookup(limit->ident_pid_hash, &lookup_i);
	if (i == NULL) {
		i_error("connect limit: disconnection for unknown "
			"(pid=%s, user=%s, service=%s, ip=%s)",
			dec2str(pid), key->username, key->service,
			net_ip2addr(&key->ip));
		return;
	}

	if (--i->refcount == 0) {
		hash_table_remove(limit->ident_pid_hash, i);
		i_free(i);
	}

	userip_hash_unref(limit, &userip_lookup);
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
				userip_hash_unref(limit, i->userip);
			i_free(i);
		}
	}
	hash_table_iterate_deinit(&iter);
}

void connect_limit_dump(struct connect_limit *limit, struct ostream *output)
{
	struct hash_iterate_context *iter;
	struct ident_pid *i, *value;
	string_t *str = str_new(default_pool, 256);
	ssize_t ret = 0;

	iter = hash_table_iterate_init(limit->ident_pid_hash);
	while (ret >= 0 &&
	       hash_table_iterate(iter, limit->ident_pid_hash, &i, &value)) T_BEGIN {
		str_truncate(str, 0);
		str_append_tabescaped(str, i->userip->service);
		if (i->userip->ip.family != 0) {
			str_append_c(str, '/');
			str_append(str, net_ip2addr(&i->userip->ip));
		}
		str_append_c(str, '/');
		str_append_tabescaped(str, i->userip->username);
		str_printfa(str, "\t%ld\t%u\n", (long)i->pid, i->refcount);
		ret = o_stream_send(output, str_data(str), str_len(str));
	} T_END;
	hash_table_iterate_deinit(&iter);
	o_stream_nsend(output, "\n", 1);
	str_free(&str);
}
