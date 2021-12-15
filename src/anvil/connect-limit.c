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

struct session {
	/* points to userip_hash keys */
	struct userip *userip;
	pid_t pid;
	unsigned int refcount;
};

struct connect_limit {
	/* userip => unsigned int refcount */
	HASH_TABLE(struct userip *, void *) userip_hash;
	/* (userip, pid) => struct session */
	HASH_TABLE(struct session *, struct session *) session_hash;
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

static unsigned int session_hash(const struct session *session)
{
	return userip_hash(session->userip) ^ session->pid;
}

static int session_cmp(const struct session *session1,
		       const struct session *session2)
{
	if (session1->pid < session2->pid)
		return -1;
	else if (session1->pid > session2->pid)
		return 1;
	else
		return userip_cmp(session1->userip, session2->userip);
}

struct connect_limit *connect_limit_init(void)
{
	struct connect_limit *limit;

	limit = i_new(struct connect_limit, 1);
	hash_table_create(&limit->userip_hash, default_pool, 0,
			  userip_hash, userip_cmp);
	hash_table_create(&limit->session_hash, default_pool, 0,
			  session_hash, session_cmp);
	return limit;
}

void connect_limit_deinit(struct connect_limit **_limit)
{
	struct connect_limit *limit = *_limit;

	*_limit = NULL;
	hash_table_destroy(&limit->userip_hash);
	hash_table_destroy(&limit->session_hash);
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
	struct session *session;
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

	struct session session_lookup = {
		.userip = userip,
		.pid = pid,
	};
	session = hash_table_lookup(limit->session_hash, &session_lookup);
	if (session == NULL) {
		session = i_new(struct session, 1);
		session->userip = userip;
		session->pid = pid;
		session->refcount = 1;
		hash_table_insert(limit->session_hash, session, session);
	} else {
		session->refcount++;
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
	struct session *session;
	struct userip userip_lookup = {
		.username = (char *)key->username,
		.service = (char *)key->service,
		.ip = key->ip,
	};

	struct session session_lookup = {
		.userip = &userip_lookup,
		.pid = pid,
	};

	session = hash_table_lookup(limit->session_hash, &session_lookup);
	if (session == NULL) {
		i_error("connect limit: disconnection for unknown "
			"(pid=%s, user=%s, service=%s, ip=%s)",
			dec2str(pid), key->username, key->service,
			net_ip2addr(&key->ip));
		return;
	}

	if (--session->refcount == 0) {
		hash_table_remove(limit->session_hash, session);
		i_free(session);
	}

	userip_hash_unref(limit, &userip_lookup);
}

void connect_limit_disconnect_pid(struct connect_limit *limit, pid_t pid)
{
	struct hash_iterate_context *iter;
	struct session *session, *value;

	/* this should happen rarely (or never), so this slow implementation
	   should be fine. */
	iter = hash_table_iterate_init(limit->session_hash);
	while (hash_table_iterate(iter, limit->session_hash, &session, &value)) {
		if (session->pid == pid) {
			hash_table_remove(limit->session_hash, session);
			for (; session->refcount > 0; session->refcount--)
				userip_hash_unref(limit, session->userip);
			i_free(session);
		}
	}
	hash_table_iterate_deinit(&iter);
}

void connect_limit_dump(struct connect_limit *limit, struct ostream *output)
{
	struct hash_iterate_context *iter;
	struct session *session, *value;
	string_t *str = str_new(default_pool, 256);
	ssize_t ret = 0;

	iter = hash_table_iterate_init(limit->session_hash);
	while (ret >= 0 &&
	       hash_table_iterate(iter, limit->session_hash, &session, &value)) T_BEGIN {
		str_truncate(str, 0);
		str_append_tabescaped(str, session->userip->service);
		if (session->userip->ip.family != 0) {
			str_append_c(str, '/');
			str_append(str, net_ip2addr(&session->userip->ip));
		}
		str_append_c(str, '/');
		str_append_tabescaped(str, session->userip->username);
		str_printfa(str, "\t%ld\t%u\n", (long)session->pid,
			    session->refcount);
		ret = o_stream_send(output, str_data(str), str_len(str));
	} T_END;
	hash_table_iterate_deinit(&iter);
	o_stream_nsend(output, "\n", 1);
	str_free(&str);
}
