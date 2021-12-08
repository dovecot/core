/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "hash.h"
#include "llist.h"
#include "str.h"
#include "str-table.h"
#include "strescape.h"
#include "ostream.h"
#include "connect-limit.h"

struct process {
	pid_t pid;
	struct session *sessions;
};

struct userip {
	char *username;
	const char *service;
	struct ip_addr ip;
};

struct session {
	/* process->sessions linked list */
	struct session *process_prev, *process_next;

	/* points to userip_hash keys */
	struct userip *userip;
	struct process *process;
	guid_128_t conn_guid;
	unsigned int refcount;
};

struct connect_limit {
	struct str_table *strings;

	/* userip => unsigned int refcount */
	HASH_TABLE(struct userip *, void *) userip_hash;
	/* (userip, pid) => struct session */
	HASH_TABLE(struct session *, struct session *) session_hash;
	/* pid_t => struct process */
	HASH_TABLE(void *, struct process *) process_hash;
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
	return userip_hash(session->userip) ^
		guid_128_hash(session->conn_guid) ^ session->process->pid;
}

static int session_cmp(const struct session *session1,
		       const struct session *session2)
{
	/* conn-guids should be unique, but only if they're not empty */
	int ret = guid_128_cmp(session1->conn_guid, session2->conn_guid);
	if (ret != 0)
		return ret;

	if (session1->process->pid < session2->process->pid)
		return -1;
	else if (session1->process->pid > session2->process->pid)
		return 1;
	else
		return userip_cmp(session1->userip, session2->userip);
}

struct connect_limit *connect_limit_init(void)
{
	struct connect_limit *limit;

	limit = i_new(struct connect_limit, 1);
	limit->strings = str_table_init();
	hash_table_create(&limit->userip_hash, default_pool, 0,
			  userip_hash, userip_cmp);
	hash_table_create(&limit->session_hash, default_pool, 0,
			  session_hash, session_cmp);
	hash_table_create_direct(&limit->process_hash, default_pool, 0);
	return limit;
}

void connect_limit_deinit(struct connect_limit **_limit)
{
	struct connect_limit *limit = *_limit;

	*_limit = NULL;
	hash_table_destroy(&limit->userip_hash);
	hash_table_destroy(&limit->session_hash);
	hash_table_destroy(&limit->process_hash);
	str_table_deinit(&limit->strings);
	i_free(limit);
}

unsigned int connect_limit_lookup(struct connect_limit *limit,
				  const struct connect_limit_key *key)
{
	struct userip userip_lookup = {
		.username = (char *)key->username,
		.service = key->service,
		.ip = key->ip,
	};
	void *value;

	value = hash_table_lookup(limit->userip_hash, &userip_lookup);
	return POINTER_CAST_TO(value, unsigned int);
}

static struct process *process_lookup(struct connect_limit *limit, pid_t pid)
{
	return hash_table_lookup(limit->process_hash, POINTER_CAST(pid));
}

static struct process *process_get(struct connect_limit *limit, pid_t pid)
{
	struct process *process;

	process = process_lookup(limit, pid);
	if (process == NULL) {
		process = i_new(struct process, 1);
		process->pid = pid;
		hash_table_insert(limit->process_hash,
				  POINTER_CAST(pid), process);
	}
	return process;
}

void connect_limit_connect(struct connect_limit *limit, pid_t pid,
			   const struct connect_limit_key *key,
			   const guid_128_t conn_guid)
{
	struct session *session;
	struct userip *userip;
	void *value;

	struct userip userip_lookup = {
		.username = (char *)key->username,
		.service = key->service,
		.ip = key->ip,
	};
	if (!hash_table_lookup_full(limit->userip_hash, &userip_lookup,
				    &userip, &value)) {
		userip = i_new(struct userip, 1);
		userip->username = i_strdup(key->username);
		userip->service = str_table_ref(limit->strings, key->service);
		userip->ip = key->ip;
		value = POINTER_CAST(1);
		hash_table_insert(limit->userip_hash, userip, value);
	} else {
		value = POINTER_CAST(POINTER_CAST_TO(value, unsigned int) + 1);
		hash_table_update(limit->userip_hash, userip, value);
	}

	struct session session_lookup = {
		.userip = userip,
		.process = process_get(limit, pid),
	};
	guid_128_copy(session_lookup.conn_guid, conn_guid);
	session = hash_table_lookup(limit->session_hash, &session_lookup);
	if (session == NULL) {
		session = i_new(struct session, 1);
		session->userip = userip;
		session->process = session_lookup.process;
		guid_128_copy(session->conn_guid, conn_guid);
		session->refcount = 1;
		hash_table_insert(limit->session_hash, session, session);
		DLLIST_PREPEND_FULL(&session->process->sessions, session,
				    process_prev, process_next);
	} else {
		session->refcount++;
	}
}

static void session_free(struct session *session)
{
	i_free(session);
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
		str_table_unref(limit->strings, &userip->service);
		i_free(userip->username);
		i_free(userip);
	}
}

void connect_limit_disconnect(struct connect_limit *limit, pid_t pid,
			      const struct connect_limit_key *key,
			      const guid_128_t conn_guid)
{
	struct process *process;
	struct session *session;

	process = process_lookup(limit, pid);
	if (process == NULL) {
		i_error("connect limit: disconnection for unknown pid %s",
			dec2str(pid));
		return;
	}

	struct userip userip_lookup = {
		.username = (char *)key->username,
		.service = key->service,
		.ip = key->ip,
	};
	struct session session_lookup = {
		.userip = &userip_lookup,
		.process = process,
	};
	guid_128_copy(session_lookup.conn_guid, conn_guid);

	session = hash_table_lookup(limit->session_hash, &session_lookup);
	if (session == NULL) {
		i_error("connect limit: disconnection for unknown "
			"(pid=%s, user=%s, service=%s, ip=%s, conn_guid=%s)",
			dec2str(pid), key->username, key->service,
			net_ip2addr(&key->ip), guid_128_to_string(conn_guid));
		return;
	}

	if (--session->refcount == 0) {
		DLLIST_REMOVE_FULL(&process->sessions, session,
				   process_prev, process_next);
		hash_table_remove(limit->session_hash, session);
		session_free(session);
	}

	userip_hash_unref(limit, &userip_lookup);
	if (process->sessions == NULL) {
		hash_table_remove(limit->process_hash, POINTER_CAST(pid));
		i_free(process);
	}
}

void connect_limit_disconnect_pid(struct connect_limit *limit, pid_t pid)
{
	struct process *process;
	struct session *session;

	process = process_lookup(limit, pid);
	if (process == NULL)
		return;

	while (process->sessions != NULL) {
		session = process->sessions;
		DLLIST_REMOVE_FULL(&process->sessions, session,
				   process_prev, process_next);

		hash_table_remove(limit->session_hash, session);
		for (; session->refcount > 0; session->refcount--)
			userip_hash_unref(limit, session->userip);
		session_free(session);
	}
	hash_table_remove(limit->process_hash, POINTER_CAST(pid));
	i_free(process);
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
		str_printfa(str, "%ld\t%u\t", (long)session->process->pid,
			    session->refcount);
		str_append_tabescaped(str, session->userip->username);
		str_append_c(str, '\t');
		str_append_tabescaped(str, session->userip->service);
		str_append_c(str, '\t');
		if (session->userip->ip.family != 0)
			str_append(str, net_ip2addr(&session->userip->ip));
		str_append_c(str, '\t');
		str_append_tabescaped(str, guid_128_to_string(session->conn_guid));
		str_append_c(str, '\n');
		ret = o_stream_send(output, str_data(str), str_len(str));
	} T_END;
	hash_table_iterate_deinit(&iter);
	o_stream_nsend(output, "\n", 1);
	str_free(&str);
}
