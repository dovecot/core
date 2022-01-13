/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
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
	/* points to user_hash keys */
	const char *username;
	const char *service;
	struct ip_addr ip;
};

struct session {
	/* process->sessions linked list */
	struct session *process_prev, *process_next;
	/* user_hash sessions linked list */
	struct session *user_prev, *user_next;

	/* points to userip_hash keys */
	struct userip *userip;
	struct process *process;
	guid_128_t conn_guid;
};

struct connect_limit {
	struct str_table *strings;

	struct connect_limit_iter *iter;

	/* username => struct session linked list */
	HASH_TABLE(char *, struct session *) user_hash;
	/* userip => unsigned int refcount */
	HASH_TABLE(struct userip *, void *) userip_hash;
	/* conn_guid => struct session */
	HASH_TABLE(const uint8_t *, struct session *) session_hash;
	/* pid_t => struct process */
	HASH_TABLE(void *, struct process *) process_hash;
};

struct connect_limit_iter {
	struct connect_limit *limit;
	ARRAY(struct connect_limit_iter_result) results;
	unsigned int idx;
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

struct connect_limit *connect_limit_init(void)
{
	struct connect_limit *limit;

	limit = i_new(struct connect_limit, 1);
	limit->strings = str_table_init();
	hash_table_create(&limit->user_hash, default_pool, 0,
			  str_hash, strcmp);
	hash_table_create(&limit->userip_hash, default_pool, 0,
			  userip_hash, userip_cmp);
	hash_table_create(&limit->session_hash, default_pool, 0,
			  guid_128_hash, guid_128_cmp);
	hash_table_create_direct(&limit->process_hash, default_pool, 0);
	return limit;
}

void connect_limit_deinit(struct connect_limit **_limit)
{
	struct connect_limit *limit = *_limit;

	*_limit = NULL;
	hash_table_destroy(&limit->user_hash);
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

static void
session_link_process(struct connect_limit *limit, struct session *session,
		     pid_t pid)
{
	struct process *process;

	process = process_lookup(limit, pid);
	if (process == NULL) {
		process = i_new(struct process, 1);
		process->pid = pid;
		hash_table_insert(limit->process_hash,
				  POINTER_CAST(pid), process);
	}

	session->process = process;
	DLLIST_PREPEND_FULL(&process->sessions, session,
			    process_prev, process_next);
}

static void
session_unlink_process(struct connect_limit *limit, struct session *session)
{
	struct process *process;

	process = session->process;
	DLLIST_REMOVE_FULL(&process->sessions, session,
			   process_prev, process_next);
	if (process->sessions == NULL) {
		hash_table_remove(limit->process_hash,
				  POINTER_CAST(process->pid));
		i_free(process);
	}
}

void connect_limit_connect(struct connect_limit *limit, pid_t pid,
			   const struct connect_limit_key *key,
			   const guid_128_t conn_guid)
{
	struct session *session, *first_user_session;
	struct userip *userip;
	char *username;
	void *value;

	i_assert(limit->iter == NULL);

	session = hash_table_lookup(limit->session_hash, conn_guid);
	if (session != NULL) {
		i_error("connect limit: connection for duplicate connection GUID %s "
			"(pid=%s -> %s, user=%s -> %s, service=%s -> %s, ip=%s -> %s)",
			guid_128_to_string(conn_guid),
			dec2str(session->process->pid), dec2str(pid),
			session->userip->username, key->username,
			session->userip->service, key->service,
			net_ip2addr(&session->userip->ip), net_ip2addr(&key->ip));
		return;
	}

	if (!hash_table_lookup_full(limit->user_hash, key->username,
				    &username, &first_user_session)) {
		username = i_strdup(key->username);
		first_user_session = NULL;
	}

	struct userip userip_lookup = {
		.username = username,
		.service = key->service,
		.ip = key->ip,
	};
	if (!hash_table_lookup_full(limit->userip_hash, &userip_lookup,
				    &userip, &value)) {
		userip = i_new(struct userip, 1);
		userip->username = username;
		userip->service = str_table_ref(limit->strings, key->service);
		userip->ip = key->ip;
		value = POINTER_CAST(1);
		hash_table_insert(limit->userip_hash, userip, value);
	} else {
		value = POINTER_CAST(POINTER_CAST_TO(value, unsigned int) + 1);
		hash_table_update(limit->userip_hash, userip, value);
	}

	session = i_new(struct session, 1);
	session->userip = userip;
	guid_128_copy(session->conn_guid, conn_guid);

	session_link_process(limit, session, pid);
	const uint8_t *conn_guid_p = session->conn_guid;
	hash_table_insert(limit->session_hash, conn_guid_p, session);
	DLLIST_PREPEND_FULL(&first_user_session, session,
			    user_prev, user_next);
	hash_table_update(limit->user_hash, username, session);
}

static void
session_free(struct connect_limit *limit, struct session *session)
{
	struct userip *userip = session->userip;
	struct session *first_user_session;
	const char *username = userip->username;
	char *orig_username;
	void *value;
	unsigned int new_refcount;

	if (!hash_table_lookup_full(limit->userip_hash, userip,
				    &userip, &value))
		i_panic("connect limit hash tables are inconsistent");

	new_refcount = POINTER_CAST_TO(value, unsigned int) - 1;
	if (new_refcount > 0) {
		value = POINTER_CAST(new_refcount);
		hash_table_update(limit->userip_hash, userip, value);
	} else {
		hash_table_remove(limit->userip_hash, userip);
		str_table_unref(limit->strings, &userip->service);
		i_free(userip);
	}

	if (!hash_table_lookup_full(limit->user_hash, username,
				    &orig_username, &first_user_session))
		i_panic("connect limit hash tables are inconsistent");

	bool hash_update = (first_user_session == session);
	DLLIST_REMOVE_FULL(&first_user_session, session, user_prev, user_next);
	if (first_user_session == NULL) {
		hash_table_remove(limit->user_hash, orig_username);
		i_free(orig_username);
	} else if (hash_update) {
		hash_table_update(limit->user_hash, orig_username,
				  first_user_session);
	}
	i_free(session);
}

void connect_limit_disconnect(struct connect_limit *limit, pid_t pid,
			      const struct connect_limit_key *key,
			      const guid_128_t conn_guid)
{
	struct session *session;

	i_assert(limit->iter == NULL);

	session = hash_table_lookup(limit->session_hash, conn_guid);
	/* Connection GUID alone should be enough to match, but if there are any
	   mismatching parameters it can cause the state to become corrupted. */
	if (session == NULL || pid != session->process->pid ||
	    !net_ip_compare(&key->ip, &session->userip->ip) ||
	    strcmp(key->username, session->userip->username) != 0 ||
	    strcmp(key->service, session->userip->service) != 0) {
		i_error("connect limit: disconnection for unknown "
			"(pid=%s, user=%s, service=%s, ip=%s, conn_guid=%s)",
			dec2str(pid), key->username, key->service,
			net_ip2addr(&key->ip), guid_128_to_string(conn_guid));
		return;
	}
	i_assert(hash_table_lookup(limit->process_hash, POINTER_CAST(pid)) != NULL);

	const uint8_t *conn_guid_p = session->conn_guid;
	hash_table_remove(limit->session_hash, conn_guid_p);
	session_unlink_process(limit, session);
	session_free(limit, session);
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

		const uint8_t *conn_guid_p = session->conn_guid;
		hash_table_remove(limit->session_hash, conn_guid_p);
		session_free(limit, session);
	}
	hash_table_remove(limit->process_hash, POINTER_CAST(pid));
	i_free(process);
}

void connect_limit_dump(struct connect_limit *limit, struct ostream *output)
{
	struct hash_iterate_context *iter;
	struct session *session;
	const uint8_t *conn_guid;
	string_t *str = str_new(default_pool, 256);
	ssize_t ret = 0;

	iter = hash_table_iterate_init(limit->session_hash);
	while (ret >= 0 &&
	       hash_table_iterate(iter, limit->session_hash,
				  &conn_guid, &session)) T_BEGIN {
		str_truncate(str, 0);
		str_printfa(str, "%ld\t", (long)session->process->pid);
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

static int
connect_limit_iter_result_cmp(const struct connect_limit_iter_result *result1,
			      const struct connect_limit_iter_result *result2)
{
	if (result1->pid < result2->pid)
		return -1;
	if (result1->pid > result2->pid)
		return 1;
	return guid_128_cmp(result1->conn_guid, result2->conn_guid);
}

struct connect_limit_iter *
connect_limit_iter_begin(struct connect_limit *limit, const char *username)
{
	struct connect_limit_iter *iter;
	struct session *session;

	i_assert(limit->iter == NULL);

	iter = i_new(struct connect_limit_iter, 1);
	iter->limit = limit;
	i_array_init(&iter->results, 32);

	session = hash_table_lookup(limit->user_hash, username);
	while (session != NULL) {
		struct connect_limit_iter_result *result =
			array_append_space(&iter->results);
		result->pid = session->process->pid;
		result->service = session->userip->service;
		guid_128_copy(result->conn_guid, session->conn_guid);
		session = session->user_next;
	}
	array_sort(&iter->results, connect_limit_iter_result_cmp);

	limit->iter = iter;
	return iter;
}

bool connect_limit_iter_next(struct connect_limit_iter *iter,
			     struct connect_limit_iter_result *result_r)
{
	const struct connect_limit_iter_result *results;
	unsigned int count;

	results = array_get(&iter->results, &count);
	if (iter->idx == count)
		return FALSE;
	*result_r = results[iter->idx++];
	return TRUE;
}

void connect_limit_iter_deinit(struct connect_limit_iter **_iter)
{
	struct connect_limit_iter *iter = *_iter;

	i_assert(iter->limit->iter == iter);
	iter->limit->iter = NULL;

	*_iter = NULL;
	array_free(&iter->results);
	i_free(iter);
}
