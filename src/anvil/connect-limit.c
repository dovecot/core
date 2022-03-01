/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "hash.h"
#include "llist.h"
#include "sort.h"
#include "str.h"
#include "str-table.h"
#include "strescape.h"
#include "ostream.h"
#include "connect-limit.h"

struct process {
	pid_t pid;
	enum kick_type kick_type;
	struct session *sessions;
};

struct userip {
	/* points to user_hash keys */
	const char *username;
	const char *protocol;
	struct ip_addr ip;
};

struct session_alt_username {
	/* alt_username_hash sessions linked list */
	struct session_alt_username *prev, *next;

	/* points to alt_username_hash keys */
	const char *alt_username;
	/* session where this alt_username belongs to */
	struct session *session;
};
HASH_TABLE_DEFINE_TYPE(session_alt_username, char *,
		       struct session_alt_username *);

struct session {
	/* process->sessions linked list */
	struct session *process_prev, *process_next;
	/* user_hash sessions linked list */
	struct session *user_prev, *user_next;

	/* points to userip_hash keys */
	struct userip *userip;
	struct process *process;
	const char *service;
	guid_128_t conn_guid;
	struct ip_addr dest_ip;

	/* Fields in the same order as connect_limit.alt_username_fields.
	   Note that these may be session-specific, which is why they're not in
	   struct user. */
	unsigned int alt_usernames_count;
	struct session_alt_username *alt_usernames;
};

struct alt_username_field {
	char *name;
	unsigned int refcount;
};

/* Track only non-proxying sessions for mail_max_userip_connections. Otherwise
   if the same server is acting as both proxy and backend the connection could
   be counted twice. */
#define SESSION_TRACK_USERIP(session) \
	((session)->dest_ip.family == 0)

struct connect_limit {
	struct str_table *strings;

	/* username => struct session linked list */
	HASH_TABLE(char *, struct session *) user_hash;
	/* userip => unsigned int refcount. Only track for sessions where
	   SESSION_TRACK_USERIP() returns TRUE. */
	HASH_TABLE(struct userip *, void *) userip_hash;
	/* conn_guid => struct session */
	HASH_TABLE(const uint8_t *, struct session *) session_hash;
	/* pid_t => struct process */
	HASH_TABLE(void *, struct process *) process_hash;

	/* Array of alt username fields. Note that if there are refcount=0
	   fields they may be reused for other usernames later on, but there
	   are never any name=NULL fields. */
	ARRAY(struct alt_username_field) alt_username_fields;
	/* alt_username => struct session linked list. This array is resized
	   every time a new alt_username_field index is added. */
	HASH_TABLE_TYPE(session_alt_username) *alt_username_hashes;
};

struct connect_limit_iter {
	pool_t pool;
	struct connect_limit *limit;
	ARRAY(struct connect_limit_iter_result) results;
	unsigned int idx;
};

static void
connect_limit_process_free(struct connect_limit *limit, struct process *process);

static unsigned int userip_hash(const struct userip *userip)
{
	return str_hash(userip->username) ^ str_hash(userip->protocol) ^
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
	return strcmp(userip1->protocol, userip2->protocol);
}

struct connect_limit *connect_limit_init(void)
{
	struct connect_limit *limit;

	limit = i_new(struct connect_limit, 1);
	limit->strings = str_table_init();
	i_array_init(&limit->alt_username_fields, 8);
	hash_table_create(&limit->user_hash, default_pool, 0,
			  str_hash, strcmp);
	hash_table_create(&limit->userip_hash, default_pool, 0,
			  userip_hash, userip_cmp);
	hash_table_create(&limit->session_hash, default_pool, 0,
			  guid_128_hash, guid_128_cmp);
	hash_table_create_direct(&limit->process_hash, default_pool, 0);
	return limit;
}

static void connect_limit_destroy_all_processes(struct connect_limit *limit)
{
	struct hash_iterate_context *iter;
	struct process *process;
	void *process_key;

	iter = hash_table_iterate_init(limit->process_hash);
	while (hash_table_iterate(iter, limit->process_hash,
				  &process_key, &process))
		connect_limit_process_free(limit, process);
	hash_table_iterate_deinit(&iter);
}

void connect_limit_deinit(struct connect_limit **_limit)
{
	struct connect_limit *limit = *_limit;
	struct alt_username_field *alt_fields;
	unsigned int i, count;

	*_limit = NULL;

	connect_limit_destroy_all_processes(limit);

	i_assert(hash_table_count(limit->user_hash) == 0);
	i_assert(hash_table_count(limit->userip_hash) == 0);
	i_assert(hash_table_count(limit->session_hash) == 0);
	i_assert(hash_table_count(limit->process_hash) == 0);

	hash_table_destroy(&limit->user_hash);
	hash_table_destroy(&limit->userip_hash);
	hash_table_destroy(&limit->session_hash);
	hash_table_destroy(&limit->process_hash);

	alt_fields = array_get_modifiable(&limit->alt_username_fields, &count);
	for (i = 0; i < count; i++) {
		hash_table_destroy(&limit->alt_username_hashes[i]);
		i_free(alt_fields[i].name);
	}
	i_free(limit->alt_username_hashes);
	array_free(&limit->alt_username_fields);
	str_table_deinit(&limit->strings);
	i_free(limit);
}

unsigned int connect_limit_lookup(struct connect_limit *limit,
				  const struct connect_limit_key *key)
{
	struct userip userip_lookup = {
		.username = (char *)key->username,
		.protocol = t_strcut(key->service, '-'),
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
		     pid_t pid, enum kick_type kick_type)
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
	/* The kick_type shouldn't change for the process, but keep updating
	   it anyway. */
	process->kick_type = kick_type;
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

static bool
alt_username_field_find(struct connect_limit *limit, const char *name,
			unsigned int *idx_r)
{
	struct alt_username_field *fields;
	unsigned int i, count, first_empty_idx = UINT_MAX;

	fields = array_get_modifiable(&limit->alt_username_fields, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(fields[i].name, name) == 0) {
			*idx_r = i;
			return TRUE;
		}
		if (fields[i].refcount == 0 && first_empty_idx == UINT_MAX)
			first_empty_idx = i;
	}
	*idx_r = first_empty_idx;
	return FALSE;
}

static unsigned int
alt_username_field_ref(struct connect_limit *limit, const char *name)
{
	struct alt_username_field *field;
	unsigned int idx;

	if (!alt_username_field_find(limit, name, &idx)) {
		/* Field wasn't found, but an existing field with refcount=0
		   may have been reused. */
		unsigned int old_count =
			array_count(&limit->alt_username_fields);
		if (idx == UINT_MAX)
			idx = old_count;
		field = array_idx_get_space(&limit->alt_username_fields, idx);
		i_free(field->name);
		field->name = i_strdup(name);

		limit->alt_username_hashes =
			i_realloc(limit->alt_username_hashes,
				  sizeof(limit->alt_username_hashes[0]) *
				  old_count,
				  sizeof(limit->alt_username_hashes[0]) *
				  I_MAX((idx+1), old_count));
		hash_table_create(&limit->alt_username_hashes[idx],
				  default_pool, 0, str_hash, strcmp);
	} else {
		field = array_idx_modifiable(&limit->alt_username_fields, idx);
	}
	field->refcount++;
	return idx;
}

static void
alt_username_field_unref(struct connect_limit *limit, unsigned int alt_idx)
{
	struct alt_username_field *field;

	field = array_idx_modifiable(&limit->alt_username_fields, alt_idx);
	i_assert(field->refcount > 0);
	field->refcount--;
}

static void
alt_username_value_link(struct connect_limit *limit,
			struct session_alt_username *alt,
			unsigned int alt_idx, const char *alt_username)
{
	struct session_alt_username *first_alt;
	char *orig_key;

	if (!hash_table_lookup_full(limit->alt_username_hashes[alt_idx],
				    alt_username, &orig_key, &first_alt)) {
		orig_key = i_strdup(alt_username);
		alt->alt_username = orig_key;
		hash_table_insert(limit->alt_username_hashes[alt_idx],
				  orig_key, alt);
	} else {
		alt->alt_username = orig_key;
		DLLIST_PREPEND(&first_alt, alt);
		hash_table_update(limit->alt_username_hashes[alt_idx],
				  orig_key, first_alt);
	}
}

static void
session_set_alt_usernames(struct connect_limit *limit, struct session *session,
			  const char *const *alt_usernames)
{
	unsigned int count = str_array_length(alt_usernames)/2;
	if (count == 0)
		return;

	unsigned int max_alt_idx = 0;
	unsigned int *alt_indexes = t_new(unsigned int, count);
	for (unsigned int i = 0; i < count; i++) {
		alt_indexes[i] = alt_username_field_ref(limit, alt_usernames[i*2]);
		max_alt_idx = I_MAX(max_alt_idx, alt_indexes[i]);
	}

	session->alt_usernames_count = max_alt_idx + 1;
	session->alt_usernames =
		i_new(struct session_alt_username,
		      session->alt_usernames_count);
	for (unsigned int i = 0; i < count; i++) {
		unsigned int alt_idx = alt_indexes[i];
		i_assert(session->alt_usernames[alt_idx].session == NULL);
		session->alt_usernames[alt_idx].session = session;
		alt_username_value_link(limit, &session->alt_usernames[alt_idx],
					alt_idx, alt_usernames[i*2 + 1]);
	}
}

static void
session_unset_alt_usernames(struct connect_limit *limit,
			    struct session *session)
{
	struct session_alt_username *first_alt, *alt;
	char *orig_key;
	unsigned int alt_idx;

	for (alt_idx = 0; alt_idx < session->alt_usernames_count; alt_idx++) {
		alt = &session->alt_usernames[alt_idx];
		if (alt->session == NULL)
			continue;

		if (!hash_table_lookup_full(limit->alt_username_hashes[alt_idx],
					    alt->alt_username,
					    &orig_key, &first_alt))
			i_panic("connect limit hash tables are inconsistent");
		bool hash_update = (first_alt == alt);
		DLLIST_REMOVE(&first_alt, alt);
		if (first_alt == NULL) {
			hash_table_remove(limit->alt_username_hashes[alt_idx],
					  orig_key);
			i_free(orig_key);
		} else if (hash_update) {
			hash_table_update(limit->alt_username_hashes[alt_idx],
					  orig_key, first_alt);
		}
		alt_username_field_unref(limit, alt_idx);
	}
	i_free(session->alt_usernames);
}

void connect_limit_connect(struct connect_limit *limit, pid_t pid,
			   const struct connect_limit_key *key,
			   const guid_128_t conn_guid,
			   enum kick_type kick_type,
			   const struct ip_addr *dest_ip,
			   const char *const *alt_usernames)
{
	struct session *session, *first_user_session;
	struct userip *userip;
	char *username;
	void *value;

	session = hash_table_lookup(limit->session_hash, conn_guid);
	if (session != NULL) {
		i_error("connect limit: connection for duplicate connection GUID %s "
			"(pid=%s -> %s, user=%s -> %s, service=%s -> %s, "
			"ip=%s -> %s, dest_ip=%s -> %s)",
			guid_128_to_string(conn_guid),
			dec2str(session->process->pid), dec2str(pid),
			session->userip->username, key->username,
			session->service, key->service,
			net_ip2addr(&session->userip->ip), net_ip2addr(&key->ip),
			net_ip2addr(&session->dest_ip), net_ip2addr(dest_ip));
		return;
	}

	if (!hash_table_lookup_full(limit->user_hash, key->username,
				    &username, &first_user_session)) {
		username = i_strdup(key->username);
		first_user_session = NULL;
	}

	session = i_new(struct session, 1);
	guid_128_copy(session->conn_guid, conn_guid);
	session->service = str_table_ref(limit->strings, key->service);
	if (dest_ip != NULL)
		session->dest_ip = *dest_ip;
	T_BEGIN {
		session_set_alt_usernames(limit, session, alt_usernames);
	} T_END;

	struct userip userip_lookup = {
		.username = username,
		.protocol = t_strcut(key->service, '-'),
		.ip = key->ip,
	};

	if (!SESSION_TRACK_USERIP(session) ||
	    !hash_table_lookup_full(limit->userip_hash, &userip_lookup,
				    &userip, &value)) {
		userip = i_new(struct userip, 1);
		userip->username = username;
		userip->protocol = str_table_ref(limit->strings,
						 userip_lookup.protocol);
		userip->ip = key->ip;
		value = POINTER_CAST(1);
		if (SESSION_TRACK_USERIP(session))
			hash_table_insert(limit->userip_hash, userip, value);
	} else {
		value = POINTER_CAST(POINTER_CAST_TO(value, unsigned int) + 1);
		hash_table_update(limit->userip_hash, userip, value);
	}
	session->userip = userip;

	session_link_process(limit, session, pid, kick_type);
	const uint8_t *conn_guid_p = session->conn_guid;
	hash_table_insert(limit->session_hash, conn_guid_p, session);
	DLLIST_PREPEND_FULL(&first_user_session, session,
			    user_prev, user_next);
	hash_table_update(limit->user_hash, username, session);
}

static void userip_free(struct connect_limit *limit, struct userip *userip)
{
	str_table_unref(limit->strings, &userip->protocol);
	i_free(userip);
}

static void
userip_hash_unref(struct connect_limit *limit, struct session *session)
{
	struct userip *userip = session->userip;
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
		userip_free(limit, userip);
	}
}

static void
session_free(struct connect_limit *limit, struct session *session)
{
	struct session *first_user_session;
	char *orig_username;
	const char *username = session->userip->username;

	if (SESSION_TRACK_USERIP(session))
		userip_hash_unref(limit, session);
	else
		userip_free(limit, session->userip);

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
	session_unset_alt_usernames(limit, session);
	str_table_unref(limit->strings, &session->service);
	i_free(session->alt_usernames);
	i_free(session);
}

void connect_limit_disconnect(struct connect_limit *limit, pid_t pid,
			      const struct connect_limit_key *key,
			      const guid_128_t conn_guid)
{
	struct session *session;

	session = hash_table_lookup(limit->session_hash, conn_guid);
	/* Connection GUID alone should be enough to match, but if there are any
	   mismatching parameters it can cause the state to become corrupted. */
	if (session == NULL || pid != session->process->pid ||
	    !net_ip_compare(&key->ip, &session->userip->ip) ||
	    strcmp(key->username, session->userip->username) != 0 ||
	    strcmp(key->service, session->service) != 0) {
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

static void
connect_limit_process_free(struct connect_limit *limit, struct process *process)
{
	struct session *session;

	while (process->sessions != NULL) {
		session = process->sessions;
		DLLIST_REMOVE_FULL(&process->sessions, session,
				   process_prev, process_next);

		const uint8_t *conn_guid_p = session->conn_guid;
		hash_table_remove(limit->session_hash, conn_guid_p);
		session_free(limit, session);
	}
	hash_table_remove(limit->process_hash, POINTER_CAST(process->pid));
	i_free(process);
}

void connect_limit_disconnect_pid(struct connect_limit *limit, pid_t pid)
{
	struct process *process;

	process = process_lookup(limit, pid);
	if (process != NULL)
		connect_limit_process_free(limit, process);
}

void connect_limit_dump(struct connect_limit *limit, struct ostream *output)
{
	struct hash_iterate_context *iter;
	struct session *session;
	const uint8_t *conn_guid;
	const struct alt_username_field *alt_field;
	unsigned int alt_idx;
	string_t *str = str_new(default_pool, 256);
	ssize_t ret = 0;

	/* Send list of alt usernames in the header */
	array_foreach(&limit->alt_username_fields, alt_field) {
		if (str_len(str) > 0)
			str_append_c(str, '\t');
		str_append_tabescaped(str, alt_field->name);
	}
	str_append_c(str, '\n');
	o_stream_nsend(output, str_data(str), str_len(str));

	/* Send all sessions */
	iter = hash_table_iterate_init(limit->session_hash);
	while (ret >= 0 &&
	       hash_table_iterate(iter, limit->session_hash,
				  &conn_guid, &session)) T_BEGIN {
		str_truncate(str, 0);
		str_printfa(str, "%lu\t", (unsigned long)session->process->pid);
		str_append_tabescaped(str, session->userip->username);
		str_append_c(str, '\t');
		str_append_tabescaped(str, session->service);
		str_append_c(str, '\t');
		if (session->userip->ip.family != 0)
			str_append(str, net_ip2addr(&session->userip->ip));
		str_append_c(str, '\t');
		str_append_tabescaped(str, guid_128_to_string(session->conn_guid));
		str_append_c(str, '\t');
		if (session->dest_ip.family != 0)
			str_append(str, net_ip2addr(&session->dest_ip));
		for (alt_idx = 0; alt_idx < session->alt_usernames_count; alt_idx++) {
			str_append_c(str, '\t');
			if (session->alt_usernames[alt_idx].alt_username != NULL) {
				str_append_tabescaped(str,
					session->alt_usernames[alt_idx].alt_username);
			}
		}
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

static struct connect_limit_iter *
connect_limit_iter_init_common(struct connect_limit *limit)
{
	struct connect_limit_iter *iter;

	pool_t pool = pool_alloconly_create("connect limit iter", 1024);
	iter = p_new(pool, struct connect_limit_iter, 1);
	iter->pool = pool;
	iter->limit = limit;
	i_array_init(&iter->results, 32);
	return iter;
}

struct connect_limit_iter *
connect_limit_iter_begin(struct connect_limit *limit, const char *username,
			 const guid_128_t conn_guid)
{
	struct connect_limit_iter *iter;
	struct session *session;
	bool check_conn_guid = conn_guid != NULL &&
		!guid_128_is_empty(conn_guid);

	iter = connect_limit_iter_init_common(limit);
	session = hash_table_lookup(limit->user_hash, username);
	while (session != NULL) {
		if (!check_conn_guid ||
		    guid_128_cmp(session->conn_guid, conn_guid) == 0) {
			struct connect_limit_iter_result *result =
				array_append_space(&iter->results);
			result->kick_type = session->process->kick_type;
			result->pid = session->process->pid;
			result->service = str_table_ref(limit->strings,
							session->service);
			result->username = p_strdup(iter->pool,
						    session->userip->username);
			guid_128_copy(result->conn_guid, session->conn_guid);
		}
		session = session->user_next;
	}
	array_sort(&iter->results, connect_limit_iter_result_cmp);
	return iter;
}

struct connect_limit_iter *
connect_limit_iter_begin_alt_username(struct connect_limit *limit,
				      const char *alt_username_field,
				      const char *alt_username,
				      const struct ip_addr *except_ip)
{
	struct connect_limit_iter *iter;
	struct session_alt_username *alt;
	unsigned int alt_idx;

	iter = connect_limit_iter_init_common(limit);
	if (!alt_username_field_find(limit, alt_username_field, &alt_idx))
		return iter;

	alt = hash_table_lookup(limit->alt_username_hashes[alt_idx],
				alt_username);
	while (alt != NULL) {
		if (except_ip == NULL ||
		    !net_ip_compare(&alt->session->userip->ip, except_ip)) {
			struct connect_limit_iter_result *result =
				array_append_space(&iter->results);
			result->kick_type = alt->session->process->kick_type;
			result->pid = alt->session->process->pid;
			result->service = str_table_ref(limit->strings,
							alt->session->service);
			guid_128_copy(result->conn_guid, alt->session->conn_guid);
			result->username = p_strdup(iter->pool, alt->session->userip->username);
		}
		alt = alt->next;
	}
	array_sort(&iter->results, connect_limit_iter_result_cmp);
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
	struct connect_limit_iter_result *result;

	*_iter = NULL;
	array_foreach_modifiable(&iter->results, result)
		str_table_unref(iter->limit->strings, &result->service);
	array_free(&iter->results);
	pool_unref(&iter->pool);
}
