/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"

#if defined(PASSDB_LDAP) || defined(USERDB_LDAP)

#include "network.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "settings.h"
#include "userdb.h"
#include "db-ldap.h"

#include <stddef.h>
#include <stdlib.h>

/* Older versions may require calling ldap_result() twice */
#if LDAP_VENDOR_VERSION <= 20112
#  define OPENLDAP_ASYNC_WORKAROUND
#endif

/* Solaris LDAP library doesn't have LDAP_OPT_SUCCESS */
#ifndef LDAP_OPT_SUCCESS
#  define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#define DEF(type, name) \
	{ type, #name, offsetof(struct ldap_settings, name) }

static struct setting_def setting_defs[] = {
	DEF(SET_STR, hosts),
	DEF(SET_STR, uris),
	DEF(SET_STR, dn),
	DEF(SET_STR, dnpass),
	DEF(SET_BOOL, auth_bind),
	DEF(SET_STR, auth_bind_userdn),
	DEF(SET_STR, deref),
	DEF(SET_STR, scope),
	DEF(SET_STR, base),
	DEF(SET_INT, ldap_version),
	DEF(SET_STR, user_attrs),
	DEF(SET_STR, user_filter),
	DEF(SET_STR, pass_attrs),
	DEF(SET_STR, pass_filter),
	DEF(SET_STR, default_pass_scheme),
	DEF(SET_STR, user_global_uid),
	DEF(SET_STR, user_global_gid),

	{ 0, NULL, 0 }
};

struct ldap_settings default_ldap_settings = {
	MEMBER(hosts) NULL,
	MEMBER(uris) NULL,
	MEMBER(dn) NULL,
	MEMBER(dnpass) NULL,
	MEMBER(auth_bind) FALSE,
	MEMBER(auth_bind_userdn) NULL,
	MEMBER(deref) "never",
	MEMBER(scope) "subtree",
	MEMBER(base) NULL,
	MEMBER(ldap_version) 2,
	MEMBER(user_attrs) "uid,homeDirectory,,,uidNumber,gidNumber",
	MEMBER(user_filter) "(&(objectClass=posixAccount)(uid=%u))",
	MEMBER(pass_attrs) "uid,userPassword",
	MEMBER(pass_filter) "(&(objectClass=posixAccount)(uid=%u))",
	MEMBER(default_pass_scheme) "crypt",
	MEMBER(user_global_uid) "",
	MEMBER(user_global_gid) ""
};

static struct ldap_connection *ldap_connections = NULL;

static void ldap_conn_close(struct ldap_connection *conn, bool flush_requests);

static int deref2str(const char *str)
{
	if (strcasecmp(str, "never") == 0)
		return LDAP_DEREF_NEVER;
	if (strcasecmp(str, "searching") == 0)
		return LDAP_DEREF_SEARCHING;
	if (strcasecmp(str, "finding") == 0)
		return LDAP_DEREF_FINDING;
	if (strcasecmp(str, "always") == 0)
		return LDAP_DEREF_ALWAYS;

	i_fatal("LDAP: Unknown deref option '%s'", str);
}

static int scope2str(const char *str)
{
	if (strcasecmp(str, "base") == 0)
		return LDAP_SCOPE_BASE;
	if (strcasecmp(str, "onelevel") == 0)
		return LDAP_SCOPE_ONELEVEL;
	if (strcasecmp(str, "subtree") == 0)
		return LDAP_SCOPE_SUBTREE;

	i_fatal("LDAP: Unknown scope option '%s'", str);
}

const char *ldap_get_error(struct ldap_connection *conn)
{
	int ret, err;

	ret = ldap_get_option(conn->ld, LDAP_OPT_ERROR_NUMBER, (void *) &err);
	if (ret != LDAP_SUCCESS) {
		i_error("LDAP: Can't get error number: %s",
			ldap_err2string(ret));
		return "??";
	}

	return ldap_err2string(err);
}

void db_ldap_search(struct ldap_connection *conn, struct ldap_request *request,
		    int scope)
{
	int msgid;

	if (!conn->connected) {
		if (!db_ldap_connect(conn)) {
			request->callback(conn, request, NULL);
			return;
		}
	}

	msgid = ldap_search(conn->ld, request->base, scope,
			    request->filter, request->attributes, 0);
	if (msgid == -1) {
		i_error("LDAP: ldap_search() failed (filter %s): %s",
			request->filter, ldap_get_error(conn));
		request->callback(conn, request, NULL);
		return;
	}

	hash_insert(conn->requests, POINTER_CAST(msgid), request);
}

static void ldap_conn_retry_requests(struct ldap_connection *conn)
{
	struct hash_table *old_requests;
        struct hash_iterate_context *iter;
	void *key, *value;

	i_assert(conn->connected);

	if (hash_size(conn->requests) == 0)
		return;

	old_requests = conn->requests;
	conn->requests = hash_create(default_pool, conn->pool, 0, NULL, NULL);

	iter = hash_iterate_init(old_requests);
	while (hash_iterate(iter, &key, &value)) {
		struct ldap_request *request = value;

		i_assert(conn->connected);
		db_ldap_search(conn, request, conn->set.ldap_scope);
	}
	hash_iterate_deinit(iter);
	hash_destroy(old_requests);
}

static void ldap_conn_reconnect(struct ldap_connection *conn)
{
	ldap_conn_close(conn, FALSE);

	if (!db_ldap_connect(conn)) {
		/* failed to reconnect. fail all requests. */
		ldap_conn_close(conn, TRUE);
	}
}

static void ldap_input(void *context)
{
	struct ldap_connection *conn = context;
        struct ldap_request *request;
	struct timeval timeout;
	LDAPMessage *res;
	int ret, msgid;

	while (conn->ld != NULL) {
		memset(&timeout, 0, sizeof(timeout));
		ret = ldap_result(conn->ld, LDAP_RES_ANY, 1, &timeout, &res);
#ifdef OPENLDAP_ASYNC_WORKAROUND
		if (ret == 0) {
			/* try again, there may be another in buffer */
			ret = ldap_result(conn->ld, LDAP_RES_ANY, 1,
					  &timeout, &res);
		}
#endif
		if (ret <= 0) {
			if (ret < 0) {
				i_error("LDAP: ldap_result() failed: %s",
					ldap_get_error(conn));
				ldap_conn_reconnect(conn);
			}
			return;
		}

		msgid = ldap_msgid(res);
		request = hash_lookup(conn->requests, POINTER_CAST(msgid));
		if (request == NULL) {
			i_error("LDAP: Reply with unknown msgid %d",
				msgid);
		} else {
			hash_remove(conn->requests, POINTER_CAST(msgid));
			request->callback(conn, request, res);
		}

		ldap_msgfree(res);
	}
}

bool db_ldap_connect(struct ldap_connection *conn)
{
	int ret, fd;

	if (conn->connected)
		return TRUE;

	if (conn->ld == NULL) {
		if (conn->set.uris != NULL) {
#ifdef LDAP_HAVE_INITIALIZE
			if (ldap_initialize(&conn->ld, conn->set.uris) != LDAP_SUCCESS)
				conn->ld = NULL;
#else
			i_fatal("LDAP: Your LDAP library doesn't support "
				"'uris' setting, use 'hosts' instead.");
#endif
		} else
			conn->ld = ldap_init(conn->set.hosts, LDAP_PORT);

		if (conn->ld == NULL)
			i_fatal("LDAP: ldap_init() failed with hosts: %s",
				conn->set.hosts);

		ret = ldap_set_option(conn->ld, LDAP_OPT_DEREF,
				      (void *) &conn->set.ldap_deref);
		if (ret != LDAP_SUCCESS) {
			i_fatal("LDAP: Can't set deref option: %s",
				ldap_err2string(ret));
		}

		ret = ldap_set_option(conn->ld, LDAP_OPT_PROTOCOL_VERSION,
				      (void *) &conn->set.ldap_version);
		if (ret != LDAP_OPT_SUCCESS) {
			i_fatal("LDAP: Can't set protocol version %u: %s",
				conn->set.ldap_version, ldap_err2string(ret));
		}
	}

	/* FIXME: we shouldn't use blocking bind */
	ret = ldap_simple_bind_s(conn->ld, conn->set.dn, conn->set.dnpass);
	if (ret == LDAP_SERVER_DOWN) {
		i_error("LDAP: Can't connect to server: %s", conn->set.hosts);
		return FALSE;
	}
	if (ret != LDAP_SUCCESS) {
		i_error("LDAP: ldap_simple_bind_s() failed (dn %s): %s",
			conn->set.dn == NULL ? "(none)" : conn->set.dn,
			ldap_get_error(conn));
		return FALSE;
	}

	conn->connected = TRUE;

	/* register LDAP input to ioloop */
	ret = ldap_get_option(conn->ld, LDAP_OPT_DESC, (void *) &fd);
	if (ret != LDAP_SUCCESS) {
		i_fatal("LDAP: Can't get connection fd: %s",
			ldap_err2string(ret));
	}

	net_set_nonblock(fd, TRUE);
	conn->io = io_add(fd, IO_READ, ldap_input, conn);

	/* in case there are requests waiting, retry them */
        ldap_conn_retry_requests(conn);
	return TRUE;
}

static void ldap_conn_close(struct ldap_connection *conn, bool flush_requests)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	if (flush_requests) {
		iter = hash_iterate_init(conn->requests);
		while (hash_iterate(iter, &key, &value)) {
			struct ldap_request *request = value;

			request->callback(conn, request, NULL);
		}
		hash_iterate_deinit(iter);
		hash_clear(conn->requests, FALSE);
	}

	conn->connected = FALSE;

	if (conn->io != NULL)
		io_remove(&conn->io);

	if (conn->ld != NULL) {
		ldap_unbind(conn->ld);
		conn->ld = NULL;
	}
}

void db_ldap_set_attrs(struct ldap_connection *conn, const char *attrlist,
		       char ***attr_names_r, struct hash_table *attr_map,
		       const char *const default_attr_map[])
{
	const char *const *attr;
	char *name, *value, *p;
	unsigned int i, size;

	if (*attrlist == '\0')
		return;

	t_push();
	attr = t_strsplit(attrlist, ",");

	/* @UNSAFE */
	for (size = 0; attr[size] != NULL; size++) ;
	*attr_names_r = p_new(conn->pool, char *, size + 1);

	for (i = 0; i < size; i++) {
		p = strchr(attr[i], '=');
		if (p == NULL) {
			name = p_strdup(conn->pool, attr[i]);
			value = *default_attr_map == NULL ? name :
				p_strdup(conn->pool, *default_attr_map);
		} else {
			name = p_strdup_until(conn->pool, attr[i], p);
			value = p_strdup(conn->pool, p + 1);
		}

		(*attr_names_r)[i] = name;
		if (*name != '\0')
			hash_insert(attr_map, name, value);

		if (*default_attr_map != NULL)
			default_attr_map++;
	}
	t_pop();
}

#define IS_LDAP_ESCAPED_CHAR(c) \
	((c) == '*' || (c) == '(' || (c) == ')' || (c) == '\\')

const char *ldap_escape(const char *str)
{
	const char *p;
	string_t *ret;

	for (p = str; *p != '\0'; p++) {
		if (IS_LDAP_ESCAPED_CHAR(*p))
			break;
	}

	if (*p == '\0')
		return str;

	ret = t_str_new((size_t) (p - str) + 64);
	str_append_n(ret, str, (size_t) (p - str));

	for (; *p != '\0'; p++) {
		if (IS_LDAP_ESCAPED_CHAR(*p))
			str_append_c(ret, '\\');
		str_append_c(ret, *p);
	}
	return str_c(ret);
}

static const char *parse_setting(const char *key, const char *value,
				 void *context)
{
	struct ldap_connection *conn = context;

	return parse_setting_from_defs(conn->pool, setting_defs,
				       &conn->set, key, value);
}

static struct ldap_connection *ldap_conn_find(const char *config_path)
{
	struct ldap_connection *conn;

	for (conn = ldap_connections; conn != NULL; conn = conn->next) {
		if (strcmp(conn->config_path, config_path) == 0)
			return conn;
	}

	return NULL;
}

struct ldap_connection *db_ldap_init(const char *config_path)
{
	struct ldap_connection *conn;
	pool_t pool;

	/* see if it already exists */
	conn = ldap_conn_find(config_path);
	if (conn != NULL) {
		conn->refcount++;
		return conn;
	}

	if (*config_path == '\0')
		i_fatal("LDAP: Configuration file path not given");

	pool = pool_alloconly_create("ldap_connection", 1024);
	conn = p_new(pool, struct ldap_connection, 1);
	conn->pool = pool;

	conn->refcount = 1;
	conn->requests = hash_create(default_pool, pool, 0, NULL, NULL);

	conn->config_path = p_strdup(pool, config_path);
	conn->set = default_ldap_settings;
	if (!settings_read(config_path, NULL, parse_setting, NULL, conn))
		exit(FATAL_DEFAULT);

	if (conn->set.base == NULL)
		i_fatal("LDAP: No base given");

	if (conn->set.uris == NULL && conn->set.hosts == NULL)
		i_fatal("LDAP: No uris or hosts set");
#ifndef LDAP_HAVE_INITIALIZE
	if (conn->set.uris == NULL) {
		i_fatal("LDAP: Dovecot compiled without support for LDAP uris "
			"(ldap_initialize not found)");
	}
#endif

        conn->set.ldap_deref = deref2str(conn->set.deref);
	conn->set.ldap_scope = scope2str(conn->set.scope);

	if (*conn->set.user_global_uid == '\0')
		conn->set.uid = (uid_t)-1;
	else {
		conn->set.uid =
			userdb_parse_uid(NULL, conn->set.user_global_uid);
		if (conn->set.uid == (uid_t)-1) {
			i_fatal("LDAP: Invalid user_global_uid: %s",
				conn->set.user_global_uid);
		}
	}

	if (*conn->set.user_global_gid == '\0')
		conn->set.gid = (gid_t)-1;
	else {
		conn->set.gid =
			userdb_parse_gid(NULL, conn->set.user_global_gid);
		if (conn->set.gid == (gid_t)-1) {
			i_fatal("LDAP: Invalid user_global_gid: %s",
				conn->set.user_global_gid);
		}
	}

	conn->next = ldap_connections;
        ldap_connections = conn;
	return conn;
}

void db_ldap_unref(struct ldap_connection **_conn)
{
        struct ldap_connection *conn = *_conn;
	struct ldap_connection **p;

	*_conn = NULL;
	i_assert(conn->refcount >= 0);
	if (--conn->refcount > 0)
		return;

	for (p = &ldap_connections; *p != NULL; p = &(*p)->next) {
		if (*p == conn) {
			*p = conn->next;
			break;
		}
	}

	ldap_conn_close(conn, TRUE);

	hash_destroy(conn->requests);
	if (conn->pass_attr_map != NULL)
		hash_destroy(conn->pass_attr_map);
	if (conn->user_attr_map != NULL)
		hash_destroy(conn->user_attr_map);
	pool_unref(conn->pool);
}

#endif
