/* Copyright (C) 2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#if defined(PASSDB_LDAP) || defined(USERDB_LDAP)

#include "common.h"
#include "network.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "settings.h"
#include "db-ldap.h"

#include <stddef.h>
#include <stdlib.h>

/* Older versions may require calling ldap_result() twice */
#if LDAP_VENDOR_VERSION <= 20112
#  define OPENLDAP_ASYNC_WORKAROUND
#endif

#define DEF(type, name) \
	{ type, #name, offsetof(struct ldap_settings, name) }

static struct setting_def setting_defs[] = {
	DEF(SET_STR, hosts),
	DEF(SET_STR, uris),
	DEF(SET_STR, dn),
	DEF(SET_STR, dnpass),
	DEF(SET_STR, deref),
	DEF(SET_STR, scope),
	DEF(SET_STR, base),
	DEF(SET_INT, ldap_version),
	DEF(SET_STR, user_attrs),
	DEF(SET_STR, user_filter),
	DEF(SET_STR, pass_attrs),
	DEF(SET_STR, pass_filter),
	DEF(SET_STR, default_pass_scheme),
	DEF(SET_INT, user_global_uid),
	DEF(SET_INT, user_global_gid)
};

struct ldap_settings default_ldap_settings = {
	MEMBER(hosts) NULL,
	MEMBER(uris) NULL,
	MEMBER(dn) NULL,
	MEMBER(dnpass) NULL,
	MEMBER(deref) "never",
	MEMBER(scope) "subtree",
	MEMBER(base) NULL,
	MEMBER(ldap_version) 2,
	MEMBER(user_attrs) NULL,
	MEMBER(user_filter) NULL,
	MEMBER(pass_attrs) NULL,
	MEMBER(pass_filter) NULL,
	MEMBER(default_pass_scheme) "crypt",
	MEMBER(user_global_uid) (uid_t)-1,
	MEMBER(user_global_gid) (gid_t)-1
};

static struct ldap_connection *ldap_connections = NULL;

static int ldap_conn_open(struct ldap_connection *conn);
static void ldap_conn_close(struct ldap_connection *conn);

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

void db_ldap_search(struct ldap_connection *conn, const char *base, int scope,
		    const char *filter, char **attributes,
		    struct ldap_request *request)
{
	int msgid;

	if (!conn->connected) {
		if (!ldap_conn_open(conn)) {
			request->callback(conn, request, NULL);
			return;
		}
	}

	msgid = ldap_search(conn->ld, base, scope, filter, attributes, 0);
	if (msgid == -1) {
		i_error("LDAP: ldap_search() failed (filter %s): %s",
			filter, ldap_get_error(conn));
		request->callback(conn, request, NULL);
		return;
	}

	hash_insert(conn->requests, POINTER_CAST(msgid), request);
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
				/* reconnect */
				ldap_conn_close(conn);
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
			i_free(request);
		}

		ldap_msgfree(res);
	}
}

static int ldap_conn_open(struct ldap_connection *conn)
{
	int ret, fd;

	if (conn->connected)
		return TRUE;

	if (conn->ld == NULL) {
		if (conn->set.uris != NULL) {
			if (ldap_initialize(&conn->ld, conn->set.uris) != LDAP_SUCCESS)
				conn->ld = NULL;
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

	/* NOTE: we use blocking connect, we couldn't do anything anyway
	   until it's done. */
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
	return TRUE;
}

static void ldap_conn_close(struct ldap_connection *conn)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(conn->requests);
	while (hash_iterate(iter, &key, &value)) {
		struct ldap_request *request = value;

		request->callback(conn, request, NULL);
		i_free(request);
	}
	hash_iterate_deinit(iter);
	hash_clear(conn->requests, FALSE);

	conn->connected = FALSE;

	if (conn->io != NULL) {
		io_remove(conn->io);
		conn->io = NULL;
	}

	if (conn->ld != NULL) {
		ldap_unbind(conn->ld);
		conn->ld = NULL;
	}
}

void db_ldap_set_attrs(struct ldap_connection *conn, const char *value,
		       unsigned int **attrs, char ***attr_names)
{
	const char *const *attr;
	unsigned int i, dest, size;

	attr = t_strsplit(value, ",");
	if (*attr == NULL || **attr == '\0')
		i_fatal("Missing uid field in attrs");

	for (size = 0; attr[size] != NULL; size++) ;

	/* +1 for terminating NULL */
	*attrs = p_new(conn->pool, unsigned int, size);
	*attr_names = p_new(conn->pool, char *, size + 1);
	for (i = 0, dest = 0; *attr != NULL; i++, attr++) {
		if (**attr != '\0') {
			(*attrs)[dest] = i;
			(*attr_names)[dest] = p_strdup(conn->pool, *attr);
			dest++;
		}
	}
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

        conn->set.ldap_deref = deref2str(conn->set.deref);
        conn->set.ldap_scope = scope2str(conn->set.scope);

	(void)ldap_conn_open(conn);

	conn->next = ldap_connections;
        ldap_connections = conn;
	return conn;
}

void db_ldap_unref(struct ldap_connection *conn)
{
	if (--conn->refcount > 0)
		return;

	ldap_conn_close(conn);

	hash_destroy(conn->requests);
	pool_unref(conn->pool);
}

#endif
