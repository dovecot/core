/* Copyright (C) 2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#if defined(PASSDB_LDAP) || defined(USERDB_LDAP)

#include "common.h"
#include "ioloop.h"
#include "hash.h"
#include "settings.h"
#include "db-ldap.h"

#include <stddef.h>

#define DEF(type, name) \
	{ type, #name, offsetof(struct ldap_settings, name) }

static struct setting_def setting_defs[] = {
	DEF(SET_STR, hosts),
	DEF(SET_STR, user),
	DEF(SET_STR, pass),
	DEF(SET_STR, deref),
	DEF(SET_STR, base),
	DEF(SET_STR, attrs),
	DEF(SET_STR, filter)
};

struct ldap_settings default_ldap_settings = {
	MEMBER(hosts) "localhost",
	MEMBER(user) NULL,
	MEMBER(pass) NULL,
	MEMBER(deref) "never",
	MEMBER(base) NULL,
	MEMBER(attrs) NULL,
	MEMBER(filter) NULL
};

static int ldap_conn_open(struct ldap_connection *conn);

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

static const char *get_ldap_error(struct ldap_connection *conn)
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
			filter, get_ldap_error(conn));
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

	for (;;) {
		memset(&timeout, 0, sizeof(timeout));
		ret = ldap_result(conn->ld, LDAP_RES_ANY, 1, &timeout, &res);
		if (ret <= 0) {
			if (ret < 0) {
				i_error("LDAP: ldap_result() failed: %s",
					get_ldap_error(conn));
			}
			return;
		}

		ret = ldap_result2error(conn->ld, res, 0);
		if (ret != LDAP_SUCCESS) {
			i_error("LDAP: ldap_result() failed: %s",
				ldap_err2string(ret));
		} else {
			msgid = ldap_msgid(res);

			request = hash_lookup(conn->requests,
					      POINTER_CAST(msgid));
			if (request != NULL) {
				request->callback(conn, request, res);
				hash_remove(conn->requests,
					    POINTER_CAST(msgid));
				i_free(request);
			} else {
				i_error("LDAP: Reply with unknown msgid %d",
					msgid);
			}
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
	}

	/* NOTE: we use blocking connect, we couldn't do anything anyway
	   until it's done. */
	ret = ldap_simple_bind_s(conn->ld, conn->set.user, conn->set.pass);
	if (ret != LDAP_SUCCESS) {
		i_error("LDAP: ldap_simple_bind_s() failed: %s",
			ldap_err2string(ret));
		return FALSE;
	}

	conn->connected = TRUE;

	/* register LDAP input to ioloop */
	ret = ldap_get_option(conn->ld, LDAP_OPT_DESC, (void *) &fd);
	if (ret != LDAP_SUCCESS) {
		i_fatal("LDAP: Can't get connection fd: %s",
			ldap_err2string(ret));
	}

	conn->io = io_add(fd, IO_READ, ldap_input, conn);
	return TRUE;
}

static void ldap_conn_close(struct ldap_connection *conn)
{
	if (conn->connected) {
		io_remove(conn->io);
		conn->io = NULL;

		conn->connected = FALSE;
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

static const char *parse_setting(const char *key, const char *value,
				 void *context)
{
	struct ldap_connection *conn = context;

	return parse_setting_from_defs(conn->pool, setting_defs,
				       &conn->set, key, value);
}

struct ldap_connection *db_ldap_init(const char *config_path)
{
	struct ldap_connection *conn;
	pool_t pool;

	pool = pool_alloconly_create("ldap_connection", 1024);
	conn = p_new(pool, struct ldap_connection, 1);
	conn->pool = pool;

	conn->refcount = 1;
	conn->requests = hash_create(default_pool, pool, 0, NULL, NULL);

	conn->set = default_ldap_settings;
	settings_read(config_path, parse_setting, conn);

	if (conn->set.user == NULL)
		i_fatal("LDAP: No user given");
	if (conn->set.pass == NULL)
		i_fatal("LDAP: No password given");
	if (conn->set.base == NULL)
		i_fatal("LDAP: No base given");

        conn->set.ldap_deref = deref2str(conn->set.deref);

	(void)ldap_conn_open(conn);
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
