/* Copyright (c) 2003-2007 Dovecot authors, see the included COPYING file */

#include "common.h"

#if defined(PASSDB_LDAP) || defined(USERDB_LDAP)

#include "network.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "settings.h"
#include "userdb.h"
#include "db-ldap.h"

#include <stddef.h>
#include <stdlib.h>

#define HAVE_LDAP_SASL
#ifdef HAVE_SASL_SASL_H
#  include <sasl/sasl.h>
#elif defined (HAVE_SASL_H)
#  include <sasl.h>
#else
#  undef HAVE_LDAP_SASL
#endif
#if SASL_VERSION_MAJOR < 2
#  undef HAVE_LDAP_SASL
#endif

#ifndef LDAP_SASL_QUIET
#  define LDAP_SASL_QUIET 0 /* Doesn't exist in Solaris LDAP */
#endif

/* Older versions may require calling ldap_result() twice */
#if LDAP_VENDOR_VERSION <= 20112
#  define OPENLDAP_ASYNC_WORKAROUND
#endif

/* Solaris LDAP library doesn't have LDAP_OPT_SUCCESS */
#ifndef LDAP_OPT_SUCCESS
#  define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

struct db_ldap_result_iterate_context {
	struct ldap_connection *conn;
	LDAPMessage *entry;
	struct auth_request *auth_request;

	struct hash_table *attr_map;
	struct var_expand_table *var_table;

	char *attr, **vals;
	const char *name, *value, *template, *val_1_arr[2];
	const char *const *static_attrs;
	BerElement *ber;

	string_t *var, *debug;
	unsigned int value_idx;
};

#define DEF_STR(name) DEF_STRUCT_STR(name, ldap_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, ldap_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, ldap_settings)

static struct setting_def setting_defs[] = {
	DEF_STR(hosts),
	DEF_STR(uris),
	DEF_STR(dn),
	DEF_STR(dnpass),
	DEF_BOOL(auth_bind),
	DEF_STR(auth_bind_userdn),
	DEF_BOOL(tls),
	DEF_BOOL(sasl_bind),
	DEF_STR(sasl_mech),
	DEF_STR(sasl_realm),
	DEF_STR(sasl_authz_id),
	DEF_STR(deref),
	DEF_STR(scope),
	DEF_STR(base),
	DEF_INT(ldap_version),
	DEF_STR(user_attrs),
	DEF_STR(user_filter),
	DEF_STR(pass_attrs),
	DEF_STR(pass_filter),
	DEF_STR(default_pass_scheme),

	{ 0, NULL, 0 }
};

struct ldap_settings default_ldap_settings = {
	MEMBER(hosts) NULL,
	MEMBER(uris) NULL,
	MEMBER(dn) NULL,
	MEMBER(dnpass) NULL,
	MEMBER(auth_bind) FALSE,
	MEMBER(auth_bind_userdn) NULL,
	MEMBER(tls) FALSE,
	MEMBER(sasl_bind) FALSE,
	MEMBER(sasl_mech) NULL,
	MEMBER(sasl_realm) NULL,
	MEMBER(sasl_authz_id) NULL,
	MEMBER(deref) "never",
	MEMBER(scope) "subtree",
	MEMBER(base) NULL,
	MEMBER(ldap_version) 2,
	MEMBER(user_attrs) "homeDirectory=home,uidNumber=uid,gidNumber=gid",
	MEMBER(user_filter) "(&(objectClass=posixAccount)(uid=%u))",
	MEMBER(pass_attrs) "uid=user,userPassword=password",
	MEMBER(pass_filter) "(&(objectClass=posixAccount)(uid=%u))",
	MEMBER(default_pass_scheme) "crypt"
};

static struct ldap_connection *ldap_connections = NULL;

static int db_ldap_bind(struct ldap_connection *conn);
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

static int ldap_get_errno(struct ldap_connection *conn)
{
	int ret, err;

	ret = ldap_get_option(conn->ld, LDAP_OPT_ERROR_NUMBER, (void *) &err);
	if (ret != LDAP_SUCCESS) {
		i_error("LDAP: Can't get error number: %s",
			ldap_err2string(ret));
		return LDAP_UNAVAILABLE;
	}

	return err;
}

const char *ldap_get_error(struct ldap_connection *conn)
{
	return ldap_err2string(ldap_get_errno(conn));
}

void db_ldap_add_delayed_request(struct ldap_connection *conn,
				 struct ldap_request *request)
{
	request->next = NULL;

	if (conn->delayed_requests_head == NULL)
		conn->delayed_requests_head = request;
	else
		conn->delayed_requests_tail->next = request;
	conn->delayed_requests_tail = request;
}

static void db_ldap_handle_next_delayed_request(struct ldap_connection *conn)
{
	struct ldap_request *request;

	if (conn->delayed_requests_head == NULL)
		return;

	request = conn->delayed_requests_head;
	conn->delayed_requests_head = request->next;
	if (conn->delayed_requests_head == NULL)
		conn->delayed_requests_tail = NULL;

	conn->retrying = TRUE;
	if (request->filter == NULL)
		request->callback(conn, request, NULL);
	else
		db_ldap_search(conn, request, conn->set.ldap_scope);
	conn->retrying = FALSE;
}

static void ldap_conn_reconnect(struct ldap_connection *conn)
{
	ldap_conn_close(conn, FALSE);

	if (db_ldap_connect(conn) < 0) {
		/* failed to reconnect. fail all requests. */
		ldap_conn_close(conn, TRUE);
	}
}

static void ldap_handle_error(struct ldap_connection *conn)
{
	int err = ldap_get_errno(conn);

	switch (err) {
	case LDAP_SUCCESS:
		i_unreached();
	case LDAP_SIZELIMIT_EXCEEDED:
	case LDAP_TIMELIMIT_EXCEEDED:
	case LDAP_NO_SUCH_ATTRIBUTE:
	case LDAP_UNDEFINED_TYPE:
	case LDAP_INAPPROPRIATE_MATCHING:
	case LDAP_CONSTRAINT_VIOLATION:
	case LDAP_TYPE_OR_VALUE_EXISTS:
	case LDAP_INVALID_SYNTAX:
	case LDAP_NO_SUCH_OBJECT:
	case LDAP_ALIAS_PROBLEM:
	case LDAP_INVALID_DN_SYNTAX:
	case LDAP_IS_LEAF:
	case LDAP_ALIAS_DEREF_PROBLEM:
	case LDAP_FILTER_ERROR:
		/* invalid input */
		break;
	case LDAP_SERVER_DOWN:
	case LDAP_TIMEOUT:
	case LDAP_UNAVAILABLE:
	case LDAP_BUSY:
#ifdef LDAP_CONNECT_ERROR
	case LDAP_CONNECT_ERROR:
#endif
	case LDAP_LOCAL_ERROR:
	case LDAP_INVALID_CREDENTIALS:
	default:
		/* connection problems */
		ldap_conn_reconnect(conn);
		break;
	}
}

void db_ldap_search(struct ldap_connection *conn, struct ldap_request *request,
		    int scope)
{
	int try, msgid = -1;

	if (db_ldap_connect(conn) < 0) {
		request->callback(conn, request, NULL);
		return;
	}

	for (try = 0; conn->connected && !conn->binding && try < 2; try++) {
		if (conn->last_auth_bind) {
			/* switch back to the default dn before doing the
			   search request. */
			if (db_ldap_bind(conn) < 0) {
				request->callback(conn, request, NULL);
				return;
			}
			break;
		}

		msgid = ldap_search(conn->ld, request->base, scope,
				    request->filter, request->attributes, 0);
		if (msgid != -1)
			break;

		i_error("LDAP: ldap_search() failed (filter %s): %s",
			request->filter, ldap_get_error(conn));
		ldap_handle_error(conn);
	}

	if (msgid != -1)
		hash_insert(conn->requests, POINTER_CAST(msgid), request);
	else
		db_ldap_add_delayed_request(conn, request);
}

static void ldap_conn_retry_requests(struct ldap_connection *conn)
{
	struct hash_table *old_requests;
        struct hash_iterate_context *iter;
	struct ldap_request *request, **p, *next;
	void *key, *value;
	bool have_hash_binds = FALSE;

	i_assert(conn->connected);

	if (hash_count(conn->requests) == 0 &&
	    conn->delayed_requests_head == NULL)
		return;

	old_requests = conn->requests;
	conn->requests = hash_create(default_pool, conn->pool, 0, NULL, NULL);

	conn->retrying = TRUE;
	/* first retry all the search requests */
	iter = hash_iterate_init(old_requests);
	while (hash_iterate(iter, &key, &value)) {
		request = value;

		if (request->filter == NULL) {
			/* bind request */
			have_hash_binds = TRUE;
		} else {
			i_assert(conn->connected);
			db_ldap_search(conn, request, conn->set.ldap_scope);
		}
	}
	hash_iterate_deinit(&iter);

	/* then delayed search requests */
	p = &conn->delayed_requests_head;
	while (*p != NULL) {
		request = *p;

		if (request->filter != NULL) {
			*p = request->next;

			i_assert(conn->connected);
			db_ldap_search(conn, request, conn->set.ldap_scope);
		} else {
			p = &(*p)->next;
		}
	}

	if (have_hash_binds && conn->set.auth_bind) {
		/* next retry all the bind requests. without auth binds the
		   only bind request can be the initial connection binding,
		   which we don't care to retry. */
		iter = hash_iterate_init(old_requests);
		while (hash_iterate(iter, &key, &value)) {
			request = value;

			if (request->filter == NULL)
				request->callback(conn, request, NULL);
		}
		hash_iterate_deinit(&iter);
	}
	if (conn->delayed_requests_head != NULL && conn->set.auth_bind) {
		request = conn->delayed_requests_head;
		for (; request != NULL; request = next) {
			next = request->next;

			i_assert(request->filter == NULL);
			request->callback(conn, request, NULL);
		}
		conn->delayed_requests_head = NULL;
	}
	hash_destroy(&old_requests);

	i_assert(conn->delayed_requests_head == NULL);
	conn->delayed_requests_tail = NULL;
	conn->retrying = FALSE;
}

static void ldap_input(struct ldap_connection *conn)
{
        struct ldap_request *request;
	struct timeval timeout;
	LDAPMessage *res;
	int ret, msgid;

	for (;;) {
		if (conn->ld == NULL)
			return;

		memset(&timeout, 0, sizeof(timeout));
		ret = ldap_result(conn->ld, LDAP_RES_ANY, 1, &timeout, &res);
#ifdef OPENLDAP_ASYNC_WORKAROUND
		if (ret == 0) {
			/* try again, there may be another in buffer */
			ret = ldap_result(conn->ld, LDAP_RES_ANY, 1,
					  &timeout, &res);
		}
#endif
		if (ret <= 0)
			break;

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

	if (ret < 0) {
		i_error("LDAP: ldap_result() failed: %s", ldap_get_error(conn));
		ldap_conn_reconnect(conn);
	} else {
		if (!conn->binding)
			db_ldap_handle_next_delayed_request(conn);
	}
}

#ifdef HAVE_LDAP_SASL
static int
sasl_interact(LDAP *ld ATTR_UNUSED, unsigned flags ATTR_UNUSED,
	      void *defaults, void *interact)
{
	struct ldap_sasl_bind_context *context = defaults;
	sasl_interact_t *in;
	const char *str;

	for (in = interact; in->id != SASL_CB_LIST_END; in++) {
		switch (in->id) {
		case SASL_CB_GETREALM:
			str = context->realm;
			break;
		case SASL_CB_AUTHNAME:
			str = context->authcid;
			break;
		case SASL_CB_USER:
			str = context->authzid;
			break;
		case SASL_CB_PASS:
			str = context->passwd;
			break;
		default:
			str = NULL;
			break;
		}
		if (str != NULL) {
			in->len = strlen(str);
			in->result = str;
		}
		
	}
	return LDAP_SUCCESS;
}
#endif

static int db_ldap_connect_finish(struct ldap_connection *conn, int ret)
{
	if (ret == LDAP_SERVER_DOWN) {
		i_error("LDAP: Can't connect to server: %s",
			conn->set.uris != NULL ?
			conn->set.uris : conn->set.hosts);
		return -1;
	}
	if (ret != LDAP_SUCCESS) {
		i_error("LDAP: binding failed (dn %s): %s",
			conn->set.dn == NULL ? "(none)" : conn->set.dn,
			ldap_get_error(conn));
		return -1;
	}

	if (!conn->connected) {
		conn->connected = TRUE;

		/* in case there are requests waiting, retry them */
		ldap_conn_retry_requests(conn);
	}
	return 0;
}

static void db_ldap_bind_callback(struct ldap_connection *conn,
				  struct ldap_request *ldap_request,
				  LDAPMessage *res)
{
	int ret;

	conn->binding = FALSE;
	conn->connecting = FALSE;
	i_free(ldap_request);

	if (res == NULL) {
		/* aborted */
		return;
	}

	ret = ldap_result2error(conn->ld, res, FALSE);
	if (db_ldap_connect_finish(conn, ret) < 0) {
		/* lost connection, close it */
		ldap_conn_close(conn, TRUE);
	}
}

static int db_ldap_bind(struct ldap_connection *conn)
{
	struct ldap_request *ldap_request;
	int msgid;

	i_assert(!conn->binding);

	ldap_request = i_new(struct ldap_request, 1);
	ldap_request->callback = db_ldap_bind_callback;
	ldap_request->context = conn;

	msgid = ldap_bind(conn->ld, conn->set.dn, conn->set.dnpass,
			  LDAP_AUTH_SIMPLE);
	if (msgid == -1) {
		if (db_ldap_connect_finish(conn, ldap_get_errno(conn)) < 0) {
			/* lost connection, close it */
			ldap_conn_close(conn, TRUE);
		}
		i_free(ldap_request);
		return -1;
	}

	conn->connecting = TRUE;
	conn->binding = TRUE;
	hash_insert(conn->requests, POINTER_CAST(msgid), ldap_request);

	/* we're binding back to the original DN, not doing an
	   authentication bind */
	conn->last_auth_bind = FALSE;
	return 0;
}

static void db_ldap_get_fd(struct ldap_connection *conn)
{
	int ret;

	/* get the connection's fd */
	ret = ldap_get_option(conn->ld, LDAP_OPT_DESC, (void *)&conn->fd);
	if (ret != LDAP_SUCCESS) {
		i_fatal("LDAP: Can't get connection fd: %s",
			ldap_err2string(ret));
	}
	i_assert(conn->fd != -1);
	net_set_nonblock(conn->fd, TRUE);
}

int db_ldap_connect(struct ldap_connection *conn)
{
	unsigned int ldap_version;
	int ret;

	if (conn->connected || conn->connecting)
		return 0;
	i_assert(!conn->binding);

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
				      (void *)&conn->set.ldap_deref);
		if (ret != LDAP_SUCCESS) {
			i_fatal("LDAP: Can't set deref option: %s",
				ldap_err2string(ret));
		}

		/* If SASL binds are used, the protocol version needs to be
		   at least 3 */
		ldap_version = conn->set.sasl_bind &&
			conn->set.ldap_version < 3 ? 3 :
			conn->set.ldap_version;
		ret = ldap_set_option(conn->ld, LDAP_OPT_PROTOCOL_VERSION,
				      (void *)&ldap_version);
		if (ret != LDAP_OPT_SUCCESS) {
			i_fatal("LDAP: Can't set protocol version %u: %s",
				ldap_version, ldap_err2string(ret));
		}
	}

	if (conn->set.tls) {
#ifdef LDAP_HAVE_START_TLS_S
		ret = ldap_start_tls_s(conn->ld, NULL, NULL);
		if (ret != LDAP_SUCCESS) {
			i_error("LDAP: ldap_start_tls_s() failed: %s",
				ldap_err2string(ret));
			return -1;
		}
#else
		i_error("LDAP: Your LDAP library doesn't support TLS");
		return -1;
#endif
	}

	if (conn->set.sasl_bind) {
#ifdef HAVE_LDAP_SASL
		struct ldap_sasl_bind_context context;

		memset(&context, 0, sizeof(context));
		context.authcid = conn->set.dn;
		context.passwd = conn->set.dnpass;
		context.realm = conn->set.sasl_realm;
		context.authzid = conn->set.sasl_authz_id;

		/* There doesn't seem to be a way to do SASL binding
		   asynchronously.. */
		ret = ldap_sasl_interactive_bind_s(conn->ld, NULL,
						   conn->set.sasl_mech,
						   NULL, NULL, LDAP_SASL_QUIET,
						   sasl_interact, &context);
		if (db_ldap_connect_finish(conn, ret) < 0)
			return -1;
		db_ldap_get_fd(conn);
#else
		i_fatal("LDAP: sasl_bind=yes but no SASL support compiled in");
#endif
	} else {
		if (db_ldap_bind(conn) < 0)
			return -1;
		db_ldap_get_fd(conn);
	}

	conn->io = io_add(conn->fd, IO_READ, ldap_input, conn);
	return 0;
}

static void ldap_conn_close(struct ldap_connection *conn, bool flush_requests)
{
	struct hash_iterate_context *iter;
	struct ldap_request *request, *next;
	void *key, *value;

	if (flush_requests) {
		iter = hash_iterate_init(conn->requests);
		while (hash_iterate(iter, &key, &value)) {
			request = value;

			request->callback(conn, request, NULL);
		}
		hash_iterate_deinit(&iter);
		hash_clear(conn->requests, FALSE);

		request = conn->delayed_requests_head;
		for (; request != NULL; request = next) {
			next = request->next;

			request->callback(conn, request, NULL);
		}
		conn->delayed_requests_head = NULL;
		conn->delayed_requests_tail = NULL;
	}

	conn->connected = FALSE;
	conn->binding = FALSE;

	if (conn->io != NULL)
		io_remove(&conn->io);

	if (conn->ld != NULL) {
		ldap_unbind(conn->ld);
		conn->ld = NULL;
	}
	conn->fd = -1;
}

void db_ldap_set_attrs(struct ldap_connection *conn, const char *attrlist,
		       char ***attr_names_r, struct hash_table *attr_map,
		       const char *skip_attr)
{
	const char *const *attr, *attr_data, *p;
	string_t *static_data;
	char *name, *value;
	unsigned int i, j, size;

	if (*attrlist == '\0')
		return;

	t_push();
	attr = t_strsplit(attrlist, ",");
	static_data = t_str_new(128);

	/* @UNSAFE */
	for (size = 0; attr[size] != NULL; size++) ;
	*attr_names_r = p_new(conn->pool, char *, size + 1);

	for (i = j = 0; i < size; i++) {
		/* allow spaces here so "foo=1, bar=2" works */
		attr_data = attr[i];
		while (*attr_data == ' ') attr_data++;

		p = strchr(attr_data, '=');
		if (p == NULL)
			name = value = p_strdup(conn->pool, attr_data);
		else if (p != attr_data) {
			name = p_strdup_until(conn->pool, attr_data, p);
			value = p_strdup(conn->pool, p + 1);
		} else {
			/* =<static key>=<static value> */
			if (str_len(static_data) > 0)
				str_append_c(static_data, ',');
			str_append(static_data, p + 1);
			continue;
		}

		if (*name != '\0' &&
		    (skip_attr == NULL || strcmp(skip_attr, value) != 0)) {
			hash_insert(attr_map, name, value);
			(*attr_names_r)[j++] = name;
		}
	}
	if (str_len(static_data) > 0) {
		hash_insert(attr_map, "",
			    p_strdup(conn->pool, str_c(static_data)));
	}
	t_pop();
}

struct var_expand_table *
db_ldap_value_get_var_expand_table(struct auth_request *auth_request)
{
	const struct var_expand_table *auth_table;
	struct var_expand_table *table;
	unsigned int count;

	auth_table = auth_request_get_var_expand_table(auth_request, NULL);
	for (count = 0; auth_table[count].key != '\0'; count++) ;
	count++;

	table = t_new(struct var_expand_table, count + 1);
	table[0].key = '$';
	memcpy(table + 1, auth_table, sizeof(*table) * count);
	return table;
}

#define IS_LDAP_ESCAPED_CHAR(c) \
	((c) == '*' || (c) == '(' || (c) == ')' || (c) == '\\')

const char *ldap_escape(const char *str,
			const struct auth_request *auth_request ATTR_UNUSED)
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

struct db_ldap_result_iterate_context *
db_ldap_result_iterate_init(struct ldap_connection *conn, LDAPMessage *entry,
			    struct auth_request *auth_request,
			    struct hash_table *attr_map)
{
	struct db_ldap_result_iterate_context *ctx;
	const char *static_data;

	ctx = t_new(struct db_ldap_result_iterate_context, 1);
	ctx->conn = conn;
	ctx->entry = entry;
	ctx->auth_request = auth_request;
	ctx->attr_map = attr_map;

	static_data = hash_lookup(attr_map, "");
	if (static_data != NULL)
		ctx->static_attrs = t_strsplit(static_data, ",");

	if (auth_request->auth->verbose_debug)
		ctx->debug = t_str_new(256);

	ctx->attr = ldap_first_attribute(conn->ld, entry, &ctx->ber);
	return ctx;
}

static void
db_ldap_result_iterate_finish(struct db_ldap_result_iterate_context *ctx)
{
	if (ctx->debug != NULL && str_len(ctx->debug) > 0) {
		auth_request_log_debug(ctx->auth_request, "ldap",
				       "result: %s", str_c(ctx->debug) + 1);
	}

	ber_free(ctx->ber, 0);
}

static void
db_ldap_result_change_attr(struct db_ldap_result_iterate_context *ctx)
{
	ctx->name = hash_lookup(ctx->attr_map, ctx->attr);

	if (ctx->debug != NULL) {
		str_printfa(ctx->debug, " %s(%s)=", ctx->attr,
			    ctx->name != NULL ? ctx->name : "?unknown?");
	}

	if (ctx->name == NULL || *ctx->name == '\0') {
		ctx->value = NULL;
		return;
	}

	if (strchr(ctx->name, '%') != NULL &&
	    (ctx->template = strchr(ctx->name, '=')) != NULL) {
		/* we want to use variables */
		ctx->name = t_strdup_until(ctx->name, ctx->template);
		ctx->template++;
		if (ctx->var_table == NULL) {
			ctx->var_table = db_ldap_value_get_var_expand_table(
							ctx->auth_request);
			ctx->var = t_str_new(256);
		}
	}

	ctx->vals = ldap_get_values(ctx->conn->ld, ctx->entry,
				    ctx->attr);
	ctx->value = ctx->vals[0];
	ctx->value_idx = 0;
}

static void
db_ldap_result_return_value(struct db_ldap_result_iterate_context *ctx)
{
	bool first = ctx->value_idx == 0;

	if (ctx->template != NULL) {
		ctx->var_table[0].value = ctx->value;
		str_truncate(ctx->var, 0);
		var_expand(ctx->var, ctx->template, ctx->var_table);
		ctx->value = str_c(ctx->var);
	}

	if (ctx->debug != NULL) {
		if (!first)
			str_append_c(ctx->debug, '/');
		if (ctx->auth_request->auth->verbose_debug_passwords ||
		    strcmp(ctx->name, "password") != 0)
			str_append(ctx->debug, ctx->value);
		else
			str_append(ctx->debug, PASSWORD_HIDDEN_STR);
	}
}

static bool db_ldap_result_int_next(struct db_ldap_result_iterate_context *ctx)
{
	const char *p;

	while (ctx->attr != NULL) {
		if (ctx->vals == NULL) {
			/* a new attribute */
			db_ldap_result_change_attr(ctx);
		} else {
			/* continuing existing attribute */
			if (ctx->value != NULL)
				ctx->value = ctx->vals[++ctx->value_idx];
		}

		if (ctx->value != NULL) {
			db_ldap_result_return_value(ctx);
			return TRUE;
		}

		ldap_value_free(ctx->vals); ctx->vals = NULL;
		ldap_memfree(ctx->attr);
		ctx->attr = ldap_next_attribute(ctx->conn->ld, ctx->entry,
						ctx->ber);
	}

	if (ctx->static_attrs != NULL && *ctx->static_attrs != NULL) {
		p = strchr(*ctx->static_attrs, '=');
		if (p == NULL) {
			ctx->name = *ctx->static_attrs;
			ctx->value = "";
		} else {
			ctx->name = t_strdup_until(*ctx->static_attrs, p);
			ctx->value = p + 1;
		}
		ctx->static_attrs++;
		return TRUE;
	}

	db_ldap_result_iterate_finish(ctx);
	return FALSE;
}

bool db_ldap_result_iterate_next(struct db_ldap_result_iterate_context *ctx,
				 const char **name_r, const char **value_r)
{
	if (!db_ldap_result_int_next(ctx))
		return FALSE;

	*name_r = ctx->name;
	*value_r = ctx->value;
	return TRUE;
}

bool db_ldap_result_iterate_next_all(struct db_ldap_result_iterate_context *ctx,
				     const char **name_r,
				     const char *const **values_r)
{
	if (!db_ldap_result_int_next(ctx))
		return FALSE;

	if (ctx->template != NULL) {
		/* we can use only one value with templates */
		ctx->val_1_arr[0] = ctx->value;
		*values_r = ctx->val_1_arr;
	} else {
		*values_r = (const char *const *)ctx->vals;
	}
	ctx->value = NULL;
	*name_r = ctx->name;
	return TRUE;
}

static const char *parse_setting(const char *key, const char *value,
				 struct ldap_connection *conn)
{
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

	conn->fd = -1;
	conn->config_path = p_strdup(pool, config_path);
	conn->set = default_ldap_settings;
	if (!settings_read(config_path, NULL, parse_setting,
			   null_settings_section_callback, conn))
		exit(FATAL_DEFAULT);

	if (conn->set.base == NULL)
		i_fatal("LDAP: No base given");

	if (conn->set.uris == NULL && conn->set.hosts == NULL)
		i_fatal("LDAP: No uris or hosts set");
#ifndef LDAP_HAVE_INITIALIZE
	if (conn->set.uris != NULL) {
		i_fatal("LDAP: Dovecot compiled without support for LDAP uris "
			"(ldap_initialize not found)");
	}
#endif

        conn->set.ldap_deref = deref2str(conn->set.deref);
	conn->set.ldap_scope = scope2str(conn->set.scope);

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

	hash_destroy(&conn->requests);
	if (conn->pass_attr_map != NULL)
		hash_destroy(&conn->pass_attr_map);
	if (conn->user_attr_map != NULL)
		hash_destroy(&conn->user_attr_map);
	pool_unref(&conn->pool);
}

#ifndef BUILTIN_LDAP
/* Building a plugin */
extern struct passdb_module_interface passdb_ldap;
extern struct userdb_module_interface userdb_ldap;

void authdb_ldap_init(void);
void authdb_ldap_deinit(void);

void authdb_ldap_init(void)
{
	passdb_register_module(&passdb_ldap);
	userdb_register_module(&userdb_ldap);

}
void authdb_ldap_deinit(void)
{
	passdb_unregister_module(&passdb_ldap);
	userdb_unregister_module(&userdb_ldap);
}
#endif

#endif
