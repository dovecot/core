/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"

#ifdef USERDB_LDAP

#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "db-ldap.h"
#include "userdb.h"

#include <ldap.h>
#include <stdlib.h>

static const char *default_attr_map[] = {
	"", "home", "mail", "system_user", "uid", "gid", NULL
};

struct userdb_ldap_request {
	struct ldap_request request;
        struct auth_request *auth_request;
        userdb_callback_t *userdb_callback;
};

static struct ldap_connection *userdb_ldap_conn;

static int append_uid_list(struct auth_request *auth_request,
                           struct auth_stream_reply *reply,
			   const char *name, char **vals)
{
	uid_t uid;

	for (; *vals != NULL; vals++) {
		uid = userdb_parse_uid(auth_request, *vals);
		if (uid == (uid_t)-1)
			return FALSE;

		auth_stream_reply_add(reply, name, dec2str(uid));
	}

	return TRUE;
}

static int append_gid_list(struct auth_request *auth_request,
                           struct auth_stream_reply *reply,
			   const char *name, char **vals)
{
	gid_t gid;

	for (; *vals != NULL; vals++) {
		gid = userdb_parse_gid(auth_request, *vals);
		if (gid == (gid_t)-1)
			return FALSE;

		auth_stream_reply_add(reply, name, dec2str(gid));
	}

	return TRUE;
}

static struct auth_stream_reply *
ldap_query_get_result(struct ldap_connection *conn, LDAPMessage *entry,
		      struct auth_request *auth_request)
{
	struct auth_stream_reply *reply;
	BerElement *ber;
	const char *name;
	char *attr, **vals;
	unsigned int i;
	int seen_uid = FALSE, seen_gid = FALSE;

	reply = auth_stream_reply_init(auth_request);
	auth_stream_reply_add(reply, NULL, auth_request->user);

	attr = ldap_first_attribute(conn->ld, entry, &ber);
	while (attr != NULL) {
		name = hash_lookup(userdb_ldap_conn->user_attr_map, attr);
		vals = ldap_get_values(conn->ld, entry, attr);

		if (name != NULL && vals != NULL && vals[0] != NULL) {
			if (strcmp(name, "uid") == 0) {
				if (!append_uid_list(auth_request, reply,
						     name, vals))
					return NULL;
				seen_uid = TRUE;
			} else if (strcmp(name, "gid") == 0) {
				if (!append_gid_list(auth_request, reply,
						     name, vals)) 
					return NULL;
				seen_gid = TRUE;
			} else {
				for (i = 0; vals[i] != NULL; i++) {
					auth_stream_reply_add(reply, name,
							      vals[i]);
				}
			}
		}
		ldap_value_free(vals);
		ldap_memfree(attr);

		attr = ldap_next_attribute(conn->ld, entry, ber);
	}

	if (!seen_uid) {
		if (conn->set.uid == (uid_t)-1) {
			auth_request_log_error(auth_request, "ldap",
				"uid not in user_attrs and no default given in "
				"user_global_uid");
			return NULL;
		}

		auth_stream_reply_add(reply, "uid", dec2str(conn->set.uid));
	}
	if (!seen_gid) {
		if (conn->set.gid == (gid_t)-1) {
			auth_request_log_error(auth_request, "ldap",
				"gid not in user_attrs and no default given in "
				"user_global_gid");
			return NULL;
		}

		auth_stream_reply_add(reply, "gid", dec2str(conn->set.gid));
	}

	return reply;
}

static void handle_request(struct ldap_connection *conn,
			   struct ldap_request *request, LDAPMessage *res)
{
	struct userdb_ldap_request *urequest =
		(struct userdb_ldap_request *) request;
	struct auth_request *auth_request = urequest->auth_request;
	LDAPMessage *entry;
	struct auth_stream_reply *reply = NULL;
	int ret;

	ret = ldap_result2error(conn->ld, res, 0);
	if (ret != LDAP_SUCCESS) {
		auth_request_log_error(auth_request, "ldap",
			"ldap_search() failed: %s", ldap_err2string(ret));
		urequest->userdb_callback(NULL, auth_request);
		return;
	}

	entry = res == NULL ? NULL : ldap_first_entry(conn->ld, res);
	if (entry == NULL) {
		if (res != NULL) {
			auth_request_log_error(auth_request, "ldap",
					       "Authenticated user not found");
		}
	} else {
		reply = ldap_query_get_result(conn, entry, auth_request);
		if (ldap_next_entry(conn->ld, entry) != NULL) {
			auth_request_log_error(auth_request, "ldap",
				"Multiple replies found for user");
			reply = NULL;
		}
	}

	urequest->userdb_callback(reply, auth_request);
}

static void userdb_ldap_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct ldap_connection *conn = userdb_ldap_conn;
        const struct var_expand_table *vars;
	const char **attr_names =
		(const char **)userdb_ldap_conn->user_attr_names;
	struct userdb_ldap_request *request;
	const char *filter, *base;
	string_t *str;

	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);

	str = t_str_new(512);
	var_expand(str, conn->set.base, vars);
	base = t_strdup(str_c(str));

	str_truncate(str, 0);
	var_expand(str, conn->set.user_filter, vars);
	filter = str_c(str);

	request = p_new(auth_request->pool, struct userdb_ldap_request, 1);
	request->request.callback = handle_request;
	request->auth_request = auth_request;
	request->userdb_callback = callback;

	auth_request_log_debug(auth_request, "ldap",
			       "base=%s scope=%s filter=%s fields=%s",
			       base, conn->set.scope, filter,
			       t_strarray_join(attr_names, ","));

	db_ldap_search(conn, base, conn->set.ldap_scope,
		       filter, userdb_ldap_conn->user_attr_names,
		       &request->request);
}

static void userdb_ldap_preinit(const char *args)
{
	userdb_ldap_conn = db_ldap_init(args);
	userdb_ldap_conn->user_attr_map =
		hash_create(default_pool, userdb_ldap_conn->pool, 0, str_hash,
			    (hash_cmp_callback_t *)strcmp);

	db_ldap_set_attrs(userdb_ldap_conn, userdb_ldap_conn->set.user_attrs,
                          &userdb_ldap_conn->user_attr_names,
			  userdb_ldap_conn->user_attr_map,
			  default_attr_map);
}

static void userdb_ldap_init(const char *args __attr_unused__)
{
	(void)db_ldap_connect(userdb_ldap_conn);
}

static void userdb_ldap_deinit(void)
{
	db_ldap_unref(userdb_ldap_conn);
}

struct userdb_module userdb_ldap = {
	"ldap",
	FALSE,

	userdb_ldap_preinit,
	userdb_ldap_init,
	userdb_ldap_deinit,

	userdb_ldap_lookup
};

#endif
