/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"

#ifdef USERDB_LDAP

#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "auth-cache.h"
#include "db-ldap.h"
#include "userdb.h"

#include <ldap.h>
#include <stdlib.h>

struct ldap_userdb_module {
	struct userdb_module module;

	struct ldap_connection *conn;
};

struct userdb_ldap_request {
	struct ldap_request request;
        struct auth_request *auth_request;
        userdb_callback_t *userdb_callback;
};

static const char *default_attr_map[] = {
	"", "home", "mail", "system_user", "uid", "gid", NULL
};

static bool append_uid_list(struct auth_request *auth_request,
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

static bool append_gid_list(struct auth_request *auth_request,
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
	bool seen_uid = FALSE, seen_gid = FALSE;

	reply = auth_stream_reply_init(auth_request);
	auth_stream_reply_add(reply, NULL, auth_request->user);

	attr = ldap_first_attribute(conn->ld, entry, &ber);
	while (attr != NULL) {
		name = hash_lookup(conn->user_attr_map, attr);
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
			} else if (*name != '\0') {
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
	ber_free(ber, 0);

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
	enum userdb_result result = USERDB_RESULT_INTERNAL_FAILURE;
	int ret;

	if (res != NULL) {
		ret = ldap_result2error(conn->ld, res, 0);
		if (ret != LDAP_SUCCESS) {
			auth_request_log_error(auth_request, "ldap",
					       "ldap_search() failed: %s", ldap_err2string(ret));
			urequest->userdb_callback(result, NULL, auth_request);
			return;
		}
	}

	entry = res == NULL ? NULL : ldap_first_entry(conn->ld, res);
	if (entry == NULL) {
		if (res != NULL) {
			result = USERDB_RESULT_USER_UNKNOWN;
			auth_request_log_error(auth_request, "ldap",
					       "Unknown user");
		}
	} else {
		reply = ldap_query_get_result(conn, entry, auth_request);
		if (ldap_next_entry(conn->ld, entry) == NULL)
			result = USERDB_RESULT_OK;
		else {
			auth_request_log_error(auth_request, "ldap",
				"Multiple replies found for user");
			reply = NULL;
		}
	}

	urequest->userdb_callback(result, reply, auth_request);
	auth_request_unref(&auth_request);
}

static void userdb_ldap_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct ldap_userdb_module *module =
		(struct ldap_userdb_module *)_module;
	struct ldap_connection *conn = module->conn;
        const struct var_expand_table *vars;
	const char **attr_names = (const char **)conn->user_attr_names;
	struct userdb_ldap_request *request;
	string_t *str;

	auth_request_ref(auth_request);
	request = p_new(auth_request->pool, struct userdb_ldap_request, 1);
	request->request.callback = handle_request;
	request->auth_request = auth_request;
	request->userdb_callback = callback;

	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);

	str = t_str_new(512);
	var_expand(str, conn->set.base, vars);
	request->request.base = p_strdup(auth_request->pool, str_c(str));

	str_truncate(str, 0);
	var_expand(str, conn->set.user_filter, vars);
	request->request.filter = p_strdup(auth_request->pool, str_c(str));

	request->request.attributes = conn->user_attr_names;

	auth_request_log_debug(auth_request, "ldap", "user search: "
			       "base=%s scope=%s filter=%s fields=%s",
			       request->request.base, conn->set.scope,
			       request->request.filter,
			       attr_names == NULL ? "(all)" :
			       t_strarray_join(attr_names, ","));

	db_ldap_search(conn, &request->request, conn->set.ldap_scope);
}

static struct userdb_module *
userdb_ldap_preinit(struct auth_userdb *auth_userdb, const char *args)
{
	struct ldap_userdb_module *module;
	struct ldap_connection *conn;

	module = p_new(auth_userdb->auth->pool, struct ldap_userdb_module, 1);
	module->conn = conn = db_ldap_init(args);
	conn->user_attr_map =
		hash_create(default_pool, conn->pool, 0, str_hash,
			    (hash_cmp_callback_t *)strcmp);

	db_ldap_set_attrs(conn, conn->set.user_attrs, &conn->user_attr_names,
			  conn->user_attr_map, default_attr_map, NULL);
	module->module.cache_key =
		auth_cache_parse_key(auth_userdb->auth->pool,
				     conn->set.user_filter);
	return &module->module;
}

static void userdb_ldap_init(struct userdb_module *_module,
			     const char *args __attr_unused__)
{
	struct ldap_userdb_module *module =
		(struct ldap_userdb_module *)_module;

	(void)db_ldap_connect(module->conn);
}

static void userdb_ldap_deinit(struct userdb_module *_module)
{
	struct ldap_userdb_module *module =
		(struct ldap_userdb_module *)_module;

	db_ldap_unref(&module->conn);
}

struct userdb_module_interface userdb_ldap = {
	"ldap",

	userdb_ldap_preinit,
	userdb_ldap_init,
	userdb_ldap_deinit,

	userdb_ldap_lookup
};

#endif
