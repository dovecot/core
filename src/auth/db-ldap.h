#ifndef __DB_LDAP_H
#define __DB_LDAP_H

#include <ldap.h>

struct ldap_connection;
struct ldap_request;

typedef void db_search_callback_t(struct ldap_connection *conn,
				  struct ldap_request *request,
				  LDAPMessage *res);

struct ldap_settings {
	const char *hosts;
	const char *uris;
	const char *dn;
	const char *dnpass;
	const char *deref;
	const char *scope;
	const char *base;
	unsigned int ldap_version;

	const char *user_attrs;
	const char *user_filter;
	const char *pass_attrs;
	const char *pass_filter;

	const char *default_pass_scheme;
	unsigned int user_global_uid;
	unsigned int user_global_gid;

	int ldap_deref, ldap_scope;
};

struct ldap_connection {
	struct ldap_connection *next;

	pool_t pool;
	int refcount;

	char *config_path;
        struct ldap_settings set;

	LDAP *ld;
	struct io *io;
	struct hash_table *requests;

	char **attr_names;
	struct hash_table *attr_map;

	unsigned int connected:1;
};

struct ldap_request {
	db_search_callback_t *callback;
	void *context;
};

void db_ldap_search(struct ldap_connection *conn, const char *base, int scope,
		    const char *filter, char **attributes,
		    struct ldap_request *request);

void db_ldap_set_attrs(struct ldap_connection *conn, const char *attrlist,
		       const char *const default_attr_map[]);

struct ldap_connection *db_ldap_init(const char *config_path);
void db_ldap_unref(struct ldap_connection *conn);

int db_ldap_connect(struct ldap_connection *conn);

const char *ldap_escape(const char *str);
const char *ldap_get_error(struct ldap_connection *conn);

#endif
