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
	const char *user;
	const char *pass;
	const char *deref;
	const char *base;
	const char *attrs;
	const char *filter;

	int ldap_deref;
};

struct ldap_connection {
	pool_t pool;
	int refcount;

	char *config_path;
        struct ldap_settings set;

	LDAP *ld;
	struct io *io;
	struct hash_table *requests;

	unsigned int connected:1;
};

struct ldap_request {
	db_search_callback_t *callback;
	void *context;
};

void db_ldap_search(struct ldap_connection *conn, const char *base, int scope,
		    const char *filter, char **attributes,
		    struct ldap_request *request);

void db_ldap_set_attrs(struct ldap_connection *conn, const char *value,
		       unsigned int **attrs, char ***attr_names);

struct ldap_connection *db_ldap_init(const char *config_path);
void db_ldap_unref(struct ldap_connection *conn);

#endif
