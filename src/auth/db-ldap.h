#ifndef __DB_LDAP_H
#define __DB_LDAP_H

/* Functions like ldap_bind() have been deprecated in OpenLDAP 2.3
   This define enables them until the code here can be refactored */
#define LDAP_DEPRECATED 1

#include <ldap.h>

struct auth_request;
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
	bool auth_bind;
	const char *auth_bind_userdn;

	bool tls;
	bool sasl_bind;
	const char *sasl_mech;
	const char *sasl_realm;
	const char *sasl_authz_id;

	const char *deref;
	const char *scope;
	const char *base;
	unsigned int ldap_version;

	const char *user_attrs;
	const char *user_filter;
	const char *pass_attrs;
	const char *pass_filter;

	const char *default_pass_scheme;

	/* ... */
	int ldap_deref, ldap_scope;
	uid_t uid;
	gid_t gid;
};

struct ldap_connection {
	struct ldap_connection *next;

	pool_t pool;
	int refcount;

	char *config_path;
        struct ldap_settings set;

	LDAP *ld;
	int fd; /* only set when connected/connecting */
	struct io *io;

	struct hash_table *requests;
	struct ldap_request *delayed_requests_head, *delayed_requests_tail;

	char **pass_attr_names, **user_attr_names;
	struct hash_table *pass_attr_map, *user_attr_map;

	unsigned int connected:1;
	unsigned int connecting:1;
	unsigned int binding:1;
	unsigned int retrying:1; /* just reconnected, resending requests */
	unsigned int last_auth_bind:1;
};

struct ldap_request {
	struct ldap_request *next; /* in conn->delayed_requests */

	db_search_callback_t *callback;
	void *context;

	/* for bind requests, base contains the DN and filter=NULL */
	const char *base;
	const char *filter;
	char **attributes; /* points to pass_attr_names / user_attr_names */
};

struct ldap_sasl_bind_context {
	const char *authcid;
	const char *passwd;
	const char *realm;
	const char *authzid;
};

void db_ldap_add_delayed_request(struct ldap_connection *conn,
				 struct ldap_request *request);
void db_ldap_search(struct ldap_connection *conn, struct ldap_request *request,
		    int scope);

void db_ldap_set_attrs(struct ldap_connection *conn, const char *attrlist,
		       char ***attr_names_r, struct hash_table *attr_map,
		       const char *const default_attr_map[],
		       const char *skip_attr);

struct ldap_connection *db_ldap_init(const char *config_path);
void db_ldap_unref(struct ldap_connection **conn);

int db_ldap_connect(struct ldap_connection *conn);

const char *ldap_escape(const char *str,
			const struct auth_request *auth_request);
const char *ldap_get_error(struct ldap_connection *conn);

#endif
