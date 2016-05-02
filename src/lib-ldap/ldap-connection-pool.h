#ifndef LDAP_CONNECTION_POOL_H
#define LDAP_CONNECTION_POOL_H

struct ldap_client;
struct ldap_client_settings;

struct ldap_connection_list {
	struct ldap_connection_list *prev, *next;
	struct ldap_connection *conn;
	int refcount;
};

struct ldap_connection_pool *
ldap_connection_pool_init(unsigned int max_connections);
void ldap_connection_pool_deinit(struct ldap_connection_pool **_pool);
/* Returns TRUE if there are connections with refcount>0 */
bool ldap_connection_pool_have_references(struct ldap_connection_pool *pool);

int ldap_connection_pool_get(struct ldap_connection_pool *pool,
			     struct ldap_client *client,
			     const struct ldap_client_settings *set,
			     struct ldap_connection_list **list_r,
			     const char **error_r);
void ldap_connection_pool_unref(struct ldap_connection_pool *pool,
				struct ldap_connection_list **list);

#endif
