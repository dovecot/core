/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ldap-connection-pool.h"
#include "ldap-private.h"

/* Max number of ldap-connections that can be created. For now this is
   unlimited since we're assuming our callers aren't calling us with many
   different settings. */
#define LDAP_CONN_POOL_MAX_CONNECTIONS UINT_MAX

struct ldap_client {
	struct ldap_connection_list *list;
};

static struct ldap_connection_pool *ldap_conn_pool = NULL;

int ldap_client_init(const struct ldap_client_settings *set,
		     struct ldap_client **client_r, const char **error_r)
{
	struct ldap_client *client;

	if (ldap_conn_pool == NULL)
		ldap_conn_pool = ldap_connection_pool_init(LDAP_CONN_POOL_MAX_CONNECTIONS);

	client = i_new(struct ldap_client, 1);
	if (ldap_connection_pool_get(ldap_conn_pool, client, set,
				     &client->list, error_r) < 0) {
		i_free(client);
		return -1;
	}
	*client_r = client;
	return 0;
}

void ldap_client_deinit(struct ldap_client **_client)
{
	struct ldap_client *client = *_client;

	*_client = NULL;

	ldap_connection_pool_unref(ldap_conn_pool, &client->list);
	i_free(client);
}

void ldap_client_switch_ioloop(struct ldap_client *client)
{
	ldap_connection_switch_ioloop(client->list->conn);
}

#undef ldap_search_start
void ldap_search_start(struct ldap_client *client,
		       const struct ldap_search_input *input,
		       ldap_result_callback_t *callback, void *context)
{
	/* FIXME: we could support multiple concurrent LDAP connections to
	   the same host. */
	return ldap_connection_search_start(client->list->conn, input, callback, context);
}

#undef ldap_compare_start
void ldap_compare_start(struct ldap_client *client,
			const struct ldap_compare_input *input,
			ldap_result_callback_t *callback, void *context)
{
	return ldap_connection_compare_start(client->list->conn, input, callback, context);
}

void ldap_clients_cleanup(void)
{
	if (ldap_conn_pool != NULL &&
	    !ldap_connection_pool_have_references(ldap_conn_pool))
		ldap_connection_pool_deinit(&ldap_conn_pool);
}
