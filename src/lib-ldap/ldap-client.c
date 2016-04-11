/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ldap-private.h"

struct ldap_client {
	/* for now we support just a single connection, but this could be
	   extended to a connection pool. */
	struct ldap_connection *conn;
};

int ldap_client_init(const struct ldap_client_settings *set,
		     struct ldap_client **client_r, const char **error_r)
{
	struct ldap_client *client;

	client = i_new(struct ldap_client, 1);
	if (ldap_connection_init(client, set, &client->conn, error_r) < 0) {
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

	ldap_connection_deinit(&client->conn);
	i_free(client);
}

void ldap_client_switch_ioloop(struct ldap_client *client)
{
	ldap_connection_switch_ioloop(client->conn);
}

#undef ldap_search_start
void ldap_search_start(struct ldap_client *client,
		       const struct ldap_search_input *input,
		       ldap_result_callback_t *callback, void *context)
{
	return ldap_connection_search_start(client->conn, input, callback, context);
}

#undef ldap_compare_start
void ldap_compare_start(struct ldap_client *client,
			const struct ldap_compare_input *input,
			ldap_result_callback_t *callback, void *context)
{
	return ldap_connection_compare_start(client->conn, input, callback, context);
}
