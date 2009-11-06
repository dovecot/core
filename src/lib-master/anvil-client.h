#ifndef ANVIL_CLIENT_H
#define ANVIL_CLIENT_H

/* reply=NULL if query failed */
typedef void anvil_callback_t(const char *reply, void *context);

/* If reconnect_callback is specified, it's called when connection is lost.
   If the callback returns FALSE, reconnection isn't attempted. */
struct anvil_client *
anvil_client_init(const char *path, bool (*reconnect_callback)(void));
void anvil_client_deinit(struct anvil_client **client);

/* Connect to anvil. If retry=TRUE, try connecting for a while */
int anvil_client_connect(struct anvil_client *client, bool retry);

/* Send a query to anvil, expect a one line reply. */
void anvil_client_query(struct anvil_client *client, const char *query,
			anvil_callback_t *callback, void *context);

#endif
