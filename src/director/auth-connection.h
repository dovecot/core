#ifndef AUTH_CONNECTION_H
#define AUTH_CONNECTION_H

/* Called for each input line. This is also called with line=NULL if
   connection gets disconnected. */
typedef void auth_input_callback(const char *line, void *context);

struct auth_connection *auth_connection_init(const char *path);
void auth_connection_deinit(struct auth_connection **conn);

void auth_connection_set_callback(struct auth_connection *conn,
				  auth_input_callback *callback, void *context);

/* Start connecting. Returns 0 if ok, -1 if connect failed. */
int auth_connection_connect(struct auth_connection *conn);
/* Send data to auth connection. */
void auth_connection_send(struct auth_connection *conn,
			  const void *data, size_t size);

void auth_connections_deinit(void);

#endif
