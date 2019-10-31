#ifndef AUTH_CONNECTION_H
#define AUTH_CONNECTION_H

struct director;

/* Called for each input line. This is also called with line=NULL if
   connection gets disconnected. */
typedef void auth_input_callback(const char *line, void *context);

struct auth_connection *
auth_connection_init(struct director *dir, const char *path);
void auth_connection_deinit(struct auth_connection **conn);

void auth_connection_set_callback(struct auth_connection *conn,
				  auth_input_callback *callback, void *context);

/* Start connecting. Returns 0 if ok, -1 if connect failed. */
int auth_connection_connect(struct auth_connection *conn);
/* Get auth connection's output stream. */
struct ostream *auth_connection_get_output(struct auth_connection *conn);

void auth_connections_deinit(void);

#endif
