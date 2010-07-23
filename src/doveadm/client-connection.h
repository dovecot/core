#ifndef CLIENT_CONNECTION_H
#define CLIENT_CONNECTION_H

struct client_connection *client_connection_create(int fd, int listen_fd);
void client_connection_destroy(struct client_connection **conn);

struct ostream *client_connection_get_output(struct client_connection *conn);

#endif
