#ifndef DIRECTOR_CONNECTION_H
#define DIRECTOR_CONNECTION_H

struct director_host;
struct director;

struct director_connection *
director_connection_init_in(struct director *dir, int fd,
			    const struct ip_addr *ip);
struct director_connection *
director_connection_init_out(struct director *dir, int fd,
			     struct director_host *host);
void director_connection_deinit(struct director_connection **conn);

void director_connection_send(struct director_connection *conn,
			      const char *data);
void director_connection_wait_sync(struct director_connection *conn);
void director_connection_send_except(struct director_connection *conn,
				     struct director_host *skip_host,
				     const char *data);

const char *director_connection_get_name(struct director_connection *conn);
struct director_host *
director_connection_get_host(struct director_connection *conn);
struct director_connection *
director_connection_find_outgoing(struct director *dir,
				  struct director_host *host);

void director_connection_cork(struct director_connection *conn);
void director_connection_uncork(struct director_connection *conn);

void director_connections_deinit(struct director *dir);

#endif
