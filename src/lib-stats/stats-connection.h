#ifndef STATS_CONNECTION_H
#define STATS_CONNECTION_H

struct stats_connection *stats_connection_create(const char *path);
void stats_connection_ref(struct stats_connection *conn);
void stats_connection_unref(struct stats_connection **conn);

/* Returns 0 on success, -1 on failure. */
int stats_connection_send(struct stats_connection *conn, const string_t *str);

#endif
