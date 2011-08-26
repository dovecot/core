#ifndef STATS_CONNECTION_H
#define STATS_CONNECTION_H

struct mail_stats;
struct mail_user;

struct stats_connection *stats_connection_create(const char *path);
void stats_connection_ref(struct stats_connection *conn);
void stats_connection_unref(struct stats_connection **conn);

void stats_connection_connect(struct stats_connection *conn,
			      struct mail_user *user);
void stats_connection_disconnect(struct stats_connection *conn,
				 struct mail_user *user);

void stats_connection_send_session(struct stats_connection *conn,
				   struct mail_user *user,
				   const struct mail_stats *stats);
void stats_connection_send(struct stats_connection *conn, const string_t *str);

#endif
