#ifndef MAIL_STATS_CONNECTION_H
#define MAIL_STATS_CONNECTION_H

#include "stats-connection.h"

struct mail_stats;
struct mail_user;

int mail_stats_connection_connect(struct stats_connection *conn,
				  struct mail_user *user);
void mail_stats_connection_disconnect(struct stats_connection *conn,
				      struct mail_user *user);

void mail_stats_connection_send_session(struct stats_connection *conn,
					struct mail_user *user,
					const struct stats *stats);
void mail_stats_connection_send(struct stats_connection *conn, const string_t *str);

#endif
