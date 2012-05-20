#ifndef REPLICATOR_CONNECTION_H
#define REPLICATOR_CONNECTION_H

#include "replication-common.h"

typedef void replicator_sync_callback_t(bool success, void *context);

struct replicator_connection *
replicator_connection_create_unix(const char *path,
				  replicator_sync_callback_t *callback);
struct replicator_connection *
replicator_connection_create_inet(const struct ip_addr *ips,
				  unsigned int ips_count, unsigned int port,
				  replicator_sync_callback_t *callback);
void replicator_connection_destroy(struct replicator_connection **conn);

void replicator_connection_notify(struct replicator_connection *conn,
				  const char *username,
				  enum replication_priority priority);
void replicator_connection_notify_sync(struct replicator_connection *conn,
				       const char *username, void *context);

extern struct replicator_connection *replicator;

#endif
