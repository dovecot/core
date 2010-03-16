#ifndef AUTH_WORKER_CLIENT_H
#define AUTH_WORKER_CLIENT_H

#define AUTH_WORKER_PROTOCOL_MAJOR_VERSION 1
#define AUTH_WORKER_PROTOCOL_MINOR_VERSION 0
#define AUTH_WORKER_MAX_LINE_LENGTH 8192

extern struct auth_worker_client *auth_worker_client;

struct auth_worker_client *auth_worker_client_create(struct auth *auth, int fd);
void auth_worker_client_destroy(struct auth_worker_client **client);
void auth_worker_client_unref(struct auth_worker_client **client);

#endif
