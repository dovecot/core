#ifndef __AUTH_REQUEST_BALANCER_H
#define __AUTH_REQUEST_BALANCER_H

#include "auth-client-interface.h"

#define AUTH_BALANCER_MAX_LINE_LENGTH \
        (AUTH_CLIENT_MAX_LINE_LENGTH + 64)

struct auth_request_handler;

void auth_request_balancer_add_child(int fd);
void auth_request_balancer_add_worker(struct auth *auth, int fd);
void auth_request_balancer_worker_destroy(struct auth_balancer_worker *worker);

void auth_request_balancer_add_handler(struct auth_request_handler *handler,
				       unsigned int connect_uid);
void auth_request_balancer_remove_handler(unsigned int connect_uid);

unsigned int auth_request_balancer_send(const char *line);
void auth_request_balancer_send_to(unsigned int id, const char *line);

void auth_request_handler_balancer_reply(struct auth_request_handler *handler,
					 const char *line);

void auth_request_balancer_child_init(void);
void auth_request_balancer_child_deinit(void);

void auth_request_balancer_worker_init(struct auth *auth);
void auth_request_balancer_worker_deinit(void);

#endif
