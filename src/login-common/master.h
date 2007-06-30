#ifndef __MASTER_H
#define __MASTER_H

struct client;

#include "../master/master-login-interface.h"

typedef void master_callback_t(struct client *client,
			       enum master_login_status status);

void master_request_login(struct client *client, master_callback_t *callback,
			  unsigned int auth_pid, unsigned int auth_id);
void master_request_abort(struct client *client);

/* Notify master of a change in our state */
void master_notify_state_change(enum master_login_state state);

/* Close connection to master process */
void master_close(void);

/* inetd: Connect to existing master process, or create new one. */
int master_connect(const char *group_name);

void master_init(int fd);
void master_deinit(void);

#endif
