#ifndef __MASTER_H
#define __MASTER_H

struct client;

#include "../master/master-login-interface.h"

typedef void master_callback_t(struct client *client, int success);

void master_request_imap(struct client *client, master_callback_t *callback,
			 unsigned int auth_pid, unsigned int auth_id);

/* Notify master that we're not listening for new connections anymore. */
void master_notify_finished(void);

/* Close connection to master process */
void master_close(void);

void master_init(void);
void master_deinit(void);

#endif
