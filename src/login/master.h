#ifndef __MASTER_H
#define __MASTER_H

#include "../master/master-interface.h"

typedef void (*MasterCallback)(enum master_reply_result result, void *context);

/* Request IMAP process for given cookie. */
void master_request_imap(int fd, unsigned int auth_process,
			 const char *login_tag,
			 unsigned char cookie[AUTH_COOKIE_SIZE],
			 struct ip_addr *ip,
			 MasterCallback callback, void *context);

/* Notify master that we're not listening for new connections anymore. */
void master_notify_finished(void);

/* Close connection to master process */
void master_close(void);

void master_init(void);
void master_deinit(void);

#endif
