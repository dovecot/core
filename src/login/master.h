#ifndef __MASTER_H
#define __MASTER_H

#include "../master/master-interface.h"

typedef void (*MasterCallback)(MasterReplyResult result, void *user_data);

/* Request IMAP process for given cookie. */
void master_request_imap(int fd, int auth_process, const char *login_tag,
			 unsigned char cookie[AUTH_COOKIE_SIZE],
			 MasterCallback callback, void *user_data);

void master_init(void);
void master_deinit(void);

#endif
