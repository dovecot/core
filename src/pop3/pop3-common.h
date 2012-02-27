#ifndef POP3_COMMON_H
#define POP3_COMMON_H

enum uidl_keys {
	UIDL_UIDVALIDITY	= 0x01,
	UIDL_UID		= 0x02,
	UIDL_MD5		= 0x04,
	UIDL_FILE_NAME		= 0x08,
	UIDL_GUID		= 0x10
};

#include "lib.h"
#include "pop3-client.h"
#include "pop3-settings.h"

typedef void pop3_client_created_func_t(struct client **client);

extern pop3_client_created_func_t *hook_client_created;

/* Sets the hook_client_created and returns the previous hook,
   which the new_hook should call if it's non-NULL. */
pop3_client_created_func_t *
pop3_client_created_hook_set(pop3_client_created_func_t *new_hook);

void pop3_refresh_proctitle(void);

#endif
