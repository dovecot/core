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

extern void (*hook_client_created)(struct client **client);

void pop3_refresh_proctitle(void);

#endif
