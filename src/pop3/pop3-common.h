#ifndef POP3_COMMON_H
#define POP3_COMMON_H

enum client_workarounds {
	WORKAROUND_OUTLOOK_NO_NULS		= 0x01,
	WORKAROUND_OE_NS_EOH			= 0x02
};

enum uidl_keys {
	UIDL_UIDVALIDITY	= 0x01,
	UIDL_UID		= 0x02,
	UIDL_MD5		= 0x04,
	UIDL_FILE_NAME		= 0x08
};

#include "lib.h"
#include "pop3-client.h"
#include "pop3-settings.h"

extern void (*hook_client_created)(struct client **client);

#endif
