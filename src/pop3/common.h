#ifndef COMMON_H
#define COMMON_H

#include "lib.h"
#include "client.h"

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

extern struct ioloop *ioloop;
extern enum client_workarounds client_workarounds;
extern bool enable_last_command, no_flag_updates, reuse_xuidl, lock_session;
extern const char *uidl_format, *logout_format;
extern enum uidl_keys uidl_keymask;

extern void (*hook_client_created)(struct client **client);

#endif
