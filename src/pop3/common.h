#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "client.h"

enum client_workarounds {
	WORKAROUND_OUTLOOK_NO_NULS		= 0x01
};

extern struct ioloop *ioloop;
extern enum client_workarounds client_workarounds;

extern void (*hook_mail_storage_created)(struct mail_storage **storage);
extern void (*hook_client_created)(struct client **client);

#endif
