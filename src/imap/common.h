#ifndef COMMON_H
#define COMMON_H

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (60*30*1000)

/* If we can't send anything to client for this long, disconnect the client */
#define CLIENT_OUTPUT_TIMEOUT_MSECS (5*60*1000)

/* Stop buffering more data into output stream after this many bytes */
#define CLIENT_OUTPUT_OPTIMAL_SIZE 2048

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

enum client_workarounds {
	WORKAROUND_DELAY_NEWMAIL		= 0x01,
	WORKAROUND_NETSCAPE_EOH			= 0x04,
	WORKAROUND_TB_EXTRA_MAILBOX_SEP		= 0x08
};

#include "lib.h"
#include "client.h"
#include "imap-settings.h"

extern struct ioloop *ioloop;

extern void (*hook_client_created)(struct client **client);

#endif
