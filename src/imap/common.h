#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "client.h"

/* Disconnect client after idling this many seconds */
#define CLIENT_IDLE_TIMEOUT (60*30)

/* If we can't send anything to client for this long, disconnect the client */
#define CLIENT_OUTPUT_TIMEOUT (5*60)

/* Stop buffering more data into output stream after this many bytes */
#define CLIENT_OUTPUT_OPTIMAL_SIZE 2048

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

/* RFC-2683 recommends at least 8000 bytes. Some clients however don't
   break large message sets to multiple commands, so we're pretty liberal
   by default. */
#define DEFAULT_IMAP_MAX_LINE_LENGTH 65536

#define DEFAULT_MAX_KEYWORD_LENGTH 50

enum client_workarounds {
	WORKAROUND_DELAY_NEWMAIL		= 0x01,
	WORKAROUND_OUTLOOK_IDLE			= 0x02,
	WORKAROUND_NETSCAPE_EOH			= 0x04,
	WORKAROUND_TB_EXTRA_MAILBOX_SEP		= 0x08
};

extern struct ioloop *ioloop;
extern unsigned int max_keyword_length;
extern unsigned int imap_max_line_length;
extern enum client_workarounds client_workarounds;
extern const char *logout_format;

extern string_t *capability_string;

extern void (*hook_client_created)(struct client **client);

#endif
