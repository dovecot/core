#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "client.h"

/* Disconnect client after idling this many seconds */
#define CLIENT_IDLE_TIMEOUT (60*30)

/* RFC-2683 recommends at least 8000 bytes. Some clients however don't
   break large message sets to multiple commands, so we're pretty liberal
   by default. */
#define DEFAULT_IMAP_MAX_LINE_LENGTH 65536

#define DEFAULT_MAX_CUSTOM_FLAG_LENGTH 50

extern struct ioloop *ioloop;
extern unsigned int max_custom_flag_length, mailbox_check_interval;
extern unsigned int imap_max_line_length;
extern enum mailbox_open_flags mailbox_open_flags;

extern string_t *capability_string;

extern void (*hook_mail_storage_created)(struct mail_storage *storage);
extern void (*hook_client_created)(struct client *client);

#endif
