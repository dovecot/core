#ifndef IMAP_COMMON_H
#define IMAP_COMMON_H

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (60*30*1000)

/* If we can't send anything to client for this long, disconnect the client */
#define CLIENT_OUTPUT_TIMEOUT_MSECS (5*60*1000)

/* Stop buffering more data into output stream after this many bytes */
#define CLIENT_OUTPUT_OPTIMAL_SIZE 2048

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

#include "lib.h"
#include "imap-client.h"
#include "imap-settings.h"

typedef void imap_client_created_func_t(struct client **client);

extern imap_client_created_func_t *hook_client_created;

/* Sets the hook_client_created and returns the previous hook,
   which the new_hook should call if it's non-NULL. */
imap_client_created_func_t *
imap_client_created_hook_set(imap_client_created_func_t *new_hook);

void imap_refresh_proctitle(void);

#endif
