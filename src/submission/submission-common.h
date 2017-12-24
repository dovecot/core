#ifndef SUBMISSION_COMMON_H
#define SUBMISSION_COMMON_H

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "smtp-reply.h"
#include "smtp-server.h"
#include "submission-client.h"
#include "submission-settings.h"

#define URL_HOST_ALLOW_ANY "*"

/* Maximum number of bytes added to a relayed message. This is used to
   calculate the SIZE capability based on what the backend server states. */
#define SUBMISSION_MAX_ADDITIONAL_MAIL_SIZE 1024
#define SUBMISSION_MAIL_DATA_MAX_INMEMORY_SIZE (1024*128)

/* Maximum time to wait for QUIT reply from relay server */
#define SUBMISSION_MAX_WAIT_QUIT_REPLY_MSECS 2000

typedef void submission_client_created_func_t(struct client **client);

extern submission_client_created_func_t *hook_client_created;
extern bool submission_debug;

extern struct smtp_server *smtp_server;
extern struct smtp_client *smtp_client;

/* Sets the hook_client_created and returns the previous hook,
   which the new_hook should call if it's non-NULL. */
submission_client_created_func_t *
submission_client_created_hook_set(submission_client_created_func_t *new_hook);

void submission_refresh_proctitle(void);

void client_handshake(struct client *client);

#endif
