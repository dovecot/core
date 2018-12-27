#ifndef LMTP_COMMON_H
#define LMTP_COMMON_H

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "settings-parser.h"
#include "master-service.h"
#include "smtp-reply.h"
#include "smtp-server.h"
#include "lmtp-client.h"
#include "lmtp-settings.h"

typedef void lmtp_client_created_func_t(struct client **client);

extern lmtp_client_created_func_t *hook_client_created;
extern struct event_category event_category_lmtp;

extern char *dns_client_socket_path, *base_dir;
extern struct mail_storage_service_ctx *storage_service;
extern struct anvil_client *anvil;

extern struct smtp_server *lmtp_server;

/* Sets the hook_client_created and returns the previous hook,
   which the new_hook should call if it's non-NULL. */
lmtp_client_created_func_t *
lmtp_client_created_hook_set(lmtp_client_created_func_t *new_hook);

void lmtp_anvil_init(void);

#endif
