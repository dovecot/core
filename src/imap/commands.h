#ifndef __COMMANDS_H
#define __COMMANDS_H

#include "commands-util.h"
#include "imap-parser.h"

client_command_func_t client_command_find(const char *name);

/* Non-Authenticated State */
int cmd_authenticate(struct client *client);
int cmd_login(struct client *client);
int cmd_logout(struct client *client);

int cmd_capability(struct client *client);
int cmd_noop(struct client *client);

/* Authenticated State */
int cmd_select(struct client *client);
int cmd_examine(struct client *client);

int cmd_create(struct client *client);
int cmd_delete(struct client *client);
int cmd_rename(struct client *client);

int cmd_subscribe(struct client *client);
int cmd_unsubscribe(struct client *client);

int cmd_list(struct client *client);
int cmd_lsub(struct client *client);

int cmd_status(struct client *client);
int cmd_append(struct client *client);

/* Selected state */
int cmd_check(struct client *client);
int cmd_close(struct client *client);
int cmd_expunge(struct client *client);
int cmd_search(struct client *client);
int cmd_sort(struct client *client);
int cmd_thread(struct client *client);
int cmd_fetch(struct client *client);
int cmd_store(struct client *client);
int cmd_copy(struct client *client);
int cmd_uid(struct client *client);
int cmd_unselect(struct client *client);

/* private: */
int _cmd_list_full(struct client *client, int subscribed);
int _cmd_select_full(struct client *client, int readonly);
int _cmd_subscribe_full(struct client *client, int subscribe);

#endif
