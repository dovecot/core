#ifndef __COMMANDS_H
#define __COMMANDS_H

#include "commands-util.h"
#include "imap-parser.h"

ClientCommandFunc client_command_find(const char *name);

/* Non-Authenticated State */
int cmd_authenticate(Client *client);
int cmd_login(Client *client);
int cmd_logout(Client *client);

int cmd_capability(Client *client);
int cmd_noop(Client *client);

/* Authenticated State */
int cmd_select(Client *client);
int cmd_examine(Client *client);

int cmd_create(Client *client);
int cmd_delete(Client *client);
int cmd_rename(Client *client);

int cmd_subscribe(Client *client);
int cmd_unsubscribe(Client *client);

int cmd_list(Client *client);
int cmd_lsub(Client *client);

int cmd_status(Client *client);
int cmd_append(Client *client);

/* Selected state */
int cmd_check(Client *client);
int cmd_close(Client *client);
int cmd_expunge(Client *client);
int cmd_search(Client *client);
int cmd_fetch(Client *client);
int cmd_store(Client *client);
int cmd_copy(Client *client);
int cmd_uid(Client *client);

/* private: */
int _cmd_list_full(Client *client, int subscribed);
int _cmd_select_full(Client *client, int readonly);
int _cmd_subscribe_full(Client *client, int subscribe);

#endif
