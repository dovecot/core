#ifndef __COMMANDS_H
#define __COMMANDS_H

struct client_command_context;

#include "mail-storage.h"
#include "imap-parser.h"
#include "imap-sync.h"
#include "commands-util.h"

typedef bool command_func_t(struct client_command_context *cmd);

struct command {
	const char *name;
	command_func_t *func;
};

/* Register command. Given name parameter must be permanently stored until
   command is unregistered. */
void command_register(const char *name, command_func_t *func);
void command_unregister(const char *name);

/* Register array of commands. */
void command_register_array(const struct command *commands, size_t count);
void command_unregister_array(const struct command *commands, size_t count);

command_func_t *command_find(const char *name);

void commands_init(void);
void commands_deinit(void);

/* IMAP4rev1 commands: */

/* Non-Authenticated State */
bool cmd_logout(struct client_command_context *cmd);

bool cmd_capability(struct client_command_context *cmd);
bool cmd_noop(struct client_command_context *cmd);

/* Authenticated State */
bool cmd_select(struct client_command_context *cmd);
bool cmd_examine(struct client_command_context *cmd);

bool cmd_create(struct client_command_context *cmd);
bool cmd_delete(struct client_command_context *cmd);
bool cmd_rename(struct client_command_context *cmd);

bool cmd_subscribe(struct client_command_context *cmd);
bool cmd_unsubscribe(struct client_command_context *cmd);

bool cmd_list(struct client_command_context *cmd);
bool cmd_lsub(struct client_command_context *cmd);

bool cmd_status(struct client_command_context *cmd);
bool cmd_append(struct client_command_context *cmd);

/* Selected state */
bool cmd_check(struct client_command_context *cmd);
bool cmd_close(struct client_command_context *cmd);
bool cmd_expunge(struct client_command_context *cmd);
bool cmd_search(struct client_command_context *cmd);
bool cmd_fetch(struct client_command_context *cmd);
bool cmd_store(struct client_command_context *cmd);
bool cmd_copy(struct client_command_context *cmd);
bool cmd_uid(struct client_command_context *cmd);

/* IMAP extensions: */
bool cmd_idle(struct client_command_context *cmd);
bool cmd_namespace(struct client_command_context *cmd);
bool cmd_sort(struct client_command_context *cmd);
bool cmd_thread(struct client_command_context *cmd);
bool cmd_uid_expunge(struct client_command_context *cmd);
bool cmd_unselect(struct client_command_context *cmd);

/* private: */
bool _cmd_list_full(struct client_command_context *cmd, bool lsub);
bool _cmd_select_full(struct client_command_context *cmd, bool readonly);
bool _cmd_subscribe_full(struct client_command_context *cmd, bool subscribe);

#endif
