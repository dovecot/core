#ifndef IMAP_COMMANDS_H
#define IMAP_COMMANDS_H

struct client_command_context;

#include "mail-storage.h"
#include "mail-namespace.h"
#include "imap-parser.h"
#include "imap-sync.h"
#include "imap-commands-util.h"

typedef bool command_func_t(struct client_command_context *cmd);
typedef void command_hook_callback_t(struct client_command_context *ctx);

enum command_flags {
	/* Command uses sequences as its input parameters */
	COMMAND_FLAG_USES_SEQS		= 0x01,
	/* Command may reply with EXPUNGE, causing sequences to break */
	COMMAND_FLAG_BREAKS_SEQS	= 0x02,
	/* Command changes the mailbox */
	COMMAND_FLAG_BREAKS_MAILBOX	= 0x04 | COMMAND_FLAG_BREAKS_SEQS,

	/* Command uses selected mailbox */
	COMMAND_FLAG_USES_MAILBOX	= COMMAND_FLAG_BREAKS_MAILBOX |
					  COMMAND_FLAG_USES_SEQS,

	/* Command requires mailbox syncing before it can do its job. */
	COMMAND_FLAG_REQUIRES_SYNC	= 0x08,
	/* Command allows replying with [NONEXISTENT] imap resp code.
	   Dovecot internally returns it for all kinds of commands,
	   but unfortunately RFC 5530 specifies it only for "delete something"
	   operations. */
	COMMAND_FLAG_USE_NONEXISTENT	= 0x10
};

struct command {
	const char *name;
	command_func_t *func;

	enum command_flags flags;
};
ARRAY_DEFINE_TYPE(command, struct command);

extern ARRAY_TYPE(command) imap_commands;

/* Register command. Given name parameter must be permanently stored until
   command is unregistered. */
void command_register(const char *name, command_func_t *func,
		      enum command_flags flags);
void command_unregister(const char *name);

/* Register array of commands. */
void command_register_array(const struct command *cmdarr, unsigned int count);
void command_unregister_array(const struct command *cmdarr, unsigned int count);

/* Register hook callbacks that are called before and after all commands */
void command_hook_register(command_hook_callback_t *pre,
			   command_hook_callback_t *post);
void command_hook_unregister(command_hook_callback_t *pre,
			     command_hook_callback_t *post);
/* Execute command and hooks */
bool command_exec(struct client_command_context *cmd);

struct command *command_find(const char *name);

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
bool cmd_cancelupdate(struct client_command_context *cmd);
bool cmd_enable(struct client_command_context *cmd);
bool cmd_id(struct client_command_context *cmd);
bool cmd_idle(struct client_command_context *cmd);
bool cmd_namespace(struct client_command_context *cmd);
bool cmd_notify(struct client_command_context *cmd);
bool cmd_sort(struct client_command_context *cmd);
bool cmd_thread(struct client_command_context *cmd);
bool cmd_uid_expunge(struct client_command_context *cmd);
bool cmd_move(struct client_command_context *cmd);
bool cmd_unselect(struct client_command_context *cmd);
bool cmd_x_cancel(struct client_command_context *cmd);

/* private: */
bool cmd_list_full(struct client_command_context *cmd, bool lsub);
bool cmd_select_full(struct client_command_context *cmd, bool readonly);
bool cmd_subscribe_full(struct client_command_context *cmd, bool subscribe);

#endif
