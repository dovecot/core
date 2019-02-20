/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "array.h"
#include "imap-login-commands.h"

static ARRAY(struct imap_login_command *) imap_login_commands;
static pool_t imap_login_commands_pool;

struct imap_login_command *imap_login_command_lookup(const char *name)
{
	struct imap_login_command *const *cmdp;

	array_foreach(&imap_login_commands, cmdp) {
		if (strcasecmp((*cmdp)->name, name) == 0)
			return *cmdp;
	}
	return NULL;
}

void imap_login_commands_register(const struct imap_login_command *commands,
				  unsigned int count)
{
	struct imap_login_command *cmd;
	unsigned int i;

	for (i = 0; i < count; i++) {
		cmd = p_new(imap_login_commands_pool, struct imap_login_command, 1);
		cmd->name = p_strdup(imap_login_commands_pool, commands[i].name);
		cmd->func = commands[i].func;
		array_push_back(&imap_login_commands, &cmd);
	}
}

static void
imap_login_command_unregister(const struct imap_login_command *unreg_cmd)
{
	struct imap_login_command *const *cmdp;

	array_foreach(&imap_login_commands, cmdp) {
		if ((*cmdp)->func == unreg_cmd->func &&
		    strcmp((*cmdp)->name, unreg_cmd->name) == 0) {
			array_delete(&imap_login_commands,
				array_foreach_idx(&imap_login_commands, cmdp), 1);
			return;
		}
	}
	i_panic("imap_login_command_unregister: Command '%s' not found", unreg_cmd->name);
}

void imap_login_commands_unregister(const struct imap_login_command *commands,
				    unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		imap_login_command_unregister(&commands[i]);
}

void imap_login_commands_init(void)
{
	imap_login_commands_pool =
		pool_alloconly_create("imap login commands", 128);
	p_array_init(&imap_login_commands, imap_login_commands_pool, 8);
}

void imap_login_commands_deinit(void)
{
	pool_unref(&imap_login_commands_pool);
}
