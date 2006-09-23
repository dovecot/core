/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "array.h"
#include "buffer.h"
#include "commands.h"

#include <stdlib.h>

const struct command imap4rev1_commands[] = {
	{ "CAPABILITY",		cmd_capability },
	{ "LOGOUT",		cmd_logout },
	{ "NOOP",		cmd_noop },

	{ "APPEND",		cmd_append },
	{ "EXAMINE",		cmd_examine },
	{ "CREATE",		cmd_create },
	{ "DELETE",		cmd_delete },
	{ "RENAME",		cmd_rename },
	{ "LIST",		cmd_list },
	{ "LSUB",		cmd_lsub },
	{ "SELECT",		cmd_select },
	{ "STATUS",		cmd_status },
	{ "SUBSCRIBE",		cmd_subscribe },
	{ "UNSUBSCRIBE",	cmd_unsubscribe },

	{ "CHECK",		cmd_check },
	{ "CLOSE",		cmd_close },
	{ "COPY",		cmd_copy },
	{ "EXPUNGE",		cmd_expunge },
	{ "FETCH",		cmd_fetch },
	{ "SEARCH",		cmd_search },
	{ "STORE",		cmd_store },
	{ "UID",		cmd_uid },
	{ "UID COPY",		cmd_copy },
	{ "UID FETCH",		cmd_fetch },
	{ "UID SEARCH",		cmd_search },
	{ "UID STORE",		cmd_store }
};
#define IMAP4REV1_COMMANDS_COUNT \
	(sizeof(imap4rev1_commands) / sizeof(imap4rev1_commands[0]))

const struct command imap_ext_commands[] = {
	{ "IDLE",		cmd_idle },
	{ "NAMESPACE",		cmd_namespace },
	{ "SORT",		cmd_sort },
	{ "THREAD",		cmd_thread },
	{ "UID EXPUNGE",	cmd_uid_expunge },
	{ "UID SORT",		cmd_sort },
	{ "UID THREAD",		cmd_thread },
	{ "UNSELECT",		cmd_unselect }
};
#define IMAP_EXT_COMMANDS_COUNT \
	(sizeof(imap_ext_commands) / sizeof(imap_ext_commands[0]))

static ARRAY_DEFINE(commands, struct command);
static bool commands_unsorted;

void command_register(const char *name, command_func_t *func)
{
	struct command cmd;

	cmd.name = name;
	cmd.func = func;
	array_append(&commands, &cmd, 1);

	commands_unsorted = TRUE;
}

void command_unregister(const char *name)
{
	const struct command *cmd;
	unsigned int i, count;

	cmd = array_get(&commands, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(cmd[i].name, name) == 0) {
			array_delete(&commands, i, 1);
			return;
		}
	}

	i_error("Trying to unregister unknown command '%s'", name);
}

void command_register_array(const struct command *cmdarr, unsigned int count)
{
	commands_unsorted = TRUE;
	array_append(&commands, cmdarr, count);
}

void command_unregister_array(const struct command *cmdarr, unsigned int count)
{
	while (count > 0) {
		command_unregister(cmdarr->name);
		count--; cmdarr++;
	}
}

static int command_cmp(const void *p1, const void *p2)
{
        const struct command *c1 = p1, *c2 = p2;

	return strcasecmp(c1->name, c2->name);
}

static int command_bsearch(const void *name, const void *cmd_p)
{
        const struct command *cmd = cmd_p;

	return strcasecmp(name, cmd->name);
}

command_func_t *command_find(const char *name)
{
	const struct command *cmd;
	void *base;
	unsigned int count;

	base = array_get_modifiable(&commands, &count);
	if (commands_unsorted) {
		qsort(base, count, sizeof(struct command), command_cmp);
                commands_unsorted = FALSE;
	}

	cmd = bsearch(name, base, count, sizeof(struct command),
		      command_bsearch);
	return cmd == NULL ? NULL : cmd->func;
}

void commands_init(void)
{
	i_array_init(&commands, 64);
	commands_unsorted = FALSE;

        command_register_array(imap4rev1_commands, IMAP4REV1_COMMANDS_COUNT);
        command_register_array(imap_ext_commands, IMAP_EXT_COMMANDS_COUNT);
}

void commands_deinit(void)
{
        command_unregister_array(imap4rev1_commands, IMAP4REV1_COMMANDS_COUNT);
        command_unregister_array(imap_ext_commands, IMAP_EXT_COMMANDS_COUNT);
	array_free(&commands);
}
