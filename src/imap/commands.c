/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "commands.h"

#include <stdlib.h>

const struct command imap4rev1_commands[] = {
	{ "AUTHENTICATE",	cmd_authenticate },
	{ "CAPABILITY",		cmd_capability },
	{ "LOGIN",		cmd_login },
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
	{ "SORT",		cmd_sort },
	{ "THREAD",		cmd_thread },
	{ "UID SORT",		cmd_sort },
	{ "UID THREAD",		cmd_thread },
	{ "UNSELECT",		cmd_unselect }
};
#define IMAP_EXT_COMMANDS_COUNT \
	(sizeof(imap_ext_commands) / sizeof(imap_ext_commands[0]))

static buffer_t *cmdbuf;
static int cmdbuf_unsorted;

void command_register(const char *name, command_func_t *func)
{
	struct command cmd;

	cmd.name = name;
	cmd.func = func;
	buffer_append(cmdbuf, &cmd, sizeof(cmd));

	cmdbuf_unsorted = TRUE;
}

void command_unregister(const char *name)
{
	const struct command *cmd;
	size_t i, size, count;

	cmd = buffer_get_data(cmdbuf, &size);
	count = size / sizeof(*cmd);

	for (i = 0; i < count; i++) {
		if (strcasecmp(cmd[i].name, name) == 0) {
			buffer_delete(cmdbuf, i * sizeof(*cmd), sizeof(*cmd));
			return;
		}
	}

	i_error("Trying to unregister unknown command '%s'", name);
}

void command_register_array(const struct command *commands, size_t count)
{
	cmdbuf_unsorted = TRUE;
	buffer_append(cmdbuf, commands, sizeof(*commands) * count);
}

void command_unregister_array(const struct command *commands, size_t count)
{
	while (count > 0) {
		command_unregister(commands->name);
		count--; commands++;
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
	size_t size;

	base = buffer_get_modifyable_data(cmdbuf, &size);
	size /= sizeof(struct command);

	if (cmdbuf_unsorted) {
		qsort(base, size, sizeof(struct command), command_cmp);
                cmdbuf_unsorted = FALSE;
	}

	cmd = bsearch(name, base, size, sizeof(struct command),
		      command_bsearch);
	return cmd == NULL ? NULL : cmd->func;
}

void commands_init(void)
{
	cmdbuf = buffer_create_dynamic(system_pool,
				       sizeof(struct command) * 64, (size_t)-1);
	cmdbuf_unsorted = FALSE;

        command_register_array(imap4rev1_commands, IMAP4REV1_COMMANDS_COUNT);
        command_register_array(imap_ext_commands, IMAP_EXT_COMMANDS_COUNT);
}

void commands_deinit(void)
{
        command_unregister_array(imap4rev1_commands, IMAP4REV1_COMMANDS_COUNT);
        command_unregister_array(imap_ext_commands, IMAP_EXT_COMMANDS_COUNT);
	buffer_free(cmdbuf);
}
