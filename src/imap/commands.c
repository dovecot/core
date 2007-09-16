/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "buffer.h"
#include "commands.h"

#include <stdlib.h>

const struct command imap4rev1_commands[] = {
	{ "CAPABILITY",		cmd_capability,  0 },
	{ "LOGOUT",		cmd_logout,      0 },
	{ "NOOP",		cmd_noop,        COMMAND_FLAG_BREAKS_SEQS },

	{ "APPEND",		cmd_append,      COMMAND_FLAG_BREAKS_SEQS },
	{ "EXAMINE",		cmd_examine,     COMMAND_FLAG_BREAKS_MAILBOX },
	{ "CREATE",		cmd_create,      0 },
	{ "DELETE",		cmd_delete,      0 },
	{ "RENAME",		cmd_rename,      0 },
	{ "LIST",		cmd_list,        0 },
	{ "LSUB",		cmd_lsub,        0 },
	{ "SELECT",		cmd_select,      COMMAND_FLAG_BREAKS_MAILBOX },
	{ "STATUS",		cmd_status,      0 },
	{ "SUBSCRIBE",		cmd_subscribe,   0 },
	{ "UNSUBSCRIBE",	cmd_unsubscribe, 0 },

	{ "CHECK",		cmd_check,       COMMAND_FLAG_BREAKS_SEQS },
	{ "CLOSE",		cmd_close,       COMMAND_FLAG_BREAKS_MAILBOX },
	{ "COPY",		cmd_copy,        COMMAND_FLAG_USES_SEQS |
						 COMMAND_FLAG_BREAKS_SEQS },
	{ "EXPUNGE",		cmd_expunge,     COMMAND_FLAG_BREAKS_SEQS },
	{ "FETCH",		cmd_fetch,       COMMAND_FLAG_USES_SEQS },
	{ "SEARCH",		cmd_search,      COMMAND_FLAG_USES_SEQS },
	{ "STORE",		cmd_store,       COMMAND_FLAG_USES_SEQS },
	{ "UID",		cmd_uid,         0 },
	{ "UID COPY",		cmd_copy,        COMMAND_FLAG_BREAKS_SEQS },
	{ "UID FETCH",		cmd_fetch,       COMMAND_FLAG_BREAKS_SEQS },
	{ "UID SEARCH",		cmd_search,      COMMAND_FLAG_BREAKS_SEQS },
	{ "UID STORE",		cmd_store,       COMMAND_FLAG_BREAKS_SEQS }
};
#define IMAP4REV1_COMMANDS_COUNT \
	(sizeof(imap4rev1_commands) / sizeof(imap4rev1_commands[0]))

const struct command imap_ext_commands[] = {
	{ "IDLE",		cmd_idle,        COMMAND_FLAG_BREAKS_SEQS },
	{ "NAMESPACE",		cmd_namespace,   0 },
	{ "SORT",		cmd_sort,        COMMAND_FLAG_USES_SEQS },
	{ "THREAD",		cmd_thread,      COMMAND_FLAG_USES_SEQS },
	{ "UID EXPUNGE",	cmd_uid_expunge, COMMAND_FLAG_BREAKS_SEQS },
	{ "UID SORT",		cmd_sort,        COMMAND_FLAG_BREAKS_SEQS },
	{ "UID THREAD",		cmd_thread,      COMMAND_FLAG_BREAKS_SEQS },
	{ "UNSELECT",		cmd_unselect,    COMMAND_FLAG_BREAKS_MAILBOX },
	{ "X-CANCEL",		cmd_x_cancel,    0 }
};
#define IMAP_EXT_COMMANDS_COUNT \
	(sizeof(imap_ext_commands) / sizeof(imap_ext_commands[0]))

static ARRAY_DEFINE(commands, struct command);
static bool commands_unsorted;

void command_register(const char *name, command_func_t *func,
		      enum command_flags flags)
{
	struct command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.name = name;
	cmd.func = func;
	cmd.flags = flags;
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

struct command *command_find(const char *name)
{
	void *base;
	unsigned int count;

	base = array_get_modifiable(&commands, &count);
	if (commands_unsorted) {
		qsort(base, count, sizeof(struct command), command_cmp);
                commands_unsorted = FALSE;
	}

	return bsearch(name, base, count, sizeof(struct command),
		       command_bsearch);
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
