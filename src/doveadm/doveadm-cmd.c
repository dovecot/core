/* Copyright (c) 2009-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "doveadm-cmd.h"

static struct doveadm_cmd *doveadm_commands[] = {
	&doveadm_cmd_stop,
	&doveadm_cmd_reload,
	&doveadm_cmd_who,
	&doveadm_cmd_penalty,
	&doveadm_cmd_kick,
	&doveadm_cmd_mailbox_mutf7,
	&doveadm_cmd_sis_deduplicate,
	&doveadm_cmd_sis_find,
	&doveadm_cmd_stats_dump
};

ARRAY_TYPE(doveadm_cmd) doveadm_cmds;

void doveadm_register_cmd(const struct doveadm_cmd *cmd)
{
	array_append(&doveadm_cmds, cmd, 1);
}

static const struct doveadm_cmd *
doveadm_cmd_find_multi_word(const struct doveadm_cmd *cmd,
			    const char *cmdname, int *_argc, char **_argv[])
{
	int argc = *_argc;
	char **argv = *_argv;
	const struct doveadm_cmd *subcmd;
	unsigned int len;

	if (argc < 2)
		return NULL;

	len = strlen(argv[1]);
	if (strncmp(cmdname, argv[1], len) != 0)
		return NULL;

	argc--; argv++;
	if (cmdname[len] == ' ') {
		/* more args */
		subcmd = doveadm_cmd_find_multi_word(cmd, cmdname + len + 1,
						     &argc, &argv);
		if (subcmd == NULL)
			return NULL;
	} else {
		if (cmdname[len] != '\0')
			return NULL;
	}

	*_argc = argc;
	*_argv = argv;
	return cmd;
}

const struct doveadm_cmd *
doveadm_cmd_find(const char *cmd_name, int *argc, char **argv[])
{
	const struct doveadm_cmd *cmd, *subcmd;
	unsigned int cmd_name_len;

	i_assert(*argc > 0);

	cmd_name_len = strlen(cmd_name);
	array_foreach(&doveadm_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0)
			return cmd;

		/* see if it matches a multi-word command */
		if (strncmp(cmd->name, cmd_name, cmd_name_len) == 0 &&
		    cmd->name[cmd_name_len] == ' ') {
			const char *subcmd_name = cmd->name + cmd_name_len + 1;

			subcmd = doveadm_cmd_find_multi_word(cmd, subcmd_name,
							     argc, argv);
			if (subcmd != NULL)
				return subcmd;
		}
	}
	return NULL;
}

void doveadm_cmds_init(void)
{
	unsigned int i;

	i_array_init(&doveadm_cmds, 32);
	for (i = 0; i < N_ELEMENTS(doveadm_commands); i++)
		doveadm_register_cmd(doveadm_commands[i]);

	doveadm_register_auth_commands();
	doveadm_register_director_commands();
	doveadm_register_instance_commands();
	doveadm_register_mount_commands();
	doveadm_register_proxy_commands();
	doveadm_register_log_commands();
	doveadm_register_replicator_commands();
	doveadm_register_dict_commands();
	doveadm_register_fs_commands();
}

void doveadm_cmds_deinit(void)
{
	array_free(&doveadm_cmds);
}
