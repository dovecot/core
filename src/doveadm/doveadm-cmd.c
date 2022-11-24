/* Copyright (c) 2009-2r016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "net.h"
#include "doveadm.h"
#include "doveadm-cmd.h"

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

static struct doveadm_cmd_ver2 *doveadm_commands_ver2[] = {
	&doveadm_cmd_mailbox_mutf7,
	&doveadm_cmd_service_stop_ver2,
	&doveadm_cmd_service_status_ver2,
	&doveadm_cmd_sis_deduplicate,
	&doveadm_cmd_sis_find,
	&doveadm_cmd_process_status_ver2,
	&doveadm_cmd_stop_ver2,
	&doveadm_cmd_reload_ver2,
	&doveadm_cmd_stats_dump_ver2,
	&doveadm_cmd_stats_add_ver2,
	&doveadm_cmd_stats_remove_ver2,
	&doveadm_cmd_penalty_ver2,
	&doveadm_cmd_kick_ver2,
	&doveadm_cmd_proxy_kick_ver2,
	&doveadm_cmd_who_ver2,
	&doveadm_cmd_proxy_list_ver2,
	&doveadm_cmd_indexer_add,
	&doveadm_cmd_indexer_remove,
	&doveadm_cmd_indexer_list,
};

ARRAY_TYPE(doveadm_cmd_ver2) doveadm_cmds_ver2;

void doveadm_cmd_register_ver2(struct doveadm_cmd_ver2 *cmd)
{
	if (cmd->cmd == NULL) {
		if (cmd->mail_cmd != NULL)
			cmd->cmd = doveadm_cmd_ver2_to_mail_cmd_wrapper;
		else i_unreached();
	}
	array_push_back(&doveadm_cmds_ver2, cmd);
}

const struct doveadm_cmd_ver2 *doveadm_cmd_find_ver2(const char *cmd_name)
{
	const struct doveadm_cmd_ver2 *cmd;

	array_foreach(&doveadm_cmds_ver2, cmd) {
		if (strcmp(cmd_name, cmd->name) == 0)
			return cmd;
	}
	return NULL;
}

const struct doveadm_cmd_ver2 *
doveadm_cmdline_find_with_args(const char *cmd_name, int *argc,
			       const char *const *argv[])
{
	int i, k;
	const struct doveadm_cmd_ver2 *cmd;
	const char *cptr;

	for (i = 0; i < *argc; i++) {
		if (strcmp((*argv)[i], cmd_name) == 0)
			break;
	}

	i_assert(i != *argc);

	array_foreach(&doveadm_cmds_ver2, cmd) {
		cptr = cmd->name;
		/* cannot reuse i here because this needs be
		   done more than once */
		for (k = 0; *cptr != '\0' && i + k < *argc; k++) {
			size_t alen = strlen((*argv)[i + k]);
			/* make sure we don't overstep */
			if (strlen(cptr) < alen)
				break;
			/* did not match */
			if (strncmp(cptr, (*argv)[i+k], alen) != 0)
				break;
			/* do not accept abbreviations */
			if (cptr[alen] != ' ' && cptr[alen] != '\0')
				break;
			cptr += alen;
			if (*cptr != '\0')
				cptr++; /* consume space */
		}
		/* name was fully consumed */
		if (*cptr == '\0') {
			if (k > 1) {
				*argc -= k-1;
				*argv += k-1;
			}
			return cmd;
		}
	}

	return NULL;
}

void doveadm_cmds_init(void)
{
	unsigned int i;

	i_array_init(&doveadm_cmds_ver2, 2);

	for (i = 0; i < N_ELEMENTS(doveadm_commands_ver2); i++)
		doveadm_cmd_register_ver2(doveadm_commands_ver2[i]);

	doveadm_register_instance_commands();
	doveadm_register_log_commands();
	doveadm_register_replicator_commands();
	doveadm_register_dict_commands();
	doveadm_register_fs_commands();
}

void doveadm_cmds_deinit(void)
{
	array_free(&doveadm_cmds_ver2);
}

bool doveadm_cmdline_try_run(const char *cmd_name,
			     int argc, const char *const argv[],
			     struct doveadm_cmd_context *cctx)
{
	const struct doveadm_cmd_ver2 *cmd;

	cmd = doveadm_cmdline_find_with_args(cmd_name, &argc, &argv);
	if (cmd == NULL)
		return FALSE;

	cctx->cmd = cmd;
	if (doveadm_cmdline_run(argc, argv, cctx) < 0)
		doveadm_exit_code = EX_USAGE;
	return TRUE;
}
