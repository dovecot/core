/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-commands.h"
#include "stats-plugin.h"
#include "stats-connection.h"
#include "imap-stats-plugin.h"

#define IMAP_STATS_IMAP_CONTEXT(obj) \
	MODULE_CONTEXT(obj, imap_stats_imap_module)

struct stats_client_command {
	union imap_module_context module_ctx;

	unsigned int id;
	bool continued;
	struct mail_stats stats, pre_stats;
	struct mailbox_transaction_stats pre_trans_stats;
};

static MODULE_CONTEXT_DEFINE_INIT(imap_stats_imap_module,
				  &imap_module_register);

const char *imap_stats_plugin_version = DOVECOT_ABI_VERSION;

static void stats_command_pre(struct client_command_context *cmd)
{
	struct stats_user *suser = STATS_USER_CONTEXT(cmd->client->user);
	struct stats_client_command *scmd;
	static unsigned int stats_cmd_id_counter = 0;

	if (suser == NULL || !suser->track_commands)
		return;

	if (strcasecmp(cmd->name, "IDLE") == 0) {
		/* IDLE can run forever and waste stats process's memory while
		   waiting for it to timeout. don't send them. */
		return;
	}

	scmd = IMAP_STATS_IMAP_CONTEXT(cmd);
	if (scmd == NULL) {
		scmd = p_new(cmd->pool, struct stats_client_command, 1);
		scmd->id = ++stats_cmd_id_counter;
		MODULE_CONTEXT_SET(cmd, imap_stats_imap_module, scmd);
	}
	mail_stats_get(suser, &scmd->pre_stats);
	scmd->pre_trans_stats = suser->session_stats.trans_stats;
}

static void stats_command_post(struct client_command_context *cmd)
{
	struct stats_user *suser = STATS_USER_CONTEXT(cmd->client->user);
	struct stats_client_command *scmd = IMAP_STATS_IMAP_CONTEXT(cmd);
	struct mail_stats stats, pre_trans_stats, trans_stats;
	unsigned int args_pos = 0;
	string_t *str;

	if (scmd == NULL)
		return;

	mail_stats_get(suser, &stats);
	mail_stats_add_diff(&scmd->stats, &scmd->pre_stats, &stats);

	/* mail_stats_get() can't see the transactions that already went
	   away, so we'll need to use the session's stats difference */
	memset(&pre_trans_stats, 0, sizeof(pre_trans_stats));
	memset(&trans_stats, 0, sizeof(trans_stats));
	pre_trans_stats.trans_stats = scmd->pre_trans_stats;
	trans_stats.trans_stats = suser->session_stats.trans_stats;
	mail_stats_add_diff(&scmd->stats, &pre_trans_stats, &trans_stats);

	str = t_str_new(128);
	str_append(str, "UPDATE-CMD\t");
	str_append(str, guid_128_to_string(suser->session_guid));

	str_printfa(str, "\t%u\t", scmd->id);
	if (cmd->state == CLIENT_COMMAND_STATE_DONE)
		str_append_c(str, 'd');
	if (scmd->continued)
		str_append_c(str, 'c');
	else {
		str_append_c(str, '\t');
		str_append(str, cmd->name);
		str_append_c(str, '\t');
		args_pos = str_len(str);
		if (cmd->args != NULL)
			str_append(str, cmd->args);
		scmd->continued = TRUE;
	}

	mail_stats_export(str, &scmd->stats);
	str_append_c(str, '\n');

	if (str_len(str) > PIPE_BUF) {
		/* truncate the args so it fits */
		i_assert(args_pos != 0);
		str_delete(str, args_pos, str_len(str) - PIPE_BUF);
		i_assert(str_len(str) == PIPE_BUF);
	}

	stats_connection_send(suser->stats_conn, str);
}

void imap_stats_plugin_init(struct module *module ATTR_UNUSED)
{
	command_hook_register(stats_command_pre, stats_command_post);
}

void imap_stats_plugin_deinit(void)
{
	command_hook_unregister(stats_command_pre, stats_command_post);
}

const char *imap_stats_plugin_dependencies[] = { "stats", NULL };
const char imap_stats_plugin_binary_dependency[] = "imap";
