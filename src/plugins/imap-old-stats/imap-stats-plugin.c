/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "base64.h"
#include "str.h"
#include "imap-commands.h"
#include "stats.h"
#include "stats-plugin.h"
#include "stats-connection.h"
#include "imap-stats-plugin.h"

#define IMAP_STATS_IMAP_CONTEXT(obj) \
	MODULE_CONTEXT(obj, imap_stats_imap_module)

struct stats_client_command {
	union imap_module_context module_ctx;

	unsigned int id;
	bool continued;
	struct stats *stats, *pre_stats;
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
		scmd->stats = stats_alloc(cmd->pool);
		scmd->pre_stats = stats_alloc(cmd->pool);
		MODULE_CONTEXT_SET(cmd, imap_stats_imap_module, scmd);
	}

	mail_user_stats_fill(cmd->client->user, scmd->pre_stats);
}

static void stats_command_post(struct client_command_context *cmd)
{
	struct stats_user *suser = STATS_USER_CONTEXT(cmd->client->user);
	struct stats_client_command *scmd = IMAP_STATS_IMAP_CONTEXT(cmd);
	struct stats *new_stats, *diff_stats;
	const char *error;
	size_t args_pos = 0, args_len = 0;
	string_t *str;
	buffer_t *buf;

	if (suser == NULL || scmd == NULL)
		return;

	new_stats = stats_alloc(pool_datastack_create());
	diff_stats = stats_alloc(pool_datastack_create());

	mail_user_stats_fill(cmd->client->user, new_stats);
	if (!stats_diff(scmd->pre_stats, new_stats, diff_stats, &error))
		i_error("stats: command stats shrank: %s", error);
	stats_add(scmd->stats, diff_stats);

	str = t_str_new(128);
	str_append(str, "UPDATE-CMD\t");
	str_append(str, suser->stats_session_id);

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
		args_len = str_len(str) - args_pos;
		scmd->continued = TRUE;
	}

	buf = t_buffer_create(128);
	stats_export(buf, scmd->stats);
	str_append_c(str, '\t');
	base64_encode(buf->data, buf->used, str);

	str_append_c(str, '\n');

	if (str_len(str) > PIPE_BUF) {
		/* truncate the args so it fits */
		size_t delete_count = str_len(str) - PIPE_BUF;

		i_assert(args_pos != 0);
		if (delete_count > args_len)
			delete_count = args_len;
		str_delete(str, args_pos + args_len - delete_count,
			   delete_count);
	}

	stats_connection_send(suser->stats_conn, str);
}

void imap_old_stats_plugin_init(struct module *module ATTR_UNUSED)
{
	command_hook_register(stats_command_pre, stats_command_post);
}

void imap_old_stats_plugin_deinit(void)
{
	command_hook_unregister(stats_command_pre, stats_command_post);
}

const char *imap_old_stats_plugin_dependencies[] = { "old_stats", NULL };
const char imap_old_stats_plugin_binary_dependency[] = "imap";
