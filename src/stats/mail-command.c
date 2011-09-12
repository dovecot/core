/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "llist.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "mail-stats.h"
#include "mail-session.h"
#include "mail-command.h"

/* commands are sorted by their last_update timestamp, oldest first */
struct mail_command *stable_mail_commands;

static size_t mail_command_memsize(const struct mail_command *cmd)
{
	return sizeof(*cmd) + strlen(cmd->name) + 1 + strlen(cmd->args) + 1;
}

static struct mail_command *
mail_command_find(struct mail_session *session, unsigned int id)
{
	struct mail_command *cmd;

	i_assert(id != 0);

	if (id > session->highest_cmd_id) {
		/* fast path for new commands */
		return NULL;
	}
	for (cmd = session->commands; cmd != NULL; cmd = cmd->session_next) {
		if (cmd->id == id)
			return cmd;
	}
	/* expired */
	return NULL;
}

static struct mail_command *
mail_command_add(struct mail_session *session, const char *name,
		 const char *args)
{
	struct mail_command *cmd;

	cmd = i_new(struct mail_command, 1);
	cmd->refcount = 1; /* unrefed at "done" */
	cmd->session = session;
	cmd->name = i_strdup(name);
	cmd->args = i_strdup(args);
	cmd->last_update = ioloop_timeval;

	DLLIST_PREPEND_FULL(&stable_mail_commands, cmd,
			    stable_prev, stable_next);
	DLLIST_PREPEND_FULL(&session->commands, cmd,
			    session_prev, session_next);
	mail_session_ref(cmd->session);
	global_memory_alloc(mail_command_memsize(cmd));
	return cmd;
}

static void mail_command_free(struct mail_command *cmd)
{
	i_assert(cmd->refcount == 0);

	global_memory_free(mail_command_memsize(cmd));

	DLLIST_REMOVE_FULL(&stable_mail_commands, cmd,
			    stable_prev, stable_next);
	DLLIST_REMOVE_FULL(&cmd->session->commands, cmd,
			   session_prev, session_next);
	mail_session_unref(&cmd->session);
	i_free(cmd->name);
	i_free(cmd->args);
	i_free(cmd);
}

void mail_command_ref(struct mail_command *cmd)
{
	cmd->refcount++;
}

void mail_command_unref(struct mail_command **_cmd)
{
	struct mail_command *cmd = *_cmd;

	i_assert(cmd->refcount > 0);
	cmd->refcount--;

	*_cmd = NULL;
}

int mail_command_update_parse(const char *const *args, const char **error_r)
{
	struct mail_session *session;
	struct mail_command *cmd;
	struct mail_stats stats, diff_stats;
	const char *error;
	unsigned int cmd_id;
	bool done;

	/* <session guid> <cmd id> <done> <name> <args> [key=value ..] */
	if (str_array_length(args) < 4) {
		*error_r = "UPDATE-CMD: Too few parameters";
		return -1;
	}
	if (mail_session_get(args[0], &session, error_r) < 0)
		return -1;

	if (str_to_uint(args[1], &cmd_id) < 0 || cmd_id == 0) {
		*error_r = "UPDATE-CMD: Invalid command id";
		return -1;
	}
	if (strcmp(args[2], "0") != 0 &&
	    strcmp(args[2], "1") != 0) {
		*error_r = "UPDATE-CMD: Invalid done parameter";
		return -1;
	}
	done = args[2][0] == '1';
	if (mail_stats_parse(args+5, &stats, error_r) < 0) {
		*error_r = t_strconcat("UPDATE-CMD: ", *error_r, NULL);
		return -1;
	}

	cmd = mail_command_find(session, cmd_id);
	if (cmd == NULL) {
		cmd = mail_command_add(session, args[3], args[4]);
		cmd->id = cmd_id;
		cmd->stats = stats;
		diff_stats = stats;

		session->num_cmds++;
		session->user->num_cmds++;
		session->user->domain->num_cmds++;
		if (session->ip != NULL)
			session->ip->num_cmds++;
	} else {
		if (!mail_stats_diff(&cmd->stats, &stats, &diff_stats,
				     &error)) {
			*error_r = t_strconcat("UPDATE-CMD: stats shrank: ",
					       error, NULL);
			return -1;
		}
		cmd->last_update = ioloop_timeval;
		mail_stats_add(&session->stats, &diff_stats);
	}
	if (done) {
		cmd->id = 0;
		mail_command_unref(&cmd);
	}
	mail_session_refresh(session, NULL);
	return 0;
}

void mail_commands_free_memory(void)
{
	while (stable_mail_commands != NULL &&
	       stable_mail_commands->refcount == 0) {
		i_assert(stable_mail_commands->id == 0);
		mail_command_free(stable_mail_commands);

		if (global_used_memory < stats_settings->memory_limit)
			break;
		if (ioloop_time -
		    stable_mail_commands->last_update.tv_sec < stats_settings->command_min_time)
			break;
	}
}

void mail_commands_init(void)
{
}

void mail_commands_deinit(void)
{
	while (stable_mail_commands != NULL) {
		struct mail_command *cmd = stable_mail_commands;

		if (cmd->id != 0)
			mail_command_unref(&cmd);
		mail_command_free(stable_mail_commands);
	}
}
