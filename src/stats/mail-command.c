/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "llist.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "mail-stats.h"
#include "mail-session.h"
#include "mail-command.h"

#define MAIL_COMMAND_TIMEOUT_SECS (60*15)

/* commands are sorted by their last_update timestamp, oldest first */
struct mail_command *stable_mail_commands_head;
struct mail_command *stable_mail_commands_tail;

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

	DLLIST2_APPEND_FULL(&stable_mail_commands_head,
			    &stable_mail_commands_tail, cmd,
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

	DLLIST2_REMOVE_FULL(&stable_mail_commands_head,
			    &stable_mail_commands_tail, cmd,
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
	unsigned int i, cmd_id;
	bool done = FALSE, continued = FALSE;

	/* <session guid> <cmd id> [d] <name> <args> [key=value ..]
	   <session guid> <cmd id> c[d] [key=value ..] */
	if (str_array_length(args) < 3) {
		*error_r = "UPDATE-CMD: Too few parameters";
		return -1;
	}
	if (mail_session_get(args[0], &session, error_r) < 0)
		return -1;

	if (str_to_uint(args[1], &cmd_id) < 0 || cmd_id == 0) {
		*error_r = "UPDATE-CMD: Invalid command id";
		return -1;
	}
	for (i = 0; args[2][i] != '\0'; i++) {
		switch (args[2][i]) {
		case 'd':
			done = TRUE;
			break;
		case 'c':
			continued = TRUE;
			break;
		default:
			*error_r = "UPDATE-CMD: Invalid flags parameter";
			return -1;
		}
	}

	cmd = mail_command_find(session, cmd_id);
	if (!continued) {
		/* new command */
		if (cmd != NULL) {
			*error_r = "UPDATE-CMD: Duplicate new command id";
			return -1;
		}
		if (str_array_length(args) < 5) {
			*error_r = "UPDATE-CMD: Too few parameters";
			return -1;
		}
		cmd = mail_command_add(session, args[3], args[4]);
		cmd->id = cmd_id;

		session->highest_cmd_id =
			I_MAX(session->highest_cmd_id, cmd_id);
		session->num_cmds++;
		session->user->num_cmds++;
		session->user->domain->num_cmds++;
		if (session->ip != NULL)
			session->ip->num_cmds++;
		args += 5;
	} else {
		if (cmd == NULL) {
			/* already expired command, ignore */
			i_warning("UPDATE-CMD: Already expired");
			return 0;
		}
		args += 3;
		cmd->last_update = ioloop_timeval;
	}
	if (mail_stats_parse(args, &stats, error_r) < 0) {
		*error_r = t_strconcat("UPDATE-CMD: ", *error_r, NULL);
		return -1;
	}
	if (!mail_stats_diff(&cmd->stats, &stats, &diff_stats, &error)) {
		*error_r = t_strconcat("UPDATE-CMD: stats shrank: ",
				       error, NULL);
		return -1;
	}
	mail_stats_add(&cmd->stats, &diff_stats);

	if (done) {
		cmd->id = 0;
		mail_command_unref(&cmd);
	}
	mail_session_refresh(session, NULL);
	return 0;
}

static bool mail_command_is_timed_out(struct mail_command *cmd)
{
	/* some commands like IDLE can run forever */
	return ioloop_time - cmd->last_update.tv_sec >
		MAIL_COMMAND_TIMEOUT_SECS;
}

void mail_commands_free_memory(void)
{
	unsigned int diff;

	while (stable_mail_commands_head != NULL) {
		struct mail_command *cmd = stable_mail_commands_head;

		if (cmd->refcount == 0)
			i_assert(cmd->id == 0);
		else if (cmd->refcount == 1 &&
			 (cmd->session->disconnected ||
			  mail_command_is_timed_out(cmd))) {
			/* session was probably lost */
			mail_command_unref(&cmd);
		} else {
			break;
		}
		mail_command_free(stable_mail_commands_head);

		if (global_used_memory < stats_settings->memory_limit ||
		    stable_mail_commands_head == NULL)
			break;

		diff = ioloop_time - stable_mail_commands_head->last_update.tv_sec;
		if (diff < stats_settings->command_min_time)
			break;
	}
}

void mail_commands_init(void)
{
}

void mail_commands_deinit(void)
{
	while (stable_mail_commands_head != NULL) {
		struct mail_command *cmd = stable_mail_commands_head;

		if (cmd->id != 0)
			mail_command_unref(&cmd);
		mail_command_free(stable_mail_commands_head);
	}
}
