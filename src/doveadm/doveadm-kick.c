/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "hash.h"
#include "doveadm.h"
#include "doveadm-who.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>

struct kick_user {
	const char *username;
	bool kick_me; /* true if username and/or ip[/mask] matches.
			 ignored when the -f switch is given. */
};

struct kick_pid {
	pid_t pid;
	ARRAY(struct kick_user) users;
	bool kick;
};

struct kick_context {
	struct who_context who;
	HASH_TABLE(void *, struct kick_pid *) pids;
	enum doveadm_client_type conn_type;
	bool force_kick;
	ARRAY(const char *) kicked_users;
};

static void
kick_aggregate_line(struct who_context *_ctx, const struct who_line *line)
{
	struct kick_context *ctx = (struct kick_context *)_ctx;
	const bool user_match = who_line_filter_match(line, &ctx->who.filter);
	struct kick_pid *k_pid;
	struct kick_user new_user, *user;

	i_zero(&new_user);

	k_pid = hash_table_lookup(ctx->pids, POINTER_CAST(line->pid));
	if (k_pid == NULL) {
		k_pid = p_new(ctx->who.pool, struct kick_pid, 1);
		k_pid->pid = line->pid;
		p_array_init(&k_pid->users, ctx->who.pool, 5);
		hash_table_insert(ctx->pids, POINTER_CAST(line->pid), k_pid);
	}

	array_foreach_modifiable(&k_pid->users, user) {
		if (strcmp(line->username, user->username) == 0) {
			if (user_match)
				user->kick_me = TRUE;
			return;
		}
	}
	new_user.username = p_strdup(ctx->who.pool, line->username);
	new_user.kick_me = user_match;
	array_push_back(&k_pid->users, &new_user);
}

static bool
kick_pid_want_kicked(struct kick_context *ctx, const struct kick_pid *k_pid,
		     bool *show_warning)
{
	unsigned int kick_count = 0;
	const struct kick_user *user;

	if (array_count(&k_pid->users) == 1) {
		user = array_first(&k_pid->users);
		if (!user->kick_me)
			return FALSE;
	} else {
		array_foreach(&k_pid->users, user) {
			if (user->kick_me)
				kick_count++;
		}
		if (kick_count == 0)
			return FALSE;
		if (kick_count < array_count(&k_pid->users) &&
		    !ctx->force_kick) {
			array_foreach(&k_pid->users, user) {
				if (!user->kick_me) {
					array_push_back(&ctx->kicked_users,
							&user->username);
				}
			}
			*show_warning = TRUE;
			return FALSE;
		}
	}
	return TRUE;
}

static void
kick_print_kicked(struct kick_context *ctx, const bool show_warning)
{
	unsigned int i, count;
	const char *const *users;
	bool cli = (ctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);

	if (array_count(&ctx->kicked_users) == 0) {
		if (cli)
			printf("no users kicked\n");
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
		return;
	}

	if (cli) {
		if (show_warning) {
			printf("warning: other connections would also be "
			       "kicked from following users:\n");
		} else {
			printf("kicked connections from the following users:\n");
		}
	}

	array_sort(&ctx->kicked_users, i_strcmp_p);
	users = array_get(&ctx->kicked_users, &count);
	doveadm_print(users[0]);
	for (i = 1; i < count; i++) {
		if (strcmp(users[i-1], users[i]) != 0)
			doveadm_print(users[i]);
	}
	if (cli)
		printf("\n");

	if (show_warning)
		printf("Use the '-f' option to enforce the disconnect.\n");
}

static void kick_users(struct kick_context *ctx)
{
	bool show_enforce_warning = FALSE;
	struct hash_iterate_context *iter;
	void *key;
	struct kick_pid *k_pid;
	const struct kick_user *user;

	p_array_init(&ctx->kicked_users, ctx->who.pool, 10);

	iter = hash_table_iterate_init(ctx->pids);
	while (hash_table_iterate(iter, ctx->pids, &key, &k_pid)) {
		if (kick_pid_want_kicked(ctx, k_pid, &show_enforce_warning))
			k_pid->kick = TRUE;
	}
	hash_table_iterate_deinit(&iter);

	if (show_enforce_warning) {
		kick_print_kicked(ctx, show_enforce_warning);
		return;
	}

	iter = hash_table_iterate_init(ctx->pids);
	while (hash_table_iterate(iter, ctx->pids, &key, &k_pid)) {
		if (!k_pid->kick)
			continue;

		if (kill(k_pid->pid, SIGTERM) < 0 && errno != ESRCH) {
			fprintf(stderr, "kill(%s, SIGTERM) failed: %m\n",
				dec2str(k_pid->pid));
		} else {
			array_foreach(&k_pid->users, user) {
				array_push_back(&ctx->kicked_users,
						&user->username);
			}
		}
	}
	hash_table_iterate_deinit(&iter);

	kick_print_kicked(ctx, show_enforce_warning);
}

static void cmd_kick(struct doveadm_cmd_context *cctx)
{
	const char *const *masks;
	struct kick_context ctx;

	i_zero(&ctx);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &(ctx.who.anvil_path)))
		ctx.who.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);
	(void)doveadm_cmd_param_bool(cctx, "force", &(ctx.force_kick));
	if (!doveadm_cmd_param_array(cctx, "mask", &masks)) {
		doveadm_exit_code = EX_USAGE;
		i_error("user and/or ip[/bits] must be specified.");
		return;
	}
	ctx.conn_type = cctx->conn_type;
	if (ctx.conn_type != DOVEADM_CONNECTION_TYPE_CLI) {
		/* force-kick is a pretty ugly option. its output can't be
		   nicely translated to an API reply. it also wouldn't be very
		   useful in scripts, only for preventing a new admin from
		   accidentally kicking too many users. it's also useful only
		   in a non-recommended setup where processes are handling
		   multiple connections. so for now we'll preserve the option
		   for CLI, but always do a force-kick with non-CLI. */
		ctx.force_kick = TRUE;
	}
	ctx.who.pool = pool_alloconly_create("kick pids", 10240);
	hash_table_create_direct(&ctx.pids, ctx.who.pool, 0);

	if (who_parse_args(&ctx.who, masks)!=0) {
		hash_table_destroy(&ctx.pids);
		pool_unref(&ctx.who.pool);
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{result} ");
	doveadm_print_header_simple("result");

	who_lookup(&ctx.who, kick_aggregate_line);
	kick_users(&ctx);

	hash_table_destroy(&ctx.pids);
	pool_unref(&ctx.who.pool);
}

struct doveadm_cmd_ver2 doveadm_cmd_kick_ver2 = {
	.name = "kick",
	.cmd = cmd_kick,
	.usage = "[-a <anvil socket path>] <user mask>[|]<ip/bits>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a',"socket-path",CMD_PARAM_STR,0)
DOVEADM_CMD_PARAM('f',"force",CMD_PARAM_BOOL,0)
DOVEADM_CMD_PARAM('\0',"mask",CMD_PARAM_ARRAY,CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
