/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "network.h"
#include "hash.h"
#include "doveadm.h"
#include "doveadm-who.h"

#include <stdio.h>
#include <stdlib.h>
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
	ARRAY_DEFINE(users, struct kick_user);
	bool kick;
};

struct kick_context {
	struct who_context who;
	struct hash_table *pids;
	bool force_kick;
	ARRAY_DEFINE(kicked_users, const char *);
};

static void
kick_aggregate_line(struct who_context *_ctx, const struct who_line *line)
{
	struct kick_context *ctx = (struct kick_context *)_ctx;
	const bool user_match = who_line_filter_match(line, &ctx->who.filter);
	struct kick_pid *k_pid;
	struct kick_user new_user, *user;

	memset(&new_user, 0, sizeof(new_user));

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
	array_append(&k_pid->users, &new_user, 1);
}

static bool
kick_pid_want_kicked(struct kick_context *ctx, const struct kick_pid *k_pid,
		     bool *show_warning)
{
	unsigned int kick_count = 0;
	const struct kick_user *user;

	if (array_count(&k_pid->users) == 1) {
		user = array_idx(&k_pid->users, 0);
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
					array_append(&ctx->kicked_users,
						     &user->username, 1);
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

	if (array_count(&ctx->kicked_users) == 0) {
		printf("no users kicked\n");
		return;
	}

	if (show_warning) {
		printf("warning: other connections would also be "
		       "kicked from following users:\n");
	} else
		printf("kicked connections from the following users:\n");

	array_sort(&ctx->kicked_users, i_strcmp_p);
	users = array_get(&ctx->kicked_users, &count);
	printf("%s ", users[0]);
	for (i = 1; i < count; i++) {
		if (strcmp(users[i-1], users[i]) != 0)
			printf("%s ", users[i]);
	}
	printf("\n");

	if (show_warning)
		printf("Use the '-f' option to enforce the disconnect.\n");
}

static void kick_users(struct kick_context *ctx)
{
	bool show_enforce_warning = FALSE;
	void *key, *value;
	struct kick_pid *k_pid;
	struct hash_iterate_context *iter;
	const struct kick_user *user;

	p_array_init(&ctx->kicked_users, ctx->who.pool, 10);

	iter = hash_table_iterate_init(ctx->pids);
	while (hash_table_iterate(iter, &key, &value)) {
		k_pid = value;
		if (kick_pid_want_kicked(ctx, k_pid, &show_enforce_warning))
			k_pid->kick = TRUE;
	}
	hash_table_iterate_deinit(&iter);

	if (show_enforce_warning) {
		kick_print_kicked(ctx, show_enforce_warning);
		return;
	}

	iter = hash_table_iterate_init(ctx->pids);
	while (hash_table_iterate(iter, &key, &value)) {
		k_pid = value;
		if (!k_pid->kick)
			continue;

		if (kill(k_pid->pid, SIGTERM) < 0 && errno != ESRCH) {
			fprintf(stderr, "kill(%s, SIGTERM) failed: %m\n",
				dec2str(k_pid->pid));
		} else {
			array_foreach(&k_pid->users, user) {
				array_append(&ctx->kicked_users,
					     &user->username, 1);
			}
		}
	}
	hash_table_iterate_deinit(&iter);

	kick_print_kicked(ctx, show_enforce_warning);
}

static void cmd_kick(int argc, char *argv[])
{
	struct kick_context ctx;
	int c;

	memset(&ctx, 0, sizeof(ctx));
	ctx.who.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);
	ctx.force_kick = FALSE;
	ctx.who.pool = pool_alloconly_create("kick pids", 10240);
	ctx.pids = hash_table_create(default_pool, ctx.who.pool, 0, NULL, NULL);

	while ((c = getopt(argc, argv, "a:f")) > 0) {
		switch (c) {
		case 'a':
			ctx.who.anvil_path = optarg;
			break;
		case 'f':
			ctx.force_kick = TRUE;
			break;
		default:
			help(&doveadm_cmd_kick);
		}
	}

	argv += optind - 1;
	if (argv[1] == NULL)
		i_fatal("user and/or ip[/bits] must be specified.");
	who_parse_args(&ctx.who, argv);

	who_lookup(&ctx.who, kick_aggregate_line);
	kick_users(&ctx);

	hash_table_destroy(&ctx.pids);
	pool_unref(&ctx.who.pool);
}

struct doveadm_cmd doveadm_cmd_kick = {
	cmd_kick, "kick",
	"[-a <anvil socket path>] [-f] <user mask>[|]<ip/bits>"
};
