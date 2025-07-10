/* Copyright (c) 2025 Patrick Cernko, see the included COPYING file
 */

#include "lib.h"
#include "module-dir.h"
#include "doveadm-dsync.h"
#include "auth-master.h"
#include "str.h"
#include "strescape.h"
#include "write-full.h"

#include "doveadm-dsync-replication-plugin.h"


struct replication_module_context {
	string_t *state_str;
	enum dsync_brain_sync_type sync_type;
        bool notify_replicator:1;
};

static void *replication_alloc(struct dsync_cmd_context *dctx) {
        struct replication_module_context *ctx;
        ctx = p_new(dctx->ctx.pool, struct replication_module_context, 1);
        i_zero(ctx);
        ctx->state_str = str_new(dctx->ctx.pool, 128);
        return (void *) ctx;
}

static void replication_init(void *_ctx,
                                struct dsync_cmd_context *dctx) {
        e_debug(dctx->ctx.cctx->event, "replication_init()");
        struct replication_module_context *ctx =
                (struct replication_module_context *) _ctx;
        ctx->notify_replicator =
                doveadm_cmd_param_flag(dctx->ctx.cctx,
                                       "notify-replicator");
        e_debug(dctx->ctx.cctx->event,
                "replication_init(): ctx->notify_replicator=%s",
                ctx->notify_replicator ? "TRUE" : "FALSE");
}

static bool replication_connected_callback(void *_ctx ATTR_UNUSED,
                                           struct dsync_cmd_context *dctx,
                                           const struct doveadm_server_reply *reply) {
        e_debug(dctx->ctx.cctx->event, "replication_connected_callback()");
	switch (reply->exit_code) {
	case DOVEADM_EX_NOREPLICATE:
		dctx->error = p_strdup_printf(dctx->ctx.pool,
                                              "user is disabled for replication. "
                                              "Remote exit_code=%u %s",
                                              reply->exit_code, reply->error);
                return TRUE;
		break;
	}
        return FALSE;
}

/* defined below */
bool
get_noreplicate(struct doveadm_cmd_context *cctx);

static int replication_run_pre(void *_ctx,
                               struct dsync_cmd_context *dctx,
                               struct mail_user *user ATTR_UNUSED) {
        e_debug(dctx->ctx.cctx->event, "replication_run_pre()");
        struct replication_module_context *ctx =
                (struct replication_module_context *) _ctx;
	bool cli = (dctx->ctx.cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);
	/* notify_replicator indicates here automated attempt,
	   we still want to allow manual sync/backup */
        bool noreplicate = get_noreplicate(dctx->ctx.cctx);
        e_debug(dctx->ctx.cctx->event,
                "replication_run_pre(): "
                "cli=%s ctx->notify_replicator=%s noreplicate=%s",
                cli ? "TRUE" : "FALSE",
                ctx->notify_replicator ? "TRUE" : "FALSE",
                noreplicate ? "TRUE" : "FALSE");
	if (!cli && ctx->notify_replicator &&
	    get_noreplicate(dctx->ctx.cctx)) {
                e_debug(dctx->ctx.cctx->event,
                        "replication_run_pre(): "
                        "setting exit_code=%d and returning -1",
                        DOVEADM_EX_NOREPLICATE);
		dctx->ctx.exit_code = DOVEADM_EX_NOREPLICATE;
		return -1;
	}
        e_debug(dctx->ctx.cctx->event, "replication_run_pre(): returning 0");
        return 0;
}

static void replication_server_run_command(void *_ctx,
                                           struct dsync_cmd_context *dctx ATTR_UNUSED,
                                           struct doveadm_client *conn ATTR_UNUSED,
                                           string_t *cmd) {
        e_debug(dctx->ctx.cctx->event,
                "replication_server_run_command(\"%s\")",
                str_c(cmd));
        struct replication_module_context *ctx =
                (struct replication_module_context *) _ctx;
        if (ctx->notify_replicator) {
		str_append(cmd, "\t-U");
        }
        e_debug(dctx->ctx.cctx->event,
                "replication_server_run_command(): cmd=\"%s\"",
                str_c(cmd));
}

static void replication_server_run_predeinit(void *_ctx,
                                             struct dsync_cmd_context *dctx ATTR_UNUSED,
                                             struct mail_user *user ATTR_UNUSED,
                                             struct dsync_ibc *ibc ATTR_UNUSED,
                                             struct dsync_brain *brain) {
        e_debug(dctx->ctx.cctx->event, "replication_server_run_predeinit()");
        struct replication_module_context *ctx =
                (struct replication_module_context *) _ctx;
	if (ctx->notify_replicator) {
		dsync_brain_get_state(brain, ctx->state_str);
                ctx->sync_type = dsync_brain_get_sync_type(brain);
                e_debug(dctx->ctx.cctx->event,
                        "replication_server_run_predeinit(): "
                        "ctx->sync_type=%d ctx->state_str=\"%s\"",
                        ctx->sync_type,
                        str_c(ctx->state_str));
	}
        e_debug(dctx->ctx.cctx->event,
                "replication_server_run_predeinit(): returning");
}

/* defined below */
void
replicator_notify(struct dsync_cmd_context *ctx,
                  enum dsync_brain_sync_type sync_type,
                  const char *state_str);

static void replication_server_run_deinit(void *_ctx,
                                          struct dsync_cmd_context *dctx,
                                          struct mail_user *user ATTR_UNUSED) {
        e_debug(dctx->ctx.cctx->event, "replication_server_run_deinit()");
        struct replication_module_context *ctx =
                (struct replication_module_context *) _ctx;
	if (ctx->notify_replicator && dctx->ctx.exit_code == 0) {
                e_debug(dctx->ctx.cctx->event,
                        "replication_server_run_deinit(): "
                        "calling replicator_notify(%d, \"%s\")",
                        ctx->sync_type,
                        str_c(ctx->state_str));
		replicator_notify(dctx, ctx->sync_type, str_c(ctx->state_str));
	}
}

const struct dsync_hooks dsync_replication_hooks = {
        .alloc = replication_alloc,
        .init = replication_init,
        .connected_callback = replication_connected_callback,
        .run_pre = replication_run_pre,
        /* we can reuse replication_init and replication_run_pre for the server as well */
        .server_init = replication_init,
        .server_run_pre = replication_run_pre,
        .server_run_command = replication_server_run_command,
        .server_run_predeinit = replication_server_run_predeinit,
        .server_run_deinit = replication_server_run_deinit,
};


/*
  look up mail_replica and noreplicate from userdb
*/
static int
get_userdb_field(struct doveadm_cmd_context *cctx,
                 const char *username,
                 const char *field,
                 char *value, const size_t value_length,
                 const char **error_r)
{
        e_debug(cctx->event,
                "get_userdb_field(\"%s\", \"%s\")",
                username, field);
	const char *auth_socket_path;
	enum auth_master_flags flags = 0;
	struct auth_master_connection *conn;
	pool_t pool;
        struct auth_user_info user_info;
	int ret;
	const char *updated_username = NULL, *const *fields;

	if (!doveadm_cmd_param_str(cctx, "socket-path", &auth_socket_path))
		auth_socket_path = doveadm_settings->auth_socket_path;

	pool = pool_alloconly_create("auth master lookup", 1024);

	/* flags |= AUTH_MASTER_FLAG_DEBUG; */
	conn = auth_master_init(auth_socket_path, flags);
	i_zero(&user_info);
	user_info.protocol = "doveadm";
	ret = auth_master_user_lookup(conn, username, &user_info,
				      pool, &updated_username, &fields);

	if (ret < 0) {
        	if (fields[0] == NULL) {
			e_error(cctx->event,
				"userdb lookup failed for %s", username);
                        *error_r = t_strdup_printf("userdb lookup failed for %s",
                                                   username);
		} else {
			e_error(cctx->event,
				"userdb lookup failed for %s: %s",
				username, fields[0]);
                        *error_r = t_strdup_printf("userdb lookup failed for %s: %s",
                                                   username, fields[0]);
		}
		ret = -1;
	} else if (ret == 0) {
        	e_error(cctx->event,
                        "userdb lookup: user %s doesn't exist",
			username);
                *error_r = t_strdup_printf("userdb lookup: user %s doesn't exist",
                                           username);
	} else {
		size_t field_len = strlen(field);

		for (; *fields != NULL; fields++) {
			if (strncmp(*fields, field, field_len) == 0 &&
			    (*fields)[field_len] == '=') {
                          if (i_strocpy(value,
                                        *fields + field_len + 1,
                                        value_length) < 0) {
                          	e_error(cctx->event,
                                        "failed to i_strocpy %s's %s field",
                                        username, field);
                                *error_r = t_strdup_printf("failed to i_strocpy %s's %s field",
                                                           username, field);
                                ret = -1;
                          } else {
                          	ret = 2;
                          }
                        }
		}
                if (ret != 2) {
                        /*
                          in case we did not find the field in the userdb result,
                          we set error_r appropriate as our called might need it initialized
                        */
                        *error_r = t_strdup_printf("field \"%s\" not found for user %s",
                                                   field, cctx->username);
                }
        }
        auth_master_deinit(&conn);
	pool_unref(&pool);
	return ret;
}

#define USERDB_FIELD_SIZE 1024

bool
get_noreplicate(struct doveadm_cmd_context *cctx)
{
        e_debug(cctx->event, "get_noreplicate()");
        char noreplicate[USERDB_FIELD_SIZE];
        const char *error_r[1024];
        int ret;

        ret = get_userdb_field(cctx, cctx->username, "noreplicate",
                               noreplicate, USERDB_FIELD_SIZE, error_r);
        if (ret < 2) {
                e_debug(cctx->event,
                        "get_noreplicate(): returning FALSE with ret=%d", ret);
                /* error, user not found, field not found */
        	return FALSE;
        }
        if ((strlen(noreplicate) > 0) &&
            ((noreplicate[0] == '0') || (strcmp(noreplicate, "no") == 0))) {
                e_debug(cctx->event,
                        "get_noreplicate(): returning FALSE with noreplicate=%s",
                        noreplicate);
                return FALSE;
        }
        e_debug(cctx->event,
                "get_noreplicate(): returning TRUE with noreplicate=%s",
                noreplicate);
	return TRUE;
}

void
replicator_notify(struct dsync_cmd_context *ctx,
                  enum dsync_brain_sync_type sync_type,
                  const char *state_str)
{
        e_debug(ctx->ctx.cctx->event,
                "replicator_notify(%d, \"%s\")",
                sync_type, state_str);
#define REPLICATOR_HANDSHAKE "VERSION\treplicator-doveadm-client\t1\t0\n"
	const char *path;
	string_t *str;
	int fd;

	path = t_strdup_printf("%s/replicator-doveadm",
			       ctx->ctx.cur_mail_user->set->base_dir);
	fd = net_connect_unix(path);
	if (fd == -1) {
		if (errno == ECONNREFUSED || errno == ENOENT) {
			/* replicator not running on this server. ignore. */
			return;
		}
		e_error(ctx->ctx.cctx->event,
			"net_connect_unix(%s) failed: %m", path);
		return;
	}
	fd_set_nonblock(fd, FALSE);

	str = t_str_new(128);
	str_append(str, REPLICATOR_HANDSHAKE"NOTIFY\t");
	str_append_tabescaped(str, ctx->ctx.cur_mail_user->username);
	str_append_c(str, '\t');
	if (sync_type == DSYNC_BRAIN_SYNC_TYPE_FULL)
		str_append_c(str, 'f');
	str_append_c(str, '\t');
	str_append_tabescaped(str, state_str);
	str_append_c(str, '\n');
	if (write_full(fd, str_data(str), str_len(str)) < 0) {
		e_error(ctx->ctx.cctx->event,
			"write(%s) failed: %m", path);
	}
	/* we only wanted to notify replicator. we don't care enough about the
	   answer to wait for it. */
	if (close(fd) < 0) {
		e_error(ctx->ctx.cctx->event,
			"close(%s) failed: %m", path);
	}
}


/* stolen from doveadm-dsync.c, adding -U option */
#define DSYNC_COMMON_PARAMS                     \
DOVEADM_CMD_MAIL_COMMON \
DOVEADM_CMD_PARAM('f', "full-sync", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('P', "purge-remote", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('R', "reverse-sync", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('l', "lock-timeout", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED) \
DOVEADM_CMD_PARAM('r', "rawlog", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('m', "mailbox", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('g', "mailbox-guid", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('n', "namespace", CMD_PARAM_ARRAY, 0) \
DOVEADM_CMD_PARAM('N', "all-namespaces", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('x', "exclude-mailbox", CMD_PARAM_ARRAY, 0) \
DOVEADM_CMD_PARAM('a', "all-mailbox", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('s', "state", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('t', "sync-since-time", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('e', "sync-until-time", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('O', "sync-flags", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('I', "sync-max-size", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('T', "timeout", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED) \
DOVEADM_CMD_PARAM('p', "destination-option", CMD_PARAM_ARRAY, 0) \
DOVEADM_CMD_PARAM('U', "notify-replicator", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('\0', "destination", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)

#define DSYNC_COMMON_USAGE \
	"[-l <secs>] [-r <rawlog path>] " \
	"[-m <mailbox>] [-g <mailbox guid>] [-n <namespace> | -N] " \
	"[-x <exclude>] [-a <all mailbox>] [-s <state>] [-T <secs>] " \
	"[-t <start date>] [-e <end date>] [-O <sync flag>] [-I <max size>] " \
	"[-p <dest option> [...]] <destination>"

struct doveadm_cmd_ver2 doveadm_cmd_replicate = {
	/* .mail_cmd = cmd_replicate_alloc, */
	.name = "replicate",
	.usage = "[-1fPRU] "DSYNC_COMMON_USAGE,
	.flags = CMD_FLAG_NO_UNORDERED_OPTIONS,
DOVEADM_CMD_PARAMS_START
DSYNC_COMMON_PARAMS
DOVEADM_CMD_PARAM('1', "oneway-sync", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_replicate_server = {
	/* .mail_cmd = cmd_replicate_server_alloc, */
	.name = "replicate-server",
	.usage = "[-r <rawlog path>] [-T <timeout secs>] [-U]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('r', "rawlog", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('T', "timeout", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('U', "notify-replicator", CMD_PARAM_BOOL, 0) \
/* previously dsync-server could have been added twice to the parameters */
DOVEADM_CMD_PARAM('\0', "ignore-arg", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};


void doveadm_update_sync_command(void);
void doveadm_update_sync_command(void) {
        /* if (isatty(2)) fprintf(stderr, "doveadm_update_sync_command()\n"); */
        /* get current "doveadm sync" command definition and cast it to non-const to overwrite parts */
        struct doveadm_cmd_ver2 *cmd = (struct doveadm_cmd_ver2 *) doveadm_cmd_find_ver2("sync");
        if (cmd == NULL) {
                fprintf(stderr, "doveadm_update_sync_command(): could not find \"sync\" command to modify.\n");
                return;
        }
        /* if (isatty(2)) fprintf(stderr, "doveadm_update_sync_command(): Found plugin \"%s\"\n", cmd->name); */

        /* add new command line options (adding -U switch) */
        cmd->usage      = doveadm_cmd_replicate.usage;
        cmd->parameters = doveadm_cmd_replicate.parameters;
}

void doveadm_update_dsync_server_command(void);
void doveadm_update_dsync_server_command(void) {
        /* if (isatty(2)) fprintf(stderr, "doveadm_update_dsync_server_command()\n"); */
        /* get current "doveadm dsync-server" command definition and cast it to non-const to overwrite parts */
        struct doveadm_cmd_ver2 *cmd = (struct doveadm_cmd_ver2 *) doveadm_cmd_find_ver2("dsync-server");
        if (cmd == NULL) {
                fprintf(stderr, "doveadm_update_dsync_server_command(): could not find \"dsync-server\" command to modify.\n");
                return;
        }
        /* if (isatty(2)) fprintf(stderr, "doveadm_update_dsync_server_command(): Found plugin \"%s\"\n", cmd->name); */

        /* add new command line options (adding -U switch) */
        cmd->usage      = doveadm_cmd_replicate_server.usage;
        cmd->parameters = doveadm_cmd_replicate_server.parameters;
}


void doveadm_dsync_replication_plugin_init(struct module *module)
{
        dsync_hooks_add(module, &dsync_replication_hooks);
        doveadm_update_sync_command();
        doveadm_update_dsync_server_command();
}

void doveadm_dsync_replication_plugin_deinit(void)
{
        /* hook system is already deinitialized when plugins get deinitized */
        /* no need to remove hook, will cause a segfault */
        /* dsync_hooks_remove(&dsync_replication_hooks); */
}
