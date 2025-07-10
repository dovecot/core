#include "doveadm.h"
#include "doveadm-client.h"
#include "doveadm-mail.h"
#include "auth-master.h"
#include "dsync/dsync-brain.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "dsync/dsync-ibc.h"
#include "strescape.h"
#include "write-full.h"

#include "doveadm-dsync-replication-plugin.h"

#include <stdio.h>
#include <unistd.h>


static int
cmd_replicate_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user);
static int
cmd_replicate_server_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user);
static int
cmd_replicate_prerun(struct doveadm_mail_cmd_context *_ctx,
                     struct mail_storage_service_user *service_user ATTR_UNUSED,
                     const char **error_r);
static int
cmd_replicate_server_prerun(struct doveadm_mail_cmd_context *_ctx,
                            struct mail_storage_service_user *service_user ATTR_UNUSED,
                            const char **error_r);
static void cmd_replicate_init(struct doveadm_mail_cmd_context *_ctx);
static void cmd_replicate_server_init(struct doveadm_mail_cmd_context *_ctx);
static void cmd_replicate_preinit(struct doveadm_mail_cmd_context *_ctx);
static void cmd_replicate_server_preinit(struct doveadm_mail_cmd_context *_ctx);

static struct doveadm_mail_cmd_context *cmd_replicate_alloc(void);
static struct doveadm_mail_cmd_context *cmd_replicate_server_alloc(void);

struct dsync_cmd_context;
static void
dsync_replicator_notify(struct dsync_cmd_context *ctx,
			enum dsync_brain_sync_type sync_type,
			const char *state_str);


/* stolen from doveadm-dsync.c and extended with '-Q' */
enum dsync_run_type {
	DSYNC_RUN_TYPE_LOCAL,
	DSYNC_RUN_TYPE_STREAM,
	DSYNC_RUN_TYPE_CMD
};

struct dsync_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	enum dsync_brain_sync_type sync_type;
	const char *mailbox;
	const char *const *destination;
	const char *const *destination_options;
	const char *sync_flags;
	const char *virtual_all_box;
	guid_128_t mailbox_guid;
	const char *state_input, *rawlog_path;
	ARRAY_TYPE(const_string) exclude_mailboxes;
	ARRAY_TYPE(const_string) namespace_prefixes;
	time_t sync_since_timestamp;
	time_t sync_until_timestamp;
	uoff_t sync_max_size;
	unsigned int io_timeout_secs;

	const char *remote_name;
	pid_t remote_pid;
	const char *const *remote_cmd_args;
	struct child_wait *child_wait;
	int exit_status;

	int fd_in, fd_out, fd_err;
	struct io *io_err;
	struct istream *input, *err_stream;
	struct ostream *output;
	size_t input_orig_bufsize, output_orig_bufsize;
	const char *err_prefix;
	struct failure_context failure_ctx;

	struct ssl_iostream *ssl_iostream;

	enum dsync_run_type run_type;
	struct doveadm_client *tcp_conn;
	const char *error;

	unsigned int lock_timeout;
	unsigned int import_commit_msgs_interval;

	bool lock:1;
	bool purge_remote:1;
	bool sync_visible_namespaces:1;
	bool oneway:1;
	bool backup:1;
	bool reverse_backup:1;
	bool remote_user_prefix:1;
	bool no_mail_sync:1;
        bool replicator_notify:1;
	bool exited:1;
	bool empty_hdr_workaround:1;
	bool no_header_hashes:1;
	bool err_line_continues:1;
};

#define DSYNC_COMMON_PARAMS                     \
DOVEADM_CMD_MAIL_COMMON \
DOVEADM_CMD_PARAM('f', "full-sync", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('P', "purge-remote", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('R', "reverse-sync", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('U', "replicator-notify", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('Q', "notify-replicator", CMD_PARAM_BOOL, 0) \
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
DOVEADM_CMD_PARAM('\0', "destination", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)

#define DSYNC_COMMON_USAGE \
	"[-l <secs>] [-r <rawlog path>] " \
	"[-m <mailbox>] [-g <mailbox guid>] [-n <namespace> | -N] " \
	"[-x <exclude>] [-a <all mailbox>] [-s <state>] [-T <secs>] " \
	"[-t <start date>] [-e <end date>] [-O <sync flag>] [-I <max size>] " \
	"[-p <dest option> [...]] <destination>"

struct doveadm_cmd_ver2 doveadm_cmd_replicate = {
	.mail_cmd = cmd_replicate_alloc,
	.name = "replicate",
	.usage = "[-1fPRUQ] "DSYNC_COMMON_USAGE,
	.flags = CMD_FLAG_NO_UNORDERED_OPTIONS,
DOVEADM_CMD_PARAMS_START
DSYNC_COMMON_PARAMS
DOVEADM_CMD_PARAM('1', "oneway-sync", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_replicate_server = {
	.mail_cmd = cmd_replicate_server_alloc,
	.name = "replicate-server",
	.usage = "[-r <rawlog path>] [-T <timeout secs>] [-U]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('r', "rawlog", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('T', "timeout", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('Q', "notify-replicator", CMD_PARAM_BOOL, 0)
/* previously dsync-server could have been added twice to the parameters */
DOVEADM_CMD_PARAM('\0', "ignore-arg", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

static void dsync_connected_callback(const struct doveadm_server_reply *reply,
				     void *context)
{
        if (isatty(2)) fprintf(stderr, "dsync_connected_callback() overridden\n");
	struct dsync_cmd_context *ctx = context;

	ctx->ctx.exit_code = reply->exit_code;
	switch (reply->exit_code) {
	case 0:
		doveadm_client_extract(ctx->tcp_conn, &ctx->input,
				       &ctx->err_stream, &ctx->output,
				       &ctx->ssl_iostream);
		ctx->err_prefix = p_strdup_printf(ctx->ctx.pool,
			"dsync-remote(%s): ", ctx->ctx.cctx->username);

		break;
	case DOVEADM_CLIENT_EXIT_CODE_DISCONNECTED:
		ctx->ctx.exit_code = EX_TEMPFAIL;
		ctx->error = p_strdup_printf(ctx->ctx.pool,
			"Disconnected from remote: %s", reply->error);
		break;
	case EX_NOUSER:
		ctx->error = "Unknown user in remote";
		break;
	default:
                ctx->error = p_strdup_printf(ctx->ctx.pool,
                                             "Failed to start remote dsync-server command: "
                                             "Remote exit_code=%u %s",
                                             reply->exit_code, reply->error);
		break;
	}
	io_loop_stop(current_ioloop);
}

static void doveadm_user_init_dsync(struct mail_user *user);
static struct dsync_ibc *
cmd_dsync_ibc_stream_init(struct dsync_cmd_context *ctx,
			  const char *name, const char *temp_prefix);

static int
cmd_dsync_server_run(struct doveadm_mail_cmd_context *_ctx,
		     struct mail_user *user)
{
        if (isatty(2)) fprintf(stderr, "cmd_dsync_server_run() overridden\n");
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

	bool cli = (cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);
	struct dsync_ibc *ibc;
	struct dsync_brain *brain;
	string_t *temp_prefix, *state_str = NULL;
	enum dsync_brain_sync_type sync_type;
	const char *name, *process_title_prefix = "";
	enum mail_error mail_error;

	if (!cli) {
		/* doveadm-server connection. start with a success reply.
		   after that follows the regular dsync protocol. */
		ctx->fd_in = ctx->fd_out = -1;
		ctx->input = cctx->input;
		ctx->output = cctx->output;
		i_stream_ref(ctx->input);
		o_stream_ref(ctx->output);
		o_stream_set_finish_also_parent(ctx->output, FALSE);
		o_stream_nsend(ctx->output, "\n+\n", 3);
		i_set_failure_prefix("dsync-server(%s): ", user->username);
		name = i_stream_get_name(ctx->input);

		if (cctx->remote_ip.family != 0) {
			/* include the doveadm client's IP address in the ps output */
			process_title_prefix = t_strdup_printf(
				"%s ", net_ip2addr(&cctx->remote_ip));
		}
	} else {
		/* the log messages go via stderr to the remote dsync,
		   so the names are reversed */
		i_set_failure_prefix("dsync-remote(%s)<%s>: ", user->username, user->session_id);
		name = "local";
	}

	doveadm_user_init_dsync(user);

	temp_prefix = t_str_new(64);
	mail_user_set_get_temp_prefix(temp_prefix, user->set);

	ibc = cmd_dsync_ibc_stream_init(ctx, name, str_c(temp_prefix));
	brain = dsync_brain_slave_init(user, ibc, FALSE, process_title_prefix,
				       doveadm_settings->dsync_alt_char[0],
				       doveadm_settings->dsync_commit_msgs_interval);

	io_loop_run(current_ioloop);
	/* io_loop_run() deactivates the context - put it back */
	mail_storage_service_io_activate_user(ctx->ctx.cur_service_user);

	if (ctx->replicator_notify) {
		state_str = t_str_new(128);
		dsync_brain_get_state(brain, state_str);
	}
	sync_type = dsync_brain_get_sync_type(brain);

	if (dsync_brain_deinit(&brain, &mail_error) < 0)
		doveadm_mail_failed_error(_ctx, mail_error);
	dsync_ibc_deinit(&ibc);

	if (!cli) {
		/* make sure nothing more is written by the generic doveadm
		   connection code */
		o_stream_close(cctx->output);
	}
	i_stream_unref(&ctx->input);
	o_stream_unref(&ctx->output);

	if (ctx->replicator_notify && _ctx->exit_code == 0)
		dsync_replicator_notify(ctx, sync_type, str_c(state_str));
	return _ctx->exit_code == 0 ? 0 : -1;
}




const char *doveadm_dsync_replication_plugin_version = DOVECOT_ABI_VERSION;


struct replicate_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	struct doveadm_mail_cmd_context *dsync_mail_cmd_ctx;

        bool notify_replicator:1;
};

void copy_mail_cmd_context(struct doveadm_mail_cmd_context *src,
                           struct doveadm_mail_cmd_context *dst);
void copy_mail_cmd_context(struct doveadm_mail_cmd_context *src,
                           struct doveadm_mail_cmd_context *dst) {
        struct doveadm_mail_cmd_vfuncs vfuncs;
        memcpy(&vfuncs, &dst->v, sizeof(struct doveadm_mail_cmd_vfuncs));
        memcpy(dst, src, sizeof(struct doveadm_mail_cmd_context));
        memcpy(&dst->v, &vfuncs, sizeof(struct doveadm_mail_cmd_vfuncs));
}

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

static bool
get_noreplicate(struct doveadm_cmd_context *cctx)
{
        char noreplicate[USERDB_FIELD_SIZE];
        const char *error_r[1024];
        int ret;

        ret = get_userdb_field(cctx, cctx->username, "noreplicate",
                               noreplicate, USERDB_FIELD_SIZE, error_r);
        if (ret < 2) {
                /* error, user not found, field not found */
        	return FALSE;
        }
        if ((strlen(noreplicate) > 0) &&
            (noreplicate[0] == '0')) {
                return FALSE;
        }
	return TRUE;
}


static void
dsync_replicator_notify(struct dsync_cmd_context *ctx,
			enum dsync_brain_sync_type sync_type,
			const char *state_str)
{
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



static int
cmd_replicate_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
        if (isatty(2)) fprintf(stderr, "cmd_replicate_run()\n");
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct replicate_cmd_context *ctx =
		container_of(_ctx, struct replicate_cmd_context, ctx);

	bool cli = (cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);
	/* replicator_notify indicates here automated attempt,
	   we still want to allow manual sync/backup */
	if (!cli && ctx->notify_replicator &&
	    get_noreplicate(cctx)) {
		ctx->ctx.exit_code = DOVEADM_EX_NOREPLICATE;
		return -1;
	}

        struct doveadm_mail_cmd_context *dmc_ctx = ctx->dsync_mail_cmd_ctx;
        copy_mail_cmd_context(_ctx, dmc_ctx);
	int ret = dmc_ctx->v.run(dmc_ctx, user);
        copy_mail_cmd_context(dmc_ctx, _ctx);
        return ret;
}

static int
cmd_replicate_server_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
        if (isatty(2)) fprintf(stderr, "cmd_replicate_server_run()\n");
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct replicate_cmd_context *ctx =
		container_of(_ctx, struct replicate_cmd_context, ctx);

	bool cli = (cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);
	/* replicator_notify indicates here automated attempt,
	   we still want to allow manual sync/backup */
	if (!cli && ctx->notify_replicator &&
	    get_noreplicate(cctx)) {
		ctx->ctx.exit_code = DOVEADM_EX_NOREPLICATE;
		return -1;
	}

        struct doveadm_mail_cmd_context *dmc_ctx = ctx->dsync_mail_cmd_ctx;
        copy_mail_cmd_context(_ctx, dmc_ctx);
	int ret = cmd_dsync_server_run(dmc_ctx, user);
        copy_mail_cmd_context(dmc_ctx, _ctx);
        return ret;
}

static int
cmd_replicate_prerun(struct doveadm_mail_cmd_context *_ctx,
		 struct mail_storage_service_user *service_user ATTR_UNUSED,
		 const char **error_r)
{
	struct replicate_cmd_context *ctx =
		container_of(_ctx, struct replicate_cmd_context, ctx);

        struct doveadm_mail_cmd_context *dmc_ctx = ctx->dsync_mail_cmd_ctx;
        copy_mail_cmd_context(_ctx, dmc_ctx);
	int ret = dmc_ctx->v.prerun(dmc_ctx, service_user, error_r);
        copy_mail_cmd_context(dmc_ctx, _ctx);
        return ret;
}

static int
cmd_replicate_server_prerun(struct doveadm_mail_cmd_context *_ctx,
		 struct mail_storage_service_user *service_user ATTR_UNUSED,
		 const char **error_r)
{
	struct replicate_cmd_context *ctx =
		container_of(_ctx, struct replicate_cmd_context, ctx);

        struct doveadm_mail_cmd_context *dmc_ctx = ctx->dsync_mail_cmd_ctx;
        copy_mail_cmd_context(_ctx, dmc_ctx);
	int ret = dmc_ctx->v.prerun(dmc_ctx, service_user, error_r);
        copy_mail_cmd_context(dmc_ctx, _ctx);
        return ret;
}

static void cmd_replicate_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct replicate_cmd_context *ctx =
		container_of(_ctx, struct replicate_cmd_context, ctx);

        struct doveadm_mail_cmd_context *dmc_ctx = ctx->dsync_mail_cmd_ctx;
        copy_mail_cmd_context(_ctx, dmc_ctx);
	dmc_ctx->v.init(dmc_ctx);
        copy_mail_cmd_context(dmc_ctx, _ctx);
}

static void cmd_replicate_server_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct replicate_cmd_context *ctx =
		container_of(_ctx, struct replicate_cmd_context, ctx);

        struct doveadm_mail_cmd_context *dmc_ctx = ctx->dsync_mail_cmd_ctx;
        copy_mail_cmd_context(_ctx, dmc_ctx);
	dmc_ctx->v.init(dmc_ctx);
        copy_mail_cmd_context(dmc_ctx, _ctx);
}

static void cmd_replicate_preinit(struct doveadm_mail_cmd_context *_ctx) {
        if (isatty(2)) fprintf(stderr, "cmd_replicate_preinit()\n");
 	struct replicate_cmd_context *ctx =
		container_of(_ctx, struct replicate_cmd_context, ctx);
        struct doveadm_mail_cmd_context *dmc_ctx = ctx->dsync_mail_cmd_ctx;
        copy_mail_cmd_context(_ctx, dmc_ctx);
	dmc_ctx->v.preinit(dmc_ctx);
        copy_mail_cmd_context(dmc_ctx, _ctx);
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	if (doveadm_cmd_param_flag(cctx, "notify-replicator")) {
                if (isatty(2)) fprintf(stderr, "cmd_replicate_preinit(): option \"-Q\" found\n");
                ctx->notify_replicator = TRUE;
        }
}

static void cmd_replicate_server_preinit(struct doveadm_mail_cmd_context *_ctx) {
        if (isatty(2)) fprintf(stderr, "cmd_replicate_server_preinit()\n");
 	struct replicate_cmd_context *ctx =
		container_of(_ctx, struct replicate_cmd_context, ctx);
        struct doveadm_mail_cmd_context *dmc_ctx = ctx->dsync_mail_cmd_ctx;
        copy_mail_cmd_context(_ctx, dmc_ctx);
	dmc_ctx->v.preinit(dmc_ctx);
        copy_mail_cmd_context(dmc_ctx, _ctx);
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	if (doveadm_cmd_param_flag(cctx, "notify-replicator")) {
                if (isatty(2)) fprintf(stderr, "cmd_replicate_server_preinit(): option \"-Q\" found\n");
                ctx->notify_replicator = TRUE;
        }
}

static struct doveadm_mail_cmd_context *(*cmd_dsync_alloc_orig)(void);

static struct doveadm_mail_cmd_context *cmd_replicate_alloc(void)
{
        if (isatty(2)) fprintf(stderr, "cmd_replicate_alloc()\n");

	struct replicate_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct replicate_cmd_context);
        ctx->dsync_mail_cmd_ctx = cmd_dsync_alloc_orig();
	ctx->ctx.v.preinit = cmd_replicate_preinit;
	ctx->ctx.v.init    = cmd_replicate_init;
	ctx->ctx.v.prerun  = cmd_replicate_prerun;
	ctx->ctx.v.run     = cmd_replicate_run;
	ctx->notify_replicator = FALSE;

	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *(*cmd_dsync_server_alloc_orig)(void);

static struct doveadm_mail_cmd_context *cmd_replicate_server_alloc(void)
{
        if (isatty(2)) fprintf(stderr, "cmd_replicate_server_alloc()\n");

	struct replicate_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct replicate_cmd_context);
        ctx->dsync_mail_cmd_ctx = cmd_dsync_server_alloc_orig();
	ctx->ctx.v.preinit = cmd_replicate_server_preinit;
	ctx->ctx.v.init    = cmd_replicate_server_init;
	ctx->ctx.v.prerun  = cmd_replicate_server_prerun;
	ctx->ctx.v.run     = cmd_replicate_server_run;
	ctx->notify_replicator = FALSE;

	return &ctx->ctx;
}

void doveadm_update_sync_command(void);
void doveadm_update_sync_command(void) {
        if (isatty(2)) fprintf(stderr, "doveadm_update_sync_command()\n");
        /* get current "doveadm sync" command definition and cast it to non-const to overwrite parts */
        struct doveadm_cmd_ver2 *cmd = (struct doveadm_cmd_ver2 *) doveadm_cmd_find_ver2("sync");
        if (cmd == NULL) {
                fprintf(stderr, "doveadm_update_sync_command(): could not find \"sync\" command to modify.\n");
                return;
        }
        if (isatty(2)) fprintf(stderr, "doveadm_update_sync_command(): Found plugin \"%s\"\n", cmd->name);

        /* store current mail_cmd allocation function pointer to reuse it later in cmd_replicate_alloc() */
        cmd_dsync_alloc_orig = cmd->mail_cmd;
        /* set new mail_cmd function */
        cmd->mail_cmd   = doveadm_cmd_replicate.mail_cmd;
        /* and new command line options (adding -U switch) */
        cmd->usage      = doveadm_cmd_replicate.usage;
        cmd->parameters = doveadm_cmd_replicate.parameters;
}

void doveadm_update_dsync_server_command(void);
void doveadm_update_dsync_server_command(void) {
        if (isatty(2)) fprintf(stderr, "doveadm_update_dsync_server_command()\n");
        /* get current "doveadm dsync-server" command definition and cast it to non-const to overwrite parts */
        struct doveadm_cmd_ver2 *cmd = (struct doveadm_cmd_ver2 *) doveadm_cmd_find_ver2("dsync-server");
        if (cmd == NULL) {
                fprintf(stderr, "doveadm_update_dsync_server_command(): could not find \"dsync-server\" command to modify.\n");
                return;
        }
        if (isatty(2)) fprintf(stderr, "doveadm_update_dsync_server_command(): Found plugin \"%s\"\n", cmd->name);

        /* store current mail_cmd allocation function pointer to reuse it later in cmd_replicate_alloc() */
        cmd_dsync_server_alloc_orig = cmd->mail_cmd;
        /* set new mail_cmd function */
        cmd->mail_cmd   = doveadm_cmd_replicate.mail_cmd;
        /* and new command line options (adding -U switch) */
        cmd->usage      = doveadm_cmd_replicate.usage;
        cmd->parameters = doveadm_cmd_replicate.parameters;
}
