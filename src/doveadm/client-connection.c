/* Copyright (c) 2010-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "base64.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "settings-parser.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-ssl.h"
#include "master-service-settings.h"
#include "mail-storage-service.h"
#include "doveadm-util.h"
#include "doveadm-server.h"
#include "doveadm-mail.h"
#include "doveadm-print.h"
#include "doveadm-settings.h"
#include "client-connection.h"

#include <unistd.h>

#define MAX_INBUF_SIZE (1024*1024)

static struct {
	int code;
	const char *str;
} exit_code_strings[] = {
	{ EX_TEMPFAIL, "TEMPFAIL" },
	{ EX_USAGE, "USAGE" },
	{ EX_NOUSER, "NOUSER" },
	{ EX_NOPERM, "NOPERM" },
	{ EX_PROTOCOL, "PROTOCOL" },
	{ EX_DATAERR, "DATAERR" },
	{ DOVEADM_EX_NOTFOUND, "NOTFOUND" }
};

static void client_connection_input(struct client_connection *conn);

static void
doveadm_cmd_server_run(struct client_connection *conn,
		       const struct doveadm_cmd *cmd, int argc, char *argv[])
{
	const char *str = NULL;
	unsigned int i;

	i_getopt_reset();
	doveadm_exit_code = 0;
	cmd->cmd(argc, argv);

	if (doveadm_exit_code == 0) {
		o_stream_nsend(conn->output, "\n+\n", 3);
		return;
	}

	for (i = 0; i < N_ELEMENTS(exit_code_strings); i++) {
		if (exit_code_strings[i].code == doveadm_exit_code) {
			str = exit_code_strings[i].str;
			break;
		}
	}
	if (str != NULL) {
		o_stream_nsend_str(conn->output,
				   t_strdup_printf("\n-%s\n", str));
	} else {
		o_stream_nsend_str(conn->output, "\n-\n");
		i_error("BUG: Command '%s' returned unknown error code %d",
			cmd->name, doveadm_exit_code);
	}
}

static int
doveadm_mail_cmd_server_parse(const struct doveadm_mail_cmd *cmd,
			      const struct doveadm_settings *set,
			      const struct mail_storage_service_input *input,
			      int argc, char *argv[],
			      struct doveadm_mail_cmd_context **ctx_r)
{
	struct doveadm_mail_cmd_context *ctx;
	const char *getopt_args;
	bool add_username_header = FALSE;
	int c;

	ctx = doveadm_mail_cmd_init(cmd, set);
	ctx->full_args = (const void *)(argv + 1);
	ctx->proxying = TRUE;

	ctx->service_flags |=
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
	if (doveadm_debug)
		ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_DEBUG;

	i_getopt_reset();
	getopt_args = t_strconcat("AF:S:u:", ctx->getopt_args, NULL);
	while ((c = getopt(argc, argv, getopt_args)) > 0) {
		switch (c) {
		case 'A':
		case 'F':
			add_username_header = TRUE;
			break;
		case 'S':
			/* ignore */
			break;
		case 'u':
			if (strchr(optarg, '*') != NULL ||
			    strchr(optarg, '?') != NULL)
				add_username_header = TRUE;
			break;
		default:
			if ((ctx->v.parse_arg == NULL ||
			     !ctx->v.parse_arg(ctx, c))) {
				i_error("doveadm %s: "
					"Client sent unknown parameter: %c",
					cmd->name, c);
				ctx->v.deinit(ctx);
				pool_unref(&ctx->pool);
				return -1;
			}
		}
	}
	argv += optind;

	if (argv[0] != NULL && cmd->usage_args == NULL) {
		i_error("doveadm %s: Client sent unknown parameter: %s",
			cmd->name, argv[0]);
		ctx->v.deinit(ctx);
		pool_unref(&ctx->pool);
		return -1;
	}
	ctx->args = (const void *)argv;

	if (doveadm_print_is_initialized() && add_username_header) {
		doveadm_print_header("username", "Username",
				     DOVEADM_PRINT_HEADER_FLAG_STICKY |
				     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
		doveadm_print_sticky("username", input->username);
	}
	*ctx_r = ctx;
	return 0;
}

static void
doveadm_mail_cmd_server_run(struct client_connection *conn,
			    struct doveadm_mail_cmd_context *ctx,
			    const struct mail_storage_service_input *input)
{
	const char *error;
	int ret;

	ctx->conn = conn;

	if (ctx->v.preinit != NULL)
		ctx->v.preinit(ctx);

	ret = doveadm_mail_single_user(ctx, input, &error);
	doveadm_mail_server_flush();
	ctx->v.deinit(ctx);
	doveadm_print_flush();
	mail_storage_service_deinit(&ctx->storage_service);

	if (ret < 0) {
		i_error("%s: %s", ctx->cmd->name, error);
		o_stream_nsend(conn->output, "\n-\n", 3);
	} else if (ret == 0) {
		o_stream_nsend_str(conn->output, "\n-NOUSER\n");
	} else if (ctx->exit_code != 0) {
		/* maybe not an error, but not a full success either */
		o_stream_nsend_str(conn->output,
				   t_strdup_printf("\n-%u\n", ctx->exit_code));
	} else {
		o_stream_nsend(conn->output, "\n+\n", 3);
	}
	pool_unref(&ctx->pool);
}

static bool client_is_allowed_command(const struct doveadm_settings *set,
				      const char *cmd_name)
{
	bool ret = FALSE;

	if (*set->doveadm_allowed_commands == '\0')
		return TRUE;

	T_BEGIN {
		const char *const *cmds =
			t_strsplit(set->doveadm_allowed_commands, ",");
		for (; *cmds != NULL; cmds++) {
			if (strcmp(*cmds, cmd_name) == 0) {
				ret = TRUE;
				break;
			}
		}
	} T_END;
	return ret;
}

static int doveadm_cmd_handle(struct client_connection *conn,
			      const char *cmd_name,
			      const struct mail_storage_service_input *input,
			      int argc, char *argv[])
{
	struct ioloop *ioloop, *prev_ioloop = current_ioloop;
	const struct doveadm_cmd *cmd;
	const struct doveadm_mail_cmd *mail_cmd;
	struct doveadm_mail_cmd_context *ctx;

	cmd = doveadm_cmd_find(cmd_name, &argc, &argv);
	if (cmd == NULL) {
		mail_cmd = doveadm_mail_cmd_find(cmd_name);
		if (mail_cmd == NULL) {
			i_error("doveadm: Client sent unknown command: %s", cmd_name);
			return -1;
		}
		if (doveadm_mail_cmd_server_parse(mail_cmd, conn->set, input,
						  argc, argv, &ctx) < 0)
			return -1;
	}

	/* some commands will want to call io_loop_run(), but we're already
	   running one and we can't call the original one recursively, so
	   create a new ioloop. */
	ioloop = io_loop_create();
	lib_signals_reset_ioloop();

	if (cmd != NULL)
		doveadm_cmd_server_run(conn, cmd, argc, argv);
	else
		doveadm_mail_cmd_server_run(conn, ctx, input);

	io_loop_set_current(prev_ioloop);
	lib_signals_reset_ioloop();
	o_stream_switch_ioloop(conn->output);
	io_loop_set_current(ioloop);
	io_loop_destroy(&ioloop);

	/* clear all headers */
	doveadm_print_deinit();
	doveadm_print_init(DOVEADM_PRINT_TYPE_SERVER);
	return 0;
}

static bool client_handle_command(struct client_connection *conn, char **args)
{
	struct mail_storage_service_input input;
	const char *flags, *cmd_name;
	unsigned int argc;

	memset(&input, 0, sizeof(input));
	input.service = "doveadm";
	input.local_ip = conn->local_ip;
	input.remote_ip = conn->remote_ip;
	input.local_port = conn->local_port;
	input.remote_port = conn->remote_port;

	for (argc = 0; args[argc] != NULL; argc++)
		args[argc] = str_tabunescape(args[argc]);

	if (argc < 3) {
		i_error("doveadm client: No command given");
		return FALSE;
	}
	flags = args[0];
	input.username = args[1];
	cmd_name = args[2];
	/* leave the command name as args[0] so getopt() works */
	args += 2;
	argc -= 2;

	doveadm_debug = FALSE;
	doveadm_verbose = FALSE;

	for (; *flags != '\0'; flags++) {
		switch (*flags) {
		case 'D':
			doveadm_debug = TRUE;
			doveadm_verbose = TRUE;
			break;
		case 'v':
			doveadm_verbose = TRUE;
			break;
		default:
			i_error("doveadm client: Unknown flag: %c", *flags);
			return FALSE;
		}
	}

	if (!client_is_allowed_command(conn->set, cmd_name)) {
		i_error("doveadm client isn't allowed to use command: %s",
			cmd_name);
		return FALSE;
	}

	o_stream_cork(conn->output);
	if (doveadm_cmd_handle(conn, cmd_name, &input, argc, args) < 0)
		o_stream_nsend(conn->output, "\n-\n", 3);
	o_stream_uncork(conn->output);

	/* flush the output and disconnect */
	net_set_nonblock(conn->fd, FALSE);
	(void)o_stream_flush(conn->output);
	net_set_nonblock(conn->fd, TRUE);
	return TRUE;
}

static int
client_connection_authenticate(struct client_connection *conn)
{
	const char *line, *pass;
	buffer_t *plain;
	const unsigned char *data;
	size_t size;

	if ((line = i_stream_read_next_line(conn->input)) == NULL) {
		if (conn->input->eof)
			return -1;
		return 0;
	}

	if (*conn->set->doveadm_password == '\0') {
		i_error("doveadm_password not set, "
			"remote authentication disabled");
		return -1;
	}

	/* FIXME: some day we should probably let auth process do this and
	   support all kinds of authentication */
	if (strncmp(line, "PLAIN\t", 6) != 0) {
		i_error("doveadm client attempted non-PLAIN authentication: %s", line);
		return -1;
	}

	plain = buffer_create_dynamic(pool_datastack_create(), 128);
	if (base64_decode(line + 6, strlen(line + 6), NULL, plain) < 0) {
		i_error("doveadm client sent invalid base64 auth PLAIN data");
		return -1;
	}
	data = plain->data;
	size = plain->used;

	if (size < 10 || data[0] != '\0' ||
	    memcmp(data+1, "doveadm", 7) != 0 || data[8] != '\0') {
		i_error("doveadm client didn't authenticate as 'doveadm'");
		return -1;
	}
	pass = t_strndup(data + 9, size - 9);
	if (strcmp(pass, conn->set->doveadm_password) != 0) {
		i_error("doveadm client authenticated with wrong password");
		return -1;
	}
	return 1;
}

static void client_log_disconnect_error(struct client_connection *conn)
{
	const char *error;

	error = conn->ssl_iostream == NULL ? NULL :
		ssl_iostream_get_last_error(conn->ssl_iostream);
	if (error == NULL) {
		error = conn->input->stream_errno == 0 ? "EOF" :
			strerror(conn->input->stream_errno);
	}
	i_error("doveadm client disconnected before handshake: %s", error);
}

static void client_connection_input(struct client_connection *conn)
{
	const char *line;
	bool ok = TRUE;
	int ret;

	if (!conn->handshaked) {
		if ((line = i_stream_read_next_line(conn->input)) == NULL) {
			if (conn->input->eof || conn->input->stream_errno != 0) {
				client_log_disconnect_error(conn);
				client_connection_destroy(&conn);
			}
			return;
		}

		if (!version_string_verify(line, "doveadm-server",
				DOVEADM_SERVER_PROTOCOL_VERSION_MAJOR)) {
			i_error("doveadm client not compatible with this server "
				"(mixed old and new binaries?)");
			client_connection_destroy(&conn);
			return;
		}
		conn->handshaked = TRUE;
	}
	if (!conn->authenticated) {
		if ((ret = client_connection_authenticate(conn)) <= 0) {
			if (ret < 0) {
				o_stream_nsend(conn->output, "-\n", 2);
				client_connection_destroy(&conn);
			}
			return;
		}
		o_stream_nsend(conn->output, "+\n", 2);
		conn->authenticated = TRUE;
	}

	while (ok && !conn->input->closed &&
	       (line = i_stream_read_next_line(conn->input)) != NULL) {
		T_BEGIN {
			char **args;

			args = p_strsplit(pool_datastack_create(), line, "\t");
			ok = client_handle_command(conn, args);
		} T_END;
	}
	if (conn->input->eof || conn->input->stream_errno != 0 || !ok)
		client_connection_destroy(&conn);
}

static int client_connection_read_settings(struct client_connection *conn)
{
	const struct setting_parser_info *set_roots[] = {
		&doveadm_setting_parser_info,
		NULL
	};
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const char *error;
	void *set;

	memset(&input, 0, sizeof(input));
	input.roots = set_roots;
	input.service = "doveadm";
	input.local_ip = conn->local_ip;
	input.remote_ip = conn->remote_ip;

	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0) {
		i_error("Error reading configuration: %s", error);
		return -1;
	}
	set = master_service_settings_get_others(master_service)[0];
	conn->set = settings_dup(&doveadm_setting_parser_info, set, conn->pool);
	return 0;
}

static int client_connection_init_ssl(struct client_connection *conn)
{
	const char *error;

	if (master_service_ssl_init(master_service,
				    &conn->input, &conn->output,
				    &conn->ssl_iostream, &error) < 0) {
		i_error("SSL init failed: %s", error);
		return -1;
	}
	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		i_error("SSL handshake failed: %s",
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}
	return 0;
}

static void
client_connection_send_auth_handshake(struct client_connection *
				      conn, int listen_fd)
{
	const char *listen_path;
	struct stat st;

	/* we'll have to do this with stat(), because at least in Linux
	   fstat() always returns mode as 0777 */
	if (net_getunixname(listen_fd, &listen_path) == 0 &&
	    stat(listen_path, &st) == 0 && S_ISSOCK(st.st_mode) &&
	    (st.st_mode & 0777) == 0600) {
		/* no need for client to authenticate */
		conn->authenticated = TRUE;
		o_stream_nsend(conn->output, "+\n", 2);
	} else {
		o_stream_nsend(conn->output, "-\n", 2);
	}
}

struct client_connection *
client_connection_create(int fd, int listen_fd, bool ssl)
{
	struct client_connection *conn;
	const char *ip;
	pool_t pool;

	pool = pool_alloconly_create("doveadm client", 1024*16);
	conn = p_new(pool, struct client_connection, 1);
	conn->pool = pool;
	conn->fd = fd;
	conn->io = io_add(fd, IO_READ, client_connection_input, conn);
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(conn->output, TRUE);

	(void)net_getsockname(fd, &conn->local_ip, &conn->local_port);
	(void)net_getpeername(fd, &conn->remote_ip, &conn->remote_port);

	i_stream_set_name(conn->input, net_ip2addr(&conn->remote_ip));
	o_stream_set_name(conn->output, net_ip2addr(&conn->remote_ip));

	ip = net_ip2addr(&conn->remote_ip);
	if (ip[0] != '\0')
		i_set_failure_prefix("doveadm(%s): ", ip);

	if (client_connection_read_settings(conn) < 0) {
		client_connection_destroy(&conn);
		return NULL;
	}
	if (ssl) {
		if (client_connection_init_ssl(conn) < 0) {
			client_connection_destroy(&conn);
			return NULL;
		}
	}
	client_connection_send_auth_handshake(conn, listen_fd);
	return conn;
}

void client_connection_destroy(struct client_connection **_conn)
{
	struct client_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->ssl_iostream != NULL)
		ssl_iostream_destroy(&conn->ssl_iostream);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	io_remove(&conn->io);
	if (close(conn->fd) < 0)
		i_error("close(client) failed: %m");
	pool_unref(&conn->pool);

	doveadm_client = NULL;
	master_service_client_connection_destroyed(master_service);
}

struct ostream *client_connection_get_output(struct client_connection *conn)
{
	return conn->output;
}
