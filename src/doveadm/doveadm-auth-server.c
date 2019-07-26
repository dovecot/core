/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "wildcard-match.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "auth-client.h"
#include "auth-master.h"
#include "master-auth.h"
#include "master-login-auth.h"
#include "mail-storage-service.h"
#include "mail-user.h"
#include "ostream.h"
#include "json-parser.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>

struct authtest_input {
	pool_t pool;
	const char *username;
	const char *master_user;
	const char *password;
	struct auth_user_info info;
	bool success;

	struct auth_client_request *request;
	struct master_auth_request master_auth_req;

	unsigned int auth_id;
	unsigned int auth_pid;
	const char *auth_cookie;

};

static struct auth_master_connection *
doveadm_get_auth_master_conn(const char *auth_socket_path)
{
	enum auth_master_flags flags = 0;

	if (doveadm_debug)
		flags |= AUTH_MASTER_FLAG_DEBUG;
	return auth_master_init(auth_socket_path, flags);
}

static int
cmd_user_input(struct auth_master_connection *conn,
	       const struct authtest_input *input,
	       const char *show_field, bool userdb)
{
	const char *lookup_name = userdb ? "userdb lookup" : "passdb lookup";
	pool_t pool;
	const char *updated_username = NULL, *const *fields, *p;
	int ret;

	pool = pool_alloconly_create("auth master lookup", 1024);

	if (userdb) {
		ret = auth_master_user_lookup(conn, input->username, &input->info,
					      pool, &updated_username, &fields);
	} else {
		ret = auth_master_pass_lookup(conn, input->username, &input->info,
					      pool, &fields);
	}
	if (ret < 0) {
		const char *msg;
		if (fields[0] == NULL) {
			msg = t_strdup_printf("\"error\":\"%s failed\"",
					      lookup_name);
		} else {
			msg = t_strdup_printf("\"error\":\"%s failed: %s\"",
					      lookup_name,
					      fields[0]);
		}
		o_stream_nsend_str(doveadm_print_ostream, msg);
		ret = -1;
	} else if (ret == 0) {
		o_stream_nsend_str(doveadm_print_ostream,
			t_strdup_printf("\"error\":\"%s: user doesn't exist\"",
				lookup_name));
	} else if (show_field != NULL) {
		size_t show_field_len = strlen(show_field);
		string_t *json_field = t_str_new(show_field_len+1);
		json_append_escaped(json_field, show_field);
		o_stream_nsend_str(doveadm_print_ostream, t_strdup_printf("\"%s\":", str_c(json_field)));
		for (; *fields != NULL; fields++) {
			if (strncmp(*fields, show_field, show_field_len) == 0 &&
			    (*fields)[show_field_len] == '=') {
				string_t *jsonval = t_str_new(32);
				json_append_escaped(jsonval, *fields + show_field_len + 1);
				o_stream_nsend_str(doveadm_print_ostream, "\"");
				o_stream_nsend_str(doveadm_print_ostream, str_c(jsonval));
				o_stream_nsend_str(doveadm_print_ostream, "\"");
			}
		}
	} else {
		string_t *jsonval = t_str_new(64);
		o_stream_nsend_str(doveadm_print_ostream, "\"source\":\"");
		o_stream_nsend_str(doveadm_print_ostream, userdb ? "userdb\"" : "passdb\"");

		if (updated_username != NULL) {
			o_stream_nsend_str(doveadm_print_ostream, ",\"updated_username\":\"");
			str_truncate(jsonval, 0);
			json_append_escaped(jsonval, updated_username);
			o_stream_nsend_str(doveadm_print_ostream, str_c(jsonval));
			o_stream_nsend_str(doveadm_print_ostream, "\"");
		}
		for (; *fields != NULL; fields++) {
			const char *field = *fields;
			if (*field == '\0') continue;
			p = strchr(*fields, '=');
			str_truncate(jsonval, 0);
			if (p != NULL) {
				field = t_strcut(*fields, '=');
			}
			str_truncate(jsonval, 0);
			json_append_escaped(jsonval, field);
			o_stream_nsend_str(doveadm_print_ostream, ",\"");
			o_stream_nsend_str(doveadm_print_ostream, str_c(jsonval));
			o_stream_nsend_str(doveadm_print_ostream, "\":");
			if (p != NULL) {
				str_truncate(jsonval, 0);
				json_append_escaped(jsonval, p+1);
				o_stream_nsend_str(doveadm_print_ostream, "\"");
				o_stream_nsend_str(doveadm_print_ostream, str_c(jsonval));
				o_stream_nsend_str(doveadm_print_ostream, "\"");
			} else {
				o_stream_nsend_str(doveadm_print_ostream, "true");
			}
		}
	}
	return ret;
}

static void auth_user_info_parse(struct auth_user_info *info, const char *arg)
{
	if (str_begins(arg, "service="))
		info->service = arg + 8;
	else if (str_begins(arg, "lip=")) {
		if (net_addr2ip(arg + 4, &info->local_ip) < 0)
			i_fatal("lip: Invalid ip");
	} else if (str_begins(arg, "rip=")) {
		if (net_addr2ip(arg + 4, &info->remote_ip) < 0)
			i_fatal("rip: Invalid ip");
	} else if (str_begins(arg, "lport=")) {
		if (net_str2port(arg + 6, &info->local_port) < 0)
			i_fatal("lport: Invalid port number");
	} else if (str_begins(arg, "rport=")) {
		if (net_str2port(arg + 6, &info->remote_port) < 0)
			i_fatal("rport: Invalid port number");
	} else {
		i_fatal("Unknown -x argument: %s", arg);
	}
}

static void
cmd_user_list(struct auth_master_connection *conn,
	      const struct authtest_input *input,
	      char *const *users)
{
	struct auth_master_user_list_ctx *ctx;
	const char *username, *user_mask = "*";
	string_t *escaped = t_str_new(256);
	bool first = TRUE;
	unsigned int i;

	if (users[0] != NULL && users[1] == NULL)
		user_mask = users[0];

	o_stream_nsend_str(doveadm_print_ostream, "{\"userList\":[");

	ctx = auth_master_user_list_init(conn, user_mask, &input->info);
	while ((username = auth_master_user_list_next(ctx)) != NULL) {
		for (i = 0; users[i] != NULL; i++) {
			if (wildcard_match_icase(username, users[i]))
				break;
		}
		if (users[i] != NULL) {
			if (first)
				first = FALSE;
			else
				o_stream_nsend_str(doveadm_print_ostream, ",");
			str_truncate(escaped, 0);
			str_append_c(escaped, '"');
			json_append_escaped(escaped, username);
			str_append_c(escaped, '"');
			o_stream_nsend(doveadm_print_ostream, escaped->data, escaped->used);
		}
	}
	if (auth_master_user_list_deinit(&ctx) < 0) {
		i_error("user listing failed");
		doveadm_exit_code = EX_DATAERR;
	}

	o_stream_nsend_str(doveadm_print_ostream, "]}");
}

static void cmd_auth_cache_flush(int argc, char *argv[])
{
	const char *master_socket_path = NULL;
	struct auth_master_connection *conn;
	unsigned int count;
	int c;

	while ((c = getopt(argc, argv, "a:")) > 0) {
		switch (c) {
		case 'a':
			master_socket_path = optarg;
			break;
		default:
			doveadm_exit_code = EX_USAGE;
			return;
		}
	}
	argv += optind;

	if (master_socket_path == NULL) {
		master_socket_path = t_strconcat(doveadm_settings->base_dir,
						 "/auth-master", NULL);
	}

	conn = doveadm_get_auth_master_conn(master_socket_path);
	if (auth_master_cache_flush(conn, (void *)argv, &count) < 0) {
		i_error("Cache flush failed");
		doveadm_exit_code = EX_TEMPFAIL;
	} else {
		doveadm_print_init("formatted");
		doveadm_print_formatted_set_format("%{entries} cache entries flushed\n");
		doveadm_print_header_simple("entries");
		doveadm_print_num(count);
	}
	auth_master_deinit(&conn);
}

static void cmd_user_mail_input_field(const char *key, const char *value,
				      const char *show_field, bool *first)
{
	string_t *jvalue = t_str_new(128);
	if (show_field != NULL && strcmp(show_field, key) != 0) return;
	/* do not emit comma on first field. we need to keep track
	   of when the first field actually gets printed as it
	   might change due to show_field */
	if (!*first)
		o_stream_nsend_str(doveadm_print_ostream, ",");
	*first = FALSE;
	json_append_escaped(jvalue, key);
	o_stream_nsend_str(doveadm_print_ostream, "\"");
	o_stream_nsend_str(doveadm_print_ostream, str_c(jvalue));
	o_stream_nsend_str(doveadm_print_ostream, "\":\"");
	str_truncate(jvalue, 0);
	json_append_escaped(jvalue, value);
	o_stream_nsend_str(doveadm_print_ostream, str_c(jvalue));
	o_stream_nsend_str(doveadm_print_ostream, "\"");
}

static void
cmd_user_mail_print_fields(const struct authtest_input *input,
			   struct mail_user *user,
			   const char *const *userdb_fields,
			   const char *show_field)
{
	const struct mail_storage_settings *mail_set;
	const char *key, *value;
	unsigned int i;
	bool first = TRUE;

	if (strcmp(input->username, user->username) != 0)
		cmd_user_mail_input_field("user", user->username, show_field, &first);
	cmd_user_mail_input_field("uid", user->set->mail_uid, show_field, &first);
	cmd_user_mail_input_field("gid", user->set->mail_gid, show_field, &first);
	cmd_user_mail_input_field("home", user->set->mail_home, show_field, &first);

	mail_set = mail_user_set_get_storage_set(user);
	cmd_user_mail_input_field("mail", mail_set->mail_location, show_field, &first);

	if (userdb_fields != NULL) {
		for (i = 0; userdb_fields[i] != NULL; i++) {
			value = strchr(userdb_fields[i], '=');
			if (value != NULL)
				key = t_strdup_until(userdb_fields[i], value++);
			else {
				key = userdb_fields[i];
				value = "";
			}
			if (strcmp(key, "uid") != 0 &&
			    strcmp(key, "gid") != 0 &&
			    strcmp(key, "home") != 0 &&
			    strcmp(key, "mail") != 0 &&
			    *key != '\0') {
				cmd_user_mail_input_field(key, value, show_field, &first);
			}
		}
	}
}

static int
cmd_user_mail_input(struct mail_storage_service_ctx *storage_service,
		    const struct authtest_input *input,
		    const char *show_field, const char *expand_field)
{
	struct mail_storage_service_input service_input;
	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	const char *error, *const *userdb_fields;
	pool_t pool;
	int ret;

	i_zero(&service_input);
	service_input.module = "mail";
	service_input.service = input->info.service;
	service_input.username = input->username;
	service_input.local_ip = input->info.local_ip;
	service_input.local_port = input->info.local_port;
	service_input.remote_ip = input->info.remote_ip;
	service_input.remote_port = input->info.remote_port;
	service_input.debug = input->info.debug;

	pool = pool_alloconly_create("userdb fields", 1024);
	mail_storage_service_save_userdb_fields(storage_service, pool,
						&userdb_fields);

	if ((ret = mail_storage_service_lookup_next(storage_service, &service_input,
						    &service_user, &user,
						    &error)) <= 0) {
		pool_unref(&pool);
		if (ret < 0)
			return -1;
		string_t *username = t_str_new(32);
		json_append_escaped(username, input->username);
		o_stream_nsend_str(doveadm_print_ostream,
			t_strdup_printf("\"error\":\"userdb lookup: user %s doesn't exist\"", str_c(username))
		);
		return 0;
	}

	if (expand_field == NULL)
		cmd_user_mail_print_fields(input, user, userdb_fields, show_field);
	else {
		string_t *str = t_str_new(128);
		if (var_expand_with_funcs(str, expand_field,
					  mail_user_var_expand_table(user),
					  mail_user_var_expand_func_table, user,
					  &error) <= 0) {
			string_t *str = t_str_new(128);
			str_printfa(str, "\"error\":\"Failed to expand field: ");
			json_append_escaped(str, error);
			str_append_c(str, '"');
			o_stream_nsend(doveadm_print_ostream, str_data(str), str_len(str));
		} else {
			string_t *value = t_str_new(128);
			json_append_escaped(value, expand_field);
			o_stream_nsend_str(doveadm_print_ostream, "\"");
			o_stream_nsend_str(doveadm_print_ostream, str_c(value));
			o_stream_nsend_str(doveadm_print_ostream, "\":\"");
			str_truncate(value, 0);
			json_append_escaped(value, str_c(str));
			o_stream_nsend_str(doveadm_print_ostream, str_c(value));
			o_stream_nsend_str(doveadm_print_ostream, "\"");
		}

	}

	mail_user_deinit(&user);
	mail_storage_service_user_unref(&service_user);
	pool_unref(&pool);
	return 1;
}

static void cmd_user_ver2(struct doveadm_cmd_context *cctx)
{
	const char * const *optval;

	const char *auth_socket_path = NULL;
	struct auth_master_connection *conn;
	struct authtest_input input;
	const char *show_field = NULL, *expand_field = NULL;
	struct mail_storage_service_ctx *storage_service = NULL;
	bool have_wildcards, userdb_only = FALSE, first = TRUE;
	int ret;

	if (!doveadm_cmd_param_str(cctx, "socket-path", &auth_socket_path))
		auth_socket_path = doveadm_settings->auth_socket_path;

	(void)doveadm_cmd_param_str(cctx, "expand-field", &expand_field);
	(void)doveadm_cmd_param_str(cctx, "field", &show_field);
	(void)doveadm_cmd_param_bool(cctx, "userdb-only", &userdb_only);

	i_zero(&input);
	if (doveadm_cmd_param_array(cctx, "auth-info", &optval))
		for(;*optval != NULL; optval++)
			auth_user_info_parse(&input.info, *optval);

	if (!doveadm_cmd_param_array(cctx, "user-mask", &optval)) {
		doveadm_exit_code = EX_USAGE;
		i_error("No user(s) specified");
		return;
	}

	if (expand_field != NULL && userdb_only) {
		i_error("-e can't be used with -u");
		doveadm_exit_code = EX_USAGE;
		return;
	}
	if (expand_field != NULL && show_field != NULL) {
		i_error("-e can't be used with -f");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	conn = doveadm_get_auth_master_conn(auth_socket_path);

	have_wildcards = FALSE;

	for(const char *const *val = optval; *val != NULL; val++) {
		if (strchr(*val, '*') != NULL ||
		    strchr(*val, '?') != NULL) {
			have_wildcards = TRUE;
			break;
		}
	}

	if (have_wildcards) {
		cmd_user_list(conn, &input, (char*const*)optval);
		auth_master_deinit(&conn);
		return;
	}

	if (!userdb_only) {
		storage_service = mail_storage_service_init(master_service, NULL,
			MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP |
			MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR |
			MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
			MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS |
			MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES |
			MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS);
		mail_storage_service_set_auth_conn(storage_service, conn);
		conn = NULL;
	}

	string_t *json = t_str_new(64);
	o_stream_nsend_str(doveadm_print_ostream, "{");

	input.info.local_ip = cctx->local_ip;
	input.info.local_port = cctx->local_port;
	input.info.remote_ip = cctx->remote_ip;
	input.info.remote_port = cctx->remote_port;

	for(const char *const *val = optval; *val != NULL; val++) {
		str_truncate(json, 0);
		json_append_escaped(json, *val);

		input.username = *val;
		if (first)
			first = FALSE;
		else
			o_stream_nsend_str(doveadm_print_ostream, ",");

		o_stream_nsend_str(doveadm_print_ostream, "\"");
		o_stream_nsend_str(doveadm_print_ostream, str_c(json));
		o_stream_nsend_str(doveadm_print_ostream, "\"");
		o_stream_nsend_str(doveadm_print_ostream, ":{");

		ret = !userdb_only ?
			cmd_user_mail_input(storage_service, &input, show_field, expand_field) :
			cmd_user_input(conn, &input, show_field, TRUE);

		o_stream_nsend_str(doveadm_print_ostream, "}");

		switch (ret) {
		case -1:
			doveadm_exit_code = EX_TEMPFAIL;
			break;
		case 0:
			doveadm_exit_code = EX_NOUSER;
			break;
		}
	}

	o_stream_nsend_str(doveadm_print_ostream,"}");

	if (storage_service != NULL)
		mail_storage_service_deinit(&storage_service);
	if (conn != NULL)
		auth_master_deinit(&conn);
}

static
struct doveadm_cmd_ver2 doveadm_cmd_auth_server[] = {
{
	.name = "auth cache flush",
	.old_cmd = cmd_auth_cache_flush,
	.usage = "[-a <master socket path>] [<user> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "user",
	.cmd = cmd_user_ver2,
	.usage = "[-a <userdb socket path>] [-x <auth info>] [-f field] [-e <value>] [-u] <user mask> [...]",
	.flags = CMD_FLAG_NO_PRINT,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('x', "auth-info", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('f', "field", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('e', "expand-field", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('u', "userdb-only", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "user-mask", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
}
};

void doveadm_register_auth_server_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_auth_server); i++) {
		doveadm_cmd_register_ver2(&doveadm_cmd_auth_server[i]);
	}
}
