/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "wildcard-match.h"
#include "settings.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "auth-client.h"
#include "auth-master.h"
#include "login-server-auth.h"
#include "mail-storage-service.h"
#include "mail-user.h"
#include "ostream.h"
#include "json-ostream.h"
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
	       struct json_ostream *json_output,
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
		if (fields[0] == NULL) {
			json_ostream_nwritef_string(json_output,
				"error", "%s failed", lookup_name);
		} else {
			json_ostream_nwritef_string(json_output,
				"error", "%s failed: %s",
				lookup_name, fields[0]);
		}
		ret = -1;
	} else if (ret == 0) {
		json_ostream_nwritef_string(json_output,
			"error", "%s: user doesn't exist", lookup_name);
	} else if (show_field != NULL) {
		size_t show_field_len = strlen(show_field);
		for (; *fields != NULL; fields++) {
			if (strncmp(*fields, show_field, show_field_len) == 0 &&
			    (*fields)[show_field_len] == '=') {
				json_ostream_nwrite_string(
					json_output, show_field,
					*fields + show_field_len + 1);
			}
		}
	} else {
		json_ostream_nwrite_string(json_output,
			"source", (userdb ? "userdb" : "passdb"));

		if (updated_username != NULL) {
			json_ostream_nwrite_string(json_output,
				"updated_username", updated_username);
		}
		for (; *fields != NULL; fields++) {
			const char *field = *fields;
			if (*field == '\0') continue;
			p = strchr(*fields, '=');
			if (p != NULL) {
				field = t_strdup_until(*fields, p);
				json_ostream_nwrite_string(json_output,
							   field, p+1);
			} else {
				json_ostream_nwrite_true(json_output, field);
			}
		}
	}
	return ret;
}

static void auth_user_info_parse(struct auth_user_info *info, const char *arg)
{
	const char *value;

	if (str_begins(arg, "service=", &value) ||
	    str_begins(arg, "protocol=", &value))
		info->protocol = value;
	else if (str_begins(arg, "lip=", &value)) {
		if (net_addr2ip(value, &info->local_ip) < 0)
			i_fatal("lip: Invalid ip");
	} else if (str_begins(arg, "rip=", &value)) {
		if (net_addr2ip(value, &info->remote_ip) < 0)
			i_fatal("rip: Invalid ip");
	} else if (str_begins(arg, "lport=", &value)) {
		if (net_str2port(value, &info->local_port) < 0)
			i_fatal("lport: Invalid port number");
	} else if (str_begins(arg, "rport=", &value)) {
		if (net_str2port(value, &info->remote_port) < 0)
			i_fatal("rport: Invalid port number");
	} else {
		i_fatal("Unknown -x argument: %s", arg);
	}
}

static void
cmd_user_list(struct doveadm_cmd_context *cctx,
	      struct auth_master_connection *conn,
	      const struct authtest_input *input,
	      struct json_ostream *json_output,
	      char *const *users)
{
	struct auth_master_user_list_ctx *ctx;
	const char *username, *user_mask = "*";
	unsigned int i;

	if (users[0] != NULL && users[1] == NULL)
		user_mask = users[0];

	json_ostream_ndescend_array(json_output, "userList");

	ctx = auth_master_user_list_init(conn, user_mask, &input->info);
	while ((username = auth_master_user_list_next(ctx)) != NULL) {
		for (i = 0; users[i] != NULL; i++) {
			if (wildcard_match_icase(username, users[i]))
				break;
		}
		if (users[i] != NULL) {
			json_ostream_nwrite_string(json_output, NULL,
						   username);
		}
	}
	if (auth_master_user_list_deinit(&ctx) < 0) {
		e_error(cctx->event, "user listing failed");
		doveadm_exit_code = EX_DATAERR;
	}

	json_ostream_nascend_array(json_output);
}

static void cmd_auth_cache_flush(struct doveadm_cmd_context *cctx)
{
	const char *master_socket_path, *const *users;
	struct auth_master_connection *conn;
	unsigned int count;

	if (!doveadm_cmd_param_str(cctx, "socket-path", &master_socket_path)) {
		master_socket_path = t_strconcat(doveadm_settings->base_dir,
						 "/auth-master", NULL);
	}
	if (!doveadm_cmd_param_array(cctx, "user", &users))
		i_fatal("Missing user parameter");

	conn = doveadm_get_auth_master_conn(master_socket_path);
	if (auth_master_cache_flush(conn, users, &count) < 0) {
		e_error(cctx->event, "Cache flush failed");
		doveadm_exit_code = EX_TEMPFAIL;
	} else {
		doveadm_print_init("formatted");
		doveadm_print_formatted_set_format("%{entries} cache entries flushed\n");
		doveadm_print_header_simple("entries");
		doveadm_print_num(count);
	}
	auth_master_deinit(&conn);
}

static void cmd_user_mail_input_field(struct json_ostream *json_output,
				      const char *key, const char *value,
				      const char *show_field)
{
	if (show_field != NULL && strcmp(show_field, key) != 0) return;

	json_ostream_nwrite_string(json_output, key, value);
}

static void
cmd_user_mail_print_fields(const struct authtest_input *input,
			   struct mail_user *user,
			   const struct mail_storage_settings *mail_set,
			   struct json_ostream *json_output,
			   const char *const *userdb_fields,
			   const char *show_field)
{
	const char *key, *value;
	unsigned int i;

	if (strcmp(input->username, user->username) != 0) {
		cmd_user_mail_input_field(json_output, "user",
			user->username, show_field);
	}
	cmd_user_mail_input_field(json_output, "uid",
				  user->set->mail_uid, show_field);
	cmd_user_mail_input_field(json_output, "gid",
				  user->set->mail_gid, show_field);
	cmd_user_mail_input_field(json_output, "home",
				  user->set->mail_home, show_field);
	cmd_user_mail_input_field(json_output, "mail_path",
				  mail_set->mail_path, show_field);

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
			    strcmp(key, "mail_path") != 0 &&
			    *key != '\0') {
				cmd_user_mail_input_field(json_output,
					key, value, show_field);
			}
		}
	}
}

static int
cmd_user_mail_input(struct mail_storage_service_ctx *storage_service,
		    const struct authtest_input *input,
		    struct json_ostream *json_output,
		    const char *show_field, const char *expand_field)
{
	struct mail_storage_service_input service_input;
	struct mail_user *user;
	const struct mail_storage_settings *mail_set;
	const char *error, *const *userdb_fields;
	int ret;

	i_zero(&service_input);
	service_input.protocol = input->info.protocol;
	service_input.username = input->username;
	service_input.local_ip = input->info.local_ip;
	service_input.local_port = input->info.local_port;
	service_input.remote_ip = input->info.remote_ip;
	service_input.remote_port = input->info.remote_port;
	service_input.debug = input->info.debug;

	if ((ret = mail_storage_service_lookup_next(storage_service, &service_input,
						    &user, &error)) <= 0) {
		if (ret < 0) {
			json_ostream_nwritef_string(json_output, "error",
				"userdb lookup: %s", error);
			return -1;
		}
		json_ostream_nwritef_string(json_output, "error",
			"userdb lookup: user %s doesn't exist",
			input->username);
		return 0;
	}
	if (settings_get(user->event, &mail_storage_setting_parser_info, 0,
			 &mail_set, &error) < 0) {
		json_ostream_nwrite_string(json_output, "error", error);
		mail_user_deinit(&user);
		return -1;
	}

	if (expand_field == NULL) {
		userdb_fields = mail_storage_service_user_get_userdb_fields(user->service_user);
		cmd_user_mail_print_fields(input, user, mail_set,
			json_output, userdb_fields, show_field);
	} else {
		string_t *str = t_str_new(128);
		const struct var_expand_params *params =
			mail_user_var_expand_params(user);
		if (var_expand(str, expand_field, params, &error) < 0) {
			json_ostream_nwritef_string(json_output,
				"error", "Failed to expand field: %s", error);
		} else {
			json_ostream_nwrite_string(json_output,
				expand_field, str_c(str));
		}
	}

	settings_free(mail_set);
	mail_user_deinit(&user);
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
	bool have_wildcards, userdb_only = FALSE;
	struct json_ostream *json_output;
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
		e_error(cctx->event, "No user(s) specified");
		return;
	}

	if (expand_field != NULL && userdb_only) {
		e_error(cctx->event, "-e can't be used with -u");
		doveadm_exit_code = EX_USAGE;
		return;
	}
	if (expand_field != NULL && show_field != NULL) {
		e_error(cctx->event, "-e can't be used with -f");
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

	json_output = json_ostream_create(doveadm_print_ostream, 0);
	json_ostream_set_no_error_handling(json_output, TRUE);
	json_ostream_ndescend_object(json_output, NULL);

	if (have_wildcards) {
		cmd_user_list(cctx, conn, &input, json_output,
			      (char*const*)optval);

		json_ostream_nascend_object(json_output);
		json_ostream_destroy(&json_output);
		auth_master_deinit(&conn);
		return;
	}

	if (!userdb_only) {
		storage_service = mail_storage_service_init(master_service,
			MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP |
			MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR |
			MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
			MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS |
			MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES |
			MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS);
		mail_storage_service_set_auth_conn(storage_service, conn);
		conn = NULL;
	}

	input.info.local_ip = cctx->local_ip;
	input.info.local_port = cctx->local_port;
	input.info.remote_ip = cctx->remote_ip;
	input.info.remote_port = cctx->remote_port;

	for(const char *const *val = optval; *val != NULL; val++) {
		input.username = *val;

		json_ostream_ndescend_object(json_output, *val);

		if (!userdb_only) {
			ret = cmd_user_mail_input(storage_service, &input,
				json_output, show_field, expand_field);
		} else {
			ret = cmd_user_input(conn, &input,
				json_output, show_field, TRUE);
		}

		json_ostream_nascend_object(json_output);

		switch (ret) {
		case -1:
			doveadm_exit_code = EX_TEMPFAIL;
			break;
		case 0:
			doveadm_exit_code = EX_NOUSER;
			break;
		}
	}

	json_ostream_nascend_object(json_output);
	json_ostream_destroy(&json_output);

	if (storage_service != NULL)
		mail_storage_service_deinit(&storage_service);
	if (conn != NULL)
		auth_master_deinit(&conn);
}

static
struct doveadm_cmd_ver2 doveadm_cmd_auth_server[] = {
{
	.name = "auth cache flush",
	.cmd = cmd_auth_cache_flush,
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
