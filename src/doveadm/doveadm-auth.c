/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "askpass.h"
#include "base64.h"
#include "str.h"
#include "wildcard-match.h"
#include "auth-client.h"
#include "auth-master.h"
#include "auth-server-connection.h"
#include "doveadm.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct authtest_input {
	const char *username;
	const char *password;
	struct auth_user_info info;
	bool success;
};

static int
cmd_user_input(const char *auth_socket_path, const struct authtest_input *input,
	       const char *show_field)
{
	struct auth_master_connection *conn;
	pool_t pool;
	const char *username, *const *fields, *p;
	int ret;

	if (auth_socket_path == NULL) {
		auth_socket_path = t_strconcat(doveadm_settings->base_dir,
					       "/auth-userdb", NULL);
	}

	pool = pool_alloconly_create("auth master lookup", 1024);

	conn = auth_master_init(auth_socket_path, 0);
	ret = auth_master_user_lookup(conn, input->username, &input->info,
				      pool, &username, &fields);
	if (ret < 0) {
		if (fields[0] == NULL)
			i_fatal("userdb lookup failed for %s", input->username);
		else {
			i_fatal("userdb lookup failed for %s: %s",
				input->username, fields[0]);
		}
	} else if (ret == 0) {
		fprintf(show_field == NULL ? stdout : stderr,
			"userdb lookup: user %s doesn't exist\n",
			input->username);
	} else if (show_field != NULL) {
		unsigned int show_field_len = strlen(show_field);

		for (; *fields; fields++) {
			if (strncmp(*fields, show_field, show_field_len) == 0 &&
			    (*fields)[show_field_len] == '=')
				printf("%s\n", *fields + show_field_len + 1);
		}
	} else {
		printf("userdb: %s\n", input->username);

		for (; *fields; fields++) {
			p = strchr(*fields, '=');
			if (p == NULL)
				printf("  %-10s\n", *fields);
			else {
				printf("  %-10s: %s\n",
				       t_strcut(*fields, '='), p + 1);
			}
		}
	}
	auth_master_deinit(&conn);
	return ret;
}

static void
auth_callback(struct auth_client_request *request ATTR_UNUSED,
	      enum auth_request_status status,
	      const char *data_base64 ATTR_UNUSED,
	      const char *const *args, void *context)
{
	struct authtest_input *input = context;

	if (!io_loop_is_running(current_ioloop))
		return;

	if (status == 0)
		i_fatal("passdb expects SASL continuation");

	if (status < 0)
		printf("passdb: %s auth failed\n", input->username);
	else {
		input->success = TRUE;
		printf("passdb: %s auth succeeded\n", input->username);
	}

	if (*args != NULL) {
		printf("extra fields:\n");
		for (; *args != NULL; args++)
			printf("  %s\n", *args);
	}
	io_loop_stop(current_ioloop);
}

static void auth_connected(struct auth_client *client,
			   bool connected, void *context)
{
	struct authtest_input *input = context;
	struct auth_request_info info;
	string_t *init_resp, *base64_resp;

	if (!connected)
		i_fatal("Couldn't connect to auth socket");

	init_resp = t_str_new(128);
	str_append_c(init_resp, '\0');
	str_append(init_resp, input->username);
	str_append_c(init_resp, '\0');
	str_append(init_resp, input->password);

	base64_resp = t_str_new(128);
	base64_encode(str_data(init_resp), str_len(init_resp), base64_resp);

	memset(&info, 0, sizeof(info));
	info.mech = "PLAIN";
	info.service = input->info.service;
	info.local_ip = input->info.local_ip;
	info.local_port = input->info.local_port;
	info.remote_ip = input->info.remote_ip;
	info.remote_port = input->info.remote_port;
	info.initial_resp_base64 = str_c(base64_resp);

	(void)auth_client_request_new(client, &info,
				      auth_callback, input);
}

static int
cmd_auth_input(const char *auth_socket_path, struct authtest_input *input)
{
	struct auth_client *client;

	if (auth_socket_path == NULL) {
		auth_socket_path = t_strconcat(doveadm_settings->base_dir,
					       "/auth-client", NULL);
	}

	client = auth_client_init(auth_socket_path, getpid(), FALSE);
	auth_client_set_connect_notify(client, auth_connected, input);

	if (!auth_client_is_disconnected(client))
		io_loop_run(current_ioloop);

	auth_client_set_connect_notify(client, NULL, NULL);
	auth_client_deinit(&client);
	return 0;
}

static void auth_user_info_parse(struct auth_user_info *info, const char *arg)
{
	if (strncmp(arg, "service=", 8) == 0)
		info->service = arg + 8;
	else if (strncmp(arg, "lip=", 4) == 0) {
		if (net_addr2ip(arg + 4, &info->local_ip) < 0)
			i_fatal("lip: Invalid ip");
	} else if (strncmp(arg, "rip=", 4) == 0) {
		if (net_addr2ip(arg + 4, &info->remote_ip) < 0)
			i_fatal("rip: Invalid ip");
	} else if (strncmp(arg, "lport=", 6) == 0) {
		info->local_port = atoi(arg + 6);
	} else if (strncmp(arg, "rport=", 6) == 0) {
		info->remote_port = atoi(arg + 6);
	} else {
		i_fatal("Unknown -x argument: %s", arg);
	}
}

static void
cmd_user_list(const char *auth_socket_path, char *const *users)
{
	struct auth_master_user_list_ctx *ctx;
	struct auth_master_connection *conn;
	const char *username;
	unsigned int i;

	if (auth_socket_path == NULL) {
		auth_socket_path = t_strconcat(doveadm_settings->base_dir,
					       "/auth-userdb", NULL);
	}

	conn = auth_master_init(auth_socket_path, 0);
	ctx = auth_master_user_list_init(conn);
	while ((username = auth_master_user_list_next(ctx)) != NULL) {
		for (i = 0; users[i] != NULL; i++) {
			if (wildcard_match_icase(username, users[i]))
				break;
		}
		if (users[i] != NULL)
			printf("%s\n", username);
	}
	if (auth_master_user_list_deinit(&ctx) < 0) {
		i_error("user listing failed");
		exit(1);
	}
	auth_master_deinit(&conn);
}

static void cmd_auth(int argc, char *argv[])
{
	const char *auth_socket_path = NULL;
	struct authtest_input input;
	int c;

	memset(&input, 0, sizeof(input));
	input.info.service = "doveadm";

	while ((c = getopt(argc, argv, "a:x:")) > 0) {
		switch (c) {
		case 'a':
			auth_socket_path = optarg;
			break;
		case 'x':
			auth_user_info_parse(&input.info, optarg);
			break;
		default:
			help(&doveadm_cmd_auth);
		}
	}

	if (optind == argc)
		help(&doveadm_cmd_auth);

	input.username = argv[optind++];
	input.password = argv[optind] != NULL ? argv[optind++] :
		t_askpass("Password: ");
	if (argv[optind] != NULL)
			i_fatal("Unexpected parameter: %s", argv[optind]);
	if (cmd_auth_input(auth_socket_path, &input) < 0)
		exit(FATAL_DEFAULT);
	if (!input.success)
		exit(1);
}

static void cmd_user(int argc, char *argv[])
{
	const char *auth_socket_path = NULL;
	struct authtest_input input;
	const char *show_field = NULL;
	unsigned int i;
	bool have_wildcards;
	int c;

	memset(&input, 0, sizeof(input));
	input.info.service = "doveadm";

	while ((c = getopt(argc, argv, "a:f:x:")) > 0) {
		switch (c) {
		case 'a':
			auth_socket_path = optarg;
			break;
		case 'f':
			show_field = optarg;
			break;
		case 'x':
			auth_user_info_parse(&input.info, optarg);
			break;
		default:
			help(&doveadm_cmd_user);
		}
	}

	if (optind == argc)
		help(&doveadm_cmd_user);

	have_wildcards = FALSE;
	for (i = optind; argv[i] != NULL; i++) {
		if (strchr(argv[i], '*') != NULL ||
		    strchr(argv[i], '?') != NULL) {
			have_wildcards = TRUE;
			break;
		}
	}

	if (have_wildcards)
		cmd_user_list(auth_socket_path, argv + optind);
	else {
		bool first = TRUE;
		bool notfound = FALSE;

		while ((input.username = argv[optind++]) != NULL) {
			if (first)
				first = FALSE;
			else
				putchar('\n');
			switch (cmd_user_input(auth_socket_path, &input,
					       show_field)) {
			case -1:
				exit(1);
			case 0:
				notfound = TRUE;
				break;
			}
		}
		if (notfound)
			exit(2);
	}
}

struct doveadm_cmd doveadm_cmd_auth = {
	cmd_auth, "auth",
	"[-a <auth socket path>] [-x <auth info>] <user> [<password>]"
};

struct doveadm_cmd doveadm_cmd_user = {
	cmd_user, "user",
	"[-a <userdb socket path>] [-x <auth info>] [-f field] <user mask> [...]"
};
