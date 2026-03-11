/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "net.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "settings.h"
#include "login-settings.h"
#include "login-common.h"
#include "client-common.h"
#include "var-expand.h"
#include "var-expand-split.h"

#include <unistd.h>
#include <fcntl.h>

static const char *const settings[] = {
	"ssl", "no",
	"login_trusted_networks", "1.2.3.0/24 2001::/64",
	NULL,
};

static struct client *test_client_alloc(pool_t pool)
{
	struct client *client = p_new(pool, struct client, 1);
	client->pool = pool;
	return client;
}

static const struct client_vfuncs test_client_vfuncs = {
	.alloc = test_client_alloc,
};

static struct login_binary test_login_binary = {
	.client_vfuncs = &test_client_vfuncs,
	.process_name = "test",
	.event_category = {
		.name = "test",
	},
	.default_port = 0,
	.default_ssl_port = 0,
	.default_login_socket = "",
};

static void test_setting_override(const char *key, const char *value)
{
	struct event *event = master_service_get_event(master_service);
	struct settings_instance *set_instance = settings_instance_find(event);
	settings_override(set_instance, key, value, SETTINGS_OVERRIDE_TYPE_USERDB);
}

static void test_set_real_endpoints(struct master_service_connection *conn, const char *local, const char *remote)
{
	const char *host;
	int ret = 0;
	ret += net_str2hostport(local, 0, &host, &conn->real_local_port);
	ret += net_addr2ip(host, &conn->real_local_ip);
	ret += net_str2hostport(remote, 0, &host, &conn->real_remote_port);
	ret += net_addr2ip(host, &conn->real_remote_ip);
	i_assert(ret == 0);
}

static void test_set_endpoints(struct master_service_connection *conn, const char *local, const char *remote)
{
	const char *host;
	int ret = 0;
	ret += net_str2hostport(local, 0, &host, &conn->local_port);
	ret += net_addr2ip(host, &conn->local_ip);
	ret += net_str2hostport(remote, 0, &host, &conn->remote_port);
	ret += net_addr2ip(host, &conn->remote_ip);
	i_assert(ret == 0);
}

static struct master_service_connection *test_connection_create(void)
{
	struct master_service_connection *conn =
		t_new(struct master_service_connection, 1);
	conn->name = "test";
	conn->type = "test";
	test_set_real_endpoints(conn, "127.0.0.1:143", "127.0.0.1:1932");
	test_set_endpoints(conn, "127.0.0.1:143", "127.0.0.1:1932");
	return conn;
}

static struct client *test_client_create(struct master_service_connection *conn)
{
	struct client *client;
	int fd = dup(dev_null_fd);
	if (fd == -1)
		i_fatal("dup(%u) failed: %m", dev_null_fd);
	conn->fd = fd;
	int ret = client_alloc(fd, conn, &client);
	if (ret < 0)
		i_fatal("client_alloc() failed");
	return client;
}

static void test_login_log_format(void)
{
	test_begin("login_log_format");
	struct master_service_connection *conn = test_connection_create();
	struct client *client = test_client_create(conn);
	test_expect_error_string("test: user=<>, rip=127.0.0.1, lip=127.0.0.1, secured");
	e_error(client->event, "test");
	client_unref(&client);

	/* Test failed expansion */
	test_setting_override("login_log_format_elements", "user=<%{user}> something=<%{other}>");
	client = test_client_create(conn);
	test_expect_error_string("Failed to expand log_format_elements=%{other}: Unknown variable 'other'");
	e_info(client->event, "test");
	client_unref(&client);

	/* Test failed expansion followed by valid expansion */
	test_setting_override("login_log_format_elements", "user=<%{user}> something=<%{other}> rip=%{remote_ip}");
	client = test_client_create(conn);
	test_expect_error_string("user=<>, rip=127.0.0.1");
	e_error(client->event, "test");
	client_unref(&client);

	/* Test spaces in expansion programs */
	test_setting_override("login_log_format_elements", "user=<%{user}> method=%{mechanism | upper | md5 % 4} hello=world");
	client = test_client_create(conn);
	client->auth_mech_name = "test";
	test_expect_error_string("user=<>, method=3, hello=world");
	e_error(client->event, "test");
	client_unref(&client);

	/* Ensure \001 won't break anything */
	test_setting_override("login_log_format_elements", "user=<%{user}> method=%{mechanism | upper | md5 % 4} hello=\001");
	client = test_client_create(conn);
	client->auth_mech_name = "test";
	test_expect_error_string("user=<>, method=3, hello=\002");
	e_error(client->event, "test");
	client_unref(&client);

	/* restore default back */
	test_setting_override("login_log_format_elements",
			      "user=<%{user}> method=%{mechanism} rip=%{remote_ip} lip=%{local_ip} mpid=%{mail_pid} %{secured} session=<%{session}>");

	test_end();
}

static void test_client_is_trusted(void)
{
	const struct {
		const char *local;
		const char *remote;
		bool set_real;
		bool trusted;
	} test_cases[] = {
		{ "127.0.0.1:143", "127.0.0.1:143", TRUE, FALSE },
		{ "127.0.0.1:143", "1.2.3.4:143", TRUE, TRUE },
		{ "127.0.0.1:143", "[::1]:143", TRUE, FALSE },
		{ "127.0.0.1:143", "[2001::1]:143", TRUE, TRUE },

		{ "127.0.0.1:143", "127.0.0.1:143", FALSE, FALSE },
		{ "127.0.0.1:143", "1.2.3.4:143", FALSE, TRUE },
		{ "127.0.0.1:143", "[::1]:143", FALSE, FALSE },
		{ "127.0.0.1:143", "[2001::1]:143", FALSE, TRUE },
	};

	test_begin("connection_trusted");

	struct master_service_connection *conn =
		test_connection_create();
	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		test_set_endpoints(conn, test_cases[i].local, test_cases[i].remote);
		if (test_cases[i].set_real)
			test_set_real_endpoints(conn, test_cases[i].local, test_cases[i].remote);
		struct client *client = test_client_create(conn);
		test_assert_idx(client->connection_trusted == test_cases[i].trusted, i);
		client_unref(&client);
	}

	test_end();
}

static void test_client_is_secured(void)
{
	const struct {
		const char *local;
		const char *remote;
		bool set_real;
		bool secured;
	} test_cases[] = {
		{ "127.0.0.1:143", "127.0.0.1:143", TRUE, TRUE },
		{ "127.0.0.1:143", "1.2.3.4:143", TRUE, TRUE },
		{ "[::1]:143", "[::1]:143", TRUE, TRUE },
		{ "127.0.0.1:143", "[2001::1]:143", TRUE, TRUE },
		{ "172.16.5.1:143", "172.16.5.4:143", TRUE, FALSE},

		{ "127.0.0.1:143", "127.0.0.1:143", FALSE, FALSE },
		{ "127.0.0.1:143", "1.2.3.4:143", FALSE, TRUE },
		{ "[::1]:143", "[::1]:143", FALSE, FALSE },
		{ "127.0.0.1:143", "[2001::1]:143", FALSE, TRUE },
		{ "172.16.5.1:143", "172.16.5.4:143", FALSE, FALSE},
	};

	test_begin("connection_secured");

	struct master_service_connection *conn =
		test_connection_create();
	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		test_set_endpoints(conn, test_cases[i].local, test_cases[i].remote);
		if (test_cases[i].set_real)
			test_set_real_endpoints(conn, test_cases[i].local, test_cases[i].remote);
		struct client *client = test_client_create(conn);
		test_assert_idx(client->connection_secured == test_cases[i].secured, i);
		client_unref(&client);
	}

	test_end();
}


static void test_settings_init(void)
{
	struct event *event = master_service_get_event(master_service);
	struct settings_root *set_root = settings_root_find(event);
	struct settings_instance *set_instance = settings_instance_new(set_root);
	for (const char *const *ptr = settings; *ptr != NULL; ptr += 2)
		settings_override(set_instance, ptr[0], ptr[1], SETTINGS_OVERRIDE_TYPE_USERDB);
	event_set_ptr(event, SETTINGS_EVENT_INSTANCE, set_instance);
}

static void test_settings_deinit(void)
{
	struct event *event = master_service_get_event(master_service);
	struct settings_instance *set_instance = settings_instance_find(event);
	settings_instance_free(&set_instance);
	event_set_ptr(event, SETTINGS_EVENT_INSTANCE, NULL);
}

int main(int argc, char **argv)
{
	void (*const test_functions[])(void) = {
		test_login_log_format,
		test_client_is_trusted,
		test_client_is_secured,
		NULL
	};
	login_binary = &test_login_binary;
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT;
	master_service = master_service_init("test-master-service-settings",
					     service_flags, &argc, &argv, "");
	test_settings_init();
	int ret = test_run(test_functions);
	test_settings_deinit();
	master_service_deinit(&master_service);
	return ret;
}
