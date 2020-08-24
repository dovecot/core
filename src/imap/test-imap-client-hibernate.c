/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "mail-storage-private.h"
#include "imap-common.h"
#include "imap-client.h"

#define EVILSTR "\t\r\n\001"
#define EVILSTR_ESCAPED "\001t\001r\001n\0011"

imap_client_created_func_t *hook_client_created = NULL;
bool imap_debug = FALSE;

void imap_refresh_proctitle(void) { }
int client_create_from_input(const struct mail_storage_service_input *input ATTR_UNUSED,
			     int fd_in ATTR_UNUSED, int fd_out ATTR_UNUSED,
			     struct client **client_r ATTR_UNUSED,
			     const char **error_r ATTR_UNUSED) { return -1; }

static void test_imap_client_hibernate(void)
{
	buffer_t *state = buffer_create_dynamic(pool_datastack_create(), 0);
	struct mail_user_settings mail_set = {
		.mail_log_prefix = EVILSTR"%u",
	};
	struct mail_user mail_user = {
		.set = &mail_set,
		.conn = {
			.local_ip = t_new(struct ip_addr, 1),
			.remote_ip = t_new(struct ip_addr, 1),
		},
		.username = EVILSTR"testuser",
		.session_id = EVILSTR"session",
		.session_create_time = 1234567,
		.pool = pool_datastack_create(),
		.uid = 4000,
		.gid = 4001,
	};
	struct imap_settings imap_set = {
		.imap_idle_notify_interval = 120,
		.imap_logout_format = "",
	};
	struct client_command_context queue = {
		.tag = EVILSTR"tag",
		.name = "IDLE",
	};
	struct client client = {
		.user = &mail_user,
		.set = &imap_set,
		.fd_in = dev_null_fd,
		.input = i_stream_create_from_data("", 0),
		.output = o_stream_create_buffer(state),
		.command_queue = &queue,
	};
	test_begin("imap client hibernate");
	test_assert(net_addr2ip("127.0.0.1", mail_user.conn.local_ip) == 0);
	test_assert(net_addr2ip("127.0.0.2", mail_user.conn.remote_ip) == 0);

	string_t *cmd = t_str_new(256);
	imap_hibernate_write_cmd(&client, cmd, state, -1);

	const char *const *args = t_strsplit(str_c(cmd), "\t");
	unsigned int i = 0;
	test_assert_strcmp(args[i++], EVILSTR_ESCAPED"testuser");
	test_assert_strcmp(args[i++], EVILSTR_ESCAPED"%u");
	test_assert_strcmp(args[i++], "idle_notify_interval=120");
	test_assert(strncmp(args[i++], "peer_dev_major=", 15) == 0);
	test_assert(strncmp(args[i++], "peer_dev_minor=", 15) == 0);
	test_assert(strncmp(args[i++], "peer_ino=", 9) == 0);
	test_assert_strcmp(args[i++], "session="EVILSTR_ESCAPED"session");
	test_assert_strcmp(args[i++], "session_created=1234567");
	test_assert_strcmp(args[i++], "lip=127.0.0.1");
	test_assert_strcmp(args[i++], "rip=127.0.0.2");
	test_assert_strcmp(args[i++], "uid=4000");
	test_assert_strcmp(args[i++], "gid=4001");
	test_assert_strcmp(args[i++], "tag="EVILSTR_ESCAPED"tag");
	test_assert(strncmp(args[i++], "stats=", 6) == 0);
	test_assert_strcmp(args[i++], "idle-cmd");
	test_assert(strncmp(args[i++], "state=", 6) == 0);
	test_assert(args[i] == NULL);

	i_stream_destroy(&client.input);
	o_stream_destroy(&client.output);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_client_hibernate,
		NULL
	};
	return test_run(test_functions);
}
