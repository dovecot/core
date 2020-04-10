/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-subprocess.h"
#include "istream.h"
#include "istream-unix.h"
#include "strescape.h"
#include "path-util.h"
#include "unlink-directory.h"
#include "settings-parser.h"
#include "master-service.h"
#include "smtp-submit.h"
#include "mail-storage-service.h"
#include "mail-storage-private.h"
#include "imap-common.h"
#include "imap-settings.h"
#include "imap-client.h"

#include <sys/stat.h>

#define TEMP_DIRNAME ".test-ich"

#define EVILSTR "\t\r\n\001"

struct test_imap_client_hibernate {
	struct client *client;
	int fd_listen;
	bool has_mailbox;
	const char *reply;
};

imap_client_created_func_t *hook_client_created = NULL;
bool imap_debug = FALSE;

static const char *tmpdir;
static struct mail_storage_service_ctx *storage_service;

void imap_refresh_proctitle(void) { }
void imap_refresh_proctitle_delayed(void) { }
int client_create_from_input(const struct mail_storage_service_input *input ATTR_UNUSED,
			     int fd_in ATTR_UNUSED, int fd_out ATTR_UNUSED,
			     bool unhibernated ATTR_UNUSED,
			     struct client **client_r ATTR_UNUSED,
			     const char **error_r ATTR_UNUSED) { return -1; }

static int imap_hibernate_server(struct test_imap_client_hibernate *ctx)
{
	i_set_failure_prefix("SERVER: ");

	int fd = net_accept(ctx->fd_listen, NULL, NULL);
	i_assert(fd > 0);
	struct istream *input = i_stream_create_unix(fd, SIZE_MAX);
	i_stream_unix_set_read_fd(input);

	/* send handshake */
	const char *str = "VERSION\timap-hibernate\t1\t0\n";
	if (write(fd, str, strlen(str)) != (ssize_t)strlen(str))
		i_fatal("write(imap-hibernate client handshake) failed: %m");

	/* read handshake */
	const char *line;
	if ((line = i_stream_read_next_line(input)) == NULL)
		i_fatal("read(imap-hibernate client handshake) failed: %s",
			i_stream_get_error(input));
	if (strcmp(line, "VERSION\timap-hibernate\t1\t0") != 0)
		i_fatal("VERSION not received");
	/* read command */
	if ((line = i_stream_read_next_line(input)) == NULL)
		i_fatal("read(imap-hibernate client command) failed: %s",
			i_stream_get_error(input));
	int fd2 = i_stream_unix_get_read_fd(input);
	test_assert(fd2 != -1);
	i_close_fd(&fd2);
	const char *const *args = t_strsplit_tabescaped(line);

	/* write reply */
	if (write(fd, ctx->reply, strlen(ctx->reply)) != (ssize_t)strlen(ctx->reply))
		i_fatal("write(imap-hibernate client command) failed: %m");

	if (ctx->has_mailbox) {
		/* read mailbox notify fd */
		i_stream_unix_set_read_fd(input);
		if (i_stream_read_next_line(input) == NULL)
			i_fatal("read(imap-hibernate notify fd) failed: %s",
				i_stream_get_error(input));

		fd2 = i_stream_unix_get_read_fd(input);
		test_assert(fd2 != -1);
		i_close_fd(&fd2);

		if (write(fd, "+\n", 2) != 2)
			i_fatal("write(imap-hibernate client command) failed: %m");
	}

	unsigned int i = 0;
	test_assert_strcmp(args[i++], EVILSTR"testuser");
	test_assert_strcmp(args[i++], EVILSTR"%u");
	test_assert_strcmp(args[i++], "idle_notify_interval=120");
	test_assert(str_begins_with(args[i++], "peer_dev_major="));
	test_assert(str_begins_with(args[i++], "peer_dev_minor="));
	test_assert(str_begins_with(args[i++], "peer_ino="));
	test_assert_strcmp(args[i++], "session="EVILSTR"session");
	test_assert(str_begins_with(args[i++], "session_created="));
	test_assert_strcmp(args[i++], "lip=127.0.0.1");
	test_assert_strcmp(args[i++], "lport=1234");
	test_assert_strcmp(args[i++], "rip=127.0.0.2");
	test_assert_strcmp(args[i++], "rport=5678");
	test_assert(str_begins_with(args[i++], "uid="));
	test_assert(str_begins_with(args[i++], "gid="));
	if (ctx->has_mailbox)
		test_assert_strcmp(args[i++], "mailbox="EVILSTR"mailbox");
	test_assert_strcmp(args[i++], "tag="EVILSTR"tag");
	test_assert(str_begins_with(args[i++], "stats="));
	test_assert_strcmp(args[i++], "idle-cmd");
	if (ctx->has_mailbox)
		test_assert_strcmp(args[i++], "notify_fd");
	test_assert(str_begins_with(args[i++], "state="));
	test_assert(args[i] == NULL);

	i_stream_unref(&input);
	i_close_fd(&ctx->fd_listen);
	i_close_fd(&fd);

	ctx->client->hibernated = TRUE; /* prevent disconnect Info message */
	client_destroy(ctx->client, NULL);

	mail_storage_service_deinit(&storage_service);
	master_service_deinit_forked(&master_service);
	return 0;
}

static void
mailbox_notify_callback(struct mailbox *box ATTR_UNUSED,
			struct client *client ATTR_UNUSED)
{
}

static void test_imap_client_hibernate(void)
{
	struct client *client;
	struct smtp_submit_settings smtp_set;
	struct mail_storage_service_user *service_user;
	struct mail_user *mail_user;
	struct test_imap_client_hibernate ctx;
	const char *error;

	storage_service = mail_storage_service_init(master_service, NULL,
		MAIL_STORAGE_SERVICE_FLAG_ALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR |
		MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS);

	const char *const input_userdb[] = {
		"mailbox_list_index=no",
		t_strdup_printf("mail=mbox:%s/mbox", tmpdir),
		NULL
	};
	struct mail_storage_service_input input = {
		.username = EVILSTR"testuser",
		.local_port = 1234,
		.remote_port = 5678,
		.userdb_fields = input_userdb,
	};
	test_assert(net_addr2ip("127.0.0.1", &input.local_ip) == 0);
	test_assert(net_addr2ip("127.0.0.2", &input.remote_ip) == 0);
	test_assert(mail_storage_service_lookup_next(storage_service, &input,
		&service_user, &mail_user, &error) == 1);
	mail_user->set->base_dir = tmpdir;
	mail_user->set->mail_log_prefix = EVILSTR"%u";
	mail_user->session_id = EVILSTR"session";
	i_zero(&smtp_set);
	i_zero(&ctx);

	struct event *event = event_create(NULL);
	int client_fd = dup(dev_null_fd);
	client = client_create(client_fd, client_fd, FALSE, event,
			       mail_user, service_user,
			       imap_setting_parser_info.defaults, &smtp_set);
	ctx.client = client;

	/* can't hibernate without IDLE */
	test_begin("imap client hibernate: non-IDLE");
	test_assert(!imap_client_hibernate(&client, &error));
	test_assert_strcmp(error, "Non-IDLE connections not supported currently");
	test_end();

	struct client_command_context *cmd = client_command_alloc(client);
	cmd->tag = EVILSTR"tag";
	cmd->name = "IDLE";
	event_unref(&event);

	/* imap-hibernate socket doesn't exist */
	test_begin("imap client hibernate: socket not found");
	test_expect_error_string("/"TEMP_DIRNAME"/imap-hibernate) failed: No such file or directory");
	test_assert(!imap_client_hibernate(&client, &error));
	test_expect_no_more_errors();
	test_assert(strstr(error, "net_connect_unix") != NULL);
	test_end();

	/* imap-hibernate socket times out */
	const char *socket_path = t_strdup_printf("%s/imap-hibernate", tmpdir);
	ctx.fd_listen = net_listen_unix(socket_path, 1);
	if (ctx.fd_listen == -1)
		i_fatal("net_listen_unix(%s) failed: %m", socket_path);
	fd_set_nonblock(ctx.fd_listen, FALSE);

	/* imap-hibernate socket returns failure */
	test_begin("imap client hibernate: error returned");
	ctx.reply = "-notgood\n";
	test_subprocess_fork(imap_hibernate_server, &ctx, FALSE);

	test_expect_error_string(TEMP_DIRNAME"/imap-hibernate returned failure: notgood");
	test_assert(!imap_client_hibernate(&client, &error));
	test_expect_no_more_errors();
	test_assert(strstr(error, "notgood") != NULL);
	test_end();

	/* create and open evil mailbox */
	client->mailbox = mailbox_alloc(client->user->namespaces->list,
					"testbox", 0);
	struct mailbox_update update = {
		.uid_validity = 12345678,
	};
	memset(update.mailbox_guid, 0x12, sizeof(update.mailbox_guid));
	test_assert(mailbox_create(client->mailbox, &update, FALSE) == 0);
	test_assert(mailbox_open(client->mailbox) == 0);
	client->mailbox->vname = EVILSTR"mailbox";

	/* successful hibernation */
	test_begin("imap client hibernate: success");
	ctx.reply = "+\n";
	ctx.has_mailbox = TRUE;
	test_subprocess_fork(imap_hibernate_server, &ctx, FALSE);
	/* start notification only after forking or we'll have trouble
	   deinitializing cleanly */
	mailbox_notify_changes(client->mailbox, mailbox_notify_callback, client);
	test_assert(imap_client_hibernate(&client, &error));
	test_end();

	i_close_fd(&ctx.fd_listen);
	mail_storage_service_deinit(&storage_service);
}

static void test_cleanup(void)
{
	const char *error;

	if (unlink_directory(tmpdir, UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0)
		i_error("unlink_directory() failed: %s", error);
}

static void test_init(void)
{
	const char *cwd, *error;

	test_assert(t_get_working_dir(&cwd, &error) == 0);
	tmpdir = t_strconcat(cwd, "/"TEMP_DIRNAME, NULL);

	test_cleanup();
	if (mkdir(tmpdir, 0700) < 0)
		i_fatal("mkdir() failed: %m");

	test_subprocesses_init(FALSE);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS |
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_STD_CLIENT |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	int ret;

	master_service = master_service_init("test-imap-client-hibernate",
					     service_flags, &argc, &argv, "D");

	master_service_init_finish(master_service);
	test_init();

	static void (*const test_functions[])(void) = {
		test_imap_client_hibernate,
		NULL
	};
	ret = test_run(test_functions);

	test_subprocesses_deinit();
	test_cleanup();
	master_service_deinit(&master_service);
	return ret;
}
