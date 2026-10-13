/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-dir.h"
#include "test-subprocess.h"
#include "istream.h"
#include "istream-unix.h"
#include "strescape.h"
#include "path-util.h"
#include "unlink-directory.h"
#include "settings-parser.h"
#include "settings.h"
#include "master-service.h"
#include "smtp-submit.h"
#include "mail-storage-service.h"
#include "mail-storage-private.h"
#include "buffer.h"
#include "seq-range-array.h"
#include "imap-common.h"
#include "imap-settings.h"
#include "imap-client.h"
#include "imap-state.h"

#include <sys/stat.h>

#define TEMP_DIRNAME ".test-ich"
#define SERVER_KILL_TIMEOUT_SECS 10

#define EVILSTR "\t\r\n\001"

struct test_imap_client_hibernate {
	struct client *client;
	int fd_listen;
	bool has_mailbox;
	bool has_notify_fd;
	bool idle_cmd;
	const char *reply;
};

imap_client_created_func_t *hook_client_created = NULL;
bool imap_debug = FALSE;
bool verbose_proctitle = FALSE;

static struct mail_storage_service_ctx *storage_service;

void imap_refresh_proctitle(void) { }
void imap_refresh_proctitle_delayed(void) { }
int client_create_from_input(const struct mail_storage_service_input *input ATTR_UNUSED,
			     const struct imap_logout_stats *stats ATTR_UNUSED,
			     int fd_in ATTR_UNUSED, int fd_out ATTR_UNUSED,
			     enum client_create_flags flags ATTR_UNUSED,
			     const buffer_t *input_buf ATTR_UNUSED,
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

	if (ctx->has_notify_fd) {
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
	test_assert_strcmp(args[i++], "autoexpunge_next_check=1234567890");
	test_assert_strcmp(args[i++], "lip=127.0.0.1");
	test_assert_strcmp(args[i++], "lport=1234");
	test_assert_strcmp(args[i++], "rip=127.0.0.2");
	test_assert_strcmp(args[i++], "rport=5678");
	test_assert(str_begins_with(args[i++], "uid="));
	test_assert(str_begins_with(args[i++], "gid="));
	if (ctx->has_mailbox)
		test_assert_strcmp(args[i++], "mailbox="EVILSTR"mailbox");
	if (ctx->idle_cmd)
		test_assert_strcmp(args[i++], "tag="EVILSTR"tag");
	test_assert_strcmp(args[i++], "auth_token=asdf");
	test_assert(str_begins_with(args[i++], "session_pid="));
	test_assert(args[i] != NULL && str_begins_with(args[i++], "stats="));
	test_assert(args[i] != NULL &&
		    str_begins_with(args[i++], "capability="));
	if (ctx->idle_cmd)
		test_assert_strcmp(args[i++], "idle-cmd");
	else
		test_assert(args[i] != NULL && str_begins_with(args[i++], "last_input="));
	if (ctx->has_notify_fd)
		test_assert_strcmp(args[i++], "notify_fd");

	const char *const stats_prefixes[] = {
		"state=",
		"fetch_hdr_count=",
		"fetch_hdr_bytes=",
		"fetch_body_count=",
		"fetch_body_bytes=",
		"deleted_count=",
		"expunged_count=",
		"trashed_count=",
		"autoexpunged_count=",
		"append_count=",
		"input_bytes_extra=",
		"output_bytes_extra=",
	};
	for (size_t p = 0; p < N_ELEMENTS(stats_prefixes); p++)
		test_assert(str_begins_with(args[i++], stats_prefixes[p]));

	test_assert(args[i] == NULL);

	i_stream_unref(&input);
	i_close_fd(&ctx->fd_listen);
	i_close_fd(&fd);

	ctx->client->hibernated = TRUE; /* prevent disconnect Info message */
	client_destroy(ctx->client, NULL);

	mail_storage_service_deinit(&storage_service);
	master_service_deinit_forked(&master_service);
	return test_has_failed() ? 1 : 0;
}

static void
mailbox_notify_callback(struct mailbox *box ATTR_UNUSED,
			struct client *client ATTR_UNUSED)
{
}

static void test_client_set_mailbox_modseq(struct client *client)
{
	struct mailbox_status status;

	/* SELECT would do this */
	mailbox_get_open_status(client->mailbox, STATUS_HIGHESTMODSEQ,
				&status);
	client->sync_last_full_modseq = status.highest_modseq;
}

static struct client *test_client_create(int *peer_fd_r)
{
	/* the client keeps a pointer to this */
	static struct smtp_submit_settings smtp_set;
	struct mail_user *mail_user;
	const char *error;

	const char *const input_userdb[] = {
		"mailbox_list_index=no",
		"mail_driver=maildir",
		t_strdup_printf("mail_path=%s/maildir", test_dir_get()),
		t_strdup_printf("base_dir=%s", test_dir_get()),
		"mail_log_prefix="EVILSTR"%u",
		"auth_token=asdf",
		NULL
	};
	struct mail_storage_service_input input = {
		.username = EVILSTR"testuser",
		.local_port = 1234,
		.remote_port = 5678,
		.userdb_fields = input_userdb,
		.session_id = EVILSTR"session",
	};
	test_assert(net_addr2ip("127.0.0.1", &input.local_ip) == 0);
	test_assert(net_addr2ip("127.0.0.2", &input.remote_ip) == 0);
	test_assert(mail_storage_service_lookup_next(storage_service, &input,
						     &mail_user, &error) == 1);

	if (master_service_get_client_limit(master_service) == 0) {
		/* The previous client's destroy used up the std client.
		   Account for a new one. */
		master_service_set_client_limit(master_service, 1);
		master_service_set_restart_request_count(master_service, 1);
		master_service_client_connection_created(master_service);
	}

	int client_fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds) < 0)
		i_fatal("socketpair() failed: %m");
	struct event *event = event_create(NULL);
	struct client *client =
		client_create(client_fds[0], client_fds[0], 0, event,
			      mail_user, imap_setting_parser_info.defaults,
			      &smtp_set, NULL);
	event_unref(&event);
	client->autoexpunge_next_check = 1234567890;
	*peer_fd_r = client_fds[1];
	return client;
}

static void test_mail_save(struct mailbox *box, const char *data)
{
	struct mailbox_transaction_context *trans;
	struct mail_save_context *save_ctx;
	struct istream *input;
	ssize_t ret;

	input = i_stream_create_from_data(data, strlen(data));
	trans = mailbox_transaction_begin(box,
			MAILBOX_TRANSACTION_FLAG_EXTERNAL, __func__);
	save_ctx = mailbox_save_alloc(trans);
	test_assert(mailbox_save_begin(&save_ctx, input) == 0);
	do {
		test_assert(mailbox_save_continue(save_ctx) == 0);
	} while ((ret = i_stream_read(input)) > 0);
	test_assert(ret == -1);
	test_assert(mailbox_save_finish(&save_ctx) == 0);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	i_stream_unref(&input);
}

static void test_mail_save_other(struct mail_user *user, const char *vname)
{
	struct mailbox *box =
		mailbox_alloc(user->namespaces->list, vname, 0);
	test_assert(mailbox_open(box) == 0);
	test_mail_save(box, "Subject: new\n\nbody\n");
	mailbox_free(&box);
}

static void test_mail_expunge_first(struct mail_user *user, const char *vname)
{
	struct mailbox *box =
		mailbox_alloc(user->namespaces->list, vname, 0);
	test_assert(mailbox_sync(box, 0) == 0);
	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(box, 0, __func__);
	struct mail *mail = mail_alloc(trans, 0, NULL);
	mail_set_seq(mail, 1);
	mail_expunge(mail);
	mail_free(&mail);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	test_assert(mailbox_sync(box, 0) == 0);
	mailbox_free(&box);
}

static int test_mail_expunge_first_child(struct test_imap_client_hibernate *ctx)
{
	test_mail_expunge_first(ctx->client->user, "nonidlebox");

	/* Free the client and mail user inherited from the parent. Mark the
	   client hibernated, so destroying it doesn't shutdown() the socket
	   shared with the parent, autoexpunge or log a disconnect. */
	ctx->client->hibernated = TRUE;
	client_destroy(ctx->client, NULL);

	mail_storage_service_deinit(&storage_service);
	master_service_deinit_forked(&master_service);
	return test_has_failed() ? 1 : 0;
}

static void test_mailbox_sync_no_expunges(struct mailbox *box)
{
	struct mailbox_sync_context *sync_ctx;
	struct mailbox_sync_rec sync_rec;
	struct mailbox_sync_status sync_status;

	/* like imap_sync_init() does for FETCH */
	sync_ctx = mailbox_sync_init(box, MAILBOX_SYNC_FLAG_NO_EXPUNGES);
	while (mailbox_sync_next(sync_ctx, &sync_rec)) ;
	test_assert(mailbox_sync_deinit(&sync_ctx, &sync_status) == 0);
	test_assert(sync_status.sync_delayed_expunges);
}

static void
test_imap_client_hibernate_idle(struct test_imap_client_hibernate *ctx)
{
	struct client *client;
	const char *error;
	int peer_fd;

	client = test_client_create(&peer_fd);
	ctx->client = client;

	/* can't hibernate when a command other than IDLE is running */
	test_begin("imap client hibernate: command in progress");
	struct client_command_context *cmd = client_command_alloc(client);
	cmd->tag = EVILSTR"tag";
	cmd->name = "NOOP";
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "Command in progress");
	test_end();

	cmd->name = "IDLE";

	/* partial input line is buffered */
	test_begin("imap client hibernate: input pending");
	if (write(peer_fd, "DON", 3) != 3)
		i_fatal("write(client) failed: %m");
	test_assert(i_stream_read(client->input) == 3);
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "input pending from client");
	i_stream_skip(client->input, 3);
	test_end();

	/* imap-hibernate socket doesn't exist */
	test_begin("imap client hibernate: socket not found");
	test_expect_error_string("/imap-hibernate) failed: No such file or directory");
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_expect_no_more_errors();
	test_assert(strstr(error, "net_connect_unix") != NULL);
	test_end();

	/* imap-hibernate socket times out */
	const char *socket_path = t_strdup_printf("%s/imap-hibernate",
						  test_dir_get());
	ctx->fd_listen = net_listen_unix(socket_path, 1);
	if (ctx->fd_listen == -1)
		i_fatal("net_listen_unix(%s) failed: %m", socket_path);
	fd_set_nonblock(ctx->fd_listen, FALSE);

	/* imap-hibernate socket returns failure */
	test_begin("imap client hibernate: error returned");
	ctx->reply = "-notgood\n";
	ctx->idle_cmd = TRUE;
	test_subprocess_fork(imap_hibernate_server, ctx, FALSE);

	test_expect_error_string("/imap-hibernate returned failure: notgood");
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_expect_no_more_errors();
	test_assert(strstr(error, "notgood") != NULL);
	test_end();

	/* Regression test for swallowed mailbox-open errors during state
	   import. import_state_mailbox() used to check the result of
	   import_state_mailbox_open() with "< 0", but that function returns
	   enum imap_state_result where errors are positive values, so the
	   errors were ignored and import wrongly reported success. That could
	   leave the client with a mailbox but no keywords array and crash in
	   the following sync. Verify that importing a state whose mailbox no
	   longer matches is rejected. */
	test_begin("imap client state import: inconsistent mailbox rejected");
	struct mailbox *import_box =
		mailbox_alloc(client->user->namespaces->list, "importbox", 0);
	struct mailbox_update import_update = {
		.uid_validity = 11111111,
	};
	memset(import_update.mailbox_guid, 0x34,
	       sizeof(import_update.mailbox_guid));
	test_assert(mailbox_create(import_box, &import_update, FALSE) == 0);
	test_assert(mailbox_open(import_box) == 0);
	test_assert(mailbox_sync(import_box, 0) == 0);
	client->mailbox = import_box;
	test_client_set_mailbox_modseq(client);

	buffer_t *state = t_buffer_create(256);
	test_assert(imap_state_export_internal(client, state, &error) == 1);

	/* close the exported mailbox and recreate it with a different GUID,
	   so the exported state no longer matches the stored mailbox */
	mailbox_free(&client->mailbox);
	client->keywords.names = NULL;
	import_box = mailbox_alloc(client->user->namespaces->list,
				   "importbox", 0);
	test_assert(mailbox_delete(import_box) == 0);
	mailbox_free(&import_box);
	import_box = mailbox_alloc(client->user->namespaces->list,
				   "importbox", 0);
	memset(import_update.mailbox_guid, 0x56,
	       sizeof(import_update.mailbox_guid));
	test_assert(mailbox_create(import_box, &import_update, FALSE) == 0);
	mailbox_free(&import_box);

	const char *import_error = NULL;
	test_assert(imap_state_import_internal(client, state->data,
		state->used, &import_error) != IMAP_STATE_OK);
	test_assert(client->mailbox == NULL);
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
	test_client_set_mailbox_modseq(client);
	client->mailbox->vname = EVILSTR"mailbox";

	/* successful hibernation */
	test_begin("imap client hibernate: success");
	ctx->reply = "+\n";
	ctx->has_mailbox = TRUE;
	ctx->has_notify_fd = TRUE;
	test_subprocess_fork(imap_hibernate_server, ctx, FALSE);
	/* start notification only after forking or we'll have trouble
	   deinitializing cleanly */
	mailbox_notify_changes(client->mailbox, mailbox_notify_callback, client);
	test_assert(imap_client_hibernate(&client, -1, &error));
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
	test_end();

	i_close_fd(&peer_fd);
}

static void test_pipe_assert_closed(int fd_pipe[2])
{
	char c;

	/* EOF only when all the write end's fds have been closed. Otherwise
	   the non-blocking read fails with EAGAIN. */
	fd_set_nonblock(fd_pipe[0], TRUE);
	test_assert(read(fd_pipe[0], &c, 1) == 0);
	i_close_fd(&fd_pipe[0]);
}

static void
test_imap_client_hibernate_idle_fd(struct test_imap_client_hibernate *ctx)
{
	struct client *client;
	const char *error;
	int peer_fd, fd_pipe[2];

	client = test_client_create(&peer_fd);
	ctx->client = client;
	ctx->idle_cmd = TRUE;
	ctx->has_mailbox = TRUE;
	ctx->has_notify_fd = TRUE;
	ctx->reply = "+\n";

	struct client_command_context *cmd = client_command_alloc(client);
	cmd->tag = EVILSTR"tag";
	cmd->name = "NOOP";

	test_begin("imap client hibernate: given notify fd closed on failure");
	if (pipe(fd_pipe) < 0)
		i_fatal("pipe() failed: %m");
	test_assert(!imap_client_hibernate(&client, fd_pipe[1], &error));
	test_assert_strcmp(error, "Command in progress");
	test_pipe_assert_closed(fd_pipe);
	test_end();

	cmd->name = "IDLE";
	client->mailbox = mailbox_alloc(client->user->namespaces->list,
					"fdbox", 0);
	test_assert(mailbox_create(client->mailbox, NULL, FALSE) == 0);
	test_assert(mailbox_open(client->mailbox) == 0);
	test_client_set_mailbox_modseq(client);
	client->mailbox->vname = EVILSTR"mailbox";

	/* No mailbox_notify_changes(), so extracting a notify fd would fail.
	   The given fd is sent instead. */
	test_begin("imap client hibernate: given notify fd sent");
	if (pipe(fd_pipe) < 0)
		i_fatal("pipe() failed: %m");
	test_subprocess_fork(imap_hibernate_server, ctx, FALSE);
	test_assert(imap_client_hibernate(&client, fd_pipe[1], &error));
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
	test_pipe_assert_closed(fd_pipe);
	test_end();

	i_close_fd(&peer_fd);
}

static void
test_imap_client_hibernate_nonidle_no_mailbox(
	struct test_imap_client_hibernate *ctx)
{
	struct client *client;
	const char *error;
	int peer_fd;

	client = test_client_create(&peer_fd);
	ctx->client = client;
	ctx->idle_cmd = FALSE;
	ctx->has_mailbox = FALSE;
	ctx->has_notify_fd = FALSE;
	ctx->reply = "+\n";

	test_begin("imap client hibernate: non-IDLE delay-newmail");
	const struct imap_settings *orig_set = client->set;
	struct imap_settings set = *orig_set;
	set.parsed_workarounds |= WORKAROUND_DELAY_NEWMAIL;
	client->set = &set;
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "delay-newmail workaround enabled");
	client->set = orig_set;
	test_end();

	test_begin("imap client hibernate: non-IDLE skipping input line");
	client->input_skip_line = TRUE;
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "Skipping the rest of a command line");
	client->input_skip_line = FALSE;
	test_end();

	test_begin("imap client hibernate: non-IDLE FETCH failures");
	p_array_init(&client->fetch_failed_uids, client->pool, 1);
	seq_range_array_add(&client->fetch_failed_uids, 1);
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "FETCH failures pending");
	array_clear(&client->fetch_failed_uids);
	test_end();

	test_begin("imap client hibernate: non-IDLE without mailbox");
	test_subprocess_fork(imap_hibernate_server, ctx, FALSE);
	test_assert(imap_client_hibernate(&client, -1, &error));
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
	test_end();

	i_close_fd(&peer_fd);
}

static void
test_imap_client_hibernate_nonidle_mailbox(
	struct test_imap_client_hibernate *ctx)
{
	struct client *client;
	buffer_t *state;
	const char *error;
	int peer_fd;

	client = test_client_create(&peer_fd);
	ctx->client = client;
	ctx->idle_cmd = FALSE;
	ctx->has_mailbox = TRUE;
	ctx->has_notify_fd = FALSE;
	ctx->reply = "+\n";

	client->mailbox = mailbox_alloc(client->user->namespaces->list,
					"nonidlebox", 0);
	test_assert(mailbox_create(client->mailbox, NULL, FALSE) == 0);
	test_assert(mailbox_open(client->mailbox) == 0);
	test_mail_save(client->mailbox, "Subject: 1\n\nbody\n");
	test_mail_save(client->mailbox, "Subject: 2\n\nbody\n");
	test_assert(mailbox_sync(client->mailbox, 0) == 0);
	test_client_set_mailbox_modseq(client);

	test_begin("imap client hibernate: non-IDLE transaction open");
	struct mailbox_transaction_context *trans =
		mailbox_transaction_begin(client->mailbox, 0, __func__);
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "Mailbox transactions open");
	mailbox_transaction_rollback(&trans);
	test_end();

	test_begin("imap client hibernate: non-IDLE delayed expunges");
	test_mail_expunge_first(client->user, "nonidlebox");
	/* The view hasn't been synced yet, but the expunge is visible in the
	   index already */
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "Expunges not sent to client yet");
	/* Sync without expunges, like FETCH does. The expunge is now delayed
	   in the view, and the client hasn't been told about it. */
	test_mailbox_sync_no_expunges(client->mailbox);
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "Expunges not sent to client yet");
	/* After a full sync the expunge is sent and hibernation is allowed */
	test_assert(mailbox_sync(client->mailbox, 0) == 0);
	test_client_set_mailbox_modseq(client);
	state = t_buffer_create(256);
	test_assert(imap_state_export_internal(client, state, &error) == 1);
	test_end();

	test_begin("imap client hibernate: non-IDLE new mail");
	/* new messages above the view's UIDNEXT aren't counted as expunges */
	test_mail_save_other(client->user, "nonidlebox");
	buffer_set_used_size(state, 0);
	test_assert(imap_state_export_internal(client, state, &error) == 1);
	test_end();

	test_begin("imap client hibernate: non-IDLE new mail and delayed expunges");
	test_assert(mailbox_sync(client->mailbox, 0) == 0);
	test_client_set_mailbox_modseq(client);
	test_mail_expunge_first(client->user, "nonidlebox");
	test_mailbox_sync_no_expunges(client->mailbox);
	test_mail_save_other(client->user, "nonidlebox");
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "Expunges not sent to client yet");
	test_assert(mailbox_sync(client->mailbox, 0) == 0);
	test_client_set_mailbox_modseq(client);
	buffer_set_used_size(state, 0);
	test_assert(imap_state_export_internal(client, state, &error) == 1);
	test_end();

	test_begin("imap client hibernate: non-IDLE expunge by another process");
	/* The expunge is committed by another process, so it isn't in this
	   process's index map until the index is refreshed. */
	test_subprocess_fork(test_mail_expunge_first_child, ctx, FALSE);
	test_subprocess_wait_all(SERVER_KILL_TIMEOUT_SECS);
	test_assert(!imap_client_hibernate(&client, -1, &error));
	test_assert_strcmp(error, "Expunges not sent to client yet");
	test_assert(mailbox_sync(client->mailbox, 0) == 0);
	test_client_set_mailbox_modseq(client);
	buffer_set_used_size(state, 0);
	test_assert(imap_state_export_internal(client, state, &error) == 1);
	test_end();

	test_begin("imap client hibernate: non-IDLE with mailbox");
	client->mailbox->vname = EVILSTR"mailbox";
	test_subprocess_fork(imap_hibernate_server, ctx, FALSE);
	test_assert(imap_client_hibernate(&client, -1, &error));
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
	test_end();

	i_close_fd(&peer_fd);
}

static void test_imap_client_hibernate(void)
{
	struct test_imap_client_hibernate ctx;

	storage_service = mail_storage_service_init(master_service,
		MAIL_STORAGE_SERVICE_FLAG_ALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR |
		MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS);
	i_zero(&ctx);

	test_imap_client_hibernate_idle(&ctx);
	test_imap_client_hibernate_idle_fd(&ctx);
	test_imap_client_hibernate_nonidle_no_mailbox(&ctx);
	test_imap_client_hibernate_nonidle_mailbox(&ctx);

	i_close_fd(&ctx.fd_listen);
	mail_storage_service_deinit(&storage_service);
}

struct test_service_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) services;
};

static const struct setting_define test_service_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = "service",
	  .offset = offsetof(struct test_service_settings, services) },
	SETTING_DEFINE_LIST_END
};

static const struct setting_parser_info test_service_setting_parser_info = {
	.name = "test_service",

	.defines = test_service_setting_defines,

	.struct_size = sizeof(struct test_service_settings),
	.pool_offset1 = 1 + offsetof(struct test_service_settings, pool),
};

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_CONFIG_BUILTIN |
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_STD_CLIENT |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	int ret;

	master_service = master_service_init("test-imap-client-hibernate",
					     service_flags, &argc, &argv, "D");

	/* imap default settings use service/imap/imap_capability, so we need
	   to register "service" named list filter. */
	settings_info_register(&test_service_setting_parser_info);

	master_service_init_finish(master_service);

	test_dir_init("ich");
	test_subprocesses_init();

	static void (*const test_functions[])(void) = {
		test_imap_client_hibernate,
		NULL
	};
	ret = test_run(test_functions);

	master_service_deinit(&master_service);
	return ret;
}
