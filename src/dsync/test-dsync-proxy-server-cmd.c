/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"
#include "test-common.h"
#include "dsync-proxy-server.h"
#include "test-dsync-worker.h"
#include "test-dsync-common.h"

#define ALL_MAIL_FLAGS "\\Answered \\Flagged \\Deleted \\Seen \\Draft \\Recent"

struct master_service *master_service;
static string_t *out;
static struct dsync_proxy_server *server;
static struct test_dsync_worker *test_worker;
static struct dsync_proxy_server_command *cur_cmd;
static const char *cur_cmd_args[20];

void master_service_stop(struct master_service *service ATTR_UNUSED) {}

static void out_clear(void)
{
	o_stream_seek(server->output, 0);
	str_truncate(out, 0);
}

static int run_more(void)
{
	int ret;

	ret = cur_cmd->func(server, cur_cmd_args);
	if (ret == 0)
		return 0;

	cur_cmd = NULL;
	return ret;
}

static int ATTR_SENTINEL
run_cmd(const char *cmd_name, ...)
{
	va_list va;
	const char *str;
	unsigned int i = 0;

	i_assert(cur_cmd == NULL);

	va_start(va, cmd_name);
	while ((str = va_arg(va, const char *)) != NULL) {
		i_assert(i < N_ELEMENTS(cur_cmd_args)+1);
		cur_cmd_args[i++] = str;
	}
	cur_cmd_args[i] = NULL;
	va_end(va);

	cur_cmd = dsync_proxy_server_command_find(cmd_name);
	i_assert(cur_cmd != NULL);
	return run_more();
}

static void test_dsync_proxy_box_list(void)
{
	struct dsync_mailbox box;

	test_begin("proxy server box list");

	test_assert(run_cmd("BOX-LIST", NULL) == 0);

	/* \noselect mailbox */
	memset(&box, 0, sizeof(box));
	box.name = "\t\001\r\nname\t\001\n\r";
	box.name_sep = '/';
	box.last_change = 992;
	box.flags = DSYNC_MAILBOX_FLAG_NOSELECT;
	test_worker->box_iter.next_box = &box;
	test_assert(run_more() == 0);
	test_assert(strcmp(str_c(out), t_strconcat(str_tabescape(box.name),
		"\t/\t992\t1\n", NULL)) == 0);
	out_clear();

	/* selectable mailbox */
	memset(&box, 0, sizeof(box));
	box.name = "foo/bar";
	box.name_sep = '/';
	memcpy(box.mailbox_guid.guid, test_mailbox_guid1, MAIL_GUID_128_SIZE);
	box.uid_validity = 4275878552;
	box.uid_next = 4023233417;
	box.message_count = 4525;
	box.highest_modseq = 18080787909545915012ULL;
	box.first_recent_uid = 353;
	test_worker->box_iter.next_box = &box;

	test_assert(run_more() == 0);

	test_assert(strcmp(str_c(out), "foo/bar\t/\t0\t0\t"
			   TEST_MAILBOX_GUID1"\t"
			   "4275878552\t"
			   "4023233417\t"
			   "4525\t"
			   "18080787909545915012\t"
			   "353\n") == 0);
	out_clear();

	/* last mailbox */
	test_worker->box_iter.last = TRUE;
	test_assert(run_more() == 1);
	test_assert(strcmp(str_c(out), "+\n") == 0);
	out_clear();

	test_end();
}

static void test_dsync_proxy_subs_list(void)
{
	const char *name;
	struct dsync_worker_subscription subs;
	struct dsync_worker_unsubscription unsubs;

	test_begin("proxy server subs list");

	test_assert(run_cmd("SUBS-LIST", NULL) == 0);

	/* subscription */
	name = "\t\001\r\nname\t\001\n\r";
	subs.vname = name;
	subs.storage_name = "\tstorage_name\n";
	subs.last_change = 1234567890;
	subs.ns_prefix = "\t\001\r\nprefix\t\001\n\r";
	test_worker->subs_iter.next_subscription = &subs;
	test_assert(run_more() == 0);
	test_assert(strcmp(str_c(out), t_strconcat(
		str_tabescape(name), "\t",
		str_tabescape(subs.storage_name), "\t",
		str_tabescape(subs.ns_prefix),
		"\t1234567890\n", NULL)) == 0);
	out_clear();

	test_worker->subs_iter.last_subs = TRUE;
	test_assert(run_more() == 0);
	test_assert(strcmp(str_c(out), "+\n") == 0);
	out_clear();

	/* unsubscription */
	memcpy(unsubs.name_sha1.guid, test_mailbox_guid1,
	       sizeof(unsubs.name_sha1.guid));
	unsubs.ns_prefix = "\t\001\r\nprefix2\t\001\n\r";
	unsubs.last_change = 987654321;
	test_worker->subs_iter.next_unsubscription = &unsubs;
	test_assert(run_more() == 0);
	test_assert(strcmp(str_c(out), t_strconcat(TEST_MAILBOX_GUID1, "\t",
		str_tabescape(unsubs.ns_prefix), "\t987654321\n", NULL)) == 0);
	out_clear();

	test_worker->subs_iter.last_unsubs = TRUE;
	test_assert(run_more() == 1);
	test_assert(strcmp(str_c(out), "+\n") == 0);
	out_clear();

	test_end();
}

static void test_dsync_proxy_msg_list(void)
{
	static const char *test_keywords[] = {
		"kw1", "kw2", NULL
	};
	struct dsync_message msg;
	struct test_dsync_worker_msg test_msg;

	test_begin("proxy server msg list");

	test_assert(run_cmd("MSG-LIST", TEST_MAILBOX_GUID1, TEST_MAILBOX_GUID2, NULL) == 0);

	memset(&msg, 0, sizeof(msg));
	msg.guid = "\t\001\r\nguid\t\001\n\r";
	msg.uid = 123;
	msg.modseq = 98765432101234;
	msg.save_date = 1234567890;

	/* no flags */
	test_msg.msg = msg;
	test_msg.mailbox_idx = 98;
	array_append(&test_worker->msg_iter.msgs, &test_msg, 1);
	test_assert(run_more() == 0);
	test_assert(strcmp(str_c(out), t_strconcat(
		"98\t", str_tabescape(msg.guid),
		"\t123\t98765432101234\t\t1234567890\n", NULL)) == 0);
	out_clear();

	/* all flags, some keywords */
	msg.modseq = 1;
	msg.save_date = 2;
	msg.guid = "guid";
	msg.flags = MAIL_FLAGS_MASK;
	msg.keywords = test_keywords;
	test_msg.msg = msg;
	test_msg.mailbox_idx = 76;
	array_append(&test_worker->msg_iter.msgs, &test_msg, 1);
	test_assert(run_more() == 0);
	test_assert(strcmp(str_c(out), "76\tguid\t123\t1\t"
			   ALL_MAIL_FLAGS" kw1 kw2\t2\n") == 0);
	out_clear();

	/* last message */
	test_worker->msg_iter.last = TRUE;
	test_assert(run_more() == 1);
	test_assert(strcmp(str_c(out), "+\n") == 0);
	out_clear();

	test_end();
}

static void test_dsync_proxy_box_create(void)
{
	struct test_dsync_box_event event;

	test_begin("proxy server box create");

	test_assert(run_cmd("BOX-CREATE", "noselect", "/",
			    "553", "1", NULL) == 1);
	test_assert(test_dsync_worker_next_box_event(test_worker, &event));
	test_assert(event.type == LAST_BOX_TYPE_CREATE);
	test_assert(strcmp(event.box.name, "noselect") == 0);
	test_assert(event.box.name_sep == '/');
	test_assert(event.box.last_change == 553);
	test_assert(event.box.flags == DSYNC_MAILBOX_FLAG_NOSELECT);
	test_assert(event.box.uid_validity == 0);

	test_assert(run_cmd("BOX-CREATE", "selectable", "?",
			    "61", "2", TEST_MAILBOX_GUID2, "1234567890", "9876",
			    "4610", "28427847284728", "853", NULL) == 1);
	test_assert(test_dsync_worker_next_box_event(test_worker, &event));
	test_assert(event.type == LAST_BOX_TYPE_CREATE);
	test_assert(strcmp(event.box.name, "selectable") == 0);
	test_assert(event.box.name_sep == '?');
	test_assert(memcmp(event.box.mailbox_guid.guid, test_mailbox_guid2, MAIL_GUID_128_SIZE) == 0);
	test_assert(event.box.flags == 2);
	test_assert(event.box.uid_validity == 1234567890);
	test_assert(event.box.uid_next == 9876);
	test_assert(event.box.message_count == 4610);
	test_assert(event.box.highest_modseq == 28427847284728);
	test_assert(event.box.first_recent_uid == 853);
	test_assert(event.box.last_change == 61);

	test_end();
}

static void test_dsync_proxy_box_delete(void)
{
	struct test_dsync_box_event event;

	test_begin("proxy server box delete");

	test_assert(run_cmd("BOX-DELETE", TEST_MAILBOX_GUID1, "4351", NULL) == 1);
	test_assert(test_dsync_worker_next_box_event(test_worker, &event));
	test_assert(event.type == LAST_BOX_TYPE_DELETE);
	test_assert(memcmp(event.box.mailbox_guid.guid, test_mailbox_guid1, MAIL_GUID_128_SIZE) == 0);
	test_assert(event.box.last_change == 4351);

	test_assert(run_cmd("BOX-DELETE", TEST_MAILBOX_GUID2, "653", NULL) == 1);
	test_assert(test_dsync_worker_next_box_event(test_worker, &event));
	test_assert(event.type == LAST_BOX_TYPE_DELETE);
	test_assert(memcmp(event.box.mailbox_guid.guid, test_mailbox_guid2, MAIL_GUID_128_SIZE) == 0);
	test_assert(event.box.last_change == 653);

	test_end();
}

static void test_dsync_proxy_box_rename(void)
{
	struct test_dsync_box_event event;

	test_begin("proxy server box rename");

	test_assert(run_cmd("BOX-RENAME", TEST_MAILBOX_GUID1, "name\t1", "/", NULL) == 1);
	test_assert(test_dsync_worker_next_box_event(test_worker, &event));
	test_assert(event.type == LAST_BOX_TYPE_RENAME);
	test_assert(memcmp(event.box.mailbox_guid.guid, test_mailbox_guid1, MAIL_GUID_128_SIZE) == 0);
	test_assert(strcmp(event.box.name, "name\t1") == 0);
	test_assert(event.box.name_sep == '/');

	test_assert(run_cmd("BOX-RENAME", TEST_MAILBOX_GUID2, "", "?", NULL) == 1);
	test_assert(test_dsync_worker_next_box_event(test_worker, &event));
	test_assert(event.type == LAST_BOX_TYPE_RENAME);
	test_assert(memcmp(event.box.mailbox_guid.guid, test_mailbox_guid2, MAIL_GUID_128_SIZE) == 0);
	test_assert(strcmp(event.box.name, "") == 0);
	test_assert(event.box.name_sep == '?');

	test_end();
}

static void test_dsync_proxy_box_update(void)
{
	struct test_dsync_box_event event;

	test_begin("proxy server box update");

	test_assert(run_cmd("BOX-UPDATE", "updated", "/",
			    "53", "2", TEST_MAILBOX_GUID1, "34343", "22",
			    "58293", "2238427847284728", "2482", NULL) == 1);
	test_assert(test_dsync_worker_next_box_event(test_worker, &event));
	test_assert(event.type == LAST_BOX_TYPE_UPDATE);
	test_assert(strcmp(event.box.name, "updated") == 0);
	test_assert(event.box.name_sep == '/');
	test_assert(memcmp(event.box.mailbox_guid.guid, test_mailbox_guid1, MAIL_GUID_128_SIZE) == 0);
	test_assert(event.box.flags == DSYNC_MAILBOX_FLAG_DELETED_MAILBOX);
	test_assert(event.box.uid_validity == 34343);
	test_assert(event.box.uid_next == 22);
	test_assert(event.box.message_count == 58293);
	test_assert(event.box.highest_modseq == 2238427847284728);
	test_assert(event.box.first_recent_uid == 2482);
	test_assert(event.box.last_change == 53);

	test_end();
}

static void test_dsync_proxy_box_select(void)
{
	test_begin("proxy server box select");

	test_assert(run_cmd("BOX-SELECT", TEST_MAILBOX_GUID1, NULL) == 1);
	test_assert(memcmp(test_worker->selected_mailbox.guid, test_mailbox_guid1, MAIL_GUID_128_SIZE) == 0);

	test_assert(run_cmd("BOX-SELECT", TEST_MAILBOX_GUID2, NULL) == 1);
	test_assert(memcmp(test_worker->selected_mailbox.guid, test_mailbox_guid2, MAIL_GUID_128_SIZE) == 0);

	test_end();
}

static void test_dsync_proxy_msg_update(void)
{
	struct test_dsync_msg_event event;

	test_begin("proxy server msg update");

	test_assert(run_cmd("MSG-UPDATE", "123", "4782782842924",
			    "kw1 "ALL_MAIL_FLAGS" kw2", NULL) == 1);
	test_assert(test_dsync_worker_next_msg_event(test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(event.msg.uid == 123);
	test_assert(event.msg.modseq == 4782782842924);
	test_assert(event.msg.flags == MAIL_FLAGS_MASK);
	test_assert(strcmp(event.msg.keywords[0], "kw1") == 0);
	test_assert(strcmp(event.msg.keywords[1], "kw2") == 0);
	test_assert(event.msg.keywords[2] == NULL);

	test_end();
}

static void test_dsync_proxy_msg_uid_change(void)
{
	struct test_dsync_msg_event event;

	test_begin("proxy server msg uid change");

	test_assert(run_cmd("MSG-UID-CHANGE", "454", "995", NULL) == 1);
	test_assert(test_dsync_worker_next_msg_event(test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_UPDATE_UID);
	test_assert(event.msg.uid == 454);
	test_assert(event.msg.modseq == 995);

	test_end();
}

static void test_dsync_proxy_msg_expunge(void)
{
	struct test_dsync_msg_event event;

	test_begin("proxy server msg expunge");

	test_assert(run_cmd("MSG-EXPUNGE", "8585", NULL) == 1);
	test_assert(test_dsync_worker_next_msg_event(test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_EXPUNGE);
	test_assert(event.msg.uid == 8585);

	test_end();
}

static void test_dsync_proxy_msg_copy(void)
{
	struct test_dsync_msg_event msg_event;

	test_begin("proxy server msg copy");

	test_assert(run_cmd("MSG-COPY", TEST_MAILBOX_GUID1, "5454",
			    "copyguid", "5678", "74782482882924", "\\Seen foo \\Draft",
			    "8294284", NULL) == 1);
	test_assert(test_dsync_worker_next_msg_event(test_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_COPY);
	test_assert(memcmp(msg_event.copy_src_mailbox.guid, test_mailbox_guid1, MAIL_GUID_128_SIZE) == 0);
	test_assert(msg_event.copy_src_uid == 5454);
	test_assert(strcmp(msg_event.msg.guid, "copyguid") == 0);
	test_assert(msg_event.msg.uid == 5678);
	test_assert(msg_event.msg.modseq == 74782482882924);
	test_assert(msg_event.msg.flags == (MAIL_SEEN | MAIL_DRAFT));
	test_assert(strcmp(msg_event.msg.keywords[0], "foo") == 0);
	test_assert(msg_event.msg.keywords[1] == NULL);
	test_assert(msg_event.msg.save_date == 8294284);

	test_end();
}

static void test_dsync_proxy_msg_save(void)
{
	static const char *input = "..dotty\n..behavior\nfrom you\n.\nstop";
	struct test_dsync_msg_event event;
	const unsigned char *data;
	size_t size;

	test_begin("proxy server msg save");

	server->input = i_stream_create_from_data(input, strlen(input));

	test_assert(run_cmd("MSG-SAVE", "28492428", "pop3uidl",
			    "saveguid", "874", "33982482882924", "\\Flagged bar \\Answered",
			    "8294284", NULL) == 1);
	test_assert(test_dsync_worker_next_msg_event(test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_SAVE);
	test_assert(event.save_data.received_date == 28492428);
	test_assert(strcmp(event.save_data.pop3_uidl, "pop3uidl") == 0);
	test_assert(strcmp(event.save_body, ".dotty\n.behavior\nfrom you") == 0);

	test_assert(strcmp(event.msg.guid, "saveguid") == 0);
	test_assert(event.msg.uid == 874);
	test_assert(event.msg.modseq == 33982482882924);
	test_assert(event.msg.flags == (MAIL_FLAGGED | MAIL_ANSWERED));
	test_assert(strcmp(event.msg.keywords[0], "bar") == 0);
	test_assert(event.msg.keywords[1] == NULL);
	test_assert(event.msg.save_date == 8294284);

	data = i_stream_get_data(server->input, &size);
	test_assert(size == 4 && memcmp(data, "stop", 4) == 0);
	i_stream_destroy(&server->input);

	test_end();
}

static struct dsync_proxy_server *
dsync_proxy_server_init_test(buffer_t *outbuf)
{
	struct dsync_proxy_server *server;

	server = i_new(struct dsync_proxy_server, 1);
	server->worker = dsync_worker_init_test();
	server->fd_in = 0;
	server->fd_out = 0;

	server->cmd_pool = pool_alloconly_create("worker server cmd", 1024);
	server->output = o_stream_create_buffer(outbuf);
	return server;
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_dsync_proxy_box_list,
		test_dsync_proxy_subs_list,
		test_dsync_proxy_msg_list,
		test_dsync_proxy_box_create,
		test_dsync_proxy_box_delete,
		test_dsync_proxy_box_rename,
		test_dsync_proxy_box_update,
		test_dsync_proxy_box_select,
		test_dsync_proxy_msg_update,
		test_dsync_proxy_msg_uid_change,
		test_dsync_proxy_msg_expunge,
		test_dsync_proxy_msg_copy,
		test_dsync_proxy_msg_save,
		NULL
	};

	test_init();

	out = buffer_create_dynamic(default_pool, 1024);
	server = dsync_proxy_server_init_test(out);
	test_worker = (struct test_dsync_worker *)server->worker;

	test_run_funcs(test_functions);
	return test_deinit();
}
