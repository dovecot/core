/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "network.h"
#include "istream.h"
#include "istream-dot.h"
#include "ostream.h"
#include "imap-util.h"
#include "dsync-worker.h"
#include "dsync-proxy.h"
#include "dsync-proxy-server.h"

#include <stdlib.h>

#define OUTBUF_THROTTLE_SIZE (1024*64)

static bool
proxy_server_is_output_full(struct dsync_proxy_server *server)
{
	return o_stream_get_buffer_used_size(server->output) >=
		OUTBUF_THROTTLE_SIZE;
}

static int
cmd_box_list(struct dsync_proxy_server *server,
	     const char *const *args ATTR_UNUSED)
{
	struct dsync_mailbox dsync_box;
	string_t *str;
	int ret;

	if (server->mailbox_iter == NULL) {
		server->mailbox_iter =
			dsync_worker_mailbox_iter_init(server->worker);
	}

	str = t_str_new(256);
	while ((ret = dsync_worker_mailbox_iter_next(server->mailbox_iter,
						     &dsync_box)) > 0) {
		str_truncate(str, 0);
		dsync_proxy_mailbox_export(str, &dsync_box);
		str_append_c(str, '\n');
		o_stream_send(server->output, str_data(str), str_len(str));
		if (proxy_server_is_output_full(server))
			break;
	}
	if (ret >= 0) {
		/* continue later */
		return 0;
	}
	if (dsync_worker_mailbox_iter_deinit(&server->mailbox_iter) < 0) {
		o_stream_send(server->output, "\t-1\n", 4);
		return -1;
	} else {
		o_stream_send(server->output, "\t0\n", 3);
		return 1;
	}
}

static int
cmd_msg_list_init(struct dsync_proxy_server *server, const char *const *args)
{
	mailbox_guid_t *mailboxes;
	unsigned int i, count;

	count = str_array_length(args);
	mailboxes = t_new(mailbox_guid_t, count);
	for (i = 0; i < count; i++) {
		if (dsync_proxy_mailbox_guid_import(args[i],
						    &mailboxes[i]) < 0) {
			i_error("msg-list: Invalid mailbox GUID '%s'", args[i]);
			return -1;
		}
	}
	server->msg_iter = dsync_worker_msg_iter_init(server->worker,
						      mailboxes, count);
	return 0;
}

static int
cmd_msg_list(struct dsync_proxy_server *server, const char *const *args)
{
	unsigned int mailbox_idx;
	struct dsync_message msg;
	string_t *str;
	int ret;

	if (server->msg_iter == NULL) {
		if (cmd_msg_list_init(server, args) < 0)
			return -1;
	}

	str = t_str_new(256);
	while ((ret = dsync_worker_msg_iter_next(server->msg_iter,
						 &mailbox_idx, &msg)) > 0) {
		str_truncate(str, 0);
		str_printfa(str, "%u\t", mailbox_idx);
		dsync_proxy_msg_export(str, &msg);
		str_append_c(str, '\n');
		o_stream_send(server->output, str_data(str), str_len(str));
		if (proxy_server_is_output_full(server))
			break;
	}
	if (ret >= 0) {
		/* continue later */
		return 0;
	}
	if (dsync_worker_msg_iter_deinit(&server->msg_iter) < 0) {
		o_stream_send(server->output, "\t-1\n", 4);
		return -1;
	} else {
		o_stream_send(server->output, "\t0\n", 3);
		return 1;
	}
}

static int
parse_box_args(const char *const *args, struct dsync_mailbox *dsync_box_r)
{
	if (args[0] == NULL)
		return -1;

	memset(dsync_box_r, 0, sizeof(*dsync_box_r));
	dsync_box_r->name = args[0];
	if (args[1] == NULL) {
		/* \noselect box */
		return 0;
	}

	/* guid uid_validity [uid_next highest_modseq] */
	if (dsync_proxy_mailbox_guid_import(args[1], &dsync_box_r->guid) < 0) {
		i_error("Invalid mailbox GUID '%s' (name: %s)",
			args[1], dsync_box_r->name);
		return -1;
	}

	if (args[2] == NULL)
		return -1;
	dsync_box_r->uid_validity = strtoul(args[2], NULL, 10);

	if (args[3] == NULL)
		return 0;
	dsync_box_r->uid_next = strtoul(args[3], NULL, 10);
	if (args[4] == NULL)
		return -1;
	dsync_box_r->highest_modseq = strtoull(args[4], NULL, 10);
	return 0;
}

static int
cmd_box_create(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_mailbox dsync_box;

	if (parse_box_args(args, &dsync_box) < 0)
		return -1;
	dsync_worker_create_mailbox(server->worker, &dsync_box);
	return 1;
}

static int
cmd_box_update(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_mailbox dsync_box;

	if (parse_box_args(args, &dsync_box) < 0)
		return -1;
	dsync_worker_update_mailbox(server->worker, &dsync_box);
	return 1;
}

static int
cmd_box_select(struct dsync_proxy_server *server, const char *const *args)
{
	mailbox_guid_t guid;

	if (args[0] == NULL ||
	    dsync_proxy_mailbox_guid_import(args[0], &guid) < 0) {
		i_error("box-select: Invalid mailbox GUID '%s'", args[0]);
		return -1;
	}

	dsync_worker_select_mailbox(server->worker, &guid);
	return 1;
}

static int
cmd_msg_update(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_message msg;

	/* uid modseq flags */
	if (str_array_length(args) < 3)
		return -1;

	memset(&msg, 0, sizeof(msg));
	msg.uid = strtoul(args[0], NULL, 10);
	msg.modseq = strtoull(args[1], NULL, 10);
	if (dsync_proxy_msg_parse_flags(pool_datastack_create(),
					args[2], &msg) < 0)
		return -1;

	dsync_worker_msg_update_metadata(server->worker, &msg);
	return 1;
}

static int
cmd_msg_uid_change(struct dsync_proxy_server *server, const char *const *args)
{
	if (args[0] == NULL)
		return -1;

	dsync_worker_msg_update_uid(server->worker, strtoul(args[0], NULL, 10));
	return 1;
}

static int
cmd_msg_expunge(struct dsync_proxy_server *server, const char *const *args)
{
	if (args[0] == NULL)
		return -1;

	dsync_worker_msg_expunge(server->worker, strtoul(args[0], NULL, 10));
	return 1;
}

static int
cmd_msg_copy(struct dsync_proxy_server *server, const char *const *args)
{
	mailbox_guid_t src_mailbox_guid;
	uint32_t src_uid;
	struct dsync_message msg;
	const char *error;

	/* src_mailbox_guid src_uid <message> */
	if (str_array_length(args) < 3)
		return -1;

	if (dsync_proxy_mailbox_guid_import(args[0], &src_mailbox_guid) < 0) {
		i_error("msg-copy: Invalid mailbox GUID '%s'", args[0]);
		return -1;
	}
	src_uid = strtoul(args[1], NULL, 10);

	if (dsync_proxy_msg_import_unescaped(pool_datastack_create(),
					     &msg, args+2, &error) < 0)
		i_error("Invalid message input: %s", error);

	dsync_worker_msg_copy(server->worker, &src_mailbox_guid, src_uid, &msg);
	return 1;
}

static int
cmd_msg_save(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_message msg;
	struct dsync_msg_static_data data;
	const char *error;

	/* received_date pop3_uidl <message> */
	if (str_array_length(args) < 3)
		return -1;

	memset(&data, 0, sizeof(data));
	data.received_date = strtoul(args[0], NULL, 10);
	data.pop3_uidl = args[1];
	data.input = i_stream_create_dot(server->input, FALSE);

	if (dsync_proxy_msg_import_unescaped(pool_datastack_create(),
					     &msg, args+2, &error) < 0)
		i_error("Invalid message input: %s", error);

	/* we rely on save reading the entire input */
	net_set_nonblock(server->fd_in, FALSE);
	dsync_worker_msg_save(server->worker, &msg, &data);
	net_set_nonblock(server->fd_in, TRUE);
	i_assert(data.input->eof);
	i_stream_destroy(&data.input);
	return 1;
}

static struct dsync_proxy_server_command commands[] = {
	{ "BOX-LIST", cmd_box_list },
	{ "MSG-LIST", cmd_msg_list },
	{ "BOX-CREATE", cmd_box_create },
	{ "BOX-UPDATE", cmd_box_update },
	{ "BOX-SELECT", cmd_box_select },
	{ "MSG-UPDATE", cmd_msg_update },
	{ "MSG-UID-CHANGE", cmd_msg_uid_change },
	{ "MSG-EXPUNGE", cmd_msg_expunge },
	{ "MSG-COPY", cmd_msg_copy },
	{ "MSG-SAVE", cmd_msg_save },
	{ NULL, NULL }
};

struct dsync_proxy_server_command *
dsync_proxy_server_command_find(const char *name)
{
	unsigned int i;

	for (i = 0; commands[i].name != NULL; i++) {
		if (strcasecmp(commands[i].name, name) == 0)
			return &commands[i];
	}
	return NULL;
}
