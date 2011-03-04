/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "network.h"
#include "istream.h"
#include "istream-dot.h"
#include "ostream.h"
#include "imap-util.h"
#include "master-service.h"
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
		o_stream_set_flush_pending(server->output, TRUE);
		return 0;
	}
	if (dsync_worker_mailbox_iter_deinit(&server->mailbox_iter) < 0) {
		o_stream_send(server->output, "-\n", 2);
		return -1;
	} else {
		o_stream_send(server->output, "+\n", 2);
		return 1;
	}
}

static bool cmd_subs_list_subscriptions(struct dsync_proxy_server *server)
{
	struct dsync_worker_subscription rec;
	string_t *str;
	int ret;

	str = t_str_new(256);
	while ((ret = dsync_worker_subs_iter_next(server->subs_iter,
						  &rec)) > 0) {
		str_truncate(str, 0);
		str_tabescape_write(str, rec.vname);
		str_append_c(str, '\t');
		str_tabescape_write(str, rec.storage_name);
		str_append_c(str, '\t');
		str_tabescape_write(str, rec.ns_prefix);
		str_printfa(str, "\t%ld\n", (long)rec.last_change);
		o_stream_send(server->output, str_data(str), str_len(str));
		if (proxy_server_is_output_full(server))
			break;
	}
	if (ret >= 0) {
		/* continue later */
		o_stream_set_flush_pending(server->output, TRUE);
		return FALSE;
	}
	return TRUE;
}

static bool cmd_subs_list_unsubscriptions(struct dsync_proxy_server *server)
{
	struct dsync_worker_unsubscription rec;
	string_t *str;
	int ret;

	str = t_str_new(256);
	while ((ret = dsync_worker_subs_iter_next_un(server->subs_iter,
						     &rec)) > 0) {
		str_truncate(str, 0);
		dsync_proxy_mailbox_guid_export(str, &rec.name_sha1);
		str_append_c(str, '\t');
		str_tabescape_write(str, rec.ns_prefix);
		str_printfa(str, "\t%ld\n", (long)rec.last_change);
		o_stream_send(server->output, str_data(str), str_len(str));
		if (proxy_server_is_output_full(server))
			break;
	}
	if (ret >= 0) {
		/* continue later */
		o_stream_set_flush_pending(server->output, TRUE);
		return FALSE;
	}
	return TRUE;
}

static int
cmd_subs_list(struct dsync_proxy_server *server,
	      const char *const *args ATTR_UNUSED)
{
	if (server->subs_iter == NULL) {
		server->subs_iter =
			dsync_worker_subs_iter_init(server->worker);
	}

	if (!server->subs_sending_unsubscriptions) {
		if (!cmd_subs_list_subscriptions(server))
			return 0;
		/* a bit hacky way to handle this. this assumes that caller
		   goes through all subscriptions first, and next starts
		   going through unsubscriptions */
		o_stream_send(server->output, "+\n", 2);
		server->subs_sending_unsubscriptions = TRUE;
	}
	if (!cmd_subs_list_unsubscriptions(server))
		return 0;

	server->subs_sending_unsubscriptions = FALSE;
	if (dsync_worker_subs_iter_deinit(&server->subs_iter) < 0) {
		o_stream_send(server->output, "-\n", 2);
		return -1;
	} else {
		o_stream_send(server->output, "+\n", 2);
		return 1;
	}
}

static int
cmd_subs_set(struct dsync_proxy_server *server, const char *const *args)
{
	if (str_array_length(args) < 3) {
		i_error("subs-set: Missing parameters");
		return -1;
	}

	dsync_worker_set_subscribed(server->worker, args[0],
				    strtoul(args[1], NULL, 10),
				    strcmp(args[2], "1") == 0);
	return 1;
}

static int
cmd_msg_list_init(struct dsync_proxy_server *server, const char *const *args)
{
	mailbox_guid_t *mailboxes;
	unsigned int i, count;
	int ret;

	count = str_array_length(args);
	mailboxes = count == 0 ? NULL : t_new(mailbox_guid_t, count);
	for (i = 0; i < count; i++) {
		T_BEGIN {
			ret = dsync_proxy_mailbox_guid_import(args[i],
							      &mailboxes[i]);
		} T_END;

		if (ret < 0) {
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
		o_stream_set_flush_pending(server->output, TRUE);
		return 0;
	}
	if (dsync_worker_msg_iter_deinit(&server->msg_iter) < 0) {
		o_stream_send(server->output, "-\n", 2);
		return -1;
	} else {
		o_stream_send(server->output, "+\n", 2);
		return 1;
	}
}

static int
cmd_box_create(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_mailbox dsync_box;
	const char *error;

	if (dsync_proxy_mailbox_import_unescaped(pool_datastack_create(),
						 args, &dsync_box,
						 &error) < 0) {
		i_error("Invalid mailbox input: %s", error);
		return -1;
	}
	dsync_worker_create_mailbox(server->worker, &dsync_box);
	return 1;
}

static int
cmd_box_delete(struct dsync_proxy_server *server, const char *const *args)
{
	mailbox_guid_t guid;
	struct dsync_mailbox dsync_box;

	if (str_array_length(args) < 2)
		return -1;
	if (dsync_proxy_mailbox_guid_import(args[0], &guid) < 0) {
		i_error("box-delete: Invalid mailbox GUID '%s'", args[0]);
		return -1;
	}

	memset(&dsync_box, 0, sizeof(dsync_box));
	dsync_box.mailbox_guid = guid;
	dsync_box.last_change = strtoul(args[1], NULL, 10);
	dsync_worker_delete_mailbox(server->worker, &dsync_box);
	return 1;
}

static int
cmd_dir_delete(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_mailbox dsync_box;

	if (str_array_length(args) < 2)
		return -1;

	memset(&dsync_box, 0, sizeof(dsync_box));
	dsync_box.name = str_tabunescape(t_strdup_noconst(args[0]));
	dsync_box.last_change = strtoul(args[1], NULL, 10);
	dsync_worker_delete_dir(server->worker, &dsync_box);
	return 1;
}

static int
cmd_box_rename(struct dsync_proxy_server *server, const char *const *args)
{
	mailbox_guid_t guid;
	struct dsync_mailbox dsync_box;

	if (str_array_length(args) < 3)
		return -1;
	if (dsync_proxy_mailbox_guid_import(args[0], &guid) < 0) {
		i_error("box-delete: Invalid mailbox GUID '%s'", args[0]);
		return -1;
	}

	memset(&dsync_box, 0, sizeof(dsync_box));
	dsync_box.name = args[1];
	dsync_box.name_sep = args[2][0];
	dsync_worker_rename_mailbox(server->worker, &guid, &dsync_box);
	return 1;
}

static int
cmd_box_update(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_mailbox dsync_box;
	const char *error;

	if (dsync_proxy_mailbox_import_unescaped(pool_datastack_create(),
						 args, &dsync_box,
						 &error) < 0) {
		i_error("Invalid mailbox input: %s", error);
		return -1;
	}
	dsync_worker_update_mailbox(server->worker, &dsync_box);
	return 1;
}

static int
cmd_box_select(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_mailbox box;
	unsigned int i, count;

	memset(&box, 0, sizeof(box));
	if (args[0] == NULL ||
	    dsync_proxy_mailbox_guid_import(args[0], &box.mailbox_guid) < 0) {
		i_error("box-select: Invalid mailbox GUID '%s'", args[0]);
		return -1;
	}
	args++;

	count = str_array_length(args);
	t_array_init(&box.cache_fields, count + 1);
	for (i = 0; i < count; i++)
		array_append(&box.cache_fields, &args[i], 1);
	dsync_worker_select_mailbox(server->worker, &box);
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
	if (args[0] == NULL || args[1] == NULL)
		return -1;

	dsync_worker_msg_update_uid(server->worker,
				    strtoul(args[0], NULL, 10),
				    strtoul(args[1], NULL, 10));
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

static void copy_callback(bool success, void *context)
{
	struct dsync_proxy_server *server = context;
	const char *reply;

	i_assert(server->copy_uid != 0);

	reply = t_strdup_printf("%d\t%u\n", success ? 1 : 0, server->copy_uid);
	o_stream_send_str(server->output, reply);
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
					     args + 2, &msg, &error) < 0)
		i_error("Invalid message input: %s", error);

	server->copy_uid = src_uid;
	dsync_worker_msg_copy(server->worker, &src_mailbox_guid, src_uid, &msg,
			      copy_callback, server);
	server->copy_uid = 0;
	return 1;
}

static void cmd_msg_save_callback(void *context)
{
	struct dsync_proxy_server *server = context;

	server->save_finished = TRUE;
}

static int
cmd_msg_save(struct dsync_proxy_server *server, const char *const *args)
{
	struct dsync_message msg;
	struct dsync_msg_static_data data;
	const char *error;
	int ret;

	if (dsync_proxy_msg_static_import_unescaped(pool_datastack_create(),
						    args, &data, &error) < 0) {
		i_error("Invalid message input: %s", error);
		return -1;
	}
	data.input = i_stream_create_dot(server->input, FALSE);

	if (dsync_proxy_msg_import_unescaped(pool_datastack_create(),
					     args + 2, &msg, &error) < 0) {
		i_error("Invalid message input: %s", error);
		return -1;
	}

	/* we rely on save reading the entire input */
	server->save_finished = FALSE;
	net_set_nonblock(server->fd_in, FALSE);
	dsync_worker_msg_save(server->worker, &msg, &data,
			      cmd_msg_save_callback, server);
	net_set_nonblock(server->fd_in, TRUE);
	ret = dsync_worker_has_failed(server->worker) ? -1 : 1;
	i_assert(server->save_finished);
	i_assert(data.input->eof || ret < 0);
	i_stream_destroy(&data.input);
	return ret;
}

static void cmd_msg_get_send_more(struct dsync_proxy_server *server)
{
	const unsigned char *data;
	size_t size;
	int ret;

	while (!proxy_server_is_output_full(server)) {
		ret = i_stream_read_data(server->get_input, &data, &size, 0);
		if (ret == -1) {
			/* done */
			o_stream_send(server->output, "\n.\n", 3);
			i_stream_unref(&server->get_input);
			return;
		} else {
			/* for now we assume input is blocking */
			i_assert(ret != 0);
		}

		dsync_proxy_send_dot_output(server->output,
					    &server->get_input_last_lf,
					    data, size);
		i_stream_skip(server->get_input, size);
	}
	o_stream_set_flush_pending(server->output, TRUE);
}

static void
cmd_msg_get_callback(enum dsync_msg_get_result result,
		     const struct dsync_msg_static_data *data, void *context)
{
	struct dsync_proxy_server *server = context;
	string_t *str;

	i_assert(server->get_uid != 0);

	switch (result) {
	case DSYNC_MSG_GET_RESULT_SUCCESS:
		break;
	case DSYNC_MSG_GET_RESULT_EXPUNGED:
		o_stream_send(server->output, "0\n", 3);
		return;
	case DSYNC_MSG_GET_RESULT_FAILED:
		o_stream_send(server->output, "-\n", 3);
		return;
	}

	str = t_str_new(128);
	str_printfa(str, "1\t%u\t", server->get_uid);
	dsync_proxy_msg_static_export(str, data);
	str_append_c(str, '\n');
	o_stream_send(server->output, str_data(str), str_len(str));

	/* then we'll still have to send the message body. */
	server->get_input = data->input;
	cmd_msg_get_send_more(server);
	if (server->get_input == NULL) {
		/* if we came here from ioloop, make sure the command gets
		   freed in the output flush callback */
		o_stream_set_flush_pending(server->output, TRUE);
	}
}

static int
cmd_msg_get(struct dsync_proxy_server *server, const char *const *args)
{
	mailbox_guid_t mailbox_guid;
	uint32_t uid;

	if (str_array_length(args) < 2)
		return -1;

	if (dsync_proxy_mailbox_guid_import(args[0], &mailbox_guid) < 0) {
		i_error("msg-get: Invalid mailbox GUID '%s'", args[0]);
		return -1;
	}

	uid = strtoul(args[1], NULL, 10);
	if (uid == 0)
		return -1;

	if (server->get_input != NULL) {
		i_assert(server->get_uid == uid);
		cmd_msg_get_send_more(server);
	} else {
		server->get_uid = uid;
		dsync_worker_msg_get(server->worker, &mailbox_guid, uid,
				     cmd_msg_get_callback, server);
	}
	if (server->get_input != NULL)
		return 0;
	server->get_uid = 0;
	return 1;
}

static void cmd_finish_callback(bool success, void *context)
{
	struct dsync_proxy_server *server = context;
	const char *reply;

	if (!success)
		reply = "fail\n";
	else if (dsync_worker_has_unexpected_changes(server->worker))
		reply = "changes\n";
	else
		reply = "ok\n";

	server->finished = TRUE;
	o_stream_send_str(server->output, reply);
}

static int
cmd_finish(struct dsync_proxy_server *server,
	   const char *const *args ATTR_UNUSED)
{
	dsync_worker_finish(server->worker, cmd_finish_callback, server);
	return 1;
}

static struct dsync_proxy_server_command commands[] = {
	{ "BOX-LIST", cmd_box_list },
	{ "SUBS-LIST", cmd_subs_list },
	{ "SUBS-SET", cmd_subs_set },
	{ "MSG-LIST", cmd_msg_list },
	{ "BOX-CREATE", cmd_box_create },
	{ "BOX-DELETE", cmd_box_delete },
	{ "DIR-DELETE", cmd_dir_delete },
	{ "BOX-RENAME", cmd_box_rename },
	{ "BOX-UPDATE", cmd_box_update },
	{ "BOX-SELECT", cmd_box_select },
	{ "MSG-UPDATE", cmd_msg_update },
	{ "MSG-UID-CHANGE", cmd_msg_uid_change },
	{ "MSG-EXPUNGE", cmd_msg_expunge },
	{ "MSG-COPY", cmd_msg_copy },
	{ "MSG-SAVE", cmd_msg_save },
	{ "MSG-GET", cmd_msg_get },
	{ "FINISH", cmd_finish },
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
