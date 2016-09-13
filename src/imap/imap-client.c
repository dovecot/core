/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ioloop.h"
#include "llist.h"
#include "str.h"
#include "hostpid.h"
#include "net.h"
#include "iostream.h"
#include "iostream-rawlog.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "var-expand.h"
#include "master-service.h"
#include "imap-resp-code.h"
#include "imap-util.h"
#include "imap-urlauth.h"
#include "mail-error.h"
#include "mail-namespace.h"
#include "mail-storage-service.h"
#include "imap-state.h"
#include "imap-search.h"
#include "imap-notify.h"
#include "imap-commands.h"

#include <unistd.h>

extern struct mail_storage_callbacks mail_storage_callbacks;
extern struct imap_client_vfuncs imap_client_vfuncs;

struct imap_module_register imap_module_register = { 0 };

struct client *imap_clients = NULL;
unsigned int imap_client_count = 0;

static const char *client_command_state_names[CLIENT_COMMAND_STATE_DONE+1] = {
	"wait-input",
	"wait-output",
	"wait-external",
	"wait-unambiguity",
	"wait-sync",
	"done"
};

static void client_idle_timeout(struct client *client)
{
	if (client->output_cmd_lock == NULL)
		client_send_line(client, "* BYE Disconnected for inactivity.");
	client_destroy(client, "Disconnected for inactivity");
}

static void client_init_urlauth(struct client *client)
{
	struct imap_urlauth_config config;

	memset(&config, 0, sizeof(config));
	config.url_host = client->set->imap_urlauth_host;
	config.url_port = client->set->imap_urlauth_port;
	config.socket_path = t_strconcat(client->user->set->base_dir,
					 "/"IMAP_URLAUTH_SOCKET_NAME, NULL);
	config.session_id = client->session_id;
	config.access_anonymous = client->user->anonymous;
	config.access_user = client->user->username;

	client->urlauth_ctx = imap_urlauth_init(client->user, &config);
}

static bool user_has_special_use_mailboxes(struct mail_user *user)
{
	struct mail_namespace *ns;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->special_use_mailboxes)
			return TRUE;
	}
	return FALSE;
}

struct client *client_create(int fd_in, int fd_out, const char *session_id,
			     struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct imap_settings *set,
			     const struct lda_settings *lda_set)
{
	const struct mail_storage_settings *mail_set;
	struct client *client;
	const char *ident;
	pool_t pool;
	bool explicit_capability = FALSE;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	pool = pool_alloconly_create("imap client", 2048);
	client = p_new(pool, struct client, 1);
	client->pool = pool;
	client->v = imap_client_vfuncs;
	client->set = set;
	client->lda_set = lda_set;
	client->service_user = service_user;
	client->session_id = p_strdup(pool, session_id);
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->input = i_stream_create_fd(fd_in,
					   set->imap_max_line_length);
	client->output = o_stream_create_fd(fd_out, (size_t)-1);
	o_stream_set_no_error_handling(client->output, TRUE);
	i_stream_set_name(client->input, "<imap client>");
	o_stream_set_name(client->output, "<imap client>");

	o_stream_set_flush_callback(client->output, client_output, client);

	p_array_init(&client->module_contexts, client->pool, 5);
	client->io = io_add_istream(client->input, client_input, client);
        client->last_input = ioloop_time;
	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);

	client->command_pool =
		pool_alloconly_create(MEMPOOL_GROWING"client command", 1024*2);
	client->user = user;
	client->notify_count_changes = TRUE;
	client->notify_flag_changes = TRUE;

	if (set->rawlog_dir[0] != '\0') {
		(void)iostream_rawlog_create(set->rawlog_dir, &client->input,
					     &client->output);
	}

	mail_namespaces_set_storage_callbacks(user->namespaces,
					      &mail_storage_callbacks, client);

	client->capability_string =
		str_new(client->pool, sizeof(CAPABILITY_STRING)+64);

	if (*set->imap_capability == '\0')
		str_append(client->capability_string, CAPABILITY_STRING);
	else if (*set->imap_capability != '+') {
		explicit_capability = TRUE;
		str_append(client->capability_string, set->imap_capability);
	} else {
		str_append(client->capability_string, CAPABILITY_STRING);
		str_append_c(client->capability_string, ' ');
		str_append(client->capability_string, set->imap_capability + 1);
	}
	if (!explicit_capability) {
		if (client->set->imap_literal_minus)
			str_append(client->capability_string, " LITERAL-");
		else
			str_append(client->capability_string, " LITERAL+");
	}
	if (user->fuzzy_search && !explicit_capability) {
		/* Enable FUZZY capability only when it actually has
		   a chance of working */
		str_append(client->capability_string, " SEARCH=FUZZY");
	}

	mail_set = mail_user_set_get_storage_set(user);
	if (mail_set->mailbox_list_index && !explicit_capability) {
		/* NOTIFY is enabled only when mailbox list indexes are
		   enabled, although even that doesn't necessarily guarantee
		   it always */
		str_append(client->capability_string, " NOTIFY");
	}

	if (*set->imap_urlauth_host != '\0' &&
	    *mail_set->mail_attribute_dict != '\0') {
		/* Enable URLAUTH capability only when dict is
		   configured correctly */
		client_init_urlauth(client);
		if (!explicit_capability)
			str_append(client->capability_string, " URLAUTH URLAUTH=BINARY");
	}
	if (set->imap_metadata && *mail_set->mail_attribute_dict != '\0') {
		client->imap_metadata_enabled = TRUE;
		if (!explicit_capability)
			str_append(client->capability_string, " METADATA");
	}
	if (!explicit_capability && user_has_special_use_mailboxes(user)) {
		/* Advertise SPECIAL-USE only if there are actually some
		   SPECIAL-USE flags in mailbox configuration. */
		str_append(client->capability_string, " SPECIAL-USE");
	}

	ident = mail_user_get_anvil_userip_ident(client->user);
	if (ident != NULL) {
		master_service_anvil_send(master_service, t_strconcat(
			"CONNECT\t", my_pid, "\timap/", ident, "\n", NULL));
		client->anvil_sent = TRUE;
	}

	imap_client_count++;
	DLLIST_PREPEND(&imap_clients, client);
	if (hook_client_created != NULL)
		hook_client_created(&client);

	imap_refresh_proctitle();
	return client;
}

void client_command_cancel(struct client_command_context **_cmd)
{
	struct client_command_context *cmd = *_cmd;
	bool cmd_ret;

	switch (cmd->state) {
	case CLIENT_COMMAND_STATE_WAIT_INPUT:
		/* a bit kludgy check: cancel command only if it has context
		   set. currently only append command matches this check. all
		   other commands haven't even started the processing yet. */
		if (cmd->context == NULL)
			break;
		/* fall through */
	case CLIENT_COMMAND_STATE_WAIT_EXTERNAL:
	case CLIENT_COMMAND_STATE_WAIT_OUTPUT:
		cmd->cancel = TRUE;
		break;
	case CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY:
	case CLIENT_COMMAND_STATE_WAIT_SYNC:
		/* commands haven't started yet */
		break;
	case CLIENT_COMMAND_STATE_DONE:
		i_unreached();
	}

	cmd_ret = !cmd->cancel || cmd->func == NULL ? TRUE :
		command_exec(cmd);
	if (!cmd_ret) {
		if (cmd->client->output->closed)
			i_panic("command didn't cancel itself: %s", cmd->name);
	} else {
		client_command_free(*_cmd != NULL ? _cmd : &cmd);
	}
}

const char *client_stats(struct client *client)
{
	static struct var_expand_table static_tab[] = {
		{ 'i', NULL, "input" },
		{ 'o', NULL, "output" },
		{ '\0', NULL, "session" },
		{ '\0', NULL, "fetch_hdr_count" },
		{ '\0', NULL, "fetch_hdr_bytes" },
		{ '\0', NULL, "fetch_body_count" },
		{ '\0', NULL, "fetch_body_bytes" },
		{ '\0', NULL, "deleted" },
		{ '\0', NULL, "expunged" },
		{ '\0', NULL, "trashed" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	string_t *str;

	tab = t_malloc_no0(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = dec2str(i_stream_get_absolute_offset(client->input));
	tab[1].value = dec2str(client->output->offset);
	tab[2].value = client->session_id;
	tab[3].value = dec2str(client->fetch_hdr_count);
	tab[4].value = dec2str(client->fetch_hdr_bytes);
	tab[5].value = dec2str(client->fetch_body_count);
	tab[6].value = dec2str(client->fetch_body_bytes);
	tab[7].value = dec2str(client->deleted_count);
	tab[8].value = dec2str(client->expunged_count);
	tab[9].value = dec2str(client->trashed_count);

	str = t_str_new(128);
	var_expand(str, client->set->imap_logout_format, tab);
	return str_c(str);
}

void client_destroy(struct client *client, const char *reason)
{
	client->v.destroy(client, reason);
}

static const char *client_get_commands_status(struct client *client)
{
	struct client_command_context *cmd, *last_cmd = NULL;
	unsigned int msecs_in_ioloop;
	uint64_t running_usecs = 0, lock_wait_usecs = 0, ioloop_wait_usecs;
	unsigned long long bytes_in = 0, bytes_out = 0;
	string_t *str;
	enum io_condition cond;
	const char *cond_str;

	if (client->command_queue == NULL)
		return "";

	str = t_str_new(128);
	str_append(str, " (");
	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
		if (cmd->name == NULL) {
			/* (parts of a) tag were received, but not yet
			   the command name */
			continue;
		}
		str_append(str, cmd->name);
		if (cmd->next != NULL)
			str_append_c(str, ',');
		running_usecs += cmd->running_usecs;
		lock_wait_usecs += cmd->lock_wait_usecs;
		bytes_in += cmd->bytes_in;
		bytes_out += cmd->bytes_out;
		last_cmd = cmd;
	}
	if (last_cmd == NULL)
		return "";

	cond = io_loop_find_fd_conditions(current_ioloop, client->fd_out);
	if ((cond & (IO_READ | IO_WRITE)) == (IO_READ | IO_WRITE))
		cond_str = "input/output";
	else if ((cond & IO_READ) != 0)
		cond_str = "input";
	else if ((cond & IO_WRITE) != 0)
		cond_str = "output";
	else
		cond_str = "nothing";

	ioloop_wait_usecs = io_loop_get_wait_usecs(current_ioloop);
	msecs_in_ioloop = (ioloop_wait_usecs -
		last_cmd->start_ioloop_wait_usecs + 999) / 1000;
	str_printfa(str, " running for %d.%03d + waiting %s for %d.%03d secs",
		    (int)((running_usecs+999)/1000 / 1000),
		    (int)((running_usecs+999)/1000 % 1000), cond_str,
		    msecs_in_ioloop / 1000, msecs_in_ioloop % 1000);
	if (lock_wait_usecs > 0) {
		int lock_wait_msecs = (lock_wait_usecs+999)/1000;
		str_printfa(str, ", %d.%03d in locks",
			    lock_wait_msecs/1000, lock_wait_msecs%1000);
	}
	str_printfa(str, ", %llu B in + %llu+%"PRIuSIZE_T" B out, state=%s)",
		    bytes_in, bytes_out,
		    o_stream_get_buffer_used_size(client->output),
		    client_command_state_names[last_cmd->state]);
	return str_c(str);
}

static void client_log_disconnect(struct client *client, const char *reason)
{
	const char *cmd_status = "";

	if (reason == NULL) {
		reason = io_stream_get_disconnect_reason(client->input,
							 client->output);
		cmd_status = client_get_commands_status(client);
	}
	i_info("%s%s %s", reason, cmd_status, client_stats(client));
}

static void client_default_destroy(struct client *client, const char *reason)
{
	struct client_command_context *cmd;

	i_assert(!client->destroyed);
	client->destroyed = TRUE;

	if (!client->disconnected) {
		client->disconnected = TRUE;
		client_log_disconnect(client, reason);
	}

	i_stream_close(client->input);
	o_stream_close(client->output);

	/* finish off all the queued commands. */
	if (client->output_cmd_lock != NULL)
		client_command_cancel(&client->output_cmd_lock);
	while (client->command_queue != NULL) {
		cmd = client->command_queue;
		client_command_cancel(&cmd);
	}
	/* handle the input_lock command last. it might have been waiting on
	   other queued commands (although we probably should just drop the
	   command at that point since it hasn't started running. but this may
	   change in future). */
	if (client->input_lock != NULL)
		client_command_cancel(&client->input_lock);

	if (client->mailbox != NULL) {
		client_search_updates_free(client);
		mailbox_free(&client->mailbox);
	}
	if (client->notify_ctx != NULL)
		imap_notify_deinit(&client->notify_ctx);
	if (client->urlauth_ctx != NULL)
		imap_urlauth_deinit(&client->urlauth_ctx);
	if (client->anvil_sent) {
		master_service_anvil_send(master_service, t_strconcat(
			"DISCONNECT\t", my_pid, "\timap/",
			mail_user_get_anvil_userip_ident(client->user),
			"\n", NULL));
	}

	if (client->free_parser != NULL)
		imap_parser_unref(&client->free_parser);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to_idle_output != NULL)
		timeout_remove(&client->to_idle_output);
	if (client->to_delayed_input != NULL)
		timeout_remove(&client->to_delayed_input);
	timeout_remove(&client->to_idle);

	/* i/ostreams are already closed at this stage, so fd can be closed */
	net_disconnect(client->fd_in);
	if (client->fd_in != client->fd_out)
		net_disconnect(client->fd_out);

	/* Free the user after client is already disconnected. It may start
	   some background work like autoexpunging. */
	mail_user_unref(&client->user);

	/* free the i/ostreams after mail_user_unref(), which could trigger
	   mail_storage_callbacks notifications that write to the ostream. */
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);

	if (array_is_created(&client->search_saved_uidset))
		array_free(&client->search_saved_uidset);
	if (array_is_created(&client->search_updates))
		array_free(&client->search_updates);
	pool_unref(&client->command_pool);
	mail_storage_service_user_free(&client->service_user);

	imap_client_count--;
	DLLIST_REMOVE(&imap_clients, client);
	pool_unref(&client->pool);

	master_service_client_connection_destroyed(master_service);
	imap_refresh_proctitle();
}

static void client_destroy_timeout(struct client *client)
{
	client_destroy(client, NULL);
}

void client_disconnect(struct client *client, const char *reason)
{
	if (client->disconnected)
		return;

	client_log_disconnect(client, reason);
	client->disconnected = TRUE;
	o_stream_nflush(client->output);
	o_stream_uncork(client->output);

	i_stream_close(client->input);
	o_stream_close(client->output);

	if (client->to_idle != NULL)
		timeout_remove(&client->to_idle);
	client->to_idle = timeout_add(0, client_destroy_timeout, client);
}

void client_disconnect_with_error(struct client *client, const char *msg)
{
	client_send_line(client, t_strconcat("* BYE ", msg, NULL));
	client_disconnect(client, msg);
}

void client_send_line(struct client *client, const char *data)
{
	(void)client_send_line_next(client, data);
}

int client_send_line_next(struct client *client, const char *data)
{
	struct const_iovec iov[2];

	if (client->output->closed)
		return -1;

	iov[0].iov_base = data;
	iov[0].iov_len = strlen(data);
	iov[1].iov_base = "\r\n";
	iov[1].iov_len = 2;

	if (o_stream_sendv(client->output, iov, 2) < 0)
		return -1;
	client->last_output = ioloop_time;

	if (o_stream_get_buffer_used_size(client->output) >=
	    CLIENT_OUTPUT_OPTIMAL_SIZE) {
		/* buffer full, try flushing */
		return o_stream_flush(client->output);
	}
	return 1;
}

static void
client_cmd_append_timing_stats(struct client_command_context *cmd,
			       string_t *str)
{
	unsigned int msecs_in_cmd, msecs_in_ioloop;
	uint64_t ioloop_wait_usecs;
	unsigned int msecs_since_cmd;

	if (cmd->start_time.tv_sec == 0)
		return;

	ioloop_wait_usecs = io_loop_get_wait_usecs(current_ioloop);
	msecs_in_cmd = (cmd->running_usecs + 999) / 1000;
	msecs_in_ioloop = (ioloop_wait_usecs -
			   cmd->start_ioloop_wait_usecs + 999) / 1000;
	msecs_since_cmd = timeval_diff_msecs(&ioloop_timeval,
					     &cmd->last_run_timeval);

	if (str_data(str)[str_len(str)-1] == '.')
		str_truncate(str, str_len(str)-1);
	str_printfa(str, " (%d.%03d + %d.%03d ",
		    msecs_in_cmd / 1000, msecs_in_cmd % 1000,
		    msecs_in_ioloop / 1000, msecs_in_ioloop % 1000);
	if (msecs_since_cmd > 0) {
		str_printfa(str, "+ %d.%03d ",
			    msecs_since_cmd / 1000, msecs_since_cmd % 1000);
	}
	str_append(str, "secs).");
}

void client_send_tagline(struct client_command_context *cmd, const char *data)
{
	struct client *client = cmd->client;
	const char *tag = cmd->tag;

	if (client->output->closed || cmd->cancel)
		return;

	i_assert(!cmd->tagline_sent);
	cmd->tagline_sent = TRUE;
	cmd->tagline_reply = p_strdup(cmd->pool, data);

	if (tag == NULL || *tag == '\0')
		tag = "*";

	T_BEGIN {
		string_t *str = t_str_new(256);
		str_printfa(str, "%s %s", tag, data);
		client_cmd_append_timing_stats(cmd, str);
		str_append(str, "\r\n");
		o_stream_nsend(client->output, str_data(str), str_len(str));
	} T_END;

	client->last_output = ioloop_time;
}

void client_send_command_error(struct client_command_context *cmd,
			       const char *msg)
{
	struct client *client = cmd->client;
	const char *error, *cmd_name;
	enum imap_parser_error parse_error;

	if (msg == NULL) {
		msg = imap_parser_get_error(cmd->parser, &parse_error);
		switch (parse_error) {
		case IMAP_PARSE_ERROR_NONE:
			i_unreached();
		case IMAP_PARSE_ERROR_LITERAL_TOO_BIG:
			client_disconnect_with_error(client, msg);
			return;
		default:
			break;
		}
	}

	if (cmd->tag == NULL)
		error = t_strconcat("BAD Error in IMAP tag: ", msg, NULL);
	else if (cmd->name == NULL)
		error = t_strconcat("BAD Error in IMAP command: ", msg, NULL);
	else {
		cmd_name = t_str_ucase(cmd->name);
		error = t_strconcat("BAD Error in IMAP command ",
				    cmd_name, ": ", msg, NULL);
	}

	client_send_tagline(cmd, error);

	if (++client->bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
		client_disconnect_with_error(client,
			"Too many invalid IMAP commands.");
	}

	cmd->param_error = TRUE;
	/* client_read_args() failures rely on this being set, so that the
	   command processing is stopped even while command function returns
	   FALSE. */
	cmd->state = CLIENT_COMMAND_STATE_DONE;
}

void client_send_internal_error(struct client_command_context *cmd)
{
	client_send_tagline(cmd,
		t_strflocaltime("NO "MAIL_ERRSTR_CRITICAL_MSG_STAMP, ioloop_time));
}

bool client_read_args(struct client_command_context *cmd, unsigned int count,
		      unsigned int flags, const struct imap_arg **args_r)
{
	string_t *str;
	int ret;

	i_assert(count <= INT_MAX);

	ret = imap_parser_read_args(cmd->parser, count, flags, args_r);
	if (ret >= (int)count) {
		/* all parameters read successfully */
		i_assert(cmd->client->input_lock == NULL ||
			 cmd->client->input_lock == cmd);

		str = t_str_new(256);
		imap_write_args(str, *args_r);
		cmd->args = p_strdup(cmd->pool, str_c(str));

		cmd->client->input_lock = NULL;
		return TRUE;
	} else if (ret == -2) {
		/* need more data */
		if (cmd->client->input->closed) {
			/* disconnected */
			cmd->state = CLIENT_COMMAND_STATE_DONE;
		}
		return FALSE;
	} else {
		/* error, or missing arguments */
		client_send_command_error(cmd, ret < 0 ? NULL :
					  "Missing arguments");
		return FALSE;
	}
}

bool client_read_string_args(struct client_command_context *cmd,
			     unsigned int count, ...)
{
	const struct imap_arg *imap_args;
	va_list va;
	const char *str;
	unsigned int i;

	if (!client_read_args(cmd, count, 0, &imap_args))
		return FALSE;

	va_start(va, count);
	for (i = 0; i < count; i++) {
		const char **ret = va_arg(va, const char **);

		if (IMAP_ARG_IS_EOL(&imap_args[i])) {
			client_send_command_error(cmd, "Missing arguments.");
			break;
		}

		if (!imap_arg_get_astring(&imap_args[i], &str)) {
			client_send_command_error(cmd, "Invalid arguments.");
			break;
		}

		if (ret != NULL)
			*ret = str;
	}
	va_end(va);

	return i == count;
}

static struct client_command_context *
client_command_find_with_flags(struct client_command_context *new_cmd,
			       enum command_flags flags,
			       enum client_command_state max_state)
{
	struct client_command_context *cmd;

	cmd = new_cmd->client->command_queue;
	for (; cmd != NULL; cmd = cmd->next) {
		if (cmd->state <= max_state &&
		    cmd != new_cmd && (cmd->cmd_flags & flags) != 0)
			return cmd;
	}
	return NULL;
}

static bool client_command_is_ambiguous(struct client_command_context *cmd)
{
	enum command_flags flags;
	enum client_command_state max_state =
		CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY;
	bool broken_client = FALSE;

	if ((cmd->cmd_flags & COMMAND_FLAG_REQUIRES_SYNC) != 0 &&
	    !imap_sync_is_allowed(cmd->client))
		return TRUE;

	if (cmd->search_save_result_used) {
		/* if there are pending commands that update the search
		   save result, wait */
		struct client_command_context *old_cmd = cmd->next;

		for (; old_cmd != NULL; old_cmd = old_cmd->next) {
			if (old_cmd->search_save_result)
				return TRUE;
		}
	}

	if ((cmd->cmd_flags & COMMAND_FLAG_BREAKS_MAILBOX) ==
	    COMMAND_FLAG_BREAKS_MAILBOX) {
		/* there must be no other command running that uses the
		   selected mailbox */
		flags = COMMAND_FLAG_USES_MAILBOX;
		max_state = CLIENT_COMMAND_STATE_DONE;
	} else if ((cmd->cmd_flags & COMMAND_FLAG_USES_SEQS) != 0) {
		/* no existing command must be breaking sequences */
		flags = COMMAND_FLAG_BREAKS_SEQS;
		broken_client = TRUE;
	} else if ((cmd->cmd_flags & COMMAND_FLAG_BREAKS_SEQS) != 0) {
		/* if existing command uses sequences, we'll have to block */
		flags = COMMAND_FLAG_USES_SEQS;
	} else {
		return FALSE;
	}

	if (client_command_find_with_flags(cmd, flags, max_state) == NULL) {
		if (cmd->client->syncing) {
			/* don't do anything until syncing is finished */
			return TRUE;
		}
		if (cmd->client->mailbox_change_lock != NULL &&
		    cmd->client->mailbox_change_lock != cmd) {
			/* don't do anything until mailbox is fully
			   opened/closed */
			return TRUE;
		}
		return FALSE;
	}

	if (broken_client) {
		client_send_line(cmd->client,
				 "* BAD ["IMAP_RESP_CODE_CLIENTBUG"] "
				 "Command pipelining results in ambiguity.");
	}

	return TRUE;
}

struct client_command_context *client_command_alloc(struct client *client)
{
	struct client_command_context *cmd;

	cmd = p_new(client->command_pool, struct client_command_context, 1);
	cmd->client = client;
	cmd->pool = client->command_pool;
	cmd->start_time = ioloop_timeval;
	cmd->last_run_timeval = ioloop_timeval;
	cmd->start_ioloop_wait_usecs = io_loop_get_wait_usecs(current_ioloop);
	p_array_init(&cmd->module_contexts, cmd->pool, 5);

	DLLIST_PREPEND(&client->command_queue, cmd);
	client->command_queue_size++;
	return cmd;
}

static struct client_command_context *
client_command_new(struct client *client)
{
	struct client_command_context *cmd;

	cmd = client_command_alloc(client);
	if (client->free_parser != NULL) {
		cmd->parser = client->free_parser;
		client->free_parser = NULL;
	} else {
		cmd->parser =
			imap_parser_create(client->input, client->output,
					   client->set->imap_max_line_length);
		if (client->set->imap_literal_minus)
			imap_parser_enable_literal_minus(cmd->parser);
	}
	return cmd;
}

void client_add_missing_io(struct client *client)
{
	if (client->io == NULL && !client->disconnected)
		client->io = io_add_istream(client->input, client_input, client);
}

void client_command_free(struct client_command_context **_cmd)
{
	struct client_command_context *cmd = *_cmd;
	struct client *client = cmd->client;
	enum client_command_state state = cmd->state;

	*_cmd = NULL;

	i_assert(!cmd->executing);
	i_assert(client->output_cmd_lock == NULL);

	/* reset input idle time because command output might have taken a
	   long time and we don't want to disconnect client immediately then */
	client->last_input = ioloop_time;
	timeout_reset(client->to_idle);

	if (cmd->cancel) {
		cmd->cancel = FALSE;
		client_send_tagline(cmd, "NO Command cancelled.");
	}

	if (!cmd->param_error)
		client->bad_counter = 0;

	if (client->input_lock == cmd)
		client->input_lock = NULL;
	if (client->mailbox_change_lock == cmd)
		client->mailbox_change_lock = NULL;

	if (cmd->parser != NULL) {
		if (client->free_parser == NULL) {
			imap_parser_reset(cmd->parser);
			client->free_parser = cmd->parser;
		} else {
			imap_parser_unref(&cmd->parser);
		}
	}

	client->command_queue_size--;
	DLLIST_REMOVE(&client->command_queue, cmd);
	cmd = NULL;

	if (client->command_queue == NULL) {
		/* no commands left in the queue, we can clear the pool */
		p_clear(client->command_pool);
		if (client->to_idle_output != NULL)
			timeout_remove(&client->to_idle_output);
	}
	imap_client_notify_command_freed(client);
	imap_refresh_proctitle();

	/* if command finished from external event, check input for more
	   unhandled commands since we may not be executing from client_input
	   or client_output. */
	if (state == CLIENT_COMMAND_STATE_WAIT_EXTERNAL &&
	    !client->disconnected) {
		client_add_missing_io(client);
		if (client->to_delayed_input == NULL) {
			client->to_delayed_input =
				timeout_add(0, client_input, client);
		}
	}
}

static void client_check_command_hangs(struct client *client)
{
	struct client_command_context *cmd;
	unsigned int unfinished_count = 0;
	bool have_wait_unfinished = FALSE;

	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
		switch (cmd->state) {
		case CLIENT_COMMAND_STATE_WAIT_INPUT:
			/* We need to be reading input for this command.
			   However, if there is already an output lock for
			   another command we'll wait for it to finish first.
			   This is needed because if there are any literals
			   we'd need to send "+ OK" responses. */
			i_assert(client->io != NULL ||
				 (client->output_cmd_lock != NULL &&
				  client->output_cmd_lock != client->input_lock));
			unfinished_count++;
			break;
		case CLIENT_COMMAND_STATE_WAIT_OUTPUT:
			i_assert((io_loop_find_fd_conditions(current_ioloop, client->fd_out) & IO_WRITE) != 0);
			unfinished_count++;
			break;
		case CLIENT_COMMAND_STATE_WAIT_EXTERNAL:
			unfinished_count++;
			break;
		case CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY:
			have_wait_unfinished = TRUE;
			break;
		case CLIENT_COMMAND_STATE_WAIT_SYNC:
			if ((io_loop_find_fd_conditions(current_ioloop, client->fd_out) & IO_WRITE) == 0)
				have_wait_unfinished = TRUE;
			else {
				/* we have an output callback, which will be
				   called soon and it'll run cmd_sync_delayed().
				   FIXME: is this actually wanted? */
			}
			break;
		case CLIENT_COMMAND_STATE_DONE:
			i_unreached();
		}
	}
	i_assert(!have_wait_unfinished || unfinished_count > 0);
}

static bool client_remove_pending_unambiguity(struct client *client)
{
	if (client->input_lock != NULL) {
		/* there's a command that has locked the input */
		struct client_command_context *cmd = client->input_lock;

		if (cmd->state != CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY)
			return TRUE;

		/* the command is waiting for existing ambiguity causing
		   commands to finish. */
		if (client_command_is_ambiguous(cmd)) {
			/* we could be waiting for existing sync to finish */
			if (!cmd_sync_delayed(client))
				return FALSE;
			if (client_command_is_ambiguous(cmd))
				return FALSE;
		}
		cmd->state = CLIENT_COMMAND_STATE_WAIT_INPUT;
	}
	return TRUE;
}

void client_continue_pending_input(struct client *client)
{
	i_assert(!client->handling_input);

	/* this function is called at the end of I/O callbacks (and only there).
	   fix up the command states and verify that they're correct. */
	while (client_remove_pending_unambiguity(client)) {
		client_add_missing_io(client);

		/* if there's unread data in buffer, handle it. */
		if (i_stream_get_data_size(client->input) == 0 ||
		    client->disconnected)
			break;
		if (!client_handle_input(client))
			break;
	}
	if (!client->input->closed && !client->output->closed)
		client_check_command_hangs(client);
}

/* Skip incoming data until newline is found,
   returns TRUE if newline was found. */
static bool client_skip_line(struct client *client)
{
	const unsigned char *data;
	size_t i, data_size;

	data = i_stream_get_data(client->input, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == '\n') {
			client->input_skip_line = FALSE;
			i++;
			break;
		}
	}

	i_stream_skip(client->input, i);
	return !client->input_skip_line;
}

static void client_idle_output_timeout(struct client *client)
{
	client_destroy(client,
		       "Disconnected for inactivity in reading our output");
}

bool client_handle_unfinished_cmd(struct client_command_context *cmd)
{
	if (cmd->state == CLIENT_COMMAND_STATE_WAIT_INPUT) {
		/* need more input */
		return FALSE;
	}
	if (cmd->state != CLIENT_COMMAND_STATE_WAIT_OUTPUT) {
		/* waiting for something */
		if (cmd->state == CLIENT_COMMAND_STATE_WAIT_SYNC) {
			/* this is mainly for APPEND. */
			client_add_missing_io(cmd->client);
		}
		return TRUE;
	}

	/* output is blocking, we can execute more commands */
	o_stream_set_flush_pending(cmd->client->output, TRUE);
	if (cmd->client->to_idle_output == NULL) {
		/* disconnect sooner if client isn't reading our output */
		cmd->client->to_idle_output =
			timeout_add(CLIENT_OUTPUT_TIMEOUT_MSECS,
				    client_idle_output_timeout, cmd->client);
	}
	return TRUE;
}

static bool client_command_input(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct command *command;

        if (cmd->func != NULL) {
		/* command is being executed - continue it */
		if (command_exec(cmd)) {
			/* command execution was finished */
			client_command_free(&cmd);
			client_add_missing_io(client);
			return TRUE;
		}

		return client_handle_unfinished_cmd(cmd);
	}

	if (cmd->tag == NULL) {
                cmd->tag = imap_parser_read_word(cmd->parser);
		if (cmd->tag == NULL)
			return FALSE; /* need more data */
		cmd->tag = p_strdup(cmd->pool, cmd->tag);
	}

	if (cmd->name == NULL) {
		cmd->name = imap_parser_read_word(cmd->parser);
		if (cmd->name == NULL)
			return FALSE; /* need more data */

		/* UID commands are a special case. better to handle them
		   here. */
		if (!cmd->uid && strcasecmp(cmd->name, "UID") == 0) {
			cmd->uid = TRUE;
			cmd->name = imap_parser_read_word(cmd->parser);
			if (cmd->name == NULL)
				return FALSE; /* need more data */
		}
		cmd->name = !cmd->uid ? p_strdup(cmd->pool, cmd->name) :
			p_strconcat(cmd->pool, "UID ", cmd->name, NULL);
		imap_refresh_proctitle();
	}

	client->input_skip_line = TRUE;

	if (cmd->name[0] == '\0') {
		/* command not given - cmd->func is already NULL. */
	} else if ((command = command_find(cmd->name)) != NULL) {
		cmd->func = command->func;
		cmd->cmd_flags = command->flags;
		if (client_command_is_ambiguous(cmd)) {
			/* do nothing until existing commands are finished */
			i_assert(cmd->state == CLIENT_COMMAND_STATE_WAIT_INPUT);
			cmd->state = CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY;
			io_remove(&client->io);
			return FALSE;
		}
	}

	if (cmd->func == NULL) {
		/* unknown command */
		client_send_command_error(cmd, "Unknown command.");
		cmd->param_error = TRUE;
		client_command_free(&cmd);
		return TRUE;
	} else {
		i_assert(!client->disconnected);

		return client_command_input(cmd);
	}
}

static bool client_handle_next_command(struct client *client, bool *remove_io_r)
{
	*remove_io_r = FALSE;

	if (client->input_lock != NULL) {
		if (client->input_lock->state ==
		    CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY ||
		    /* we can't send literal "+ OK" replies if output is
		       locked by another command. */
		    (client->output_cmd_lock != NULL &&
		     client->output_cmd_lock != client->input_lock)) {
			*remove_io_r = TRUE;
			return FALSE;
		}
		return client_command_input(client->input_lock);
	}

	if (client->input_skip_line) {
		/* first eat the previous command line */
		if (!client_skip_line(client))
			return FALSE;
		client->input_skip_line = FALSE;
	}

	/* don't bother creating a new client command before there's at least
	   some input */
	if (i_stream_get_data_size(client->input) == 0)
		return FALSE;

	/* beginning a new command */
	if (client->command_queue_size >= CLIENT_COMMAND_QUEUE_MAX_SIZE ||
	    client->output_cmd_lock != NULL) {
		/* wait for some of the commands to finish */
		*remove_io_r = TRUE;
		return FALSE;
	}

	client->input_lock = client_command_new(client);
	return client_command_input(client->input_lock);
}

bool client_handle_input(struct client *client)
{
	bool ret, remove_io, handled_commands = FALSE;

	i_assert(!client->disconnected);

	client->handling_input = TRUE;
	do {
		T_BEGIN {
			ret = client_handle_next_command(client, &remove_io);
		} T_END;
		if (ret)
			handled_commands = TRUE;
	} while (ret && !client->disconnected && client->io != NULL);
	client->handling_input = FALSE;

	if (remove_io)
		io_remove(&client->io);
	else
		client_add_missing_io(client);
	if (!handled_commands)
		return FALSE;

	if (client->input_lock == NULL) {
		/* finished handling all commands. sync them all at once now. */
		cmd_sync_delayed(client);
	} else if (client->input_lock->state == CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY) {
		/* the command may be waiting for previous command to sync. */
		cmd_sync_delayed(client);
	}
	return TRUE;
}

void client_input(struct client *client)
{
	struct client_command_context *cmd;
	struct ostream *output = client->output;
	ssize_t bytes;

	i_assert(client->io != NULL);

	client->last_input = ioloop_time;
	timeout_reset(client->to_idle);

	if (client->to_delayed_input != NULL)
		timeout_remove(&client->to_delayed_input);

	bytes = i_stream_read(client->input);
	if (bytes == -1) {
		/* disconnected */
		client_destroy(client, NULL);
		return;
	}

	o_stream_ref(output);
	o_stream_cork(output);
	if (!client_handle_input(client) && bytes == -2) {
		/* parameter word is longer than max. input buffer size.
		   this is most likely an error, so skip the new data
		   until newline is found. */
		client->input_skip_line = TRUE;

		cmd = client->input_lock != NULL ? client->input_lock :
			client_command_new(client);
		cmd->param_error = TRUE;
		client_send_command_error(cmd, "Too long argument.");
		client_command_free(&cmd);
	}
	o_stream_uncork(output);
	o_stream_unref(&output);
	imap_refresh_proctitle();

	if (client->disconnected)
		client_destroy(client, NULL);
	else
		client_continue_pending_input(client);
}

static void client_output_cmd(struct client_command_context *cmd)
{
	bool finished;

	/* continue processing command */
	finished = command_exec(cmd);

	if (!finished)
		(void)client_handle_unfinished_cmd(cmd);
	else {
		/* command execution was finished */
		client_command_free(&cmd);
	}
}

static void client_output_commands(struct client *client)
{
	struct client_command_context *cmd;

	/* mark all commands non-executed */
	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next)
		cmd->temp_executed = FALSE;

	if (client->output_cmd_lock != NULL) {
		client->output_cmd_lock->temp_executed = TRUE;
		client_output_cmd(client->output_cmd_lock);
	}
	while (client->output_cmd_lock == NULL) {
		/* go through the entire commands list every time in case
		   multiple commands were freed. temp_executed keeps track of
		   which messages we've called so far */
		cmd = client->command_queue;
		for (; cmd != NULL; cmd = cmd->next) {
			if (!cmd->temp_executed &&
			    cmd->state == CLIENT_COMMAND_STATE_WAIT_OUTPUT) {
				cmd->temp_executed = TRUE;
				client_output_cmd(cmd);
				break;
			}
		}
		if (cmd == NULL) {
			/* all commands executed */
			break;
		}
	}
}

int client_output(struct client *client)
{
	int ret;

	i_assert(!client->destroyed);

	client->last_output = ioloop_time;
	timeout_reset(client->to_idle);
	if (client->to_idle_output != NULL)
		timeout_reset(client->to_idle_output);

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, NULL);
		return 1;
	}

	client_output_commands(client);
	(void)cmd_sync_delayed(client);

	imap_refresh_proctitle();
	if (client->output->closed)
		client_destroy(client, NULL);
	else {
		/* corking is added automatically by ostream-file. we need to
		   uncork here before client_check_command_hangs() is called,
		   because otherwise it can assert-crash due to ioloop not
		   having IO_WRITE callback set for the ostream. */
		o_stream_uncork(client->output);
		client_continue_pending_input(client);
	}
	return ret;
}

bool client_handle_search_save_ambiguity(struct client_command_context *cmd)
{
	struct client_command_context *old_cmd = cmd->next;

	/* search only commands that were added before this command
	   (commands are prepended to the queue, so they're after ourself) */
	for (; old_cmd != NULL; old_cmd = old_cmd->next) {
		if (old_cmd->search_save_result)
			break;
	}
	if (old_cmd == NULL)
		return FALSE;

	/* ambiguity, wait until it's over */
	i_assert(cmd->state == CLIENT_COMMAND_STATE_WAIT_INPUT);
	cmd->client->input_lock = cmd;
	cmd->state = CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY;
	cmd->search_save_result_used = TRUE;
	io_remove(&cmd->client->io);
	return TRUE;
}

int client_enable(struct client *client, enum mailbox_feature features)
{
	struct mailbox_status status;
	int ret;

	if ((client->enabled_features & features) == features)
		return 0;

	client->enabled_features |= features;
	if (client->mailbox == NULL)
		return 0;

	ret = mailbox_enable(client->mailbox, features);
	if ((features & MAILBOX_FEATURE_CONDSTORE) != 0 && ret == 0) {
		/* CONDSTORE being enabled while mailbox is selected.
		   Notify client of the latest HIGHESTMODSEQ. */
		ret = mailbox_get_status(client->mailbox,
					 STATUS_HIGHESTMODSEQ, &status);
		if (ret == 0) {
			client_send_line(client, t_strdup_printf(
				"* OK [HIGHESTMODSEQ %llu] Highest",
				(unsigned long long)status.highest_modseq));
		}
	}
	if (ret < 0) {
		client_send_untagged_storage_error(client,
			mailbox_get_storage(client->mailbox));
	}
	return ret;
}

struct imap_search_update *
client_search_update_lookup(struct client *client, const char *tag,
			    unsigned int *idx_r)
{
	struct imap_search_update *updates;
	unsigned int i, count;

	if (!array_is_created(&client->search_updates))
		return NULL;

	updates = array_get_modifiable(&client->search_updates, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(updates[i].tag, tag) == 0) {
			*idx_r = i;
			return &updates[i];
		}
	}
	return NULL;
}

void client_search_updates_free(struct client *client)
{
	struct imap_search_update *update;

	if (!array_is_created(&client->search_updates))
		return;

	array_foreach_modifiable(&client->search_updates, update)
		imap_search_update_free(update);
	array_clear(&client->search_updates);
}

void clients_destroy_all(struct mail_storage_service_ctx *storage_service)
{
	while (imap_clients != NULL) {
		client_send_line(imap_clients, "* BYE Server shutting down.");
		mail_storage_service_io_activate_user(imap_clients->service_user);
		client_destroy(imap_clients, "Server shutting down.");
	}
	mail_storage_service_io_deactivate(storage_service);
}

struct imap_client_vfuncs imap_client_vfuncs = {
	imap_state_export_base,
	imap_state_import_base,
	client_default_destroy
};
