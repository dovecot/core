/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ioloop.h"
#include "llist.h"
#include "str.h"
#include "hostpid.h"
#include "net.h"
#include "iostream.h"
#include "iostream-rawlog.h"
#include "istream.h"
#include "istream-concat.h"
#include "ostream.h"
#include "ostream-multiplex.h"
#include "time-util.h"
#include "settings.h"
#include "master-service.h"
#include "imap-resp-code.h"
#include "imap-util.h"
#include "imap-urlauth.h"
#include "mail-error.h"
#include "smtp-submit-settings.h"
#include "mail-namespace.h"
#include "mail-storage-service.h"
#include "mail-autoexpunge.h"
#include "imap-state.h"
#include "imap-search.h"
#include "imap-notify.h"
#include "imap-commands.h"
#include "imap-feature.h"

#include <unistd.h>

/* If the last command took longer than this to run, log statistics on
   where the time was spent. */
#define IMAP_CLIENT_DISCONNECT_LOG_STATS_CMD_MIN_RUNNING_MSECS 1000

extern struct mail_storage_callbacks imap_storage_callbacks;
extern struct imap_client_vfuncs imap_client_vfuncs;

struct imap_module_register imap_module_register = { 0 };

struct client *imap_clients = NULL;
unsigned int imap_client_count = 0;

unsigned int imap_feature_condstore = UINT_MAX;
unsigned int imap_feature_qresync = UINT_MAX;
unsigned int imap_feature_utf8accept = UINT_MAX;
unsigned int imap_feature_imap4rev2 = UINT_MAX;

static const char *client_command_state_names[] = {
	"wait-input",
	"wait-output",
	"wait-external",
	"wait-unambiguity",
	"wait-sync",
	"done"
};
static_assert_array_size(client_command_state_names,
			 CLIENT_COMMAND_STATE_DONE+1);

static void client_idle_timeout(struct client *client)
{
	if (client->output_cmd_lock == NULL)
		client_send_line(client, "* BYE Disconnected for inactivity.");
	client_destroy(client, t_strdup_printf(
		"Inactivity - no input for %"PRIdTIME_T" secs",
		ioloop_time - client->last_input));
}

static void client_init_urlauth(struct client *client)
{
	struct imap_urlauth_config config;

	i_zero(&config);
	config.url_host = client->set->imap_urlauth_host;
	config.url_port = client->set->imap_urlauth_port;
	config.socket_path = t_strconcat(client->user->set->base_dir,
					 "/"IMAP_URLAUTH_SOCKET_NAME, NULL);
	config.session_id = client->user->session_id;
	config.access_user = client->user->username;
	config.access_service = "imap";
	config.access_anonymous = client->user->anonymous;

	client->urlauth_ctx = imap_urlauth_init(client->user, &config);
}

static void
imap_unset_capability(struct settings_instance *set_instance, const char *capability)
{
	settings_override(set_instance,
			  t_strdup_printf("imap_capability/%s", capability),
			  "no", SETTINGS_OVERRIDE_TYPE_CODE);
}

struct client *client_create(int fd_in, int fd_out,
			     enum client_create_flags flags,
			     struct event *event, struct mail_user *user,
			     const struct imap_settings *set,
			     const struct smtp_submit_settings *smtp_set)
{
	struct client *client;
	pool_t pool;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	pool = pool_alloconly_create("imap client", 2048);
	client = p_new(pool, struct client, 1);
	client->pool = pool;
	client->v = imap_client_vfuncs;
	client->event = event;
	event_ref(client->event);
	client->unhibernated = (flags & CLIENT_CREATE_FLAG_UNHIBERNATED) != 0;
	client->set = set;
	client->smtp_set = smtp_set;
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->input = i_stream_create_fd(fd_in,
					   set->imap_max_line_length);
	client->output = o_stream_create_fd(fd_out, SIZE_MAX);
	if ((flags & CLIENT_CREATE_FLAG_MULTIPLEX_OUTPUT) != 0) {
		client->multiplex_output =
			o_stream_create_multiplex(client->output, SIZE_MAX,
				OSTREAM_MULTIPLEX_FORMAT_STREAM_CONTINUE);
		o_stream_unref(&client->output);
		client->output = client->multiplex_output;
	}
	o_stream_set_no_error_handling(client->output, TRUE);
	i_stream_set_name(client->input, "<imap client>");
	o_stream_set_name(client->output, "<imap client>");

	o_stream_set_flush_callback(client->output, client_output, client);

	p_array_init(&client->module_contexts, client->pool, 5);
	client->last_input = ioloop_time;
	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);

	client->command_pool =
		pool_alloconly_create(MEMPOOL_GROWING"client command", 1024*2);
	client->user = user;
	client->notify_count_changes = TRUE;
	client->notify_flag_changes = TRUE;
	p_array_init(&client->enabled_features, client->pool, 8);

	struct settings_instance *set_instance =
		mail_storage_service_user_get_settings_instance(
			client->user->service_user);
	/* All capabilities are enabled by defaults.
	   Remove the capabilities here that can't work due current settings. */
	if (client->set->imap_literal_minus)
		imap_unset_capability(set_instance, "LITERAL+");
	 else
		imap_unset_capability(set_instance, "LITERAL-");
	/* Enable FUZZY capability only when it actually has a chance of working */
	if (!user->fuzzy_search)
		imap_unset_capability(set_instance, "SEARCH=FUZZY");

	/* NOTIFY is enabled only when mailbox list indexes are enabled,
	   although even that doesn't necessarily guarantee it always */
	if (!set->mailbox_list_index)
		imap_unset_capability(set_instance, "NOTIFY");

	const char *error;
	int ret = mailbox_attribute_dict_is_enabled(user, &error);
	if (ret < 0 && client->init_error == NULL)
		client->init_error = p_strdup(user->pool, error);
	bool have_mailbox_attribute_dict = ret > 0;

	/* Enable URLAUTH capability only when dict is configured correctly */
	if (*set->imap_urlauth_host != '\0' && have_mailbox_attribute_dict)
		client_init_urlauth(client);
	else {
		imap_unset_capability(set_instance, "URLAUTH");
		imap_unset_capability(set_instance, "URLAUTH=BINARY");
	}
	if (!set->imap_metadata || !have_mailbox_attribute_dict)
		imap_unset_capability(set_instance, "METADATA");
	if (!client->set->mail_utf8_extensions)
		imap_unset_capability(set_instance, "UTF8=ACCEPT");
	if (!client->set->imap4rev2_enable)
		imap_unset_capability(set_instance, "IMAP4rev2");

	const struct imap_settings *modified_set;
	if (settings_get(client->user->event, &imap_setting_parser_info,
			 0, &modified_set, &error) < 0) {
		if (client->init_error == NULL)
			client->init_error = p_strdup(user->pool, error);
	} else {
		client->capability_string = str_new(client->pool, 256);
		imap_write_capability(client->capability_string,
				      &modified_set->imap_capability);
		settings_free(modified_set);
	}

	struct master_service_anvil_session anvil_session;
	mail_user_get_anvil_session(client->user, &anvil_session);
	if (master_service_anvil_connect(master_service, &anvil_session,
					 TRUE, client->anvil_conn_guid))
		client->anvil_sent = TRUE;

	imap_client_count++;
	DLLIST_PREPEND(&imap_clients, client);
	if (hook_client_created != NULL)
		hook_client_created(&client);

	imap_refresh_proctitle();
	return client;
}

void client_create_finish_io(struct client *client)
{
	if (client->set->rawlog_dir[0] != '\0') {
		client->pre_rawlog_input = client->input;
		client->pre_rawlog_output = client->output;
		(void)iostream_rawlog_create(client->set->rawlog_dir,
					     &client->input, &client->output);
		if (client->input != client->pre_rawlog_input) {
			/* rawlog enabled */
			client->post_rawlog_input = client->input;
			client->post_rawlog_output = client->output;
		} else {
			/* rawlog setting is set, but rawlog wasn't actually
			   started. */
			client->pre_rawlog_input = NULL;
			client->pre_rawlog_output = NULL;
		}
	}
	client->io = io_add_istream(client->input, client_input, client);
}

int client_create_finish(struct client *client, const char **error_r)
{
	if (client->init_error != NULL) {
		*error_r = client->init_error;
		return -1;
	}
	if (mail_namespaces_init(client->user, error_r) < 0)
		return -1;
	mail_namespaces_set_storage_callbacks(client->user->namespaces,
					      &imap_storage_callbacks, client);
	client->v.init(client);
	return 0;
}

void client_add_istream_prefix(struct client *client,
			       const unsigned char *data, size_t size)
{
	i_assert(client->io == NULL);

	struct istream *inputs[] = {
		i_stream_create_copy_from_data(data, size),
		client->input,
		NULL
	};
	client->input = i_stream_create_concat(inputs);
	i_stream_copy_fd(client->input, inputs[1]);
	i_stream_unref(&inputs[0]);
	i_stream_unref(&inputs[1]);

	i_stream_set_input_pending(client->input, TRUE);
}

static void client_default_init(struct client *client ATTR_UNUSED)
{
	/* nothing */
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
	const struct var_expand_table logout_tab[] = {
		{ .key = "input", .value = dec2str(i_stream_get_absolute_offset(client->input) + client->logout_stats.input_bytes_extra) },
		{ .key = "output", .value = dec2str(client->output->offset + client->logout_stats.output_bytes_extra) },
		{ .key = "session", .value = client->user->session_id },
		{ .key = "fetch_hdr_count", .value = dec2str(client->logout_stats.fetch_hdr_count) },
		{ .key = "fetch_hdr_bytes", .value = dec2str(client->logout_stats.fetch_hdr_bytes) },
		{ .key = "fetch_body_count", .value = dec2str(client->logout_stats.fetch_body_count) },
		{ .key = "fetch_body_bytes", .value = dec2str(client->logout_stats.fetch_body_bytes) },
		{ .key = "deleted", .value = dec2str(client->logout_stats.deleted_count) },
		{ .key = "expunged", .value = dec2str(client->logout_stats.expunged_count) },
		{ .key = "trashed", .value = dec2str(client->logout_stats.trashed_count) },
		{ .key = "autoexpunged", .value = dec2str(client->logout_stats.autoexpunged_count) },
		{ .key = "appended", .value = dec2str(client->logout_stats.append_count) },
		VAR_EXPAND_TABLE_END
	};
	const struct var_expand_params *user_params =
		mail_user_var_expand_params(client->user);
	const struct var_expand_params params = {
		.tables_arr = (const struct var_expand_table*[]){
			logout_tab,
			user_params->table,
			NULL
		},
		.providers = user_params->providers,
		.context = user_params->context,
		.event = client->event,
	};
	string_t *str;
	const char *error;

	event_add_int(client->event, "net_in_bytes", i_stream_get_absolute_offset(client->input));
	event_add_int(client->event, "net_out_bytes", client->output->offset);

	str = t_str_new(128);
	if (var_expand(str, client->set->imap_logout_format,
			   &params, &error) < 0) {
		e_error(client->event,
			"Failed to expand imap_logout_format=%s: %s",
			client->set->imap_logout_format, error);
	}

	return str_c(str);
}

void client_destroy(struct client *client, const char *reason)
{
	client->v.destroy(client, reason);
}

static void
client_command_stats_append(string_t *str,
			    const struct client_command_stats *stats,
			    const char *wait_condition,
			    size_t buffered_size)
{
	uint64_t ioloop_wait_usecs;
	unsigned int msecs_in_ioloop;

	ioloop_wait_usecs = io_loop_get_wait_usecs(current_ioloop);
	msecs_in_ioloop = (ioloop_wait_usecs -
		stats->start_ioloop_wait_usecs + 999) / 1000;
	str_printfa(str, "running for %d.%03d + waiting ",
		    (int)((stats->running_usecs+999)/1000 / 1000),
		    (int)((stats->running_usecs+999)/1000 % 1000));
	if (wait_condition[0] != '\0')
		str_printfa(str, "%s ", wait_condition);
	str_printfa(str, "for %d.%03d secs",
		    msecs_in_ioloop / 1000, msecs_in_ioloop % 1000);
	if (stats->lock_wait_usecs > 0) {
		int lock_wait_msecs = (stats->lock_wait_usecs+999)/1000;
		str_printfa(str, ", %d.%03d in locks",
			    lock_wait_msecs/1000, lock_wait_msecs%1000);
	}
	str_printfa(str, ", %"PRIu64" B in + %"PRIu64,
		    stats->bytes_in, stats->bytes_out);
	if (buffered_size > 0)
		str_printfa(str, "+%zu", buffered_size);
	str_append(str, " B out");
}

static const char *client_get_last_command_status(struct client *client)
{
	if (client->logged_out)
		return "";
	if (client->last_cmd_name == NULL) {
		if (client->unhibernated)
			return " (No commands sent after unhibernation)";
		else
			return " (No commands sent)";
	}

	/* client disconnected without sending LOGOUT. if the last command
	   took over 1 second to run, log it. */
	const struct client_command_stats *stats = &client->last_cmd_stats;

	string_t *str = t_str_new(128);
	long long last_run_msecs = timeval_diff_msecs(&ioloop_timeval,
						      &stats->last_run_timeval);
	str_printfa(str, " (%s finished %lld.%03lld secs ago",
		    client->last_cmd_name, last_run_msecs/1000,
		    last_run_msecs%1000);

	if (timeval_diff_msecs(&stats->last_run_timeval, &stats->start_time) >=
	    IMAP_CLIENT_DISCONNECT_LOG_STATS_CMD_MIN_RUNNING_MSECS) {
		str_append(str, " - ");
		client_command_stats_append(str, stats, "", 0);
	}
	str_append_c(str, ')');
	return str_c(str);
}

static const char *client_get_commands_status(struct client *client)
{
	struct client_command_context *cmd, *last_cmd = NULL;
	struct client_command_stats all_stats;
	string_t *str;
	enum io_condition cond;
	const char *cond_str;

	if (client->command_queue == NULL)
		return client_get_last_command_status(client);

	i_zero(&all_stats);
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
		all_stats.running_usecs += cmd->stats.running_usecs;
		all_stats.lock_wait_usecs += cmd->stats.lock_wait_usecs;
		all_stats.bytes_in += cmd->stats.bytes_in;
		all_stats.bytes_out += cmd->stats.bytes_out;
		last_cmd = cmd;
	}
	if (last_cmd == NULL)
		return client_get_last_command_status(client);

	cond = io_loop_find_fd_conditions(current_ioloop, client->fd_out);
	if ((cond & (IO_READ | IO_WRITE)) == (IO_READ | IO_WRITE))
		cond_str = "input/output";
	else if ((cond & IO_READ) != 0)
		cond_str = "input";
	else if ((cond & IO_WRITE) != 0)
		cond_str = "output";
	else
		cond_str = "nothing";

	all_stats.start_ioloop_wait_usecs =
		last_cmd->stats.start_ioloop_wait_usecs;
	str_append_c(str, ' ');
	client_command_stats_append(str, &all_stats, cond_str,
		o_stream_get_buffer_used_size(client->output));
	str_printfa(str, ", state=%s)",
		    client_command_state_names[last_cmd->state]);
	return str_c(str);
}

static void client_log_disconnect(struct client *client, const char *reason)
{
	e_info(client->event, "Disconnected: %s %s", reason, client_stats(client));
}

static void client_default_destroy(struct client *client, const char *reason)
{
	struct client_command_context *cmd;

	i_assert(!client->destroyed);
	client->destroyed = TRUE;
	client->disconnected = TRUE;

	if (client->disconnect_reason != NULL)
		reason = client->disconnect_reason;
	if (reason == NULL)
		reason = t_strconcat(
			io_stream_get_disconnect_reason(client->input,
							client->output),
			client_get_commands_status(client), NULL);

	i_stream_close(client->input);
	o_stream_close(client->output);
	o_stream_close(client->side_channel_output);

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

	if (client->notify_ctx != NULL)
		imap_notify_deinit(&client->notify_ctx);
	if (client->urlauth_ctx != NULL)
		imap_urlauth_deinit(&client->urlauth_ctx);
	/* Keep mailbox closing close to last, so anything that could
	   potentially have transactions open will close them first. */
	if (client->mailbox != NULL)
		imap_client_close_mailbox(client);
	if (client->anvil_sent) {
		struct master_service_anvil_session anvil_session;
		mail_user_get_anvil_session(client->user, &anvil_session);
		master_service_anvil_disconnect(master_service, &anvil_session,
						client->anvil_conn_guid);
	}

	if (client->free_parser != NULL)
		imap_parser_unref(&client->free_parser);
	io_remove(&client->io);
	timeout_remove(&client->to_idle_output);
	timeout_remove(&client->to_idle);

	if (!client->hibernated && client->fd_in == client->fd_out)
		(void)shutdown(client->fd_out, SHUT_RDWR);
	/* i/ostreams are already closed at this stage, so fd can be closed */
	fd_close_maybe_stdio(&client->fd_in, &client->fd_out);

	/* Autoexpunging might run for a long time. Disconnect the client
	   before it starts, and refresh proctitle so it's clear that it's
	   doing autoexpunging. We've also sent DISCONNECT to anvil already,
	   because this is background work and shouldn't really be counted
	   as an active IMAP session for the user.

	   Don't autoexpunge if the client is hibernated - it shouldn't be any
	   different from the non-hibernating IDLE case. For frequent
	   hibernations it could also be doing unnecessarily much work. */
	imap_refresh_proctitle();
	if (!client->hibernated) {
		client->logout_stats.autoexpunged_count = mail_user_autoexpunge(client->user);
		client_log_disconnect(client, reason);
	}
	mail_user_deinit(&client->user);

	/* free the i/ostreams after mail_user_unref(), which could trigger
	   mail_storage_callbacks notifications that write to the ostream. */
	o_stream_destroy(&client->side_channel_output);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);

	if (array_is_created(&client->search_saved_uidset))
		array_free(&client->search_saved_uidset);
	if (array_is_created(&client->search_updates))
		array_free(&client->search_updates);
	pool_unref(&client->command_pool);

	imap_client_count--;
	DLLIST_REMOVE(&imap_clients, client);

	settings_free(client->set);
	settings_free(client->smtp_set);
	event_unref(&client->event);
	i_free(client->last_cmd_name);
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

	client->disconnected = TRUE;
	client->disconnect_reason = p_strdup(client->pool, reason);
	/* Finish the ostream. With IMAP COMPRESS this sends the EOF marker. */
	(void)o_stream_finish(client->output);
	o_stream_uncork(client->output);

	i_stream_close(client->input);
	o_stream_close(client->output);

	timeout_remove(&client->to_idle);
	client->to_idle = timeout_add(0, client_destroy_timeout, client);
}

void client_disconnect_with_error(struct client *client,
				  const char *client_error)
{
	client_send_line(client, t_strconcat("* BYE ", client_error, NULL));
	client_disconnect(client, client_error);
}

void client_add_capability(struct client *client, const char *capability)
{
	/* require a single capability at a time (feels cleaner) */
	i_assert(strchr(capability, ' ') == NULL);
	if (settings_boollist_is_stopped(&client->set->imap_capability)) {
		/* explicit capability - don't change it */
		return;
	}
	str_append_c(client->capability_string, ' ');
	str_append(client->capability_string, capability);
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
	long long msecs_since_cmd;

	if (cmd->stats.start_time.tv_sec == 0)
		return;
	command_stats_flush(cmd);

	ioloop_wait_usecs = io_loop_get_wait_usecs(current_ioloop);
	msecs_in_cmd = (cmd->stats.running_usecs + 999) / 1000;
	msecs_in_ioloop = (ioloop_wait_usecs -
			   cmd->stats.start_ioloop_wait_usecs + 999) / 1000;
	msecs_since_cmd = timeval_diff_msecs(&ioloop_timeval,
					     &cmd->stats.last_run_timeval);

	if (str_data(str)[str_len(str)-1] == '.')
		str_truncate(str, str_len(str)-1);
	str_printfa(str, " (%d.%03d + %d.%03d ",
		    msecs_in_cmd / 1000, msecs_in_cmd % 1000,
		    msecs_in_ioloop / 1000, msecs_in_ioloop % 1000);
	if (msecs_since_cmd > 0) {
		str_printfa(str, "+ %lld.%03lld ",
			    msecs_since_cmd / 1000, msecs_since_cmd % 1000);
	}
	str_append(str, "secs).");
}

void client_send_tagline(struct client_command_context *cmd, const char *data)
{
	cmd->client->v.send_tagline(cmd, data);
}

static void
client_default_send_tagline(struct client_command_context *cmd, const char *data)
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

static int
client_default_sync_notify_more(struct imap_sync_context *ctx ATTR_UNUSED)
{
	return 1;
}

void client_send_command_error(struct client_command_context *cmd,
			       const char *client_error)
{
	struct client *client = cmd->client;
	const char *error, *cmd_name;
	enum imap_parser_error parse_error;

	if (client_error == NULL) {
		client_error = imap_parser_get_error(cmd->parser, &parse_error);
		switch (parse_error) {
		case IMAP_PARSE_ERROR_NONE:
			i_unreached();
		case IMAP_PARSE_ERROR_LITERAL_TOO_BIG:
			client_disconnect_with_error(client, client_error);
			return;
		default:
			break;
		}
	}

	if (cmd->tag == NULL)
		error = t_strconcat("BAD Error in IMAP tag: ", client_error, NULL);
	else if (cmd->name == NULL)
		error = t_strconcat("BAD Error in IMAP command: ", client_error, NULL);
	else {
		cmd_name = t_str_ucase(cmd->name);
		error = t_strconcat("BAD Error in IMAP command ",
				    cmd_name, ": ", client_error, NULL);
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
	int ret;

	i_assert(count <= INT_MAX);

	ret = imap_parser_read_args(cmd->parser, count, flags, args_r);
	if (ret >= (int)count) {
		/* all parameters read successfully */
		i_assert(cmd->client->input_lock == NULL ||
			 cmd->client->input_lock == cmd);

		client_args_finished(cmd, *args_r);
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

void client_args_finished(struct client_command_context *cmd,
			  const struct imap_arg *args)
{
	string_t *str = t_str_new(256);

	if (cmd->args != NULL && cmd->args[0] != '\0') {
		str_append(str, cmd->args);
		str_append_c(str, ' ');
	}
	imap_write_args(str, args);
	cmd->args = p_strdup(cmd->pool, str_c(str));
	event_add_str(cmd->event, "cmd_args", cmd->args);

	str_truncate(str, 0);
	if (cmd->human_args != NULL && cmd->human_args[0] != '\0') {
		str_append(str, cmd->human_args);
		str_append_c(str, ' ');
	}
	imap_write_args_for_human(str, args);
	cmd->human_args = p_strdup(cmd->pool, str_c(str));
	event_add_str(cmd->event, "cmd_human_args", cmd->human_args);
}

static struct client_command_context *
client_command_find_with_flags(struct client_command_context *new_cmd,
			       enum command_flags flags,
			       enum client_command_state max_state)
{
	struct client_command_context *cmd;

	cmd = new_cmd->client->command_queue;
	for (; cmd != NULL; cmd = cmd->next) {
		/* The tagline_sent check is a bit kludgy here. Plugins may
		   hook into sync_notify_more() and send the tagline before
		   finishing the command. During this stage the state was been
		   dropped from _WAIT_SYNC to _WAIT_OUTPUT, so the <= max_state
		   check doesn't work correctly here. (Perhaps we should add
		   a new _WAIT_SYNC_OUTPUT?) */
		if (cmd->state <= max_state && !cmd->tagline_sent &&
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
	cmd->global_event = event_create(client->event);
	cmd->event = event_create(cmd->global_event);
	cmd->stats.start_time = ioloop_timeval;
	cmd->stats.last_run_timeval = ioloop_timeval;
	cmd->stats.start_ioloop_wait_usecs =
		io_loop_get_wait_usecs(current_ioloop);
	p_array_init(&cmd->module_contexts, cmd->pool, 5);

	DLLIST_PREPEND(&client->command_queue, cmd);
	client->command_queue_size++;

	imap_client_notify_command_allocated(client);
	return cmd;
}

void client_command_init_finished(struct client_command_context *cmd)
{
	event_add_str(cmd->global_event, "cmd_tag", cmd->tag);
	/* use "unknown" until we checked that the command name is known/valid */
	event_add_str(cmd->event, "cmd_name", "unknown");
	/* the actual command name received from client - as-is */
	event_add_str(cmd->event, "cmd_input_name", cmd->name);
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

	if (cmd->name != NULL) {
		i_free(client->last_cmd_name);
		client->last_cmd_name = i_strdup(cmd->name);
		client->last_cmd_stats = cmd->stats;
	}

	if (!cmd->param_error)
		client->bad_counter = 0;

	if (client->input_lock == cmd)
		client->input_lock = NULL;
	if (client->mailbox_change_lock == cmd)
		client->mailbox_change_lock = NULL;

	if (!cmd->internal)
		event_set_name(cmd->event, "imap_command_finished");
	if (cmd->tagline_reply != NULL) {
		event_add_str(cmd->event, "tagged_reply_state",
			      t_strcut(cmd->tagline_reply, ' '));
		event_add_str(cmd->event, "tagged_reply", cmd->tagline_reply);
	}
	event_add_timeval(cmd->event, "last_run_time",
			  &cmd->stats.last_run_timeval);
	event_add_int(cmd->event, "running_usecs", cmd->stats.running_usecs);
	event_add_int(cmd->event, "lock_wait_usecs", cmd->stats.lock_wait_usecs);
	event_add_int(cmd->event, "net_in_bytes", cmd->stats.bytes_in);
	event_add_int(cmd->event, "net_out_bytes", cmd->stats.bytes_out);

	if (cmd->name != NULL) {
		string_t *str = t_str_new(128);
		str_printfa(str, "Command finished: %s", cmd->name);
		if (cmd->human_args != NULL)
			str_printfa(str, " %s", cmd->human_args);
		if (cmd->tagline_reply != NULL)
			str_printfa(str, ": %s", cmd->tagline_reply);
		e_debug(cmd->event, "%s", str_c(str));
	}
	event_unref(&cmd->event);
	event_unref(&cmd->global_event);

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
		io_set_pending(client->io);
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

	if (client->disconnected) {
		client_destroy(client, NULL);
		return;
	}

	/* this function is called at the end of I/O callbacks (and only there).
	   fix up the command states and verify that they're correct. */
	while (client_remove_pending_unambiguity(client)) {
		client_add_missing_io(client);

		/* if there's unread data in buffer, handle it. */
		if (i_stream_get_data_size(client->input) == 0 ||
		    client->disconnected)
			break;

		struct ostream *output = client->output;
		o_stream_ref(output);
		o_stream_cork(output);
		bool ret = client_handle_input(client);
		o_stream_uncork(output);
		o_stream_unref(&output);
		if (!ret)
			break;
	}
	if (client->input->closed || client->output->closed)
		client_destroy(client, NULL);
	else
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
	if (i > 0) {
		/* We can be here if an earlier i_stream_read() has returned -2.
		   If there are multiple istreams layers, there might already
		   be input buffered in the istream. Make sure we finish
		   emptying the istream buffers so we don't hang. */
		i_stream_set_input_pending(client->input, TRUE);
	}
	return !client->input_skip_line;
}

static void client_idle_output_timeout(struct client *client)
{
	client_destroy(client, t_strdup_printf(
		"Client has not read server output for %"PRIdTIME_T" secs",
		ioloop_time - client->last_output));
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

static void
client_command_failed_early(struct client_command_context **_cmd,
			    const char *error)
{
	struct client_command_context *cmd = *_cmd;

	/* ignore the rest of this line */
	cmd->client->input_skip_line = TRUE;

	io_loop_time_refresh();
	command_stats_start(cmd);
	client_send_command_error(cmd, error);
	cmd->param_error = TRUE;
	client_command_free(_cmd);
}

static bool client_command_input(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const struct command *command;
	const char *tag, *name;
	int ret;

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
		ret = imap_parser_read_tag(cmd->parser, &tag);
		if (ret == 0)
			return FALSE; /* need more data */
		if (ret < 0) {
			client_command_failed_early(&cmd, "Invalid tag.");
			return TRUE;
		}
		cmd->tag = p_strdup(cmd->pool, tag);
	}

	if (cmd->name == NULL) {
		ret = imap_parser_read_command_name(cmd->parser, &name);
		if (ret == 0)
			return FALSE; /* need more data */
		if (ret < 0) {
			client_command_failed_early(&cmd, "Invalid command name.");
			return TRUE;
		}

		/* UID commands are a special case. better to handle them
		   here. */
		if (!cmd->uid && strcasecmp(name, "UID") == 0) {
			cmd->uid = TRUE;
			return client_command_input(cmd);
		}
		cmd->name = !cmd->uid ? p_strdup(cmd->pool, name) :
			p_strconcat(cmd->pool, "UID ", name, NULL);
		client_command_init_finished(cmd);
		imap_refresh_proctitle();
	}

	client->input_skip_line = TRUE;

	if (cmd->name[0] == '\0') {
		/* command not given - cmd->func is already NULL. */
	} else if ((command = command_find(cmd->name)) != NULL) {
		cmd->func = command->func;
		cmd->cmd_flags = command->flags;
		/* valid command - overwrite the "unknown" string set earlier */
		event_add_str(cmd->global_event, "cmd_name", command->name);
		event_strlist_append(cmd->global_event, "reason_code",
			event_reason_code_prefix("imap", "cmd_", command->name));
		event_add_str(cmd->event, "cmd_name", command->name);
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
		client_command_failed_early(&cmd, "Unknown command.");
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

	i_assert(o_stream_is_corked(client->output) ||
		 client->output->stream_errno != 0);
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

		/* We may have delayed syncing previous commands to handle this
		   one. Do it now to avoid hanging. */
		(void)cmd_sync_delayed(client);
	}
	o_stream_uncork(output);
	o_stream_unref(&output);
	imap_refresh_proctitle();

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

	imap_refresh_proctitle_delayed();
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

bool client_enable(struct client *client, unsigned int feature_idx)
{
	if (client_has_enabled(client, feature_idx))
		return TRUE;

	const struct imap_feature *feat = imap_feature_idx(feature_idx);
	if (!feat->callback(client))
		return FALSE;

	/* set after the callback, so the callback can see what features were
	   previously set */
	bool value = TRUE;
	array_idx_set(&client->enabled_features, feature_idx, &value);
	return TRUE;
}

bool client_has_enabled(struct client *client, unsigned int feature_idx)
{
	if (feature_idx >= array_count(&client->enabled_features))
		return FALSE;
	const bool *featurep =
		array_idx(&client->enabled_features, feature_idx);
	return *featurep;
}

static bool imap_client_enable_condstore(struct client *client)
{
	struct mailbox_status status;
	int ret;

	if (client->mailbox == NULL)
		return TRUE;

	if ((client_enabled_mailbox_features(client) & MAILBOX_FEATURE_CONDSTORE) != 0)
		return TRUE;

	ret = mailbox_enable(client->mailbox, MAILBOX_FEATURE_CONDSTORE);
	if (ret == 0) {
		/* CONDSTORE being enabled while mailbox is selected.
		   Notify client of the latest HIGHESTMODSEQ. */
		ret = mailbox_get_status(client->mailbox,
					 STATUS_HIGHESTMODSEQ, &status);
		if (ret == 0) {
			client_send_line(client, t_strdup_printf(
				"* OK [HIGHESTMODSEQ %"PRIu64"] Highest",
				status.highest_modseq));
		}
	}
	if (ret < 0) {
		client_send_untagged_storage_error(client,
			mailbox_get_storage(client->mailbox));
	}
	return TRUE;
}

static bool imap_client_enable_qresync(struct client *client)
{
	/* enable also CONDSTORE */
	return client_enable(client, imap_feature_condstore);
}

#ifdef EXPERIMENTAL_MAIL_UTF8
static bool imap_client_enable_utf8accept(struct client *client)
{
	if (!client->set->mail_utf8_extensions) {
		e_debug(client->event, "Client attempted to enable UTF8 when it's disabled");
		return FALSE;
	}

	if (client->mailbox != NULL)
		mailbox_enable(client->mailbox, MAILBOX_FEATURE_UTF8ACCEPT);
	return TRUE;
}
#endif

#ifdef EXPERIMENTAL_IMAP4REV2
static bool imap_client_enable_imap4rev2(struct client *client)
{
	if (!client->set->imap4rev2_enable) {
		e_debug(client->event, "Client attempted to enable IMAP4rev2 while it's disabled on the server.");
		return FALSE;
	}

	if (client->mailbox != NULL)
		mailbox_enable(client->mailbox, MAILBOX_FEATURE_IMAP4REV2);

	/* If IMAP4rev2 is enabled always enable QRESYNC */
	client_enable(client, imap_feature_qresync);
	return TRUE;
}
#endif

enum mailbox_feature client_enabled_mailbox_features(struct client *client)
{
	enum mailbox_feature mailbox_features = 0;
	const struct imap_feature *feature;
	const bool *client_enabled;
	unsigned int count;

	client_enabled = array_get(&client->enabled_features, &count);
	for (unsigned int idx = 0; idx < count; idx++) {
		if (client_enabled[idx]) {
			feature = imap_feature_idx(idx);
			mailbox_features |= feature->mailbox_features;
		}
	}
	return mailbox_features;
}

const char *const *client_enabled_features(struct client *client)
{
	ARRAY_TYPE(const_string) feature_strings;
	const struct imap_feature *feature;
	const bool *client_enabled;
	unsigned int count;

	t_array_init(&feature_strings, 8);
	client_enabled = array_get(&client->enabled_features, &count);
	for (unsigned int idx = 0; idx < count; idx++) {
		if (client_enabled[idx]) {
			feature = imap_feature_idx(idx);
			array_push_back(&feature_strings, &feature->feature);
		}
	}
	array_append_zero(&feature_strings);
	return array_front(&feature_strings);
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

void clients_init(void)
{
	imap_feature_condstore =
		imap_feature_register("CONDSTORE", MAILBOX_FEATURE_CONDSTORE,
				      imap_client_enable_condstore);
	imap_feature_qresync =
		imap_feature_register("QRESYNC", MAILBOX_FEATURE_CONDSTORE,
				      imap_client_enable_qresync);
#ifdef EXPERIMENTAL_MAIL_UTF8
	imap_feature_utf8accept =
		imap_feature_register("UTF8=ACCEPT", MAILBOX_FEATURE_UTF8ACCEPT,
				      imap_client_enable_utf8accept);
#endif
#ifdef EXPERIMENTAL_IMAP4REV2
	imap_feature_imap4rev2 =
		imap_feature_register("IMAP4rev2", MAILBOX_FEATURE_IMAP4REV2,
				      imap_client_enable_imap4rev2);

#endif
}

void client_kick(struct client *client, bool shutdown)
{
	mail_storage_service_io_activate_user(client->user->service_user);
	if (client->output_cmd_lock == NULL) {
		client_send_line(client,
				 "* BYE "MASTER_SERVICE_SHUTTING_DOWN_MSG".");
	}
	client_destroy(client, shutdown ?
		       MASTER_SERVICE_SHUTTING_DOWN_MSG :
		       MASTER_SERVICE_USER_KICKED_MSG);
}

void clients_destroy_all(void)
{
	bool shutdown = !master_service_is_user_kicked(master_service);
	while (imap_clients != NULL)
		client_kick(imap_clients, shutdown);
}

struct imap_client_vfuncs imap_client_vfuncs = {
	.init = client_default_init,
	.destroy = client_default_destroy,

	.send_tagline = client_default_send_tagline,
	.sync_notify_more = client_default_sync_notify_more,

	.state_export = imap_state_export_base,
	.state_import = imap_state_import_base,
};
