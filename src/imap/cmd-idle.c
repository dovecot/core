/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "net.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "crc32.h"
#include "mail-storage-settings.h"
#include "imap-commands.h"
#include "imap-sync.h"

#include <stdlib.h>

struct cmd_idle_context {
	struct client *client;
	struct client_command_context *cmd;

	struct imap_sync_context *sync_ctx;
	struct timeout *keepalive_to;

	unsigned int manual_cork:1;
	unsigned int sync_pending:1;
};

static void idle_add_keepalive_timeout(struct cmd_idle_context *ctx);
static bool cmd_idle_continue(struct client_command_context *cmd);

static void
idle_finish(struct cmd_idle_context *ctx, bool done_ok, bool free_cmd)
{
	struct client *client = ctx->client;

	if (ctx->keepalive_to != NULL)
		timeout_remove(&ctx->keepalive_to);

	if (ctx->sync_ctx != NULL) {
		/* we're here only in connection failure cases */
		(void)imap_sync_deinit(ctx->sync_ctx, ctx->cmd);
	}

	o_stream_cork(client->output);
	if (client->io != NULL)
		io_remove(&client->io);

	if (client->mailbox != NULL)
		mailbox_notify_changes_stop(client->mailbox);

	if (done_ok)
		client_send_tagline(ctx->cmd, "OK Idle completed.");
	else
		client_send_tagline(ctx->cmd, "BAD Expected DONE.");

	o_stream_uncork(client->output);
	if (free_cmd)
		client_command_free(&ctx->cmd);
}

static bool
idle_client_handle_input(struct cmd_idle_context *ctx, bool free_cmd)
{
	const char *line;

	while ((line = i_stream_next_line(ctx->client->input)) != NULL) {
		if (ctx->client->input_skip_line)
			ctx->client->input_skip_line = FALSE;
		else {
			idle_finish(ctx, strcasecmp(line, "DONE") == 0,
				    free_cmd);
			return TRUE;
		}
	}
	return FALSE;
}

static void idle_client_input_more(struct cmd_idle_context *ctx)
{
	struct client *client = ctx->client;

	client->last_input = ioloop_time;
	timeout_reset(client->to_idle);

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_disconnect(client, "Disconnected in IDLE");
		return;
	case -2:
		client->input_skip_line = TRUE;
		idle_finish(ctx, FALSE, TRUE);
		client_continue_pending_input(client);
		return;
	}

	if (ctx->sync_ctx != NULL) {
		/* we're still sending output to client. wait until it's all
		   sent so we don't lose any changes. */
		io_remove(&client->io);
		return;
	}

	if (idle_client_handle_input(ctx, TRUE)) {
		if (!client->disconnected)
			client_continue_pending_input(client);
	}
}

static void idle_client_input(struct cmd_idle_context *ctx)
{
	struct client *client = ctx->client;

	idle_client_input_more(ctx);
	if (client->disconnected)
		client_destroy(client, NULL);
}

static void keepalive_timeout(struct cmd_idle_context *ctx)
{
	if (ctx->client->output_cmd_lock != NULL) {
		/* it's busy sending output */
		return;
	}

	if (o_stream_get_buffer_used_size(ctx->client->output) == 0) {
		/* Sending this keeps NATs/stateful firewalls alive.
		   Sending this also catches dead connections. Don't send
		   anything if there is already data waiting in output
		   buffer. */
		o_stream_cork(ctx->client->output);
		client_send_line(ctx->client, "* OK Still here");
		o_stream_uncork(ctx->client->output);
	}
	/* Make sure idling connections don't get disconnected. There are
	   several clients that really want to IDLE forever and there's not
	   much harm in letting them do so. */
	timeout_reset(ctx->client->to_idle);
	/* recalculate time for the next keepalive timeout */
	idle_add_keepalive_timeout(ctx);
}

static void idle_sync_now(struct mailbox *box, struct cmd_idle_context *ctx)
{
	i_assert(ctx->sync_ctx == NULL);

	ctx->sync_pending = FALSE;
	ctx->sync_ctx = imap_sync_init(ctx->client, box, 0, 0);
	(void)cmd_idle_continue(ctx->cmd);
}

static void idle_callback(struct mailbox *box, struct cmd_idle_context *ctx)
{
	struct client *client = ctx->client;

	if (ctx->sync_ctx != NULL)
		ctx->sync_pending = TRUE;
	else {
		ctx->manual_cork = TRUE;
		idle_sync_now(box, ctx);
		if (client->disconnected)
			client_destroy(client, NULL);
	}
}

static bool remote_ip_is_usable(const struct ip_addr *ip)
{
	unsigned int addr;

	if (ip->family == 0)
		return FALSE;
	if (ip->family == AF_INET) {
		addr = ip->u.ip4.s_addr;
		if (addr >= 167772160 && addr <= 184549375)
			return FALSE; /* 10/8 */
		if (addr >= 3232235520 && addr <= 3232301055)
			return FALSE; /* 192.168/16 */
		if (addr >= 2886729728 && addr <= 2887778303)
			return FALSE; /* 172.16/12 */
		if (addr >= 2130706432 && addr <= 2147483647)
			return FALSE; /* 127/8 */
	}
#ifdef HAVE_IPV6
	else if (ip->family == AF_INET6) {
		addr = ip->u.ip6.s6_addr[0];
		if (addr == 0xfc || addr == 0xfd)
			return FALSE; /* fc00::/7 */
	}
#endif
	return TRUE;
}

static void idle_add_keepalive_timeout(struct cmd_idle_context *ctx)
{
	unsigned int interval = ctx->client->set->imap_idle_notify_interval;
	unsigned int client_hash;

	if (interval == 0)
		return;

	/* set the interval so that the client gets the keepalive notifications
	   at exactly the same time for all the connections. this helps to
	   reduce battery usage in mobile devices. but we don't really want to
	   send this notification for everyone at the same time, because it
	   would cause huge peaks of activity.

	   basing the notifications on the username works well for one account,
	   but basing it on the IP address allows the client to get all of the
	   notifications at the same time for multiple accounts as well (of
	   course assuming Dovecot is running on all the servers :)

	   one potential downside to using IP is that if a proxy hides the
	   client's IP address notifications are sent to everyone at the same
	   time, but this can be avoided by using a properly configured Dovecot
	   proxy. we'll also try to avoid this by not doing it for the commonly
	   used intranet IP ranges. */
	client_hash = ctx->client->user->remote_ip != NULL &&
		remote_ip_is_usable(ctx->client->user->remote_ip) ?
		net_ip_hash(ctx->client->user->remote_ip) :
		crc32_str(ctx->client->user->username);
	interval -= (time(NULL) + client_hash) % interval;

	if (ctx->keepalive_to != NULL)
		timeout_remove(&ctx->keepalive_to);
	ctx->keepalive_to = timeout_add(interval * 1000,
					keepalive_timeout, ctx);
}

static bool cmd_idle_continue(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_idle_context *ctx = cmd->context;
	uoff_t orig_offset = client->output->offset;

	if (cmd->cancel) {
		idle_finish(ctx, FALSE, FALSE);
		return TRUE;
	}

	if (ctx->manual_cork)  {
		/* we're coming from idle_callback instead of a normal
		   I/O handler, so we'll have to do corking manually */
		o_stream_cork(client->output);
	}

	if (ctx->sync_ctx != NULL) {
		if (imap_sync_more(ctx->sync_ctx) == 0) {
			/* unfinished */
			if (ctx->manual_cork) {
				ctx->manual_cork = FALSE;
				o_stream_uncork(client->output);
			}
			cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;
			return FALSE;
		}

		if (imap_sync_deinit(ctx->sync_ctx, ctx->cmd) < 0) {
			client_send_untagged_storage_error(client,
				mailbox_get_storage(client->mailbox));
			mailbox_notify_changes_stop(client->mailbox);
		}
		ctx->sync_ctx = NULL;
	}
	if (client->output->offset != orig_offset &&
	    ctx->keepalive_to != NULL)
		idle_add_keepalive_timeout(ctx);

	if (ctx->sync_pending) {
		/* more changes occurred while we were sending changes to
		   client */
		idle_sync_now(client->mailbox, ctx);
		/* NOTE: this recurses back to this function,
		   so we return here instead of doing everything twice. */
		return FALSE;
	}
	cmd->state = CLIENT_COMMAND_STATE_WAIT_INPUT;

	if (ctx->manual_cork) {
		ctx->manual_cork = FALSE;
		o_stream_uncork(client->output);
	}

	if (client->output->closed) {
		idle_finish(ctx, FALSE, FALSE);
		return TRUE;
	}
	if (client->io == NULL) {
		/* input is pending */
		client->io = io_add(i_stream_get_fd(client->input),
				    IO_READ, idle_client_input, ctx);
		idle_client_input_more(ctx);
	}
	return FALSE;
}

bool cmd_idle(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_idle_context *ctx;

	ctx = p_new(cmd->pool, struct cmd_idle_context, 1);
	ctx->cmd = cmd;
	ctx->client = client;
	idle_add_keepalive_timeout(ctx);

	if (client->mailbox != NULL)
		mailbox_notify_changes(client->mailbox, idle_callback, ctx);
	client_send_line(client, "+ idling");

	io_remove(&client->io);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, idle_client_input, ctx);

	cmd->func = cmd_idle_continue;
	cmd->context = ctx;

	/* check immediately if there are changes. if they came before we
	   added mailbox-notifier, we wouldn't see them otherwise. */
	if (client->mailbox != NULL)
		idle_sync_now(client->mailbox, ctx);
	return idle_client_handle_input(ctx, FALSE);
}
