/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "commands.h"
#include "imap-sync.h"

#include <stdlib.h>

#define DEFAULT_IDLE_CHECK_INTERVAL 30

struct cmd_idle_context {
	struct client *client;

	struct imap_sync_context *sync_ctx;
	struct timeout *to;
	uint32_t dummy_seq;

	unsigned int idle_timeout:1;
	unsigned int sync_pending:1;
};

static int cmd_idle_continue(struct client *client);

static void idle_finish(struct cmd_idle_context *ctx, int done_ok)
{
	struct client *client = ctx->client;

	if (ctx->to != NULL) {
		timeout_remove(ctx->to);
		ctx->to = NULL;
	}

	o_stream_cork(client->output);

	if (ctx->dummy_seq != 0) {
		/* outlook idle workaround */
		client_send_line(client,
			t_strdup_printf("* %u EXPUNGE", ctx->dummy_seq));
	}

	io_remove(client->io);
	client->io = NULL;

	if (client->mailbox != NULL)
		mailbox_notify_changes(client->mailbox, 0, NULL, NULL);

	if (done_ok)
		client_send_tagline(client, "OK Idle completed.");
	else
		client_send_tagline(client, "BAD Expected DONE.");

	o_stream_uncork(client->output);

	client->bad_counter = 0;
	_client_reset_command(client);
}

static void idle_client_input(void *context)
{
        struct cmd_idle_context *ctx = context;
	struct client *client = ctx->client;
	char *line;

	client->last_input = ioloop_time;

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_destroy(client);
		return;
	case -2:
		client->input_skip_line = TRUE;
		idle_finish(ctx, FALSE);
		return;
	}

	while ((line = i_stream_next_line(client->input)) != NULL) {
		if (client->input_skip_line)
			client->input_skip_line = FALSE;
		else {
			idle_finish(ctx, strcmp(line, "DONE") == 0);
			break;
		}
	}
}

static void idle_send_expunge(struct cmd_idle_context *ctx)
{
	struct client *client = ctx->client;

	ctx->dummy_seq = client->messages_count+1;
	client_send_line(client,
			 t_strdup_printf("* %u EXISTS", ctx->dummy_seq));
	mailbox_notify_changes(client->mailbox, 0, NULL, NULL);
}

static void idle_timeout(void *context)
{
	struct cmd_idle_context *ctx = context;

	/* outlook workaround - it hasn't sent anything for a long time and
	   we're about to disconnect unless it does something. send a fake
	   EXISTS to see if it responds. it's expunged later. */

	timeout_remove(ctx->to);
	ctx->to = NULL;

	if (ctx->sync_ctx != NULL) {
		/* we're already syncing.. do this after it's finished */
		ctx->idle_timeout = TRUE;
		return;
	}

	idle_send_expunge(ctx);
}

static void idle_callback(struct mailbox *box, void *context)
{
        struct cmd_idle_context *ctx = context;

	if (ctx->sync_ctx != NULL)
		ctx->sync_pending = TRUE;
	else {
		ctx->sync_pending = FALSE;
		ctx->sync_ctx = imap_sync_init(ctx->client, box, 0);
		cmd_idle_continue(ctx->client);
	}
}

static int cmd_idle_continue(struct client *client)
{
	struct cmd_idle_context *ctx = client->cmd_context;

	if (client->output->closed) {
		idle_finish(ctx, FALSE);
		return TRUE;
	}

	if (ctx->sync_ctx != NULL) {
		if (imap_sync_more(ctx->sync_ctx) == 0) {
			/* unfinished */
			return FALSE;
		}

		if (imap_sync_deinit(ctx->sync_ctx) < 0) {
			client_send_untagged_storage_error(client,
				mailbox_get_storage(client->mailbox));
			mailbox_notify_changes(client->mailbox, 0, NULL, NULL);
		}
		ctx->sync_ctx = NULL;
	}

	if (ctx->idle_timeout) {
		/* outlook workaround */
		idle_send_expunge(ctx);
	} else if (ctx->sync_pending) {
		/* more changes occured while we were sending changes to
		   client */
                idle_callback(client->mailbox, client);
	}

	return FALSE;
}

int cmd_idle(struct client *client)
{
	struct cmd_idle_context *ctx;
	const char *str;
	unsigned int interval;

	ctx = p_new(client->cmd_pool, struct cmd_idle_context, 1);
	ctx->client = client;

	if ((client_workarounds & WORKAROUND_OUTLOOK_IDLE) != 0 &&
	    client->mailbox != NULL) {
		ctx->to = timeout_add((CLIENT_IDLE_TIMEOUT - 60) * 1000,
				      idle_timeout, ctx);
	}

	str = getenv("MAILBOX_IDLE_CHECK_INTERVAL");
	interval = str == NULL ? 0 : (unsigned int)strtoul(str, NULL, 10);
	if (interval == 0)
		interval = DEFAULT_IDLE_CHECK_INTERVAL;

	if (client->mailbox != NULL) {
		mailbox_notify_changes(client->mailbox, interval,
				       idle_callback, ctx);
	}
	client_send_line(client, "+ idling");

	io_remove(client->io);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, idle_client_input, ctx);

	client->command_pending = TRUE;
	client->cmd_func = cmd_idle_continue;
	client->cmd_context = ctx;
	return FALSE;
}
