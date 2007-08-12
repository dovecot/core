/* Copyright (C) 2002-2004 Timo Sirainen */

#include "common.h"
#include "array.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "message-send.h"
#include "message-size.h"
#include "imap-date.h"
#include "commands.h"
#include "imap-fetch.h"
#include "imap-util.h"

#include <stdlib.h>

#define BODY_NIL_REPLY \
	"\"text\" \"plain\" NIL NIL NIL \"7bit\" 0 0 NIL NIL NIL"

const struct imap_fetch_handler default_handlers[7];
static buffer_t *fetch_handlers = NULL;

static int imap_fetch_handler_cmp(const void *p1, const void *p2)
{
        const struct imap_fetch_handler *h1 = p1, *h2 = p2;

	return strcmp(h1->name, h2->name);
}

void imap_fetch_handlers_register(const struct imap_fetch_handler *handlers,
				  size_t count)
{
	void *data;
	size_t size;

	if (fetch_handlers == NULL)
		fetch_handlers = buffer_create_dynamic(default_pool, 128);
	buffer_append(fetch_handlers, handlers, sizeof(*handlers) * count);

	data = buffer_get_modifiable_data(fetch_handlers, &size);
	qsort(data, size / sizeof(*handlers), sizeof(*handlers),
	      imap_fetch_handler_cmp);
}

static int imap_fetch_handler_bsearch(const void *name_p, const void *handler_p)
{
	const char *name = name_p;
        const struct imap_fetch_handler *h = handler_p;
	int i;

	for (i = 0; h->name[i] != '\0'; i++) {
		if (h->name[i] != name[i]) {
			if (name[i] < 'A' || name[i] >= 'Z')
				return -1;
			return name[i] - h->name[i];
		}
	}

	return name[i] < 'A' || name[i] >= 'Z' ? 0 : -1;
}

bool imap_fetch_init_handler(struct imap_fetch_context *ctx, const char *name,
			     const struct imap_arg **args)
{
	const struct imap_fetch_handler *handler;

	handler = bsearch(name, fetch_handlers->data,
			  fetch_handlers->used /
			  sizeof(struct imap_fetch_handler),
                          sizeof(struct imap_fetch_handler),
			  imap_fetch_handler_bsearch);
	if (handler == NULL) {
		client_send_command_error(ctx->cmd,
			t_strconcat("Unknown command ", name, NULL));
		return FALSE;
	}

	return handler->init(ctx, name, args);
}

struct imap_fetch_context *imap_fetch_init(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct imap_fetch_context *ctx;

	if (fetch_handlers == NULL) {
		imap_fetch_handlers_register(default_handlers,
					     sizeof(default_handlers) /
					     sizeof(default_handlers[0]));
	}

	ctx = p_new(cmd->pool, struct imap_fetch_context, 1);
	ctx->client = client;
	ctx->cmd = cmd;
	ctx->box = client->mailbox;

	ctx->cur_str = str_new(default_pool, 8192);
	ctx->all_headers_buf = buffer_create_dynamic(cmd->pool, 128);
	p_array_init(&ctx->handlers, cmd->pool, 16);
	ctx->line_finished = TRUE;
	return ctx;
}

#undef imap_fetch_add_handler
void imap_fetch_add_handler(struct imap_fetch_context *ctx,
			    bool buffered, bool want_deinit,
			    const char *name, const char *nil_reply,
			    imap_fetch_handler_t *handler, void *context)
{
	/* partially because of broken clients, but also partially because
	   it potentially can make client implementations faster, we have a
	   buffered parameter which basically means that the handler promises
	   to write the output in ctx->cur_str. The cur_str is then sent to
	   client before calling any non-buffered handlers.

	   We try to keep the handler registration order the same as the
	   client requested them. This is especially useful to get UID
	   returned first, which some clients rely on..
	*/
	const struct imap_fetch_context_handler *handlers;
	struct imap_fetch_context_handler h;
	unsigned int i, size;

	if (context == NULL) {
		/* don't allow duplicate handlers */
		handlers = array_get(&ctx->handlers, &size);

		for (i = 0; i < size; i++) {
			if (handlers[i].handler == handler &&
			    handlers[i].context == NULL)
				return;
		}
	}

	memset(&h, 0, sizeof(h));
	h.handler = handler;
	h.context = context;
	h.buffered = buffered;
	h.want_deinit = want_deinit;
	h.name = p_strdup(ctx->cmd->pool, name);
	h.nil_reply = p_strdup(ctx->cmd->pool, nil_reply);

	if (!buffered)
		array_append(&ctx->handlers, &h, 1);
	else {
		array_insert(&ctx->handlers, ctx->buffered_handlers_count,
			     &h, 1);
                ctx->buffered_handlers_count++;
	}
}

void imap_fetch_begin(struct imap_fetch_context *ctx,
		      struct mail_search_arg *search_arg)
{
	const void *null = NULL;
	const void *data;

	if (ctx->flags_update_seen) {
		if (mailbox_is_readonly(ctx->box))
			ctx->flags_update_seen = FALSE;
		else if (!ctx->flags_have_handler) {
			ctx->flags_show_only_seen_changes = TRUE;
			(void)imap_fetch_init_handler(ctx, "FLAGS", NULL);
		}
	}

	if (buffer_get_used_size(ctx->all_headers_buf) != 0 &&
	    ((ctx->fetch_data & (MAIL_FETCH_STREAM_HEADER |
				 MAIL_FETCH_STREAM_BODY)) == 0)) {
		buffer_append(ctx->all_headers_buf, &null, sizeof(null));

		data = buffer_get_data(ctx->all_headers_buf, NULL);
		ctx->all_headers_ctx =
			mailbox_header_lookup_init(ctx->box, data);
	}

	if ((ctx->fetch_data &
	     (MAIL_FETCH_STREAM_HEADER | MAIL_FETCH_STREAM_BODY)) != 0)
		ctx->fetch_data |= MAIL_FETCH_NUL_STATE;

	ctx->trans = mailbox_transaction_begin(ctx->box,
		MAILBOX_TRANSACTION_FLAG_HIDE);
	ctx->select_counter = ctx->client->select_counter;
	ctx->mail = mail_alloc(ctx->trans, ctx->fetch_data,
			       ctx->all_headers_ctx);
	ctx->search_ctx =
		mailbox_search_init(ctx->trans, NULL, search_arg, NULL);
}

static int imap_fetch_flush_buffer(struct imap_fetch_context *ctx)
{
	const unsigned char *data;
	size_t len;

	data = str_data(ctx->cur_str);
	len = str_len(ctx->cur_str);

	/* there's an extra space at the end if we added any fetch items
	   to buffer */
	if (data[len-1] == ' ') {
		len--;
		ctx->first = FALSE;
	}

	if (o_stream_send(ctx->client->output, data, len) < 0)
		return -1;

	str_truncate(ctx->cur_str, 0);
	return 0;
}

static int imap_fetch_send_nil_reply(struct imap_fetch_context *ctx)
{
	const struct imap_fetch_context_handler *handler;

	if (!ctx->first)
		str_append_c(ctx->cur_str, ' ');

	handler = array_idx(&ctx->handlers, ctx->cur_handler);
	str_printfa(ctx->cur_str, "%s %s ",
		    handler->name, handler->nil_reply);

	if (!handler->buffered) {
		if (imap_fetch_flush_buffer(ctx) < 0)
			return -1;
	}
	return 0;
}

int imap_fetch(struct imap_fetch_context *ctx)
{
	struct client *client = ctx->client;
	const struct imap_fetch_context_handler *handlers;
	unsigned int count;
	int ret;

	if (ctx->cont_handler != NULL) {
		ret = ctx->cont_handler(ctx);
		if (ret == 0)
			return 0;

		if (ret < 0) {
			if (ctx->client->output->closed)
				return -1;

			if (ctx->cur_mail->expunged) {
				/* not an error, just lost it. */
				ctx->partial_fetch = TRUE;
				if (imap_fetch_send_nil_reply(ctx) < 0)
					return -1;
			} else {
				return -1;
			}
		}

		ctx->cont_handler = NULL;
		ctx->cur_offset = 0;
                ctx->cur_handler++;
	}

	/* assume initially that we're locking it */
	i_assert(client->output_lock == NULL ||
		 client->output_lock == ctx->cmd);
	client->output_lock = ctx->cmd;

	handlers = array_get(&ctx->handlers, &count);
	for (;;) {
		if (o_stream_get_buffer_used_size(client->output) >=
		    CLIENT_OUTPUT_OPTIMAL_SIZE) {
			ret = o_stream_flush(client->output);
			if (ret <= 0) {
				if (!ctx->line_partial) {
					/* last line was fully sent */
					client->output_lock = NULL;
				}
				return ret;
			}
		}

		if (ctx->cur_mail == NULL) {
			if (ctx->cmd->cancel)
				return 1;

			if (ctx->cur_input != NULL)
				i_stream_unref(&ctx->cur_input);

			if (mailbox_search_next(ctx->search_ctx,
						ctx->mail) <= 0)
				break;
			ctx->cur_mail = ctx->mail;

			str_printfa(ctx->cur_str, "* %u FETCH (",
				    ctx->cur_mail->seq);
			ctx->first = TRUE;
			ctx->line_finished = FALSE;
		}

		for (; ctx->cur_handler < count; ctx->cur_handler++) {
			if (str_len(ctx->cur_str) > 0 &&
			    !handlers[ctx->cur_handler].buffered) {
				/* first non-buffered handler.
				   flush the buffer. */
				ctx->line_partial = TRUE;
				if (imap_fetch_flush_buffer(ctx) < 0)
					return -1;
			}

			t_push();
			ret = handlers[ctx->cur_handler].
				handler(ctx, ctx->cur_mail,
					handlers[ctx->cur_handler].context);
			t_pop();

			if (ret == 0) {
				if (!ctx->line_partial) {
					/* last line was fully sent */
					client->output_lock = NULL;
				}
				return 0;
			}

			if (ret < 0) {
				if (ctx->cur_mail->expunged) {
					/* not an error, just lost it. */
					ctx->partial_fetch = TRUE;
					if (imap_fetch_send_nil_reply(ctx) < 0)
						return -1;
				} else {
					i_assert(ret < 0 ||
						 ctx->cont_handler != NULL);
					return -1;
				}
			}

			ctx->cont_handler = NULL;
			ctx->cur_offset = 0;
		}

		if (str_len(ctx->cur_str) > 0) {
			/* no non-buffered handlers */
			if (imap_fetch_flush_buffer(ctx) < 0)
				return -1;
		}

		ctx->line_finished = TRUE;
		ctx->line_partial = FALSE;
		if (o_stream_send(client->output, ")\r\n", 3) < 0)
			return -1;
		ctx->client->last_output = ioloop_time;

		ctx->cur_mail = NULL;
		ctx->cur_handler = 0;
	}

	return 1;
}

int imap_fetch_deinit(struct imap_fetch_context *ctx)
{
	const struct imap_fetch_context_handler *handlers;
	unsigned int i, count;

	handlers = array_get(&ctx->handlers, &count);
	for (i = 0; i < count; i++) {
		if (handlers[i].want_deinit)
			handlers[i].handler(ctx, NULL, handlers[i].context);
	}

	if (!ctx->line_finished) {
		if (imap_fetch_flush_buffer(ctx) < 0)
			ctx->failed = TRUE;
		if (o_stream_send(ctx->client->output, ")\r\n", 3) < 0)
			ctx->failed = TRUE;
	}
	str_free(&ctx->cur_str);

	if (ctx->cur_input != NULL)
		i_stream_unref(&ctx->cur_input);

	if (ctx->mail != NULL)
		mail_free(&ctx->mail);

	if (ctx->search_ctx != NULL) {
		if (mailbox_search_deinit(&ctx->search_ctx) < 0)
			ctx->failed = TRUE;
	}
	if (ctx->all_headers_ctx != NULL)
		mailbox_header_lookup_deinit(&ctx->all_headers_ctx);

	if (ctx->trans != NULL) {
		/* even if something failed, we want to commit changes to
		   cache, as well as possible \Seen flag changes for FETCH
		   replies we returned so far. */
		if (mailbox_transaction_commit(&ctx->trans, 0) < 0)
			ctx->failed = TRUE;
	}
	return ctx->failed ? -1 : 0;
}

static int fetch_body(struct imap_fetch_context *ctx, struct mail *mail,
		      void *context __attr_unused__)
{
	const char *body;

	body = mail_get_special(mail, MAIL_FETCH_IMAP_BODY);
	if (body == NULL)
		return -1;

	if (ctx->first)
		ctx->first = FALSE;
	else {
		if (o_stream_send(ctx->client->output, " ", 1) < 0)
			return -1;
	}

	if (o_stream_send(ctx->client->output, "BODY (", 6) < 0 ||
	    o_stream_send_str(ctx->client->output, body) < 0 ||
	    o_stream_send(ctx->client->output, ")", 1) < 0)
		return -1;
	return 1;
}

static bool fetch_body_init(struct imap_fetch_context *ctx, const char *name,
			    const struct imap_arg **args)
{
	if (name[4] == '\0') {
		ctx->fetch_data |= MAIL_FETCH_IMAP_BODY;
		imap_fetch_add_handler(ctx, FALSE, FALSE, name,
				       "("BODY_NIL_REPLY")", fetch_body, NULL);
		return TRUE;
	}
	return fetch_body_section_init(ctx, name, args);
}

static int fetch_bodystructure(struct imap_fetch_context *ctx,
			       struct mail *mail, void *context __attr_unused__)
{
	const char *bodystructure;

	bodystructure = mail_get_special(mail, MAIL_FETCH_IMAP_BODYSTRUCTURE);
	if (bodystructure == NULL)
		return -1;

	if (ctx->first)
		ctx->first = FALSE;
	else {
		if (o_stream_send(ctx->client->output, " ", 1) < 0)
			return -1;
	}

	if (o_stream_send(ctx->client->output, "BODYSTRUCTURE (", 15) < 0 ||
	    o_stream_send_str(ctx->client->output, bodystructure) < 0 ||
	    o_stream_send(ctx->client->output, ")", 1) < 0)
		return -1;

	return 1;
}

static bool
fetch_bodystructure_init(struct imap_fetch_context *ctx, const char *name,
			 const struct imap_arg **args __attr_unused__)
{
	ctx->fetch_data |= MAIL_FETCH_IMAP_BODYSTRUCTURE;
	imap_fetch_add_handler(ctx, FALSE, FALSE, name,
			       "("BODY_NIL_REPLY" NIL NIL NIL NIL)",
			       fetch_bodystructure, NULL);
	return TRUE;
}

static int fetch_envelope(struct imap_fetch_context *ctx, struct mail *mail,
			  void *context __attr_unused__)
{
	const char *envelope;

	envelope = mail_get_special(mail, MAIL_FETCH_IMAP_ENVELOPE);
	if (envelope == NULL)
		return -1;

	if (ctx->first)
		ctx->first = FALSE;
	else {
		if (o_stream_send(ctx->client->output, " ", 1) < 0)
			return -1;
	}

	if (o_stream_send(ctx->client->output, "ENVELOPE (", 10) < 0 ||
	    o_stream_send_str(ctx->client->output, envelope) < 0 ||
	    o_stream_send(ctx->client->output, ")", 1) < 0)
		return -1;
	return 1;
}

static bool
fetch_envelope_init(struct imap_fetch_context *ctx, const char *name,
		    const struct imap_arg **args __attr_unused__)
{
	ctx->fetch_data |= MAIL_FETCH_IMAP_ENVELOPE;
	imap_fetch_add_handler(ctx, FALSE, FALSE, name,
			       "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)",
			       fetch_envelope, NULL);
	return TRUE;
}

static int fetch_flags(struct imap_fetch_context *ctx, struct mail *mail,
		       void *context __attr_unused__)
{
	enum mail_flags flags;
	const char *const *keywords;

	flags = mail_get_flags(mail);
	keywords = mail_get_keywords(mail);

	if (ctx->flags_update_seen && (flags & MAIL_SEEN) == 0) {
		/* Add \Seen flag */
		flags |= MAIL_SEEN;
		mail_update_flags(mail, MODIFY_ADD, MAIL_SEEN);
	} else if (ctx->flags_show_only_seen_changes) {
		return 1;
	}

	str_append(ctx->cur_str, "FLAGS (");
	imap_write_flags(ctx->cur_str, flags, keywords);
	str_append(ctx->cur_str, ") ");
	return 1;
}

static bool
fetch_flags_init(struct imap_fetch_context *ctx, const char *name,
		 const struct imap_arg **args __attr_unused__)
{
	ctx->flags_have_handler = TRUE;
	ctx->fetch_data |= MAIL_FETCH_FLAGS;
	imap_fetch_add_handler(ctx, TRUE, FALSE, name, "()", fetch_flags, NULL);
	return TRUE;
}

static int fetch_internaldate(struct imap_fetch_context *ctx, struct mail *mail,
			      void *context __attr_unused__)
{
	time_t time;

	time = mail_get_received_date(mail);
	if (time == (time_t)-1)
		return -1;

	str_printfa(ctx->cur_str, "INTERNALDATE \"%s\" ",
		    imap_to_datetime(time));
	return 1;
}

static bool
fetch_internaldate_init(struct imap_fetch_context *ctx, const char *name,
			const struct imap_arg **args __attr_unused__)
{
	ctx->fetch_data |= MAIL_FETCH_RECEIVED_DATE;
	imap_fetch_add_handler(ctx, TRUE, FALSE, name,
			       "\"01-01-1970 00:00:00 +0000\"",
			       fetch_internaldate, NULL);
	return TRUE;
}

static int fetch_uid(struct imap_fetch_context *ctx, struct mail *mail,
		     void *context __attr_unused__)
{
	str_printfa(ctx->cur_str, "UID %u ", mail->uid);
	return 1;
}

static bool
fetch_uid_init(struct imap_fetch_context *ctx __attr_unused__, const char *name,
	       const struct imap_arg **args __attr_unused__)
{
	imap_fetch_add_handler(ctx, TRUE, FALSE, name, NULL, fetch_uid, NULL);
	return TRUE;
}

const struct imap_fetch_handler default_handlers[7] = {
	{ "BODY", fetch_body_init },
	{ "BODYSTRUCTURE", fetch_bodystructure_init },
	{ "ENVELOPE", fetch_envelope_init },
	{ "FLAGS", fetch_flags_init },
	{ "INTERNALDATE", fetch_internaldate_init },
	{ "RFC822", fetch_rfc822_init },
	{ "UID", fetch_uid_init }
};
