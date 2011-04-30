/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "array.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "message-send.h"
#include "message-size.h"
#include "imap-date.h"
#include "imap-utf7.h"
#include "mail-search-build.h"
#include "imap-commands.h"
#include "imap-quote.h"
#include "imap-fetch.h"
#include "imap-util.h"

#include <stdlib.h>
#include <ctype.h>

#define BODY_NIL_REPLY \
	"\"text\" \"plain\" NIL NIL NIL \"7bit\" 0 0"
#define ENVELOPE_NIL_REPLY \
	"(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"

static ARRAY_DEFINE(fetch_handlers, struct imap_fetch_handler);

static int imap_fetch_handler_cmp(const struct imap_fetch_handler *h1,
				  const struct imap_fetch_handler *h2)
{
	return strcmp(h1->name, h2->name);
}

void imap_fetch_handlers_register(const struct imap_fetch_handler *handlers,
				  size_t count)
{
	array_append(&fetch_handlers, handlers, count);
	array_sort(&fetch_handlers, imap_fetch_handler_cmp);
}

static int
imap_fetch_handler_bsearch(const char *name, const struct imap_fetch_handler *h)
{
	return strcmp(name, h->name);
}

bool imap_fetch_init_handler(struct imap_fetch_context *ctx, const char *name,
			     const struct imap_arg **args)
{
	const struct imap_fetch_handler *handler;
	const char *lookup_name, *p;

	for (p = name; i_isalnum(*p) || *p == '-'; p++) ;
	lookup_name = t_strdup_until(name, p);

	handler = array_bsearch(&fetch_handlers, lookup_name,
				imap_fetch_handler_bsearch);
	if (handler == NULL) {
		client_send_command_error(ctx->cmd,
			t_strconcat("Unknown parameter ", name, NULL));
		return FALSE;
	}

	return handler->init(ctx, name, args);
}

struct imap_fetch_context *
imap_fetch_init(struct client_command_context *cmd, struct mailbox *box)
{
	struct client *client = cmd->client;
	struct imap_fetch_context *ctx;

	ctx = p_new(cmd->pool, struct imap_fetch_context, 1);
	ctx->client = client;
	ctx->cmd = cmd;
	ctx->box = box;

	ctx->cur_str = str_new(default_pool, 8192);
	p_array_init(&ctx->all_headers, cmd->pool, 64);
	p_array_init(&ctx->handlers, cmd->pool, 16);
	p_array_init(&ctx->tmp_keywords, cmd->pool,
		     client->keywords.announce_count + 8);
	ctx->line_finished = TRUE;
	return ctx;
}

bool imap_fetch_add_changed_since(struct imap_fetch_context *ctx,
				  uint64_t modseq)
{
	struct mail_search_arg *search_arg;

	search_arg = p_new(ctx->search_args->pool, struct mail_search_arg, 1);
	search_arg->type = SEARCH_MODSEQ;
	search_arg->value.modseq =
		p_new(ctx->cmd->pool, struct mail_search_modseq, 1);
	search_arg->value.modseq->modseq = modseq + 1;

	search_arg->next = ctx->search_args->args->next;
	ctx->search_args->args->next = search_arg;

	return imap_fetch_init_handler(ctx, "MODSEQ", NULL);
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
	const struct imap_fetch_context_handler *ctx_handler;
	struct imap_fetch_context_handler h;

	if (context == NULL) {
		/* don't allow duplicate handlers */
		array_foreach(&ctx->handlers, ctx_handler) {
			if (ctx_handler->handler == handler &&
			    ctx_handler->context == NULL)
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

static void
expunges_drop_known(struct imap_fetch_context *ctx,
		    struct mailbox_transaction_context *trans,
		    ARRAY_TYPE(seq_range) *expunged_uids)
{
	struct mailbox_status status;
	struct mail *mail;
	const uint32_t *seqs, *uids;
	unsigned int i, count;

	seqs = array_get(ctx->qresync_sample_seqset, &count);
	uids = array_idx(ctx->qresync_sample_uidset, 0);
	i_assert(array_count(ctx->qresync_sample_uidset) == count);
	i_assert(count > 0);

	mailbox_get_open_status(ctx->box, STATUS_MESSAGES, &status);
	mail = mail_alloc(trans, 0, NULL);

	/* FIXME: we could do removals from the middle as well */
	for (i = 0; i < count && seqs[i] <= status.messages; i++) {
		mail_set_seq(mail, seqs[i]);
		if (uids[i] != mail->uid)
			break;
	}
	if (i > 0)
		seq_range_array_remove_range(expunged_uids, 1, uids[i-1]);
	mail_free(&mail);
}

static int get_expunges_fallback(struct imap_fetch_context *ctx,
				 const ARRAY_TYPE(seq_range) *uid_filter_arr,
				 ARRAY_TYPE(seq_range) *expunged_uids)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	const struct seq_range *uid_filter;
	struct mailbox_status status;
	unsigned int i, count;
	uint32_t next_uid;
	int ret = 0;

	uid_filter = array_get(uid_filter_arr, &count);
	i_assert(count > 0);
	i = 0;
	next_uid = uid_filter[0].seq1;

	/* search UIDs only in given range */
	search_args = mail_search_build_init();
	search_args->args = p_new(search_args->pool, struct mail_search_arg, 1);
	search_args->args->type = SEARCH_UIDSET;
	i_array_init(&search_args->args->value.seqset, count);
	array_append_array(&search_args->args->value.seqset, uid_filter_arr);

	trans = mailbox_transaction_begin(ctx->box, 0);
	search_ctx = mailbox_search_init(trans, search_args, NULL, 0, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(search_ctx, &mail)) {
		if (mail->uid == next_uid) {
			if (next_uid < uid_filter[i].seq2)
				next_uid++;
			else if (++i < count)
				next_uid = uid_filter[i].seq1;
			else
				break;
		} else {
			/* next_uid .. mail->uid-1 are expunged */
			i_assert(mail->uid > next_uid);
			while (mail->uid > uid_filter[i].seq2) {
				seq_range_array_add_range(expunged_uids,
							  next_uid,
							  uid_filter[i].seq2);
				i++;
				i_assert(i < count);
				next_uid = uid_filter[i].seq1;
			}
			if (next_uid != mail->uid) {
				seq_range_array_add_range(expunged_uids,
							  next_uid,
							  mail->uid - 1);
			}
			if (uid_filter[i].seq2 != mail->uid)
				next_uid = mail->uid + 1;
			else if (++i < count)
				next_uid = uid_filter[i].seq1;
			else
				break;
		}
	}
	if (i < count) {
		i_assert(next_uid <= uid_filter[i].seq2);
		seq_range_array_add_range(expunged_uids, next_uid,
					  uid_filter[i].seq2);
		i++;
	}
	for (; i < count; i++) {
		seq_range_array_add_range(expunged_uids, uid_filter[i].seq1,
					  uid_filter[i].seq2);
	}

	mailbox_get_open_status(ctx->box, STATUS_UIDNEXT, &status);
	seq_range_array_remove_range(expunged_uids, status.uidnext,
				     (uint32_t)-1);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	if (ret == 0 && ctx->qresync_sample_seqset != NULL &&
	    array_is_created(ctx->qresync_sample_seqset))
		expunges_drop_known(ctx, trans, expunged_uids);

	(void)mailbox_transaction_commit(&trans);
	return ret;
}

static int
imap_fetch_send_vanished(struct imap_fetch_context *ctx)
{
	const struct mail_search_arg *uidarg = ctx->search_args->args;
	const struct mail_search_arg *modseqarg = uidarg->next;
	const ARRAY_TYPE(seq_range) *uid_filter = &uidarg->value.seqset;
	uint64_t modseq = modseqarg->value.modseq->modseq - 1;
	ARRAY_TYPE(seq_range) expunged_uids_range;
	string_t *str;
	int ret = 0;

	i_array_init(&expunged_uids_range, array_count(uid_filter));
	if (!mailbox_get_expunged_uids(ctx->box, modseq, uid_filter, &expunged_uids_range)) {
		/* return all expunged UIDs */
		if (get_expunges_fallback(ctx, uid_filter,
					  &expunged_uids_range) < 0) {
			array_clear(&expunged_uids_range);
			ret = -1;
		}
	}
	if (array_count(&expunged_uids_range) > 0) {
		str = str_new(default_pool, 128);
		str_append(str, "* VANISHED (EARLIER) ");
		imap_write_seq_range(str, &expunged_uids_range);
		str_append(str, "\r\n");
		o_stream_send(ctx->client->output, str_data(str), str_len(str));
		str_free(&str);
	}
	array_free(&expunged_uids_range);
	return ret;
}

int imap_fetch_begin(struct imap_fetch_context *ctx)
{
	const void *data;

	if (ctx->send_vanished) {
		if (imap_fetch_send_vanished(ctx) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
	}

	if (ctx->flags_update_seen) {
		if (mailbox_is_readonly(ctx->box))
			ctx->flags_update_seen = FALSE;
		else if (!ctx->flags_have_handler) {
			ctx->flags_show_only_seen_changes = TRUE;
			(void)imap_fetch_init_handler(ctx, "FLAGS", NULL);
		}
	}

	if (array_count(&ctx->all_headers) > 0 &&
	    ((ctx->fetch_data & (MAIL_FETCH_STREAM_HEADER |
				 MAIL_FETCH_STREAM_BODY)) == 0)) {
		(void)array_append_space(&ctx->all_headers);

		data = array_idx(&ctx->all_headers, 0);
		ctx->all_headers_ctx =
			mailbox_header_lookup_init(ctx->box, data);
	}

	if ((ctx->fetch_data &
	     (MAIL_FETCH_STREAM_HEADER | MAIL_FETCH_STREAM_BODY)) != 0)
		ctx->fetch_data |= MAIL_FETCH_NUL_STATE;

	ctx->trans = mailbox_transaction_begin(ctx->box,
		MAILBOX_TRANSACTION_FLAG_HIDE |
		MAILBOX_TRANSACTION_FLAG_REFRESH);
	ctx->select_counter = ctx->client->select_counter;

	/* Delayed uidset -> seqset conversion. VANISHED needs the uidset. */
	mail_search_args_init(ctx->search_args, ctx->box, TRUE,
			      &ctx->cmd->client->search_saved_uidset);
	ctx->search_ctx =
		mailbox_search_init(ctx->trans, ctx->search_args, NULL,
				    ctx->fetch_data, ctx->all_headers_ctx);
	return 0;
}

static int imap_fetch_flush_buffer(struct imap_fetch_context *ctx)
{
	const unsigned char *data;
	size_t len;

	data = str_data(ctx->cur_str);
	len = str_len(ctx->cur_str);

	if (len == 0)
		return 0;

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

static int imap_fetch_more_int(struct imap_fetch_context *ctx)
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
			if (client->output->closed)
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
		if (ctx->cur_input != NULL)
			i_stream_unref(&ctx->cur_input);
	}

	handlers = array_get(&ctx->handlers, &count);
	for (;;) {
		if (o_stream_get_buffer_used_size(client->output) >=
		    CLIENT_OUTPUT_OPTIMAL_SIZE) {
			ret = o_stream_flush(client->output);
			if (ret <= 0)
				return ret;
		}

		if (ctx->cur_mail == NULL) {
			if (ctx->cmd->cancel)
				return 1;

			if (!mailbox_search_next(ctx->search_ctx,
						 &ctx->cur_mail))
				break;

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

			i_assert(ctx->cur_input == NULL);
			T_BEGIN {
				const struct imap_fetch_context_handler *h =
					&handlers[ctx->cur_handler];

				ret = h->handler(ctx, ctx->cur_mail,
						 h->context);
			} T_END;

			if (ret == 0)
				return 0;

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
			if (ctx->cur_input != NULL)
				i_stream_unref(&ctx->cur_input);
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
		client->last_output = ioloop_time;

		ctx->cur_mail = NULL;
		ctx->cur_handler = 0;
	}

	return 1;
}

int imap_fetch_more(struct imap_fetch_context *ctx)
{
	int ret;

	i_assert(ctx->client->output_lock == NULL ||
		 ctx->client->output_lock == ctx->cmd);

	ret = imap_fetch_more_int(ctx);
	if (ret < 0)
		ctx->failed = TRUE;
	if (ctx->line_partial) {
		/* nothing can be sent until FETCH is finished */
		ctx->client->output_lock = ctx->cmd;
	}
	return ret;
}

int imap_fetch_deinit(struct imap_fetch_context *ctx)
{
	const struct imap_fetch_context_handler *handler;

	array_foreach(&ctx->handlers, handler) {
		if (handler->want_deinit)
			handler->handler(ctx, NULL, handler->context);
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

	mail_search_args_unref(&ctx->search_args);
	if (ctx->search_ctx != NULL) {
		if (mailbox_search_deinit(&ctx->search_ctx) < 0)
			ctx->failed = TRUE;
	}
	if (ctx->all_headers_ctx != NULL)
		mailbox_header_lookup_unref(&ctx->all_headers_ctx);

	if (ctx->trans != NULL) {
		/* even if something failed, we want to commit changes to
		   cache, as well as possible \Seen flag changes for FETCH
		   replies we returned so far. */
		if (mailbox_transaction_commit(&ctx->trans) < 0)
			ctx->failed = TRUE;
	}
	return ctx->failed ? -1 : 0;
}

static int fetch_body(struct imap_fetch_context *ctx, struct mail *mail,
		      void *context ATTR_UNUSED)
{
	const char *body;

	if (mail_get_special(mail, MAIL_FETCH_IMAP_BODY, &body) < 0)
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
			       struct mail *mail, void *context ATTR_UNUSED)
{
	const char *bodystructure;

	if (mail_get_special(mail, MAIL_FETCH_IMAP_BODYSTRUCTURE,
			     &bodystructure) < 0)
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
			 const struct imap_arg **args ATTR_UNUSED)
{
	ctx->fetch_data |= MAIL_FETCH_IMAP_BODYSTRUCTURE;
	imap_fetch_add_handler(ctx, FALSE, FALSE, name,
			       "("BODY_NIL_REPLY" NIL NIL NIL NIL)",
			       fetch_bodystructure, NULL);
	return TRUE;
}

static int fetch_envelope(struct imap_fetch_context *ctx, struct mail *mail,
			  void *context ATTR_UNUSED)
{
	const char *envelope;

	if (mail_get_special(mail, MAIL_FETCH_IMAP_ENVELOPE, &envelope) < 0)
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
		    const struct imap_arg **args ATTR_UNUSED)
{
	ctx->fetch_data |= MAIL_FETCH_IMAP_ENVELOPE;
	imap_fetch_add_handler(ctx, FALSE, FALSE, name, ENVELOPE_NIL_REPLY,
			       fetch_envelope, NULL);
	return TRUE;
}

static int fetch_flags(struct imap_fetch_context *ctx, struct mail *mail,
		       void *context ATTR_UNUSED)
{
	enum mail_flags flags;
	const char *const *keywords;

	flags = mail_get_flags(mail);
	if (ctx->flags_update_seen && (flags & MAIL_SEEN) == 0) {
		/* Add \Seen flag */
		ctx->seen_flags_changed = TRUE;
		flags |= MAIL_SEEN;
		mail_update_flags(mail, MODIFY_ADD, MAIL_SEEN);
	} else if (ctx->flags_show_only_seen_changes) {
		return 1;
	}

	keywords = client_get_keyword_names(ctx->client, &ctx->tmp_keywords,
			mail_get_keyword_indexes(mail));

	str_append(ctx->cur_str, "FLAGS (");
	imap_write_flags(ctx->cur_str, flags, keywords);
	str_append(ctx->cur_str, ") ");
	return 1;
}

static bool
fetch_flags_init(struct imap_fetch_context *ctx, const char *name,
		 const struct imap_arg **args ATTR_UNUSED)
{
	ctx->flags_have_handler = TRUE;
	ctx->fetch_data |= MAIL_FETCH_FLAGS;
	imap_fetch_add_handler(ctx, TRUE, FALSE, name, "()", fetch_flags, NULL);
	return TRUE;
}

static int fetch_internaldate(struct imap_fetch_context *ctx, struct mail *mail,
			      void *context ATTR_UNUSED)
{
	time_t date;

	if (mail_get_received_date(mail, &date) < 0)
		return -1;

	str_printfa(ctx->cur_str, "INTERNALDATE \"%s\" ",
		    imap_to_datetime(date));
	return 1;
}

static bool
fetch_internaldate_init(struct imap_fetch_context *ctx, const char *name,
			const struct imap_arg **args ATTR_UNUSED)
{
	ctx->fetch_data |= MAIL_FETCH_RECEIVED_DATE;
	imap_fetch_add_handler(ctx, TRUE, FALSE, name,
			       "\"01-Jan-1970 00:00:00 +0000\"",
			       fetch_internaldate, NULL);
	return TRUE;
}

static int fetch_modseq(struct imap_fetch_context *ctx, struct mail *mail,
			void *context ATTR_UNUSED)
{
	uint64_t modseq;

	modseq = mail_get_modseq(mail);
	if (ctx->client->highest_fetch_modseq < modseq)
		ctx->client->highest_fetch_modseq = modseq;
	str_printfa(ctx->cur_str, "MODSEQ (%llu) ",
		    (unsigned long long)modseq);
	return 1;
}

static bool
fetch_modseq_init(struct imap_fetch_context *ctx, const char *name,
		  const struct imap_arg **args ATTR_UNUSED)
{
	(void)client_enable(ctx->client, MAILBOX_FEATURE_CONDSTORE);
	imap_fetch_add_handler(ctx, TRUE, FALSE, name, NULL,
			       fetch_modseq, NULL);
	return TRUE;
}

static int fetch_uid(struct imap_fetch_context *ctx, struct mail *mail,
		     void *context ATTR_UNUSED)
{
	str_printfa(ctx->cur_str, "UID %u ", mail->uid);
	return 1;
}

static bool
fetch_uid_init(struct imap_fetch_context *ctx ATTR_UNUSED, const char *name,
	       const struct imap_arg **args ATTR_UNUSED)
{
	imap_fetch_add_handler(ctx, TRUE, FALSE, name, NULL, fetch_uid, NULL);
	return TRUE;
}

static int fetch_guid(struct imap_fetch_context *ctx, struct mail *mail,
		      void *context ATTR_UNUSED)
{
	const char *value;

	if (mail_get_special(mail, MAIL_FETCH_GUID, &value) < 0)
		return -1;

	str_append(ctx->cur_str, "X-GUID ");
	imap_quote_append_string(ctx->cur_str, value, FALSE);
	str_append_c(ctx->cur_str, ' ');
	return 1;
}

static bool
fetch_guid_init(struct imap_fetch_context *ctx ATTR_UNUSED, const char *name,
		const struct imap_arg **args ATTR_UNUSED)
{
	imap_fetch_add_handler(ctx, TRUE, FALSE, name, "", fetch_guid, NULL);
	return TRUE;
}

static int fetch_x_mailbox(struct imap_fetch_context *ctx, struct mail *mail,
			   void *context ATTR_UNUSED)
{
	const char *name;
	string_t *mutf7_name;

	if (mail_get_special(mail, MAIL_FETCH_MAILBOX_NAME, &name) < 0)
		i_panic("mailbox name not returned");

	mutf7_name = t_str_new(strlen(name)*2);
	if (imap_utf8_to_utf7(name, mutf7_name) < 0)
		i_panic("FETCH: Mailbox name not UTF-8: %s", name);

	str_append(ctx->cur_str, "X-MAILBOX ");
	imap_quote_append_string(ctx->cur_str, str_c(mutf7_name), FALSE);
	str_append_c(ctx->cur_str, ' ');
	return 1;
}

static bool
fetch_x_mailbox_init(struct imap_fetch_context *ctx ATTR_UNUSED,
		     const char *name,
		     const struct imap_arg **args ATTR_UNUSED)
{
	imap_fetch_add_handler(ctx, TRUE, FALSE, name, NULL,
			       fetch_x_mailbox, NULL);
	return TRUE;
}

static int fetch_x_real_uid(struct imap_fetch_context *ctx, struct mail *mail,
			    void *context ATTR_UNUSED)
{
	str_printfa(ctx->cur_str, "X-REAL-UID %u ",
		    mail_get_real_mail(mail)->uid);
	return 1;
}

static bool
fetch_x_real_uid_init(struct imap_fetch_context *ctx ATTR_UNUSED,
		      const char *name,
		      const struct imap_arg **args ATTR_UNUSED)
{
	imap_fetch_add_handler(ctx, TRUE, FALSE, name, NULL,
			       fetch_x_real_uid, NULL);
	return TRUE;
}

static int fetch_x_savedate(struct imap_fetch_context *ctx, struct mail *mail,
			    void *context ATTR_UNUSED)
{
	time_t date;

	if (mail_get_save_date(mail, &date) < 0)
		return -1;

	str_printfa(ctx->cur_str, "X-SAVEDATE \"%s\" ",
		    imap_to_datetime(date));
	return 1;
}

static bool
fetch_x_savedate_init(struct imap_fetch_context *ctx, const char *name,
		      const struct imap_arg **args ATTR_UNUSED)
{
	ctx->fetch_data |= MAIL_FETCH_SAVE_DATE;
	imap_fetch_add_handler(ctx, TRUE, FALSE, name,
			       "\"01-Jan-1970 00:00:00 +0000\"",
			       fetch_x_savedate, NULL);
	return TRUE;
}

static const struct imap_fetch_handler
imap_fetch_default_handlers[] = {
	{ "BODY", fetch_body_init },
	{ "BODYSTRUCTURE", fetch_bodystructure_init },
	{ "ENVELOPE", fetch_envelope_init },
	{ "FLAGS", fetch_flags_init },
	{ "INTERNALDATE", fetch_internaldate_init },
	{ "MODSEQ", fetch_modseq_init },
	{ "RFC822", fetch_rfc822_init },
	{ "UID", fetch_uid_init },
	{ "X-GUID", fetch_guid_init },
	{ "X-MAILBOX", fetch_x_mailbox_init },
	{ "X-REAL-UID", fetch_x_real_uid_init },
	{ "X-SAVEDATE", fetch_x_savedate_init }
};

void imap_fetch_handlers_init(void)
{
	i_array_init(&fetch_handlers, 32);
	imap_fetch_handlers_register(imap_fetch_default_handlers,
				     N_ELEMENTS(imap_fetch_default_handlers));
}

void imap_fetch_handlers_deinit(void)
{
	array_free(&fetch_handlers);
}
