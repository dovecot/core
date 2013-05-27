/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "str.h"
#include "hex-binary.h"
#include "index-mail.h"
#include "dbox-attachment.h"
#include "dbox-file.h"
#include "dbox-save.h"

void dbox_save_add_to_index(struct dbox_save_context *ctx)
{
	struct mail_save_data *mdata = &ctx->ctx.data;
	enum mail_flags save_flags;

	save_flags = mdata->flags & ~MAIL_RECENT;
	mail_index_append(ctx->trans, mdata->uid, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (mdata->keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, mdata->keywords);
	}
	if (mdata->min_modseq != 0) {
		mail_index_update_modseq(ctx->trans, ctx->seq,
					 mdata->min_modseq);
	}
}

void dbox_save_begin(struct dbox_save_context *ctx, struct istream *input)
{
	struct mail_save_context *_ctx = &ctx->ctx;
	struct mail_storage *_storage = _ctx->transaction->box->storage;
	struct dbox_storage *storage = (struct dbox_storage *)_storage;
	struct dbox_message_header dbox_msg_hdr;
	struct istream *crlf_input;

	dbox_save_add_to_index(ctx);

	if (_ctx->dest_mail == NULL) {
		if (ctx->mail == NULL)
			ctx->mail = mail_alloc(_ctx->transaction, 0, NULL);
		_ctx->dest_mail = ctx->mail;
	}
	mail_set_seq_saving(_ctx->dest_mail, ctx->seq);

	crlf_input = i_stream_create_lf(input);
	ctx->input = index_mail_cache_parse_init(_ctx->dest_mail, crlf_input);
	i_stream_unref(&crlf_input);

	/* write a dummy header. it'll get rewritten when we're finished */
	memset(&dbox_msg_hdr, 0, sizeof(dbox_msg_hdr));
	o_stream_cork(ctx->dbox_output);
	if (o_stream_send(ctx->dbox_output, &dbox_msg_hdr,
			  sizeof(dbox_msg_hdr)) < 0) {
		mail_storage_set_critical(_storage, "write(%s) failed: %m",
					  o_stream_get_name(ctx->dbox_output));
		ctx->failed = TRUE;
	}
	_ctx->data.output = ctx->dbox_output;

	if (_ctx->data.received_date == (time_t)-1)
		_ctx->data.received_date = ioloop_time;
	index_attachment_save_begin(_ctx, storage->attachment_fs, ctx->input);
}

int dbox_save_continue(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mail_storage *storage = _ctx->transaction->box->storage;

	if (ctx->failed)
		return -1;

	if (_ctx->data.attach != NULL)
		return index_attachment_save_continue(_ctx);

	do {
		if (o_stream_send_istream(_ctx->data.output, ctx->input) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
					"write(%s) failed: %m",
					o_stream_get_name(_ctx->data.output));
			}
			ctx->failed = TRUE;
			return -1;
		}
		index_mail_cache_parse_continue(_ctx->dest_mail);

		/* both tee input readers may consume data from our primary
		   input stream. we'll have to make sure we don't return with
		   one of the streams still having data in them. */
	} while (i_stream_read(ctx->input) > 0);
	return 0;
}

void dbox_save_end(struct dbox_save_context *ctx)
{
	struct mail_save_data *mdata = &ctx->ctx.data;
	struct ostream *dbox_output = ctx->dbox_output;

	if (mdata->attach != NULL && !ctx->failed) {
		if (index_attachment_save_finish(&ctx->ctx) < 0)
			ctx->failed = TRUE;
	}
	if (o_stream_nfinish(mdata->output) < 0) {
		mail_storage_set_critical(ctx->ctx.transaction->box->storage,
					  "write(%s) failed: %m",
					  o_stream_get_name(mdata->output));
		ctx->failed = TRUE;
	}
	if (mdata->output != dbox_output) {
		if (mdata->output != NULL) {
			/* e.g. zlib plugin had changed this */
			o_stream_ref(dbox_output);
			o_stream_destroy(&mdata->output);
			mdata->output = dbox_output;
		} else {
			i_assert(ctx->failed);
		}
	}
	index_mail_cache_parse_deinit(ctx->ctx.dest_mail,
				      ctx->ctx.data.received_date,
				      !ctx->failed);
}

void dbox_save_write_metadata(struct mail_save_context *_ctx,
			      struct ostream *output, uoff_t output_msg_size,
			      const char *orig_mailbox_name,
			      guid_128_t guid_128)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mail_save_data *mdata = &ctx->ctx.data;
	struct dbox_metadata_header metadata_hdr;
	const char *guid;
	string_t *str;
	uoff_t vsize;

	memset(&metadata_hdr, 0, sizeof(metadata_hdr));
	memcpy(metadata_hdr.magic_post, DBOX_MAGIC_POST,
	       sizeof(metadata_hdr.magic_post));
	o_stream_nsend(output, &metadata_hdr, sizeof(metadata_hdr));

	str = t_str_new(256);
	if (output_msg_size != ctx->input->v_offset) {
		/* a plugin changed the data written to disk, so the
		   "message size" dbox header doesn't contain the actual
		   "physical" message size. we need to save it as a
		   separate metadata header. */
		str_printfa(str, "%c%llx\n", DBOX_METADATA_PHYSICAL_SIZE,
			    (unsigned long long)ctx->input->v_offset);
	}
	str_printfa(str, "%c%lx\n", DBOX_METADATA_RECEIVED_TIME,
		    (unsigned long)mdata->received_date);
	if (mail_get_virtual_size(_ctx->dest_mail, &vsize) < 0)
		i_unreached();
	str_printfa(str, "%c%llx\n", DBOX_METADATA_VIRTUAL_SIZE,
		    (unsigned long long)vsize);
	if (mdata->pop3_uidl != NULL) {
		i_assert(strchr(mdata->pop3_uidl, '\n') == NULL);
		str_printfa(str, "%c%s\n", DBOX_METADATA_POP3_UIDL,
			    mdata->pop3_uidl);
		ctx->have_pop3_uidls = TRUE;
	}
	if (mdata->pop3_order != 0) {
		str_printfa(str, "%c%u\n", DBOX_METADATA_POP3_ORDER,
			    mdata->pop3_order);
		ctx->have_pop3_orders = TRUE;
	}

	guid = mdata->guid;
	if (guid != NULL)
		mail_generate_guid_128_hash(guid, guid_128);
	else {
		guid_128_generate(guid_128);
		guid = guid_128_to_string(guid_128);
	}
	str_printfa(str, "%c%s\n", DBOX_METADATA_GUID, guid);

	if (orig_mailbox_name != NULL &&
	    strchr(orig_mailbox_name, '\r') == NULL &&
	    strchr(orig_mailbox_name, '\n') == NULL) {
		/* save the original mailbox name so if mailbox indexes get
		   corrupted we can place at least some (hopefully most) of
		   the messages to correct mailboxes. */
		str_printfa(str, "%c%s\n", DBOX_METADATA_ORIG_MAILBOX,
			    orig_mailbox_name);
	}

	dbox_attachment_save_write_metadata(_ctx, str);

	str_append_c(str, '\n');
	o_stream_nsend(output, str_data(str), str_len(str));
}

void dbox_save_update_header_flags(struct dbox_save_context *ctx,
				   struct mail_index_view *sync_view,
				   uint32_t ext_id,
				   unsigned int flags_offset)
{
	const void *data;
	size_t data_size;
	uint8_t old_flags = 0, flags;

	mail_index_get_header_ext(sync_view, ext_id, &data, &data_size);
	if (flags_offset < data_size)
		old_flags = *((const uint8_t *)data + flags_offset);
	else {
		/* grow old dbox header */
		mail_index_ext_resize_hdr(ctx->trans, ext_id, flags_offset+1);
	}

	flags = old_flags;
	if (ctx->have_pop3_uidls)
		flags |= DBOX_INDEX_HEADER_FLAG_HAVE_POP3_UIDLS;
	if (ctx->have_pop3_orders)
		flags |= DBOX_INDEX_HEADER_FLAG_HAVE_POP3_ORDERS;
	if (flags != old_flags) {
		/* flags changed, update them */
		mail_index_update_header_ext(ctx->trans, ext_id,
					     flags_offset, &flags, 1);
	}
}
