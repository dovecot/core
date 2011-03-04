/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

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
	enum mail_flags save_flags;

	save_flags = ctx->ctx.flags & ~MAIL_RECENT;
	mail_index_append(ctx->trans, ctx->ctx.uid, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (ctx->ctx.keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, ctx->ctx.keywords);
	}
	if (ctx->ctx.min_modseq != 0) {
		mail_index_update_modseq(ctx->trans, ctx->seq,
					 ctx->ctx.min_modseq);
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
	mail_set_seq(_ctx->dest_mail, ctx->seq);
	_ctx->dest_mail->saving = TRUE;

	crlf_input = i_stream_create_lf(input);
	ctx->input = index_mail_cache_parse_init(_ctx->dest_mail, crlf_input);
	i_stream_unref(&crlf_input);

	/* write a dummy header. it'll get rewritten when we're finished */
	memset(&dbox_msg_hdr, 0, sizeof(dbox_msg_hdr));
	o_stream_cork(ctx->dbox_output);
	if (o_stream_send(ctx->dbox_output, &dbox_msg_hdr,
			  sizeof(dbox_msg_hdr)) < 0) {
		mail_storage_set_critical(_storage,
			"o_stream_send(%s) failed: %m", 
			ctx->cur_file->cur_path);
		ctx->failed = TRUE;
	}
	_ctx->output = ctx->dbox_output;

	if (_ctx->received_date == (time_t)-1)
		_ctx->received_date = ioloop_time;
	index_attachment_save_begin(_ctx, storage->attachment_fs, ctx->input);
}

int dbox_save_continue(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mail_storage *storage = _ctx->transaction->box->storage;

	if (ctx->failed)
		return -1;

	if (_ctx->attach != NULL)
		return index_attachment_save_continue(_ctx);

	do {
		if (o_stream_send_istream(_ctx->output, ctx->input) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
					"o_stream_send_istream(%s) failed: %m",
					ctx->cur_file->cur_path);
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
	struct ostream *dbox_output = ctx->dbox_output;

	if (ctx->ctx.attach != NULL) {
		if (index_attachment_save_finish(&ctx->ctx) < 0)
			ctx->failed = TRUE;
	}
	if (ctx->ctx.output == dbox_output)
		return;

	/* e.g. zlib plugin had changed this */
	o_stream_ref(dbox_output);
	o_stream_destroy(&ctx->ctx.output);
	ctx->ctx.output = dbox_output;
}

void dbox_save_write_metadata(struct mail_save_context *_ctx,
			      struct ostream *output, uoff_t output_msg_size,
			      const char *orig_mailbox_name,
			      uint8_t guid_128[MAIL_GUID_128_SIZE])
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct dbox_metadata_header metadata_hdr;
	const char *guid;
	string_t *str;
	uoff_t vsize;

	memset(&metadata_hdr, 0, sizeof(metadata_hdr));
	memcpy(metadata_hdr.magic_post, DBOX_MAGIC_POST,
	       sizeof(metadata_hdr.magic_post));
	o_stream_send(output, &metadata_hdr, sizeof(metadata_hdr));

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
		    (unsigned long)_ctx->received_date);
	if (mail_get_virtual_size(_ctx->dest_mail, &vsize) < 0)
		i_unreached();
	str_printfa(str, "%c%llx\n", DBOX_METADATA_VIRTUAL_SIZE,
		    (unsigned long long)vsize);
	if (_ctx->pop3_uidl != NULL) {
		i_assert(strchr(_ctx->pop3_uidl, '\n') == NULL);
		str_printfa(str, "%c%s\n", DBOX_METADATA_POP3_UIDL,
			    _ctx->pop3_uidl);
	}

	guid = _ctx->guid;
	if (guid != NULL)
		mail_generate_guid_128_hash(guid, guid_128);
	else {
		mail_generate_guid_128(guid_128);
		guid = binary_to_hex(guid_128, MAIL_GUID_128_SIZE);
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
	o_stream_send(output, str_data(str), str_len(str));
}
