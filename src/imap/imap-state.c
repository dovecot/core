/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "crc32.h"
#include "numpack.h"
#include "net.h"
#include "ostream.h"
#include "str.h"
#include "str-sanitize.h"
#include "imap-util.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "mailbox-recent-flags.h"
#include "imap-client.h"
#include "imap-feature.h"
#include "imap-fetch.h"
#include "imap-search-args.h"
#include "imap-state.h"

enum imap_state_type_public {
	IMAP_STATE_TYPE_MAILBOX			= 'B',
	IMAP_STATE_TYPE_ENABLED_FEATURE		= 'F',
	IMAP_STATE_TYPE_SEARCHRES		= '1',
};

enum imap_state_type_internal {
	IMAP_STATE_TYPE_ID_LOGGED		= 'I',
	IMAP_STATE_TYPE_TLS_COMPRESSION		= 'C',
};

struct mailbox_import_state {
	const char *vname;
	guid_128_t mailbox_guid;
	bool examined;
	uint32_t keywords_count, keywords_crc32, uids_crc32;
	uint32_t uidvalidity, uidnext, messages;
	uint64_t highest_modseq;
	ARRAY_TYPE(seq_range) recent_uids;
};

static void
export_seq_range(buffer_t *dest, const ARRAY_TYPE(seq_range) *range)
{
	const struct seq_range *uids;
	unsigned int i, count;
	uint32_t next_uid;

	uids = array_get(range, &count);
	numpack_encode(dest, count);
	next_uid = 1;
	for (i = 0; i < count; i++) {
		i_assert(uids[i].seq1 >= next_uid);
		if (uids[i].seq1 == uids[i].seq2) {
			numpack_encode(dest, (uids[i].seq1 - next_uid) << 1);
		} else {
			numpack_encode(dest, 1 | ((uids[i].seq1 - next_uid) << 1));
			numpack_encode(dest, uids[i].seq2 - uids[i].seq1 - 1);
		}
		next_uid = uids[i].seq2 + 1;
	}
}

static int
import_seq_range(const unsigned char **data, const unsigned char *end,
		 ARRAY_TYPE(seq_range) *range)
{
	uint32_t i, count, next_uid, num, uid1, uid2;

	if (numpack_decode32(data, end, &count) < 0)
		return -1;
	next_uid = 1;

	for (i = 0; i < count; i++) {
		if (numpack_decode32(data, end, &num) < 0)
			return -1;
		uid1 = next_uid + (num >> 1);
		if ((num & 1) == 0) {
			uid2 = uid1;
			seq_range_array_add(range, uid1);
		} else {
			if (numpack_decode32(data, end, &num) < 0)
				return -1;
			uid2 = uid1 + num + 1;
			seq_range_array_add_range(range, uid1, uid2);
		}
		next_uid = uid2 + 1;
	}
	return 0;
}

int imap_state_export_internal(struct client *client, buffer_t *dest,
			       const char **error_r)
{
	/* the only IMAP command we allow running is IDLE or X-STATE */
	if (client->command_queue_size > 1) {
		*error_r = "Multiple commands in progress";
		return 0;
	}
	if (client->command_queue == NULL ||
	    strcasecmp(client->command_queue->name, "IDLE") != 0) {
		/* this would require saving the seq <-> uid mapping
		   and restore it on import. quite a lot of trouble if
		   messages have been expunged in the mean time. */
		*error_r = "Non-IDLE connections not supported currently";
		return 0;
	}
	return client->v.state_export(client, TRUE, dest, error_r);
}

int imap_state_export_external(struct client *client, buffer_t *dest,
			       const char **error_r)
{
	if (client->command_queue_size > 1) {
		*error_r = "Multiple commands in progress";
		return 0;
	}

	i_assert(client->command_queue_size == 1);
	i_assert(strcmp(client->command_queue->name, "X-STATE") == 0);
	return client->v.state_export(client, FALSE, dest, error_r);
}

static int
imap_state_import(struct client *client, bool internal,
		  const unsigned char *data, size_t size, const char **error_r)
{
	ssize_t ret;

	while (size > 0) {
		ret = client->v.state_import(client, internal,
					     data, size, error_r);
		if (ret <= 0) {
			i_assert(*error_r != NULL);
			return ret < 0 ? -1 : 0;
		}
		i_assert((size_t)ret <= size);
		data += ret;
		size -= ret;
	}
	return 1;
}

int imap_state_import_internal(struct client *client,
			       const unsigned char *data, size_t size,
			       const char **error_r)
{
	return imap_state_import(client, TRUE, data, size, error_r);
}

int imap_state_import_external(struct client *client,
			       const unsigned char *data, size_t size,
			       const char **error_r)
{
	return imap_state_import(client, FALSE, data, size, error_r);
}

static int
imap_state_export_mailbox_mails(buffer_t *dest, struct mailbox *box,
				const char **error_r)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	ARRAY_TYPE(seq_range) recent_uids;
	uint32_t crc = 0;
	int ret = 1;

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);

	trans = mailbox_transaction_begin(box, 0,
				"unhibernate imap_state_export_mailbox_mails");
	search_ctx = mailbox_search_init(trans, search_args, NULL, 0, NULL);
	mail_search_args_unref(&search_args);

	t_array_init(&recent_uids, 8);
	while (mailbox_search_next(search_ctx, &mail)) {
		crc = crc32_data_more(crc, &mail->uid, sizeof(mail->uid));
		if ((mail_get_flags(mail) & MAIL_RECENT) != 0)
			seq_range_array_add(&recent_uids, mail->uid);
	}
	if (mailbox_search_deinit(&search_ctx) < 0) {
		*error_r = mailbox_get_last_internal_error(box, NULL);
		ret = -1;
	}
	(void)mailbox_transaction_commit(&trans);

	numpack_encode(dest, crc);
	export_seq_range(dest, &recent_uids);
	return ret;
}

static uint32_t
mailbox_status_keywords_crc32(const struct mailbox_status *status)
{
	const char *const *strp;
	uint32_t crc = 0;

	array_foreach(status->keywords, strp)
		crc = crc32_str(*strp);
	return crc;
}

static int
imap_state_export_mailbox(buffer_t *dest, struct client *client,
			  struct mailbox *box, const char **error_r)
{
        struct mailbox_status status;
	struct mailbox_metadata metadata;
	const char *vname = mailbox_get_vname(box);
	enum mail_error mail_error;

	mailbox_get_open_status(box, STATUS_UIDVALIDITY | STATUS_UIDNEXT |
				STATUS_MESSAGES | STATUS_HIGHESTMODSEQ |
				STATUS_KEYWORDS,
				&status);
	if (status.nonpermanent_modseqs) {
		*error_r = "Nonpermanent modseqs";
		return 0;
	}

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0) {
		*error_r = mailbox_get_last_internal_error(box, &mail_error);
		/* if the selected mailbox can't have a GUID, fail silently */
		return mail_error == MAIL_ERROR_NOTPOSSIBLE ? 0 : -1;
	}

	buffer_append_c(dest, IMAP_STATE_TYPE_MAILBOX);
	buffer_append(dest, vname, strlen(vname)+1);
	buffer_append(dest, metadata.guid, sizeof(metadata.guid));

	buffer_append_c(dest, client->mailbox_examined ? 1 : 0);
	numpack_encode(dest, status.uidvalidity);
	numpack_encode(dest, status.uidnext);
	numpack_encode(dest, status.messages);
	if (client_has_enabled(client, imap_feature_qresync) &&
	    !client->nonpermanent_modseqs)
		numpack_encode(dest, client->sync_last_full_modseq);
	else
		numpack_encode(dest, status.highest_modseq);

	/* keywords count + CRC32 should be enough to figure out if it
	   needs to be resent */
	numpack_encode(dest, array_count(status.keywords));
	numpack_encode(dest, mailbox_status_keywords_crc32(&status));

	/* we're now basically done, but just in case there's a bug add a
	   checksum of the currently existing UIDs and verify it when
	   importing. this also writes the list of recent UIDs. */
	return imap_state_export_mailbox_mails(dest, box, error_r);
}

int imap_state_export_base(struct client *client, bool internal,
			   buffer_t *dest, const char **error_r)
{
	int ret;

	str_append(dest, "base\n");
	if (array_is_created(&client->search_updates) &&
	    array_count(&client->search_updates) > 0) {
		/* these could be tricky */
		*error_r = "CONTEXT=SEARCH updates not supported currently";
		return 0;
	}
	if (client->notify_ctx != NULL) {
		/* FIXME: this really should be supported. also IDLE wouldn't
		   be needed if NOTIFY allows sending EXPUNGEs to selected
		   mailbox. */
		*error_r = "NOTIFY not supported currently";
		return 0;
	}

	if (client->mailbox != NULL) {
		ret = imap_state_export_mailbox(dest, client,
						client->mailbox, error_r);
		if (ret <= 0)
			return ret;
	}

	/* IMAP features */
	const char *const *features = client_enabled_features(client);
	if (features != NULL) {
		for (unsigned int i = 0; features[i] != NULL; i++) {
			buffer_append_c(dest, IMAP_STATE_TYPE_ENABLED_FEATURE);
			buffer_append(dest, features[i], strlen(features[i])+1);
		}
	}
	if (internal) {
		if (client->id_logged)
			buffer_append_c(dest, IMAP_STATE_TYPE_ID_LOGGED);
		if (client->tls_compression)
			buffer_append_c(dest, IMAP_STATE_TYPE_TLS_COMPRESSION);
	}

	/* IMAP SEARCHRES extension */
	if (array_is_created(&client->search_saved_uidset) &&
	    array_count(&client->search_saved_uidset) > 0) {
		buffer_append_c(dest, IMAP_STATE_TYPE_SEARCHRES);
		export_seq_range(dest, &client->search_saved_uidset);
	}
	return 1;
}

static int
import_string(const unsigned char **data, const unsigned char *end,
	      const char **str_r)
{
	const unsigned char *p;

	p = memchr(*data, '\0', end - *data);
	if (p == NULL)
		return -1;
	*str_r = (const void *)*data;
	*data = p + 1;
	return 0;
}

static int
import_send_expunges(struct client *client,
		     const struct mailbox_import_state *state,
		     unsigned int *expunge_count_r,
		     const char **error_r)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	uint32_t crc = 0, seq, expunged_uid;
	ARRAY_TYPE(seq_range) uids_filter, expunged_uids;
	ARRAY_TYPE(uint32_t) expunged_seqs;
	struct seq_range_iter iter;
	const uint32_t *seqs;
	unsigned int i, expunge_count, n = 0;
	string_t *str;
	int ret = 0;

	*expunge_count_r = 0;

	if (state->messages == 0) {
		/* the mailbox was empty originally - there couldn't be any
		   pending expunges. */
		return 0;
	}
	if (state->uidnext <= 1) {
		*error_r = "Invalid UIDNEXT";
		return -1;
	}

	/* get all the message UIDs expunged since the last known modseq */
	t_array_init(&uids_filter, 1);
	t_array_init(&expunged_uids, 128);
	seq_range_array_add_range(&uids_filter, 1, state->uidnext-1);
	if (!mailbox_get_expunged_uids(client->mailbox, state->highest_modseq,
				       &uids_filter, &expunged_uids)) {
		*error_r = t_strdup_printf(
			"Couldn't get recently expunged UIDs "
			"(uidnext=%u highest_modseq=%"PRIu64")",
			state->uidnext, state->highest_modseq);
		return -1;
	}
	seq_range_array_iter_init(&iter, &expunged_uids);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);

	trans = mailbox_transaction_begin(client->mailbox, 0,
					  "unhibernate import_send_expunges");
	search_ctx = mailbox_search_init(trans, search_args, NULL, 0, NULL);
	mail_search_args_unref(&search_args);

	/* find sequence numbers for the expunged UIDs */
	t_array_init(&expunged_seqs, array_count(&expunged_uids)+1); seq = 0;
	while (mailbox_search_next(search_ctx, &mail)) {
		while (seq_range_array_iter_nth(&iter, n, &expunged_uid) &&
		       expunged_uid < mail->uid && seq < state->messages) {
			seq++; n++;
			array_push_back(&expunged_seqs, &seq);
			crc = crc32_data_more(crc, &expunged_uid,
					      sizeof(expunged_uid));
		}
		if (seq == state->messages)
			break;
		crc = crc32_data_more(crc, &mail->uid, sizeof(mail->uid));
		if (++seq == state->messages)
			break;
	}
	while (seq_range_array_iter_nth(&iter, n, &expunged_uid) &&
	       seq < state->messages) {
		seq++; n++;
		array_push_back(&expunged_seqs, &seq);
		crc = crc32_data_more(crc, &expunged_uid,
				      sizeof(expunged_uid));
	}

	if (mailbox_search_deinit(&search_ctx) < 0) {
		*error_r = mailbox_get_last_internal_error(client->mailbox, NULL);
		ret = -1;
	} else if (seq != state->messages) {
		*error_r = t_strdup_printf("Message count mismatch after "
					   "handling expunges (%u != %u)",
					   seq, state->messages);
		ret = -1;
	}
	(void)mailbox_transaction_commit(&trans);
	if (ret < 0)
		return -1;

	seqs = array_get(&expunged_seqs, &expunge_count);
	if (client->messages_count + expunge_count < state->messages) {
		*error_r = t_strdup_printf("Message count too low after "
					   "handling expunges (%u < %u)",
					   client->messages_count + expunge_count,
					   state->messages);
		return -1;
	}
	if (crc != state->uids_crc32) {
		*error_r = t_strdup_printf("Message UIDs CRC32 mismatch (%u != %u)",
					   crc, state->uids_crc32);
		return -1;
	}

	if (!client_has_enabled(client, imap_feature_qresync)) {
		str = t_str_new(32);
		for (i = expunge_count; i > 0; i--) {
			str_truncate(str, 0);
			str_printfa(str, "* %u EXPUNGE", seqs[i-1]);
			client_send_line(client, str_c(str));
		}
	} else {
		str = str_new(default_pool, 128);
		str_append(str, "* VANISHED ");
		imap_write_seq_range(str, &expunged_uids);
		str_append(str, "\r\n");
		o_stream_nsend(client->output, str_data(str), str_len(str));
		str_free(&str);
	}
	*expunge_count_r = expunge_count;
	return 0;
}

static int
import_send_flag_changes(struct client *client,
			 const struct mailbox_import_state *state,
			 unsigned int *flag_change_count_r)
{
	struct imap_fetch_context *fetch_ctx;
	struct mail_search_args *search_args;
	ARRAY_TYPE(seq_range) old_uids;
	pool_t pool;
	int ret;

	*flag_change_count_r = 0;
	if (state->messages == 0)
		return 0;

	t_array_init(&old_uids, 1);
	seq_range_array_add_range(&old_uids, 1, state->uidnext-1);

	search_args = mail_search_build_init();
	search_args->args = p_new(search_args->pool, struct mail_search_arg, 1);
	search_args->args->type = SEARCH_UIDSET;
	search_args->args->value.seqset = old_uids;
	imap_search_add_changed_since(search_args, state->highest_modseq);

	pool = pool_alloconly_create("imap state flag changes", 1024);
	fetch_ctx = imap_fetch_alloc(client, pool, "unhibernate");
	pool_unref(&pool);

	imap_fetch_init_nofail_handler(fetch_ctx, imap_fetch_flags_init);
	if (client_has_enabled(client, imap_feature_qresync)) {
		imap_fetch_init_nofail_handler(fetch_ctx, imap_fetch_uid_init);
		imap_fetch_init_nofail_handler(fetch_ctx, imap_fetch_modseq_init);
	}

	imap_fetch_begin(fetch_ctx, client->mailbox, search_args);
	mail_search_args_unref(&search_args);

	/* FIXME: ideally do this asynchronously.. */
	while (imap_fetch_more_no_lock_update(fetch_ctx) == 0) ;

	ret = imap_fetch_end(fetch_ctx);
	*flag_change_count_r = fetch_ctx->fetched_mails_count;
	imap_fetch_free(&fetch_ctx);
	return ret;
}

static ssize_t
import_state_mailbox_struct(const unsigned char *data, size_t size,
			    struct mailbox_import_state *state_r,
			    const char **error_r)
{
	const unsigned char *p = data, *end = data + size;

	i_zero(state_r);
	t_array_init(&state_r->recent_uids, 8);

	/* vname */
	if (import_string(&p, end, &state_r->vname) < 0) {
		*error_r = "Mailbox state truncated at name";
		return 0;
	}

	/* GUID */
	if (end-p < (int)sizeof(state_r->mailbox_guid)) {
		*error_r = "Mailbox state truncated at GUID";
		return 0;
	}
	memcpy(state_r->mailbox_guid, p, sizeof(state_r->mailbox_guid));
	p += sizeof(state_r->mailbox_guid);

	if (guid_128_is_empty(state_r->mailbox_guid)) {
		*error_r = "Empty GUID";
		return 0;
	}

	/* EXAMINEd vs SELECTed */
	if (p == end) {
		*error_r = "Mailbox state truncated at examined-flag";
		return 0;
	}
	state_r->examined = p[0] != 0;
	p++;

	/* mailbox state */
	if (numpack_decode32(&p, end, &state_r->uidvalidity) < 0 ||
	    numpack_decode32(&p, end, &state_r->uidnext) < 0 ||
	    numpack_decode32(&p, end, &state_r->messages) < 0 ||
	    numpack_decode(&p, end, &state_r->highest_modseq) < 0 ||
	    numpack_decode32(&p, end, &state_r->keywords_count) < 0 ||
	    numpack_decode32(&p, end, &state_r->keywords_crc32) < 0 ||
	    numpack_decode32(&p, end, &state_r->uids_crc32) < 0 ||
	    import_seq_range(&p, end, &state_r->recent_uids) < 0) {
		*error_r = "Mailbox state truncated";
		return 0;
	}
	if (state_r->uidvalidity == 0) {
		*error_r = "Empty UIDVALIDITY";
		return 0;
	}
	if (state_r->uidnext == 0) {
		*error_r = "Empty UIDNEXT";
		return 0;
	}
	return p - data;
}

static int
import_state_mailbox_open(struct client *client,
			  const struct mailbox_import_state *state,
			  const char **error_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_metadata metadata;
        struct mailbox_status status;
	const struct seq_range *range;
	enum mailbox_flags flags = 0;
	unsigned int expunge_count, new_mails_count = 0, flag_change_count = 0;
	uint32_t uid;
	int ret = 0;

	ns = mail_namespace_find(client->user->namespaces, state->vname);
	if (ns == NULL) {
		*error_r = "Namespace not found for mailbox";
		return -1;
	}

	if (state->examined)
		flags |= MAILBOX_FLAG_READONLY;
	else
		flags |= MAILBOX_FLAG_DROP_RECENT;
	box = mailbox_alloc(ns->list, state->vname, flags);
	mailbox_set_reason(box, "unhibernate");
	if (mailbox_open(box) < 0) {
		*error_r = t_strdup_printf("Couldn't open mailbox: %s",
			mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		return -1;
	}

	ret = mailbox_enable(box, client_enabled_mailbox_features(client));
	if (ret < 0 || mailbox_sync(box, 0) < 0) {
		*error_r = t_strdup_printf("Couldn't sync mailbox: %s",
			mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		return -1;
	}
	/* verify that this still looks like the same mailbox */
	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0) {
		*error_r = mailbox_get_last_internal_error(box, NULL);
		mailbox_free(&box);
		return -1;
	}
	if (!guid_128_equals(metadata.guid, state->mailbox_guid)) {
		*error_r = t_strdup_printf("Mailbox GUID has changed %s->%s",
					   guid_128_to_string(state->mailbox_guid),
					   guid_128_to_string(metadata.guid));
		mailbox_free(&box);
		return -1;
	}
	mailbox_get_open_status(box, STATUS_UIDVALIDITY | STATUS_UIDNEXT |
				STATUS_HIGHESTMODSEQ | STATUS_RECENT |
				STATUS_KEYWORDS, &status);
	if (status.uidvalidity != state->uidvalidity) {
		*error_r = t_strdup_printf("Mailbox UIDVALIDITY has changed %u->%u",
					    state->uidvalidity, status.uidvalidity);
		mailbox_free(&box);
		return -1;
	}
	if (status.uidnext < state->uidnext) {
		*error_r = t_strdup_printf("Mailbox UIDNEXT shrank %u -> %u",
					   state->uidnext, status.uidnext);
		mailbox_free(&box);
		return -1;
	}
	if (status.highest_modseq < state->highest_modseq) {
		*error_r = t_strdup_printf("Mailbox HIGHESTMODSEQ shrank %"PRIu64" -> %"PRIu64,
					   state->highest_modseq,
					   status.highest_modseq);
		mailbox_free(&box);
		return -1;
	}

	client->mailbox = box;
	client->mailbox_examined = state->examined;
	client->messages_count = status.messages;
	client->uidvalidity = status.uidvalidity;
	client->notify_uidnext = status.uidnext;

	if (import_send_expunges(client, state, &expunge_count, error_r) < 0)
		return -1;
	i_assert(expunge_count <= state->messages);
	if (state->messages - expunge_count > client->messages_count) {
		*error_r = t_strdup_printf("Mailbox message count shrank %u -> %u",
					   client->messages_count,
					   state->messages - expunge_count);
		return -1;
	}

	client_update_mailbox_flags(client, status.keywords);
	array_foreach(&state->recent_uids, range) {
		for (uid = range->seq1; uid <= range->seq2; uid++) {
			uint32_t seq;

			if (mail_index_lookup_seq(box->view, uid, &seq))
				mailbox_recent_flags_set_uid_forced(box, uid);
		}
	}
	client->recent_count = mailbox_recent_flags_count(box);

	if (state->messages - expunge_count < client->messages_count) {
		/* new messages arrived */
		new_mails_count = client->messages_count -
			(state->messages - expunge_count);
		client_send_line(client,
			t_strdup_printf("* %u EXISTS", client->messages_count));
		client_send_line(client,
			t_strdup_printf("* %u RECENT", client->recent_count));
	}

	if (array_count(status.keywords) == state->keywords_count &&
	    mailbox_status_keywords_crc32(&status) == state->keywords_crc32) {
		/* no changes to keywords */
		client->keywords.announce_count = state->keywords_count;
	} else {
		client_send_mailbox_flags(client, TRUE);
	}
	if (import_send_flag_changes(client, state, &flag_change_count) < 0) {
		*error_r = "Couldn't send flag changes";
		return -1;
	}
	if (client_has_enabled(client, imap_feature_qresync) &&
	    !client->nonpermanent_modseqs &&
	    status.highest_modseq != state->highest_modseq) {
		client_send_line(client, t_strdup_printf(
			"* OK [HIGHESTMODSEQ %"PRIu64"] Highest",
			status.highest_modseq));
		client->sync_last_full_modseq = status.highest_modseq;
	}
	e_debug(client->event,
		"Unhibernation sync: %u expunges, %u new messages, %u flag changes, %"PRIu64" modseq changes",
		expunge_count, new_mails_count, flag_change_count,
		status.highest_modseq - state->highest_modseq);
	return 0;
}

static ssize_t
import_state_mailbox(struct client *client, const unsigned char *data,
		     size_t size, const char **error_r)
{
	struct mailbox_import_state state;
	ssize_t ret;

	if (client->mailbox != NULL) {
		*error_r = "Duplicate mailbox state";
		return 0;
	}

	ret = import_state_mailbox_struct(data, size, &state, error_r);
	if (ret <= 0) {
		i_assert(*error_r != NULL);
		return ret;
	}
	if (import_state_mailbox_open(client, &state, error_r) < 0) {
		*error_r = t_strdup_printf("Mailbox %s: %s", state.vname, *error_r);
		return -1;
	}
	return ret;
}

static ssize_t
import_state_enabled_feature(struct client *client, const unsigned char *data,
			     size_t size, const char **error_r)
{
	const unsigned char *p = data, *end = data + size;
	const char *name;
	unsigned int feature_idx;

	if (import_string(&p, end, &name) < 0) {
		*error_r = "Mailbox state truncated at name";
		return 0;
	}
	if (!imap_feature_lookup(name, &feature_idx)) {
		*error_r = t_strdup_printf("Unknown feature '%s'", name);
		return 0;
	}
	client_enable(client, feature_idx);
	return p - data;
}

static ssize_t
import_state_searchres(struct client *client, const unsigned char *data,
		       size_t size, const char **error_r)
{
	const unsigned char *p = data;

	i_array_init(&client->search_saved_uidset, 128);
	if (import_seq_range(&p, data+size, &client->search_saved_uidset) < 0) {
		*error_r = "Invalid SEARCHRES seq-range";
		return 0;
	}
	return p - data;
}

static ssize_t
import_state_id_logged(struct client *client,
		       const unsigned char *data ATTR_UNUSED,
		       size_t size ATTR_UNUSED,
		       const char **error_r ATTR_UNUSED)
{
	client->id_logged = TRUE;
	return 0;
}

static ssize_t
import_state_tls_compression(struct client *client,
			     const unsigned char *data ATTR_UNUSED,
			     size_t size ATTR_UNUSED,
			     const char **error_r ATTR_UNUSED)
{
	client->tls_compression = TRUE;
	return 0;
}

void imap_state_import_idle_cmd_tag(struct client *client, const char *tag)
{
	if (client->state_import_idle_continue) {
		/* IDLE command continues */
		struct client_command_context *cmd;
		struct command *command;

		cmd = client_command_alloc(client);
		cmd->tag = p_strdup(cmd->pool, tag);
		cmd->name = "IDLE";

		command = command_find("IDLE");
		i_assert(command != NULL);
		cmd->func = command->func;
		cmd->cmd_flags = command->flags;
		client_command_init_finished(cmd);

		if (command_exec(cmd)) {
			/* IDLE terminated because of an external change, but
			   DONE was already buffered */
			client_command_free(&cmd);
			client_add_missing_io(client);
		} else {
			i_assert(cmd->state == CLIENT_COMMAND_STATE_WAIT_INPUT ||
				 cmd->state == CLIENT_COMMAND_STATE_WAIT_OUTPUT);
		}
	} else {
		/* we're finishing IDLE command */
		client_send_line(client, t_strdup_printf(
			"%s %s Idle completed.", tag,
			client->state_import_bad_idle_done ? "BAD" : "OK"));
	}
}

static struct {
	enum imap_state_type_public type;
	ssize_t (*import)(struct client *client, const unsigned char *data,
			  size_t size, const char **error_r);
} imap_states_public[] = {
	{ IMAP_STATE_TYPE_MAILBOX, import_state_mailbox },
	{ IMAP_STATE_TYPE_ENABLED_FEATURE, import_state_enabled_feature },
	{ IMAP_STATE_TYPE_SEARCHRES, import_state_searchres }
};

static struct {
	enum imap_state_type_internal type;
	ssize_t (*import)(struct client *client, const unsigned char *data,
			  size_t size, const char **error_r);
} imap_states_internal[] = {
	{ IMAP_STATE_TYPE_ID_LOGGED, import_state_id_logged },
	{ IMAP_STATE_TYPE_TLS_COMPRESSION, import_state_tls_compression }
};

static ssize_t
imap_state_try_import_public(struct client *client, const unsigned char *data,
			     size_t size, const char **error_r)
{
	unsigned int i;
	ssize_t ret;

	i_assert(size > 0);

	for (i = 0; i < N_ELEMENTS(imap_states_public); i++) {
		if (imap_states_public[i].type == data[0]) {
			ret = imap_states_public[i].
				import(client, data+1, size-1, error_r);
			return ret < 0 ? -1 : ret+1;
		}
	}
	return -2;
}

static ssize_t
imap_state_try_import_internal(struct client *client, const unsigned char *data,
			       size_t size, const char **error_r)
{
	unsigned int i;
	ssize_t ret;

	i_assert(size > 0);

	for (i = 0; i < N_ELEMENTS(imap_states_internal); i++) {
		if (imap_states_internal[i].type == data[0]) {
			ret = imap_states_internal[i].
				import(client, data+1, size-1, error_r);
			return ret < 0 ? -1 : ret+1;
		}
	}
	return -2;
}

ssize_t imap_state_import_base(struct client *client, bool internal,
			       const unsigned char *data, size_t size,
			       const char **error_r)
{
	const unsigned char *p;
	ssize_t ret;
	size_t pos;

	i_assert(client->mailbox == NULL);

	*error_r = NULL;

	if (size < 5 || memcmp(data, "base\n", 5) != 0) {
		p = memchr(data, '\n', size);
		if (p == NULL)
			p = data + I_MIN(size, 20);
		*error_r = t_strdup_printf("Unknown state block '%s'",
					   str_sanitize(t_strdup_until(data, p), 20));
		return 0;
	}

	pos = 5;
	while (pos < size) {
		ret = imap_state_try_import_public(client, data+pos,
						   size-pos, error_r);
		if (ret == -2 && internal) {
			ret = imap_state_try_import_internal(client, data+pos,
							     size-pos, error_r);
		}
		if (ret < 0 || *error_r != NULL) {
			if (ret == -2) {
				*error_r = t_strdup_printf("Unknown type '%c'",
							   data[pos]);
			}
			i_assert(*error_r != NULL);
			return ret < 0 ? -1 : 0;
		}
		i_assert(size - pos >= (size_t)ret);
		pos += ret;
	}
	return pos;
}
